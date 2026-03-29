use crate::auth::xml::TunnelConfig;
use crate::error::{FortiError, Result};
use crate::ppp::codec::{PppFrame, PppProtocol};
use crate::ppp::lcp::{LcpCode, LcpState};
use crate::reconnect::DisconnectReason;
use crate::tunnel::TlsTunnel;
use crate::tun;

use std::time::Duration;
use tracing::{debug, error, info};

/// Set up TUN device, routes, and DNS. Returns the device and interface name.
pub fn setup_tun(config: &TunnelConfig) -> Result<(tun_rs::AsyncDevice, String)> {
    let (tun_dev, iface_name) = tun::create_tun(config.ip_address)?;
    tun::routes::install_routes(&config.routes, &iface_name)?;
    tun::dns::configure_dns(&config.dns_servers)?;

    info!(
        "VPN active on {} — IP={}, {} routes, {} DNS servers",
        iface_name,
        config.ip_address,
        config.routes.len(),
        config.dns_servers.len(),
    );

    Ok((tun_dev, iface_name))
}

/// Remove routes and DNS configuration.
pub fn cleanup_tun(config: &TunnelConfig, iface_name: &str) {
    info!("Cleaning up routes and DNS...");
    tun::routes::remove_routes(&config.routes, iface_name);
    tun::dns::remove_dns();
}

/// Run the VPN data plane event loop.
///
/// Forwards packets between the TUN device and the TLS tunnel, handles LCP
/// keepalive, and listens for Ctrl+C.
///
/// Returns a `DisconnectReason` indicating why the loop exited.
pub async fn event_loop(
    tunnel: &mut TlsTunnel,
    lcp: &mut LcpState,
    tun_dev: &tun_rs::AsyncDevice,
) -> DisconnectReason {
    let mut keepalive = tokio::time::interval(Duration::from_secs(10));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut missed_echoes: u32 = 0;
    let mut tun_buf = vec![0u8; 4096];
    let mut pkt_count: u64 = 0;

    loop {
        tokio::select! {
            // TUN → Tunnel (outbound: app sends packet through VPN)
            result = tun_dev.recv(&mut tun_buf) => {
                let n = match result {
                    Ok(n) => n,
                    Err(e) => return DisconnectReason::IoError(format!("TUN read error: {}", e)),
                };
                if n == 0 {
                    continue;
                }

                let version = tun_buf[0] >> 4;
                let protocol = match version {
                    4 => PppProtocol::Ipv4,
                    6 => {
                        debug!("TUN: ignoring outbound IPv6 packet");
                        continue;
                    }
                    _ => {
                        debug!("TUN: unknown IP version {}, skipping", version);
                        continue;
                    }
                };

                pkt_count += 1;
                if pkt_count <= 5 {
                    debug!("TUN → tunnel: {} bytes IPv4", n);
                }
                if let Err(e) = send_ppp(tunnel, protocol, tun_buf[..n].to_vec()).await {
                    return DisconnectReason::IoError(format!("tunnel send error: {}", e));
                }
            }

            // Tunnel → TUN (inbound: FortiGate sends packet to us)
            result = tunnel.recv_frame() => {
                let frame = match result {
                    Ok(f) => f,
                    Err(FortiError::TunnelError(msg)) if msg.contains("tunnel closed") => {
                        return DisconnectReason::TunnelClosed;
                    }
                    Err(e) => return DisconnectReason::IoError(format!("tunnel recv error: {}", e)),
                };
                let ppp = match PppFrame::decode(frame.payload()) {
                    Ok(p) => p,
                    Err(e) => {
                        debug!("PPP decode error: {}, skipping frame", e);
                        continue;
                    }
                };

                match ppp.protocol() {
                    PppProtocol::Ipv4 => {
                        pkt_count += 1;
                        if pkt_count <= 10 {
                            debug!("Tunnel → TUN: {} bytes IPv4", ppp.data().len());
                        }
                        if let Err(e) = tun_dev.send(ppp.data()).await {
                            return DisconnectReason::IoError(format!("TUN write error: {}", e));
                        }
                    }
                    PppProtocol::Lcp => {
                        let code = LcpCode::from_u8(ppp.data().first().copied().unwrap_or(0));
                        let responses = lcp.handle_packet(ppp.data());
                        for resp in responses {
                            if let Err(e) = send_ppp(tunnel, PppProtocol::Lcp, resp).await {
                                return DisconnectReason::IoError(format!("LCP send error: {}", e));
                            }
                        }
                        if code == LcpCode::EchoReply {
                            missed_echoes = 0;
                        }
                        if code == LcpCode::TerminateRequest {
                            info!("Server sent LCP Terminate-Request");
                            return DisconnectReason::ServerTerminated;
                        }
                    }
                    PppProtocol::Ipv6 => {
                        debug!("Ignoring inbound IPv6 packet");
                    }
                    other => {
                        debug!("Ignoring PPP protocol {:?}", other);
                    }
                }
            }

            // Keepalive timer
            _ = keepalive.tick() => {
                if let Err(e) = send_ppp(tunnel, PppProtocol::Lcp, lcp.build_echo_request()).await {
                    return DisconnectReason::IoError(format!("keepalive send error: {}", e));
                }
                missed_echoes += 1;
                if missed_echoes > 3 {
                    error!("Dead peer detected ({} missed echoes)", missed_echoes);
                    return DisconnectReason::DeadPeer;
                }
            }

            // Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received");
                return DisconnectReason::UserQuit;
            }
        }
    }
}

/// Legacy entry point — runs setup, event loop, and cleanup.
/// Kept for backward compatibility during transition; will be removed
/// once ReconnectController is wired in.
pub async fn run(
    mut tunnel: TlsTunnel,
    mut lcp: LcpState,
    config: &TunnelConfig,
) -> Result<()> {
    let (tun_dev, iface_name) = setup_tun(config)?;

    info!("Press Ctrl+C to disconnect.");

    let reason = event_loop(&mut tunnel, &mut lcp, &tun_dev).await;

    // Cleanup
    cleanup_tun(config, &iface_name);
    let _ = send_ppp(&mut tunnel, PppProtocol::Lcp, lcp.build_terminate_request()).await;
    info!("VPN disconnected.");

    match reason {
        DisconnectReason::UserQuit | DisconnectReason::ServerTerminated => Ok(()),
        DisconnectReason::DeadPeer => Err(FortiError::TunnelError("dead peer detected".into())),
        DisconnectReason::TunnelClosed => Err(FortiError::TunnelError("tunnel closed by peer".into())),
        DisconnectReason::IoError(msg) => Err(FortiError::TunnelError(msg)),
    }
}

async fn send_ppp(tunnel: &mut TlsTunnel, protocol: PppProtocol, data: Vec<u8>) -> Result<()> {
    let frame = PppFrame::new(protocol, data);
    tunnel.send_frame(frame.encode()).await
}
