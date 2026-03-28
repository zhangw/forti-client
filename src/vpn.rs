use crate::auth::xml::TunnelConfig;
use crate::error::{FortiError, Result};
use crate::ppp::codec::{PppFrame, PppProtocol};
use crate::ppp::lcp::{LcpCode, LcpState};
use crate::tunnel::TlsTunnel;
use crate::tun;

use std::time::Duration;
use tracing::{debug, error, info};

/// Run the VPN data plane: TUN device, routes, DNS, packet forwarding, keepalive.
///
/// Takes ownership of the tunnel and runs until disconnection (Ctrl+C, dead peer, or error).
/// Handles all cleanup on exit.
pub async fn run(
    mut tunnel: TlsTunnel,
    mut lcp: LcpState,
    config: &TunnelConfig,
) -> Result<()> {
    // 1. Create TUN device
    let (tun_dev, iface_name) = tun::create_tun(config.ip_address)?;

    // 2. Install routes
    tun::routes::install_routes(&config.routes, &iface_name)?;

    // 3. Configure DNS
    tun::dns::configure_dns(&config.dns_servers)?;

    info!(
        "VPN active on {} — IP={}, {} routes, {} DNS servers",
        iface_name,
        config.ip_address,
        config.routes.len(),
        config.dns_servers.len(),
    );
    info!("Press Ctrl+C to disconnect.");

    // 4. Run the event loop
    let result = event_loop(&mut tunnel, &mut lcp, &tun_dev).await;

    // 5. Cleanup (always runs)
    info!("Cleaning up...");
    tun::routes::remove_routes(&config.routes, &iface_name);
    tun::dns::remove_dns();

    let _ = send_ppp(&mut tunnel, PppProtocol::Lcp, lcp.build_terminate_request()).await;

    info!("VPN disconnected.");
    result
}

async fn event_loop(
    tunnel: &mut TlsTunnel,
    lcp: &mut LcpState,
    tun_dev: &tun_rs::AsyncDevice,
) -> Result<()> {
    let mut keepalive = tokio::time::interval(Duration::from_secs(10));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut missed_echoes: u32 = 0;
    let mut tun_buf = vec![0u8; 4096];
    let mut pkt_count: u64 = 0;

    loop {
        tokio::select! {
            // TUN → Tunnel (outbound: app sends packet through VPN)
            result = tun_dev.recv(&mut tun_buf) => {
                let n = result.map_err(|e| FortiError::TunnelError(
                    format!("TUN read error: {}", e)
                ))?;
                if n == 0 {
                    continue;
                }

                // tun-rs on macOS gives raw IP packets (no AF header).
                // Determine IP version from the first nibble.
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
                send_ppp(tunnel, protocol, tun_buf[..n].to_vec()).await?;
            }

            // Tunnel → TUN (inbound: FortiGate sends packet to us)
            result = tunnel.recv_frame() => {
                let frame = result?;
                let ppp = PppFrame::decode(frame.payload())?;

                match ppp.protocol() {
                    PppProtocol::Ipv4 => {
                        // tun-rs expects raw IP packets (no AF header)
                        pkt_count += 1;
                        if pkt_count <= 10 {
                            debug!("Tunnel → TUN: {} bytes IPv4", ppp.data().len());
                        }
                        tun_dev.send(ppp.data()).await.map_err(|e| {
                            FortiError::TunnelError(format!("TUN write error: {}", e))
                        })?;
                    }
                    PppProtocol::Lcp => {
                        let code = LcpCode::from_u8(ppp.data().first().copied().unwrap_or(0));
                        let responses = lcp.handle_packet(ppp.data());
                        for resp in responses {
                            send_ppp(tunnel, PppProtocol::Lcp, resp).await?;
                        }
                        if code == LcpCode::EchoReply {
                            missed_echoes = 0;
                        }
                        if code == LcpCode::TerminateRequest {
                            info!("Server sent LCP Terminate-Request");
                            return Ok(());
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
                send_ppp(tunnel, PppProtocol::Lcp, lcp.build_echo_request()).await?;
                missed_echoes += 1;
                if missed_echoes > 3 {
                    error!("Dead peer detected ({} missed echoes)", missed_echoes);
                    return Err(FortiError::TunnelError("dead peer detected".into()));
                }
            }

            // Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received");
                return Ok(());
            }
        }
    }
}

async fn send_ppp(tunnel: &mut TlsTunnel, protocol: PppProtocol, data: Vec<u8>) -> Result<()> {
    let frame = PppFrame::new(protocol, data);
    tunnel.send_frame(frame.encode()).await
}
