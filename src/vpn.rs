use crate::auth::xml::TunnelConfig;
use crate::error::{FortiError, Result};
use crate::ppp::codec::{PppFrame, PppProtocol};
use crate::ppp::lcp::LcpState;
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

    // Send LCP Terminate-Request (best-effort)
    let term_req = lcp.build_terminate_request();
    let ppp_frame = PppFrame::new(PppProtocol::Lcp, term_req);
    let _ = tunnel.send_frame(ppp_frame.encode()).await;

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

    loop {
        tokio::select! {
            // TUN -> Tunnel (outbound: app sends packet through VPN)
            result = tun_dev.recv(&mut tun_buf) => {
                let n = result.map_err(|e| FortiError::TunnelError(
                    format!("TUN read error: {}", e)
                ))?;
                if n <= 4 {
                    continue; // too short -- no IP packet after AF header
                }
                // Strip the 4-byte AF header (macOS utun requirement)
                let ip_packet = &tun_buf[4..n];
                let ppp = PppFrame::new(PppProtocol::Ipv4, ip_packet.to_vec());
                tunnel.send_frame(ppp.encode()).await?;
            }

            // Tunnel -> TUN (inbound: FortiGate sends packet to us)
            result = tunnel.recv_frame() => {
                let frame = result?;
                let ppp = PppFrame::decode(frame.payload())?;

                match ppp.protocol() {
                    PppProtocol::Ipv4 => {
                        // Prepend 4-byte AF_INET header for macOS utun
                        let mut buf = vec![0u8, 0, 0, 2]; // AF_INET = 2
                        buf.extend_from_slice(ppp.data());
                        tun_dev.send(&buf).await.map_err(|e| {
                            FortiError::TunnelError(format!("TUN write error: {}", e))
                        })?;
                    }
                    PppProtocol::Lcp => {
                        let code = ppp.data().first().copied().unwrap_or(0);
                        let responses = lcp.handle_packet(ppp.data());
                        for resp in responses {
                            let ppp_frame = PppFrame::new(PppProtocol::Lcp, resp);
                            tunnel.send_frame(ppp_frame.encode()).await?;
                        }
                        if code == 10 {
                            // Echo-Reply received -- peer is alive
                            missed_echoes = 0;
                        }
                        if code == 5 {
                            // Terminate-Request from server
                            info!("Server sent LCP Terminate-Request");
                            return Ok(());
                        }
                    }
                    PppProtocol::Ipv6 => {
                        debug!("Ignoring IPv6 packet");
                    }
                    other => {
                        debug!("Ignoring PPP protocol {:?}", other);
                    }
                }
            }

            // Keepalive timer
            _ = keepalive.tick() => {
                let echo = lcp.build_echo_request();
                let ppp_frame = PppFrame::new(PppProtocol::Lcp, echo);
                tunnel.send_frame(ppp_frame.encode()).await?;
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
