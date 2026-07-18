use crate::auth::xml::TunnelConfig;
use crate::error::{FortiError, Result};
use crate::power_monitor::PowerEvent;
use crate::ppp::codec::{PppFrame, PppProtocol};
use crate::ppp::lcp::{LcpCode, LcpState};
use crate::reconnect::DisconnectReason;
use crate::shutdown::Shutdown;
use crate::tun;
use crate::tunnel::TlsTunnel;

use std::future::Future;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Set up TUN device, routes, and DNS. Returns the device and interface name.
pub async fn setup_tun(
    config: &TunnelConfig,
    shutdown: &Shutdown,
) -> Result<(tun_rs::AsyncDevice, String)> {
    let (tun_dev, iface_name) = tun::create_tun(config.ip_address)?;
    if let Err(error) = tun::routes::install_routes(&config.routes, &iface_name, shutdown).await {
        tun::routes::remove_routes(&config.routes, &iface_name).await;
        return Err(error);
    }
    if let Err(error) = tun::dns::configure_dns(&config.dns_servers, shutdown).await {
        tun::routes::remove_routes(&config.routes, &iface_name).await;
        tun::dns::remove_dns().await;
        return Err(error);
    }

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
pub async fn cleanup_tun(config: &TunnelConfig, iface_name: &str) {
    info!("Cleaning up routes and DNS...");
    tun::routes::remove_routes(&config.routes, iface_name).await;
    tun::dns::remove_dns().await;
}

async fn next_power_event(rx: &mut mpsc::UnboundedReceiver<PowerEvent>) -> PowerEvent {
    match rx.recv().await {
        Some(event) => event,
        None => std::future::pending().await,
    }
}

/// Await an operation while retaining immediate shutdown and sleep handling.
async fn interruptible<T>(
    operation: impl Future<Output = T>,
    shutdown: &Shutdown,
    power_rx: &mut mpsc::UnboundedReceiver<PowerEvent>,
) -> std::result::Result<T, DisconnectReason> {
    tokio::pin!(operation);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Err(DisconnectReason::UserQuit),
            event = next_power_event(power_rx) => {
                if event == PowerEvent::WillSleep {
                    return Err(DisconnectReason::SystemSleep);
                }
            }
            result = &mut operation => return Ok(result),
        }
    }
}

/// Run the VPN data plane event loop.
///
/// Every potentially blocking I/O operation remains interruptible by the
/// process-wide shutdown signal and by a system sleep notification.
pub async fn event_loop(
    tunnel: &mut TlsTunnel,
    lcp: &mut LcpState,
    tun_dev: &tun_rs::AsyncDevice,
    shutdown: &Shutdown,
    power_rx: &mut mpsc::UnboundedReceiver<PowerEvent>,
) -> DisconnectReason {
    let mut keepalive = tokio::time::interval(Duration::from_secs(10));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut missed_echoes: u32 = 0;
    let mut tun_buf = vec![0u8; 4096];
    let mut pkt_count: u64 = 0;
    let mut last_tick = std::time::Instant::now();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                info!("Shutdown requested");
                return DisconnectReason::UserQuit;
            }
            event = next_power_event(power_rx) => {
                if event == PowerEvent::WillSleep {
                    info!("System sleep requested");
                    return DisconnectReason::SystemSleep;
                }
            }

            // TUN → Tunnel
            result = tun_dev.recv(&mut tun_buf) => {
                let n = match result {
                    Ok(n) => n,
                    Err(e) => return DisconnectReason::IoError(format!("TUN read error: {}", e)),
                };
                if n == 0 { continue; }

                let protocol = match tun_buf[0] >> 4 {
                    4 => PppProtocol::Ipv4,
                    6 => {
                        debug!("TUN: ignoring outbound IPv6 packet");
                        continue;
                    }
                    version => {
                        debug!("TUN: unknown IP version {}, skipping", version);
                        continue;
                    }
                };

                pkt_count += 1;
                if pkt_count <= 5 {
                    debug!("TUN → tunnel: {} bytes IPv4", n);
                }
                match interruptible(
                    send_ppp(tunnel, protocol, tun_buf[..n].to_vec()),
                    shutdown,
                    power_rx,
                ).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return DisconnectReason::IoError(format!("tunnel send error: {}", e)),
                    Err(reason) => return reason,
                }
            }

            // Tunnel → TUN
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
                        match interruptible(tun_dev.send(ppp.data()), shutdown, power_rx).await {
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => return DisconnectReason::IoError(format!("TUN write error: {}", e)),
                            Err(reason) => return reason,
                        }
                    }
                    PppProtocol::Lcp => {
                        let code = LcpCode::from_u8(ppp.data().first().copied().unwrap_or(0));
                        let responses = lcp.handle_packet(ppp.data());
                        for resp in responses {
                            match interruptible(
                                send_ppp(tunnel, PppProtocol::Lcp, resp),
                                shutdown,
                                power_rx,
                            ).await {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => return DisconnectReason::IoError(format!("LCP send error: {}", e)),
                                Err(reason) => return reason,
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
                    PppProtocol::Ipv6 => debug!("Ignoring inbound IPv6 packet"),
                    other => debug!("Ignoring PPP protocol {:?}", other),
                }
            }

            _ = keepalive.tick() => {
                if crate::reconnect::detect_sleep_gap(last_tick, Duration::from_secs(10)) {
                    info!("Timing gap detected ({}s since last tick) — possible sleep/wake",
                        last_tick.elapsed().as_secs());
                    return DisconnectReason::DeadPeer;
                }
                last_tick = std::time::Instant::now();

                match interruptible(
                    send_ppp(tunnel, PppProtocol::Lcp, lcp.build_echo_request()),
                    shutdown,
                    power_rx,
                ).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return DisconnectReason::IoError(format!("keepalive send error: {}", e)),
                    Err(reason) => return reason,
                }
                missed_echoes += 1;
                if missed_echoes > 3 {
                    error!("Dead peer detected ({} missed echoes)", missed_echoes);
                    return DisconnectReason::DeadPeer;
                }
            }
        }
    }
}

async fn send_ppp(tunnel: &mut TlsTunnel, protocol: PppProtocol, data: Vec<u8>) -> Result<()> {
    let frame = PppFrame::new(protocol, data);
    tunnel.send_frame(frame.encode()).await
}
