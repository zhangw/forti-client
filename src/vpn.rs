use crate::auth::xml::TunnelConfig;
use crate::error::{FortiError, Result};
use crate::power_monitor::PowerEvent;
use crate::ppp::codec::{PppFrame, PppProtocol};
use crate::ppp::lcp::{LcpCode, LcpState};
use crate::reconnect::DisconnectReason;
use crate::shutdown::Shutdown;
use crate::tun;
use crate::tunnel::codec::FortinetFrame;
use crate::tunnel::TlsTunnel;

use std::future::Future;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

async fn finish_tun_setup<
    RouteSetup,
    DnsSetup,
    Cleanup,
    RouteFuture,
    DnsFuture,
    CleanupFuture,
    RouteOutput,
    DnsOutput,
>(
    route_setup: RouteSetup,
    dns_setup: DnsSetup,
    cleanup: Cleanup,
) -> Result<()>
where
    RouteSetup: FnOnce() -> RouteFuture,
    DnsSetup: FnOnce() -> DnsFuture,
    Cleanup: FnOnce() -> CleanupFuture,
    RouteFuture: Future<Output = Result<RouteOutput>>,
    DnsFuture: Future<Output = Result<DnsOutput>>,
    CleanupFuture: Future<Output = ()>,
{
    if let Err(error) = route_setup().await {
        cleanup().await;
        return Err(error);
    }
    if let Err(error) = dns_setup().await {
        cleanup().await;
        return Err(error);
    }
    Ok(())
}

/// Set up TUN device, routes, and DNS. Returns the device and interface name.
pub async fn setup_tun(
    config: &TunnelConfig,
    shutdown: &Shutdown,
) -> Result<(tun_rs::AsyncDevice, String)> {
    let (tun_dev, iface_name) = tun::create_tun(config.ip_address)?;
    finish_tun_setup(
        || tun::routes::install_routes(&config.routes, &iface_name, shutdown),
        || tun::dns::configure_dns(&config.dns_servers, shutdown),
        || cleanup_tun(config, &iface_name),
    )
    .await?;

    info!(
        "VPN active on {} — IP={}, {} routes, {} DNS servers",
        iface_name,
        config.ip_address,
        config.routes.len(),
        config.dns_servers.len(),
    );

    Ok((tun_dev, iface_name))
}

async fn cleanup_with_deadline<RouteCleanup, DnsCleanup>(
    route_cleanup: RouteCleanup,
    dns_cleanup: DnsCleanup,
    deadline: Duration,
) -> bool
where
    RouteCleanup: Future<Output = ()>,
    DnsCleanup: Future<Output = ()>,
{
    tokio::time::timeout(deadline, async {
        route_cleanup.await;
        dns_cleanup.await;
    })
    .await
    .is_ok()
}

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Remove routes and DNS configuration under one global deadline.
pub async fn cleanup_tun(config: &TunnelConfig, iface_name: &str) {
    info!("Starting bounded VPN route/DNS cleanup");
    let cleanup_phase = std::sync::atomic::AtomicU8::new(0);
    let completed = cleanup_with_deadline(
        async {
            info!("Removing VPN routes");
            tun::routes::remove_routes(&config.routes, iface_name).await;
        },
        async {
            cleanup_phase.store(1, std::sync::atomic::Ordering::Relaxed);
            info!("Removing VPN DNS configuration");
            tun::dns::remove_dns().await;
        },
        CLEANUP_TIMEOUT,
    )
    .await;

    if !completed {
        if cleanup_phase.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            error!("Route cleanup exceeded the global 10s deadline; DNS cleanup was skipped");
        } else {
            error!("DNS cleanup exceeded the remaining global 10s deadline");
        }
    }
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
        if shutdown.is_cancelled() {
            return Err(DisconnectReason::UserQuit);
        }
        tokio::select! {
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

trait TunIo {
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize>;
    async fn send(&self, packet: &[u8]) -> std::io::Result<usize>;
}

impl TunIo for tun_rs::AsyncDevice {
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        tun_rs::AsyncDevice::recv(self, buffer).await
    }

    async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        tun_rs::AsyncDevice::send(self, packet).await
    }
}

trait TunnelIo {
    async fn recv_frame(&mut self) -> Result<FortinetFrame>;
    async fn send_frame(&mut self, payload: Vec<u8>) -> Result<()>;
}

impl TunnelIo for TlsTunnel {
    async fn recv_frame(&mut self) -> Result<FortinetFrame> {
        TlsTunnel::recv_frame(self).await
    }

    async fn send_frame(&mut self, payload: Vec<u8>) -> Result<()> {
        TlsTunnel::send_frame(self, payload).await
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
    event_loop_with_io(tunnel, lcp, tun_dev, shutdown, power_rx).await
}

async fn event_loop_with_io<Tunnel, Tun>(
    tunnel: &mut Tunnel,
    lcp: &mut LcpState,
    tun_dev: &Tun,
    shutdown: &Shutdown,
    power_rx: &mut mpsc::UnboundedReceiver<PowerEvent>,
) -> DisconnectReason
where
    Tunnel: TunnelIo,
    Tun: TunIo,
{
    let mut keepalive = tokio::time::interval(Duration::from_secs(10));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut missed_echoes: u32 = 0;
    let mut tun_buf = vec![0u8; 4096];
    let mut pkt_count: u64 = 0;
    let mut last_tick = std::time::Instant::now();

    loop {
        if shutdown.is_cancelled() {
            info!("Shutdown requested");
            return DisconnectReason::UserQuit;
        }
        tokio::select! {
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
                    Err(FortiError::TunnelClosed) => {
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

async fn send_ppp<Tunnel: TunnelIo>(
    tunnel: &mut Tunnel,
    protocol: PppProtocol,
    data: Vec<u8>,
) -> Result<()> {
    let frame = PppFrame::new(protocol, data);
    tunnel.send_frame(frame.encode()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn cleanup_deadline_covers_routes_and_dns_as_one_budget() {
        let cleanup = cleanup_with_deadline(
            async { tokio::time::sleep(Duration::from_secs(8)).await },
            async { tokio::time::sleep(Duration::from_secs(8)).await },
            Duration::from_secs(10),
        );
        assert!(!cleanup.await);
    }

    #[tokio::test]
    async fn interruptible_observes_already_cancelled_shutdown() {
        let shutdown = Shutdown::new();
        shutdown.cancel();
        let (_power_tx, mut power_rx) = mpsc::unbounded_channel();
        let result = interruptible(std::future::pending::<()>(), &shutdown, &mut power_rx).await;
        assert_eq!(result, Err(DisconnectReason::UserQuit));
    }

    #[tokio::test]
    async fn dns_setup_failure_runs_shared_cleanup() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let result = finish_tun_setup(
            {
                let calls = calls.clone();
                move || async move {
                    calls.lock().unwrap().push("routes");
                    Ok(())
                }
            },
            {
                let calls = calls.clone();
                move || async move {
                    calls.lock().unwrap().push("dns");
                    Err::<(), _>(FortiError::TunnelError("dns failed".into()))
                }
            },
            {
                let calls = calls.clone();
                move || async move { calls.lock().unwrap().push("cleanup") }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(*calls.lock().unwrap(), ["routes", "dns", "cleanup"]);
    }

    #[tokio::test]
    async fn route_setup_failure_skips_dns_and_runs_shared_cleanup() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let result = finish_tun_setup(
            {
                let calls = calls.clone();
                move || async move {
                    calls.lock().unwrap().push("routes");
                    Err::<(), _>(FortiError::TunnelError("routes failed".into()))
                }
            },
            {
                let calls = calls.clone();
                move || async move {
                    calls.lock().unwrap().push("dns");
                    Ok(())
                }
            },
            {
                let calls = calls.clone();
                move || async move { calls.lock().unwrap().push("cleanup") }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(*calls.lock().unwrap(), ["routes", "cleanup"]);
    }

    #[derive(Default)]
    struct Progress {
        tun_reads: usize,
        tun_writes: usize,
        tunnel_reads: usize,
        tunnel_writes: usize,
        keepalives: usize,
    }

    struct FakeTun {
        progress: std::sync::Arc<std::sync::Mutex<Progress>>,
    }

    impl TunIo for FakeTun {
        async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.progress.lock().unwrap().tun_reads += 1;
            buffer[..4].copy_from_slice(&[0x45, 0, 0, 0]);
            Ok(4)
        }

        async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
            self.progress.lock().unwrap().tun_writes += 1;
            Ok(packet.len())
        }
    }

    struct FakeTunnel {
        progress: std::sync::Arc<std::sync::Mutex<Progress>>,
    }

    impl TunnelIo for FakeTunnel {
        async fn recv_frame(&mut self) -> Result<FortinetFrame> {
            let mut progress = self.progress.lock().unwrap();
            if progress.tun_reads > 0
                && progress.tun_writes > 0
                && progress.tunnel_reads > 0
                && progress.tunnel_writes > 0
                && progress.keepalives > 0
            {
                return Err(FortiError::TunnelClosed);
            }
            progress.tunnel_reads += 1;
            drop(progress);
            Ok(FortinetFrame::new(
                PppFrame::new(PppProtocol::Ipv4, vec![0x45, 0, 0, 0]).encode(),
            ))
        }

        async fn send_frame(&mut self, payload: Vec<u8>) -> Result<()> {
            if let Ok(frame) = PppFrame::decode(&payload) {
                let mut progress = self.progress.lock().unwrap();
                match frame.protocol() {
                    PppProtocol::Lcp => progress.keepalives += 1,
                    PppProtocol::Ipv4 => progress.tunnel_writes += 1,
                    _ => {}
                }
            }
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn actual_event_loop_kernel_gives_all_ready_sources_progress() {
        let progress = std::sync::Arc::new(std::sync::Mutex::new(Progress::default()));
        let mut tunnel = FakeTunnel {
            progress: progress.clone(),
        };
        let tun = FakeTun {
            progress: progress.clone(),
        };
        let mut lcp = LcpState::new(1500);
        let shutdown = Shutdown::new();
        let (_power_tx, mut power_rx) = mpsc::unbounded_channel();

        let reason =
            event_loop_with_io(&mut tunnel, &mut lcp, &tun, &shutdown, &mut power_rx).await;
        assert_eq!(reason, DisconnectReason::TunnelClosed);
        let progress = progress.lock().unwrap();
        assert!(progress.tun_reads > 0);
        assert!(progress.tun_writes > 0);
        assert!(progress.tunnel_reads > 0);
        assert!(progress.tunnel_writes > 0);
        assert!(progress.keepalives > 0);
    }
}
