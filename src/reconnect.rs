/// Reason the VPN event loop exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// 3+ missed LCP echo replies.
    DeadPeer,
    /// Peer sent EOF (TCP close).
    TunnelClosed,
    /// Server sent LCP Terminate-Request.
    ServerTerminated,
    /// TUN or TLS I/O failure.
    IoError(String),
    /// User pressed Ctrl+C.
    UserQuit,
}

/// What the reconnect controller should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconnectAction {
    /// Attempt reconnect reusing the existing SVPNCOOKIE.
    RetryWithCookie,
    /// Cookie expired or rejected — full re-authentication needed.
    ReAuthenticate,
    /// User requested exit — clean up and terminate.
    Exit,
}

/// Classify a disconnect reason into a reconnect action.
pub fn classify_disconnect(reason: &DisconnectReason) -> ReconnectAction {
    match reason {
        DisconnectReason::UserQuit => ReconnectAction::Exit,
        _ => ReconnectAction::RetryWithCookie,
    }
}

use std::time::{Duration, Instant};

/// Detect if the system likely slept by checking if elapsed time since the last
/// keepalive tick is much larger than expected (> 3x the interval).
pub fn detect_sleep_gap(last_tick: Instant, expected_interval: Duration) -> bool {
    last_tick.elapsed() > expected_interval * 3
}

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Exponential backoff timer: 1s, 2s, 4s, 8s, ..., capped at 60s.
pub struct Backoff {
    current: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Backoff {
    pub fn new() -> Self {
        Self {
            current: BACKOFF_INITIAL,
        }
    }

    /// Return the current backoff duration.
    pub fn current(&self) -> Duration {
        self.current
    }

    /// Advance to the next backoff interval.
    pub fn next(&mut self) {
        self.current = (self.current * 2).min(BACKOFF_MAX);
    }

    /// Reset backoff to initial value (after successful reconnect).
    pub fn reset(&mut self) {
        self.current = BACKOFF_INITIAL;
    }
}

use secrecy::{ExposeSecret, SecretString};

use crate::auth::xml::TunnelConfig;
use crate::auth::AuthClient;
use crate::error::{FortiError, Result};
use crate::network_monitor::{NetworkEvent, NetworkMonitor};
use crate::power_monitor::{PowerEvent, PowerMonitor};
use crate::ppp::codec::{PppFrame, PppProtocol};
use crate::ppp::PppEngine;
use crate::tunnel::TlsTunnel;
use crate::vpn;

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Current state of the reconnect controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial connection in progress.
    Connecting,
    /// Tunnel is up and forwarding traffic.
    Connected,
    /// Attempting to reconnect.
    Reconnecting,
    /// Cookie expired — running full re-authentication.
    ReAuthenticating,
    /// Waiting for network to return after sleep/wake (Layer 3).
    WaitingForNetwork,
    /// Final cleanup before exit.
    Cleanup,
}

/// Parameters needed to authenticate (for re-auth on cookie expiry).
pub struct AuthParams {
    pub server: String,
    pub port: u16,
    pub saml: bool,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub realm: Option<String>,
    pub tls_config: Arc<rustls::ClientConfig>,
    pub enable_keylog: bool,
}

/// Reconnect controller: owns TUN/routes/DNS, drives the reconnect state machine.
pub struct ReconnectController {
    auth_params: AuthParams,
    svpn_cookie: String,
    tunnel_config: TunnelConfig,
    backoff: Backoff,
    state: ConnectionState,
}

impl ReconnectController {
    pub fn new(auth_params: AuthParams, svpn_cookie: String, tunnel_config: TunnelConfig) -> Self {
        Self {
            auth_params,
            svpn_cookie,
            tunnel_config,
            backoff: Backoff::new(),
            state: ConnectionState::Connecting,
        }
    }

    /// Run the reconnect loop. Returns only on user quit or unrecoverable error.
    pub async fn run(&mut self) -> Result<()> {
        // Setup TUN, routes, DNS (persist across reconnects)
        let (mut tun_dev, mut iface_name) = vpn::setup_tun(&self.tunnel_config)?;
        let mut current_ip = self.tunnel_config.ip_address;
        info!("Press Ctrl+C to disconnect.");

        // Start network monitor (uses hostname, not SocketAddr — supports DNS names)
        let (_network_monitor, mut network_rx) = NetworkMonitor::start(&self.auth_params.server)
            .map_err(|e| FortiError::TunnelError(format!("network monitor failed: {}", e)))?;

        // Start power monitor
        let (_power_monitor, mut power_rx) = PowerMonitor::start()
            .map_err(|e| FortiError::TunnelError(format!("power monitor failed: {}", e)))?;

        self.state = ConnectionState::Connected;

        loop {
            // Connect tunnel + PPP
            // Known limitation: WillSleep events during connect_tunnel() are deferred
            // until the next tokio::select! iteration. The system will still sleep after
            // its 30s timeout, and the timing gap heuristic will catch it on wake.
            let connect_result = self.connect_tunnel().await;
            let (mut tunnel, mut lcp) = match connect_result {
                Ok((tunnel, lcp, new_ip)) => {
                    self.backoff.reset();
                    // If server assigned a different IP, recreate TUN device + routes
                    if new_ip != current_ip {
                        warn!(
                            "IP changed: {} → {} — recreating TUN device",
                            current_ip, new_ip
                        );
                        vpn::cleanup_tun(&self.tunnel_config, &iface_name);
                        self.tunnel_config.ip_address = new_ip;
                        let (new_tun, new_iface) = vpn::setup_tun(&self.tunnel_config)?;
                        tun_dev = new_tun;
                        iface_name = new_iface;
                        current_ip = new_ip;
                    }
                    info!("Tunnel established, entering data plane");
                    (tunnel, lcp)
                }
                Err(e) => {
                    // Check if it's a cookie rejection (HTTP 403)
                    let err_msg = format!("{}", e);
                    if err_msg.contains("403") || err_msg.contains("Forbidden") {
                        warn!("Cookie rejected, attempting re-authentication");
                        self.state = ConnectionState::ReAuthenticating;
                        match self.re_authenticate().await {
                            Ok(()) => {
                                info!("Re-authentication successful, retrying tunnel");
                                continue;
                            }
                            Err(auth_err) => {
                                error!("Re-authentication failed: {}", auth_err);
                                // Fall through to backoff
                            }
                        }
                    }

                    let delay = self.backoff.current();
                    warn!("Tunnel connect failed: {}. Retrying in {:?}", e, delay);
                    self.backoff.next();

                    if self.wait_for_retry(delay, &mut network_rx).await {
                        break;
                    }
                    continue;
                }
            };

            // Drain stale power events before entering the event loop select.
            // Without this, a stale HasPoweredOn would poison the pattern-matching
            // select branch (tokio disables non-matching pattern branches).
            while let Ok(event) = power_rx.try_recv() {
                debug!("Draining stale power event: {:?}", event);
            }

            // Run event loop — also check for sleep events between iterations.
            // We can't use tokio::select! with event_loop + power_rx because
            // event_loop borrows tunnel/lcp, preventing send_terminate in sleep path.
            // Instead, check power_rx after event_loop returns.
            let reason = vpn::event_loop(&mut tunnel, &mut lcp, &tun_dev).await;

            // Check if a WillSleep arrived while the event loop was running
            let is_sleep = matches!(power_rx.try_recv(), Ok(PowerEvent::WillSleep));

            // Send LCP terminate before closing tunnel
            let _ = Self::send_terminate(&mut tunnel, &mut lcp).await;
            drop(tunnel);

            if is_sleep {
                info!("System going to sleep — waiting for wake");
                self.state = ConnectionState::WaitingForNetwork;
                loop {
                    tokio::select! {
                        event = power_rx.recv() => {
                            if matches!(event, Some(PowerEvent::HasPoweredOn)) {
                                info!("System woke up — reconnecting");
                                self.backoff.reset();
                                break;
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            info!("Ctrl+C during wake");
                            self.state = ConnectionState::Cleanup;
                            vpn::cleanup_tun(&self.tunnel_config, &iface_name);
                            info!("VPN disconnected.");
                            return Ok(());
                        }
                    }
                }
                // Drain any stale network events queued during sleep so wait_for_retry
                // doesn't act on stale state on its first iteration.
                while let Ok(event) = network_rx.try_recv() {
                    debug!("Draining stale network event after wake: {:?}", event);
                }
                continue; // Go back to top of loop to reconnect
            }
            info!("Event loop exited: {:?}", reason);

            let action = classify_disconnect(&reason);
            match action {
                ReconnectAction::Exit => {
                    self.state = ConnectionState::Cleanup;
                    break;
                }
                ReconnectAction::RetryWithCookie | ReconnectAction::ReAuthenticate => {
                    let delay = self.backoff.current();
                    self.state = ConnectionState::Reconnecting;
                    info!("Reconnecting in {:?}...", delay);
                    self.backoff.next();

                    if self.wait_for_retry(delay, &mut network_rx).await {
                        break;
                    }
                }
            }
        }

        // Final cleanup
        vpn::cleanup_tun(&self.tunnel_config, &iface_name);
        info!("VPN disconnected.");
        Ok(())
    }

    /// Connect the TLS tunnel and run PPP negotiation.
    /// Uses the cookie fast path: skip resource reservation and XML fetch.
    /// Returns the tunnel, LCP state, and the IPCP-assigned IP address.
    async fn connect_tunnel(
        &self,
    ) -> Result<(TlsTunnel, crate::ppp::lcp::LcpState, std::net::Ipv4Addr)> {
        let mut tunnel = TlsTunnel::connect(
            &self.auth_params.server,
            self.auth_params.port,
            &self.svpn_cookie,
            self.auth_params.tls_config.clone(),
        )
        .await?;

        let mut ppp = PppEngine::new(1500);
        let ipcp_config = ppp.negotiate(&mut tunnel).await?;
        let lcp = ppp.into_lcp();

        Ok((tunnel, lcp, ipcp_config.ip_address))
    }

    /// Re-authenticate (SAML or credential) and update stored cookie/config.
    async fn re_authenticate(&mut self) -> Result<()> {
        let auth_client = AuthClient::new(
            &self.auth_params.server,
            self.auth_params.port,
            self.auth_params.enable_keylog,
        )?;

        let auth_result = if self.auth_params.saml {
            info!("Re-authenticating via SAML...");
            auth_client.login_saml().await?
        } else {
            let username = self
                .auth_params
                .username
                .as_deref()
                .ok_or_else(|| FortiError::AuthFailed("no username for re-auth".into()))?;
            let password = self
                .auth_params
                .password
                .as_ref()
                .ok_or_else(|| FortiError::AuthFailed("no password for re-auth".into()))?;
            info!("Re-authenticating with credentials...");
            auth_client
                .login(
                    username,
                    password.expose_secret(),
                    self.auth_params.realm.as_deref(),
                )
                .await?
        };

        self.svpn_cookie = auth_result.svpn_cookie;

        if auth_result.tunnel_config.ip_address != self.tunnel_config.ip_address {
            info!(
                "Re-auth assigned new IP {} (was {}) — TUN will be recreated on next connect",
                auth_result.tunnel_config.ip_address, self.tunnel_config.ip_address,
            );
        }
        self.tunnel_config = auth_result.tunnel_config;

        Ok(())
    }

    /// Try to send LCP Terminate-Request before closing tunnel.
    async fn send_terminate(
        tunnel: &mut TlsTunnel,
        lcp: &mut crate::ppp::lcp::LcpState,
    ) -> Result<()> {
        let frame = PppFrame::new(PppProtocol::Lcp, lcp.build_terminate_request());
        tunnel.send_frame(frame.encode()).await
    }

    /// Wait for backoff timer, but cancel early if network becomes reachable.
    /// Returns true if user pressed Ctrl+C (should exit).
    async fn wait_for_retry(
        &mut self,
        delay: Duration,
        network_rx: &mut mpsc::Receiver<NetworkEvent>,
    ) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(delay) => false,
            event = network_rx.recv() => {
                match event {
                    Some(NetworkEvent::Reachable) => {
                        info!("Network reachable — reconnecting immediately");
                        self.backoff.reset();
                        false
                    }
                    Some(NetworkEvent::Unreachable) => {
                        debug!("Network unreachable during backoff — will retry when reachable");
                        // Don't reset backoff — network is down, no point reconnecting faster
                        false
                    }
                    None => {
                        debug!("Network monitor channel closed");
                        false
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C during backoff");
                self.state = ConnectionState::Cleanup;
                true
            }
        }
    }
}
