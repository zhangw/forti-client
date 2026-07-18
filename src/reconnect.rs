use std::future::Future;
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::auth::xml::TunnelConfig;
use crate::auth::AuthClient;
use crate::error::{FortiError, Result};
use crate::network_monitor::{NetworkEvent, NetworkMonitor};
use crate::power_monitor::{PowerEvent, PowerMonitor};
use crate::ppp::codec::{PppFrame, PppProtocol};
use crate::ppp::PppEngine;
use crate::shutdown::Shutdown;
use crate::tunnel::TlsTunnel;
use crate::vpn;

/// Reason the VPN event loop exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    DeadPeer,
    TunnelClosed,
    ServerTerminated,
    IoError(String),
    SystemSleep,
    UserQuit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconnectAction {
    RetryWithCookie,
    ReAuthenticate,
    Exit,
}

pub fn classify_disconnect(reason: &DisconnectReason) -> ReconnectAction {
    match reason {
        DisconnectReason::UserQuit => ReconnectAction::Exit,
        _ => ReconnectAction::RetryWithCookie,
    }
}

/// Detect a likely sleep gap from a delayed keepalive tick.
pub fn detect_sleep_gap(last_tick: Instant, expected_interval: Duration) -> bool {
    last_tick.elapsed() > expected_interval * 3
}

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
const REAUTH_AFTER_CONNECT_FAILURES: u32 = 3;
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(2);
const MONITOR_FALLBACK_TIMEOUT: Duration = Duration::from_secs(15);

/// A typed rejection re-authenticates immediately. Repeated failures are a
/// compatibility fallback for FortiGates that report an expired cookie as EOF,
/// PPP timeout, or another non-HTTP failure.
pub fn should_reauthenticate(error: &FortiError, consecutive_failures: u32) -> bool {
    matches!(error, FortiError::CookieRejected(_))
        || consecutive_failures >= REAUTH_AFTER_CONNECT_FAILURES
}

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

    pub fn current(&self) -> Duration {
        self.current
    }

    pub fn next(&mut self) {
        self.current = (self.current * 2).min(BACKOFF_MAX);
    }

    pub fn reset(&mut self) {
        self.current = BACKOFF_INITIAL;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Reconnecting,
    ReAuthenticating,
    WaitingForNetwork,
    Cleanup,
}

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

pub struct ReconnectController {
    auth_params: AuthParams,
    svpn_cookie: String,
    tunnel_config: TunnelConfig,
    backoff: Backoff,
    state: ConnectionState,
    shutdown: Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Interrupt {
    Shutdown,
    Sleep,
    NetworkDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryOutcome {
    Retry,
    Shutdown,
}

async fn next_network_event(rx: &mut mpsc::UnboundedReceiver<NetworkEvent>) -> NetworkEvent {
    match rx.recv().await {
        Some(event) => event,
        None => std::future::pending().await,
    }
}

async fn next_power_event(rx: &mut mpsc::UnboundedReceiver<PowerEvent>) -> PowerEvent {
    match rx.recv().await {
        Some(event) => event,
        None => std::future::pending().await,
    }
}

async fn interruptible<T>(
    operation: impl Future<Output = T>,
    shutdown: &Shutdown,
    network_rx: &mut mpsc::UnboundedReceiver<NetworkEvent>,
    power_rx: &mut mpsc::UnboundedReceiver<PowerEvent>,
) -> std::result::Result<T, Interrupt> {
    tokio::pin!(operation);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Err(Interrupt::Shutdown),
            power = next_power_event(power_rx) => {
                if power == PowerEvent::WillSleep {
                    return Err(Interrupt::Sleep);
                }
            }
            network = next_network_event(network_rx) => {
                if network == NetworkEvent::Unreachable {
                    return Err(Interrupt::NetworkDown);
                }
            }
            result = &mut operation => return Ok(result),
        }
    }
}

impl ReconnectController {
    pub fn new(
        auth_params: AuthParams,
        svpn_cookie: String,
        tunnel_config: TunnelConfig,
        shutdown: Shutdown,
    ) -> Self {
        Self {
            auth_params,
            svpn_cookie,
            tunnel_config,
            backoff: Backoff::new(),
            state: ConnectionState::Connecting,
            shutdown,
        }
    }

    /// Run until shutdown or an unrecoverable local setup error. Once TUN setup
    /// succeeds, every return path passes through final route/DNS cleanup.
    pub async fn run(&mut self) -> Result<()> {
        let (mut tun_dev, mut iface_name) =
            match vpn::setup_tun(&self.tunnel_config, &self.shutdown).await {
                Ok(setup) => setup,
                Err(_) if self.shutdown.is_cancelled() => return Ok(()),
                Err(error) => return Err(error),
            };
        let mut applied_config = self.tunnel_config.clone();
        info!("Press Ctrl+C to disconnect.");

        let (_network_monitor, mut network_rx) =
            match NetworkMonitor::start(&self.auth_params.server) {
                Ok(value) => value,
                Err(e) => {
                    vpn::cleanup_tun(&applied_config, &iface_name).await;
                    return Err(FortiError::TunnelError(format!(
                        "network monitor failed: {}",
                        e
                    )));
                }
            };
        let (_power_monitor, mut power_rx) = match PowerMonitor::start() {
            Ok(value) => value,
            Err(e) => {
                vpn::cleanup_tun(&applied_config, &iface_name).await;
                return Err(FortiError::TunnelError(format!(
                    "power monitor failed: {}",
                    e
                )));
            }
        };

        self.state = ConnectionState::Connected;
        let shutdown = self.shutdown.clone();
        let mut terminal_error: Option<FortiError> = None;
        let mut consecutive_connect_failures = 0u32;

        'reconnect: loop {
            let connect_result = match interruptible(
                self.connect_tunnel(),
                &shutdown,
                &mut network_rx,
                &mut power_rx,
            )
            .await
            {
                Ok(result) => result,
                Err(Interrupt::Shutdown) => break,
                Err(Interrupt::Sleep) => {
                    if self.wait_for_wake(&mut power_rx).await {
                        break;
                    }
                    continue;
                }
                Err(Interrupt::NetworkDown) => {
                    if self.wait_for_network(&mut network_rx, &mut power_rx).await {
                        break;
                    }
                    continue;
                }
            };

            let (mut tunnel, mut lcp, negotiated_ip) = match connect_result {
                Ok(connected) => {
                    consecutive_connect_failures = 0;
                    self.backoff.reset();
                    connected
                }
                Err(connect_error) => {
                    consecutive_connect_failures = consecutive_connect_failures.saturating_add(1);
                    if should_reauthenticate(&connect_error, consecutive_connect_failures) {
                        warn!(
                            "Tunnel authentication may be stale after {} failure(s): {}",
                            consecutive_connect_failures, connect_error
                        );
                        self.state = ConnectionState::ReAuthenticating;
                        match interruptible(
                            self.re_authenticate(),
                            &shutdown,
                            &mut network_rx,
                            &mut power_rx,
                        )
                        .await
                        {
                            Ok(Ok(())) => {
                                info!("Re-authentication successful, retrying tunnel");
                                consecutive_connect_failures = 0;
                                self.backoff.reset();
                                continue;
                            }
                            Ok(Err(auth_error)) => {
                                error!("Re-authentication failed: {}", auth_error);
                                consecutive_connect_failures = 0;
                            }
                            Err(Interrupt::Shutdown) => break,
                            Err(Interrupt::Sleep) => {
                                if self.wait_for_wake(&mut power_rx).await {
                                    break;
                                }
                                continue;
                            }
                            Err(Interrupt::NetworkDown) => {
                                if self.wait_for_network(&mut network_rx, &mut power_rx).await {
                                    break;
                                }
                                continue;
                            }
                        }
                    }

                    let delay = self.backoff.current();
                    warn!(
                        "Tunnel connect failed: {}. Retrying in {:?}",
                        connect_error, delay
                    );
                    self.backoff.next();
                    if self
                        .wait_for_retry(delay, &mut network_rx, &mut power_rx)
                        .await
                        == RetryOutcome::Shutdown
                    {
                        break;
                    }
                    continue;
                }
            };

            // IPCP is authoritative for the address used by this tunnel. A
            // reconnect may assign a new IP even when no full re-auth occurred.
            if apply_negotiated_ip(&mut self.tunnel_config, negotiated_ip) {
                info!("IPCP assigned a new address: {}", negotiated_ip);
            }

            // Re-authentication can change routes or DNS without changing the IP.
            // Recreate the interface for any applied network-config change so old
            // routes are removed and final cleanup refers to the correct config.
            if network_config_changed(&applied_config, &self.tunnel_config) {
                warn!("VPN network configuration changed — recreating TUN device");
                vpn::cleanup_tun(&applied_config, &iface_name).await;
                match vpn::setup_tun(&self.tunnel_config, &shutdown).await {
                    Ok((new_tun, new_iface)) => {
                        tun_dev = new_tun;
                        iface_name = new_iface;
                        applied_config = self.tunnel_config.clone();
                    }
                    Err(_) if shutdown.is_cancelled() => break 'reconnect,
                    Err(e) => {
                        terminal_error = Some(e);
                        break 'reconnect;
                    }
                }
            }

            info!("Tunnel established, entering data plane");
            self.state = ConnectionState::Connected;
            let reason =
                vpn::event_loop(&mut tunnel, &mut lcp, &tun_dev, &shutdown, &mut power_rx).await;

            if !matches!(
                reason,
                DisconnectReason::UserQuit | DisconnectReason::SystemSleep
            ) {
                let _ = tokio::time::timeout(
                    TERMINATE_TIMEOUT,
                    Self::send_terminate(&mut tunnel, &mut lcp),
                )
                .await;
            }
            drop(tunnel);

            if reason == DisconnectReason::SystemSleep {
                if self.wait_for_wake(&mut power_rx).await {
                    break;
                }
                while let Ok(event) = network_rx.try_recv() {
                    debug!("Draining network event after wake: {:?}", event);
                }
                continue;
            }

            info!("Event loop exited: {:?}", reason);
            match classify_disconnect(&reason) {
                ReconnectAction::Exit => break,
                ReconnectAction::RetryWithCookie | ReconnectAction::ReAuthenticate => {
                    let delay = self.backoff.current();
                    self.state = ConnectionState::Reconnecting;
                    info!("Reconnecting in {:?}...", delay);
                    self.backoff.next();
                    if self
                        .wait_for_retry(delay, &mut network_rx, &mut power_rx)
                        .await
                        == RetryOutcome::Shutdown
                    {
                        break;
                    }
                }
            }
        }

        self.state = ConnectionState::Cleanup;
        vpn::cleanup_tun(&applied_config, &iface_name).await;
        info!("VPN disconnected.");
        match terminal_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

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
        self.tunnel_config = auth_result.tunnel_config;
        Ok(())
    }

    async fn send_terminate(
        tunnel: &mut TlsTunnel,
        lcp: &mut crate::ppp::lcp::LcpState,
    ) -> Result<()> {
        let frame = PppFrame::new(PppProtocol::Lcp, lcp.build_terminate_request());
        tunnel.send_frame(frame.encode()).await
    }

    /// Returns true when shutdown was requested.
    async fn wait_for_network(
        &mut self,
        network_rx: &mut mpsc::UnboundedReceiver<NetworkEvent>,
        power_rx: &mut mpsc::UnboundedReceiver<PowerEvent>,
    ) -> bool {
        self.state = ConnectionState::WaitingForNetwork;
        info!("Network unreachable — waiting for reachability");
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return true,
                _ = tokio::time::sleep(MONITOR_FALLBACK_TIMEOUT) => {
                    warn!("No network reachability update after 15s — retrying with bounded connect timeout");
                    return false;
                }
                event = next_network_event(network_rx) => {
                    if event == NetworkEvent::Reachable {
                        info!("Network reachable — reconnecting");
                        self.backoff.reset();
                        return false;
                    }
                }
                event = next_power_event(power_rx) => {
                    if event == PowerEvent::WillSleep && self.wait_for_wake(power_rx).await {
                        return true;
                    }
                }
            }
        }
    }

    /// Returns true when shutdown was requested.
    async fn wait_for_wake(&mut self, power_rx: &mut mpsc::UnboundedReceiver<PowerEvent>) -> bool {
        self.state = ConnectionState::WaitingForNetwork;
        info!("System going to sleep — waiting for wake");
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return true,
                _ = tokio::time::sleep(MONITOR_FALLBACK_TIMEOUT) => {
                    warn!("No wake notification after 15s — retrying with bounded connect timeout");
                    return false;
                }
                event = next_power_event(power_rx) => {
                    if event == PowerEvent::HasPoweredOn {
                        info!("System woke up — reconnecting");
                        self.backoff.reset();
                        return false;
                    }
                }
            }
        }
    }

    async fn wait_for_retry(
        &mut self,
        delay: Duration,
        network_rx: &mut mpsc::UnboundedReceiver<NetworkEvent>,
        power_rx: &mut mpsc::UnboundedReceiver<PowerEvent>,
    ) -> RetryOutcome {
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => RetryOutcome::Shutdown,
            _ = tokio::time::sleep(delay) => RetryOutcome::Retry,
            event = next_network_event(network_rx) => {
                match event {
                    NetworkEvent::Reachable => {
                        info!("Network reachable — reconnecting immediately");
                        self.backoff.reset();
                        RetryOutcome::Retry
                    }
                    NetworkEvent::Unreachable => {
                        if self.wait_for_network(network_rx, power_rx).await {
                            RetryOutcome::Shutdown
                        } else {
                            RetryOutcome::Retry
                        }
                    }
                }
            }
            event = next_power_event(power_rx) => {
                if event == PowerEvent::WillSleep && self.wait_for_wake(power_rx).await {
                    RetryOutcome::Shutdown
                } else {
                    RetryOutcome::Retry
                }
            }
        }
    }
}

fn network_config_changed(old: &TunnelConfig, new: &TunnelConfig) -> bool {
    old.ip_address != new.ip_address
        || old.dns_servers != new.dns_servers
        || old.routes != new.routes
}

fn apply_negotiated_ip(config: &mut TunnelConfig, negotiated_ip: std::net::Ipv4Addr) -> bool {
    if config.ip_address == negotiated_ip {
        return false;
    }
    config.ip_address = negotiated_ip;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_cookie_rejection_reauthenticates_immediately() {
        assert!(should_reauthenticate(&FortiError::CookieRejected(403), 1));
    }

    #[test]
    fn repeated_ambiguous_failures_eventually_reauthenticate() {
        let error = FortiError::PppError("timeout".into());
        assert!(!should_reauthenticate(&error, 2));
        assert!(should_reauthenticate(&error, 3));
    }

    #[test]
    fn negotiated_ip_change_marks_network_config_changed() {
        let mut config = TunnelConfig::parse(
            r#"<sslvpn-tunnel><assigned-addr ipv4="10.0.0.2" /></sslvpn-tunnel>"#,
        )
        .unwrap();
        let applied = config.clone();
        let new_ip = "10.0.0.3".parse().unwrap();

        assert!(apply_negotiated_ip(&mut config, new_ip));
        assert_eq!(config.ip_address, new_ip);
        assert!(network_config_changed(&applied, &config));
    }

    #[tokio::test]
    async fn interruptible_operation_observes_shutdown() {
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        let (_network_tx, mut network_rx) = mpsc::unbounded_channel();
        let (_power_tx, mut power_rx) = mpsc::unbounded_channel();
        trigger.cancel();
        let result = interruptible(
            std::future::pending::<()>(),
            &shutdown,
            &mut network_rx,
            &mut power_rx,
        )
        .await;
        assert_eq!(result, Err(Interrupt::Shutdown));
    }

    #[tokio::test]
    async fn interruptible_operation_observes_network_loss() {
        let shutdown = Shutdown::new();
        let (network_tx, mut network_rx) = mpsc::unbounded_channel();
        let (_power_tx, mut power_rx) = mpsc::unbounded_channel();
        network_tx.send(NetworkEvent::Unreachable).unwrap();
        let result = interruptible(
            std::future::pending::<()>(),
            &shutdown,
            &mut network_rx,
            &mut power_rx,
        )
        .await;
        assert_eq!(result, Err(Interrupt::NetworkDown));
    }

    #[tokio::test]
    async fn interruptible_operation_observes_sleep() {
        let shutdown = Shutdown::new();
        let (_network_tx, mut network_rx) = mpsc::unbounded_channel();
        let (power_tx, mut power_rx) = mpsc::unbounded_channel();
        power_tx.send(PowerEvent::WillSleep).unwrap();
        let result = interruptible(
            std::future::pending::<()>(),
            &shutdown,
            &mut network_rx,
            &mut power_rx,
        )
        .await;
        assert_eq!(result, Err(Interrupt::Sleep));
    }
}
