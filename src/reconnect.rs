use std::future::Future;
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::auth::xml::TunnelConfig;
use crate::auth::AuthClient;
use crate::error::{AuthRequirement, ConnectFailureKind, FortiError, Result, SamlFailureKind};
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

fn should_send_terminate(reason: &DisconnectReason) -> bool {
    *reason != DisconnectReason::SystemSleep
}

fn auth_failure_is_terminal(attempt: AuthAttemptKind, failure: SamlFailureKind) -> bool {
    attempt == AuthAttemptKind::Required && failure == SamlFailureKind::TerminalConfiguration
}

fn prepare_cookie_for_auth(attempt: AuthAttemptKind, cookie: &mut String) {
    if attempt == AuthAttemptKind::Required {
        cookie.clear();
    }
}

/// Detect a likely sleep gap from a delayed keepalive tick.
pub fn detect_sleep_gap(last_tick: Instant, expected_interval: Duration) -> bool {
    last_tick.elapsed() > expected_interval * 3
}

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
const POST_UPGRADE_FAILURES_BEFORE_PROBE: u32 = 3;
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(2);
const MONITOR_FALLBACK_TIMEOUT: Duration = Duration::from_secs(15);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAttemptKind {
    Required,
    CompatibilityProbe,
}

/// Pure reconnect decision state. An episode ends only after both TLS and PPP
/// negotiation succeed.
pub struct ReconnectPolicy {
    backoff: Backoff,
    auth_requirement: AuthRequirement,
    transport_attempts: u32,
    post_upgrade_failures: u32,
    compatibility_probe_used: bool,
    saml_attempts: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl ReconnectPolicy {
    pub fn new() -> Self {
        Self {
            backoff: Backoff::new(),
            auth_requirement: AuthRequirement::NotRequired,
            transport_attempts: 0,
            post_upgrade_failures: 0,
            compatibility_probe_used: false,
            saml_attempts: 0,
        }
    }

    pub fn auth_requirement(&self) -> AuthRequirement {
        self.auth_requirement
    }

    /// Return the only operation permitted by the authentication gate. A
    /// compatibility probe is marked used before it starts, so a timeout cannot
    /// launch another browser in the same reconnect episode.
    pub fn next_auth_attempt(&mut self) -> Option<AuthAttemptKind> {
        let attempt = match self.auth_requirement {
            AuthRequirement::NotRequired => return None,
            AuthRequirement::Required => AuthAttemptKind::Required,
            AuthRequirement::CompatibilityProbeAllowed => {
                self.auth_requirement = AuthRequirement::NotRequired;
                AuthAttemptKind::CompatibilityProbe
            }
        };
        self.saml_attempts = self.saml_attempts.saturating_add(1);
        Some(attempt)
    }

    pub fn on_connect_failure(&mut self, kind: ConnectFailureKind) {
        match kind {
            ConnectFailureKind::TransportUnavailable => {
                self.transport_attempts = self.transport_attempts.saturating_add(1);
                self.post_upgrade_failures = 0;
            }
            ConnectFailureKind::CookieRejected => {
                // A definitive rejection begins a new required-auth episode.
                self.transport_attempts = 0;
                self.post_upgrade_failures = 0;
                self.compatibility_probe_used = false;
                self.auth_requirement = AuthRequirement::Required;
            }
            ConnectFailureKind::PostUpgrade => {
                self.post_upgrade_failures = self.post_upgrade_failures.saturating_add(1);
                if self.post_upgrade_failures >= POST_UPGRADE_FAILURES_BEFORE_PROBE
                    && !self.compatibility_probe_used
                {
                    self.compatibility_probe_used = true;
                    self.auth_requirement = AuthRequirement::CompatibilityProbeAllowed;
                }
            }
            ConnectFailureKind::LocalSetup | ConnectFailureKind::Cancelled => {}
        }
    }

    pub fn on_saml_failure(&mut self, attempt: AuthAttemptKind, _kind: SamlFailureKind) {
        self.auth_requirement = match attempt {
            // A rejected cookie remains unusable until a new cookie is obtained.
            AuthAttemptKind::Required => AuthRequirement::Required,
            // A compatibility probe is optional. Its failure returns to cookie
            // retries without permitting another probe in this episode.
            AuthAttemptKind::CompatibilityProbe => AuthRequirement::NotRequired,
        };
    }

    pub fn on_saml_success(&mut self) {
        self.auth_requirement = AuthRequirement::NotRequired;
        // Deliberately do not reset backoff or the current reconnect episode.
    }

    pub fn on_network_reachable(&mut self) {
        // Reachability only changes when the next attempt can run.
    }

    pub fn on_system_wake(&mut self) {
        // Wake only changes when the next attempt can run.
    }

    pub fn on_tunnel_established(&mut self) {
        self.backoff.reset();
        self.auth_requirement = AuthRequirement::NotRequired;
        self.transport_attempts = 0;
        self.post_upgrade_failures = 0;
        self.compatibility_probe_used = false;
        self.saml_attempts = 0;
    }

    pub fn current_delay(&self) -> Duration {
        self.backoff.current()
    }

    pub fn next_delay(&mut self) -> Duration {
        let delay = self.backoff.current();
        self.backoff.next();
        delay
    }

    pub fn transport_attempts(&self) -> u32 {
        self.transport_attempts
    }

    pub fn negotiation_failures(&self) -> u32 {
        self.post_upgrade_failures
    }

    pub fn saml_attempts(&self) -> u32 {
        self.saml_attempts
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    EstablishingTunnel,
    Authenticating,
    Running,
    WaitingToRetry,
    WaitingForNetwork,
    CleaningUp,
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
    policy: ReconnectPolicy,
    state: ConnectionState,
    shutdown: Shutdown,
}

fn classify_tunnel_connect_error(error: &FortiError) -> ConnectFailureKind {
    match error {
        FortiError::CookieRejected(_) => ConnectFailureKind::CookieRejected,
        FortiError::PostUpgradeNegotiation(_)
        | FortiError::ProtocolError(_)
        | FortiError::TunnelClosed => ConnectFailureKind::PostUpgrade,
        FortiError::TransportUnavailable(_)
        | FortiError::Io(_)
        | FortiError::Tls(_)
        | FortiError::TunnelError(_)
        | FortiError::PppError(_)
        | FortiError::AuthFailed(_)
        | FortiError::SamlCallbackTimedOut
        | FortiError::SamlCallbackInvalid(_)
        | FortiError::SamlTerminalConfiguration(_)
        | FortiError::Http(_) => ConnectFailureKind::TransportUnavailable,
    }
}

struct ConnectFailure {
    kind: ConnectFailureKind,
    source: FortiError,
}

type ConnectedTunnel = (TlsTunnel, crate::ppp::lcp::LcpState, std::net::Ipv4Addr);

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
        if shutdown.is_cancelled() {
            return Err(Interrupt::Shutdown);
        }
        tokio::select! {
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
            policy: ReconnectPolicy::new(),
            state: ConnectionState::EstablishingTunnel,
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

        let shutdown = self.shutdown.clone();
        let mut terminal_error: Option<FortiError> = None;

        'reconnect: loop {
            if let Some(attempt_kind) = self.policy.next_auth_attempt() {
                self.state = ConnectionState::Authenticating;
                info!(
                    state = ?self.state,
                    auth_requirement = ?self.policy.auth_requirement(),
                    saml_attempt = self.policy.saml_attempts(),
                    attempt_kind = ?attempt_kind,
                    "Starting reconnect authentication attempt"
                );

                // A definitively rejected cookie must never be retried. An
                // optional compatibility probe keeps the old cookie available
                // if the SAML path itself times out.
                prepare_cookie_for_auth(attempt_kind, &mut self.svpn_cookie);
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
                        self.policy.on_saml_success();
                        continue;
                    }
                    Ok(Err(auth_error)) => {
                        let failure_kind = SamlFailureKind::classify(&auth_error);
                        error!(
                            state = ?self.state,
                            failure_class = ?failure_kind,
                            auth_requirement = ?self.policy.auth_requirement(),
                            error = %auth_error,
                            "Re-authentication failed"
                        );
                        if auth_failure_is_terminal(attempt_kind, failure_kind) {
                            terminal_error = Some(auth_error);
                            break 'reconnect;
                        }
                        self.policy.on_saml_failure(attempt_kind, failure_kind);
                        let delay = self.policy.next_delay();
                        if self
                            .wait_for_retry(delay, &mut network_rx, &mut power_rx)
                            .await
                            == RetryOutcome::Shutdown
                        {
                            break;
                        }
                        continue;
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

            self.state = ConnectionState::EstablishingTunnel;
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
                    // This is the sole backoff reset point: TLS and PPP both
                    // succeeded, ending the reconnect episode.
                    self.policy.on_tunnel_established();
                    connected
                }
                Err(connect_failure) => {
                    self.policy.on_connect_failure(connect_failure.kind);
                    warn!(
                        state = ?self.state,
                        failure_class = ?connect_failure.kind,
                        connect_attempt = self.policy.transport_attempts(),
                        negotiation_failure_count = self.policy.negotiation_failures(),
                        auth_requirement = ?self.policy.auth_requirement(),
                        error = %connect_failure.source,
                        "Tunnel connection attempt failed"
                    );
                    if self.policy.auth_requirement() != AuthRequirement::NotRequired {
                        continue;
                    }

                    let delay = self.policy.next_delay();
                    warn!(
                        state = ?ConnectionState::WaitingToRetry,
                        backoff_ms = delay.as_millis() as u64,
                        "Backing off before tunnel retry"
                    );
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
            self.state = ConnectionState::Running;
            let reason =
                vpn::event_loop(&mut tunnel, &mut lcp, &tun_dev, &shutdown, &mut power_rx).await;

            if should_send_terminate(&reason) {
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
                    let delay = self.policy.next_delay();
                    info!(
                        state = ?ConnectionState::WaitingToRetry,
                        backoff_ms = delay.as_millis() as u64,
                        "Backing off before reconnect"
                    );
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

        self.state = ConnectionState::CleaningUp;
        vpn::cleanup_tun(&applied_config, &iface_name).await;
        info!("VPN disconnected.");
        match terminal_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn connect_tunnel(&self) -> std::result::Result<ConnectedTunnel, ConnectFailure> {
        let mut tunnel = TlsTunnel::connect(
            &self.auth_params.server,
            self.auth_params.port,
            &self.svpn_cookie,
            self.auth_params.tls_config.clone(),
        )
        .await
        .map_err(|source| ConnectFailure {
            kind: classify_tunnel_connect_error(&source),
            source,
        })?;

        let mut ppp = PppEngine::new(1500);
        let ipcp_config = ppp
            .negotiate(&mut tunnel)
            .await
            .map_err(|source| ConnectFailure {
                kind: if matches!(source, FortiError::CookieRejected(_)) {
                    ConnectFailureKind::CookieRejected
                } else {
                    ConnectFailureKind::PostUpgrade
                },
                source,
            })?;
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
            if self.shutdown.is_cancelled() {
                return true;
            }
            tokio::select! {
                    _ = self.shutdown.cancelled() => return true,
                _ = tokio::time::sleep(MONITOR_FALLBACK_TIMEOUT) => {
                    warn!("No network reachability update after 15s — retrying with bounded connect timeout");
                    return false;
                }
                event = next_network_event(network_rx) => {
                    if event == NetworkEvent::Reachable {
                        info!("Network reachable — reconnecting");
                        self.policy.on_network_reachable();
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
            if self.shutdown.is_cancelled() {
                return true;
            }
            tokio::select! {
                    _ = self.shutdown.cancelled() => return true,
                _ = tokio::time::sleep(MONITOR_FALLBACK_TIMEOUT) => {
                    warn!("No wake notification after 15s — retrying with bounded connect timeout");
                    return false;
                }
                event = next_power_event(power_rx) => {
                    if event == PowerEvent::HasPoweredOn {
                        info!("System woke up — reconnecting");
                        self.policy.on_system_wake();
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
        self.state = ConnectionState::WaitingToRetry;
        if self.shutdown.is_cancelled() {
            return RetryOutcome::Shutdown;
        }
        tokio::select! {
            _ = self.shutdown.cancelled() => RetryOutcome::Shutdown,
            _ = tokio::time::sleep(delay) => RetryOutcome::Retry,
            event = next_network_event(network_rx) => {
                match event {
                    NetworkEvent::Reachable => {
                        info!("Network reachable — reconnecting immediately");
                        self.policy.on_network_reachable();
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
    fn connect_errors_are_classified_by_phase() {
        assert_eq!(
            classify_tunnel_connect_error(&FortiError::TransportUnavailable(
                "TLS tunnel connect timed out after 30s".into()
            )),
            ConnectFailureKind::TransportUnavailable
        );
        assert_eq!(
            classify_tunnel_connect_error(&FortiError::PostUpgradeNegotiation(
                "connection closed after tunnel request".into()
            )),
            ConnectFailureKind::PostUpgrade
        );
        assert_eq!(
            classify_tunnel_connect_error(&FortiError::ProtocolError(
                "malformed tunnel HTTP response".into()
            )),
            ConnectFailureKind::PostUpgrade
        );
        assert_eq!(
            classify_tunnel_connect_error(&FortiError::CookieRejected(403)),
            ConnectFailureKind::CookieRejected
        );
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

    #[test]
    fn user_quit_attempts_terminate_but_sleep_does_not() {
        assert!(should_send_terminate(&DisconnectReason::UserQuit));
        assert!(should_send_terminate(&DisconnectReason::DeadPeer));
        assert!(!should_send_terminate(&DisconnectReason::SystemSleep));
    }

    #[test]
    fn only_required_terminal_auth_failure_stops_controller() {
        assert!(auth_failure_is_terminal(
            AuthAttemptKind::Required,
            SamlFailureKind::TerminalConfiguration
        ));
        assert!(!auth_failure_is_terminal(
            AuthAttemptKind::CompatibilityProbe,
            SamlFailureKind::TerminalConfiguration
        ));
        assert!(!auth_failure_is_terminal(
            AuthAttemptKind::Required,
            SamlFailureKind::CallbackTimedOut
        ));
    }

    #[test]
    fn auth_attempt_invalidates_only_definitively_rejected_cookie() {
        let mut required_cookie = "rejected".to_string();
        prepare_cookie_for_auth(AuthAttemptKind::Required, &mut required_cookie);
        assert!(required_cookie.is_empty());

        let mut compatibility_cookie = "possibly-valid".to_string();
        prepare_cookie_for_auth(
            AuthAttemptKind::CompatibilityProbe,
            &mut compatibility_cookie,
        );
        assert_eq!(compatibility_cookie, "possibly-valid");
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
