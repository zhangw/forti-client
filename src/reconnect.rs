use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::auth::xml::TunnelConfig;
use crate::auth::AuthClient;
use crate::error::{AuthRequirement, ConnectFailureKind, FortiError, Result, SamlFailureKind};
use crate::network_monitor::{NetworkEvent, NetworkMonitor, ReachabilityTarget};
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
    connect_attempts: u32,
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
            connect_attempts: 0,
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

    pub fn on_connect_attempt(&mut self) {
        self.connect_attempts = self.connect_attempts.saturating_add(1);
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
        self.connect_attempts = 0;
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

    pub fn connect_attempts(&self) -> u32 {
        self.connect_attempts
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
    RefreshingConfig,
    Running,
    WaitingToRetry,
    WaitingForNetwork,
    CleaningUp,
}

pub struct AuthParams {
    pub server: String,
    pub port: u16,
    /// Gateway address resolved once at startup. Reconnects connect straight to
    /// it so they never depend on the system resolver, which the tunnel itself
    /// may have pointed at VPN-internal DNS servers.
    pub server_addr: Option<SocketAddr>,
    pub saml: bool,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub realm: Option<String>,
    pub tls_config: Arc<rustls::ClientConfig>,
    pub enable_keylog: bool,
}

impl AuthParams {
    fn auth_client(&self) -> Result<AuthClient> {
        let client = AuthClient::new(&self.server, self.port, self.enable_keylog)?;
        Ok(match self.server_addr {
            Some(addr) => client.with_pinned_addr(addr),
            None => client,
        })
    }
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
        | FortiError::PppError(_)
        | FortiError::TunnelClosed => ConnectFailureKind::PostUpgrade,
        FortiError::TransportUnavailable(_)
        | FortiError::Io(_)
        | FortiError::Tls(_)
        | FortiError::TunnelError(_)
        | FortiError::AuthFailed(_)
        | FortiError::SamlCallbackTimedOut
        | FortiError::SamlCallbackInvalid(_)
        | FortiError::SamlCallbackPortUnavailable(_)
        | FortiError::SamlTerminalConfiguration(_)
        | FortiError::Http(_) => ConnectFailureKind::TransportUnavailable,
    }
}

struct ConnectFailure {
    kind: ConnectFailureKind,
    source: FortiError,
}

type ConnectedTunnel<Tunnel, Lcp> = (Tunnel, Lcp, std::net::Ipv4Addr);
type DriverConnectResult<Tunnel, Lcp> =
    std::result::Result<ConnectedTunnel<Tunnel, Lcp>, ConnectFailure>;
type DriverFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

trait ControllerDriver: Send {
    type Tun: Sync;
    type Tunnel: Send;
    type Lcp: Send;

    fn setup_tun<'a>(
        &'a mut self,
        config: &'a TunnelConfig,
        shutdown: &'a Shutdown,
    ) -> DriverFuture<'a, Result<(Self::Tun, String)>>;
    fn cleanup_tun<'a>(
        &'a mut self,
        config: &'a TunnelConfig,
        iface_name: &'a str,
    ) -> DriverFuture<'a, ()>;
    fn start_monitors(
        &mut self,
        target: ReachabilityTarget,
    ) -> Result<(
        mpsc::UnboundedReceiver<NetworkEvent>,
        mpsc::UnboundedReceiver<PowerEvent>,
    )>;
    fn authenticate<'a>(&'a mut self, params: &'a AuthParams) -> DriverFuture<'a, Result<String>>;
    fn fetch_tunnel_config<'a>(
        &'a mut self,
        params: &'a AuthParams,
        cookie: &'a str,
    ) -> DriverFuture<'a, Result<TunnelConfig>>;
    /// Withdraw the VPN DNS servers while no tunnel carries them. Returns an
    /// error if the withdrawal could not be completed, so the caller can keep
    /// treating VPN DNS as installed rather than falsely recording a withdraw.
    fn suspend_dns(&mut self) -> DriverFuture<'_, Result<()>>;
    /// Reinstall the VPN DNS servers once a tunnel is carrying them again.
    fn resume_dns<'a>(
        &'a mut self,
        config: &'a TunnelConfig,
        shutdown: &'a Shutdown,
    ) -> DriverFuture<'a, Result<()>>;
    fn connect_tunnel<'a>(
        &'a mut self,
        params: &'a AuthParams,
        cookie: &'a str,
    ) -> DriverFuture<'a, DriverConnectResult<Self::Tunnel, Self::Lcp>>;
    fn event_loop<'a>(
        &'a mut self,
        tunnel: &'a mut Self::Tunnel,
        lcp: &'a mut Self::Lcp,
        tun: &'a Self::Tun,
        shutdown: &'a Shutdown,
        power_rx: &'a mut mpsc::UnboundedReceiver<PowerEvent>,
    ) -> DriverFuture<'a, DisconnectReason>;
    fn send_terminate<'a>(
        &'a mut self,
        tunnel: &'a mut Self::Tunnel,
        lcp: &'a mut Self::Lcp,
    ) -> DriverFuture<'a, Result<()>>;
}

#[derive(Default)]
struct ProductionDriver {
    network_monitor: Option<NetworkMonitor>,
    power_monitor: Option<PowerMonitor>,
}

impl ControllerDriver for ProductionDriver {
    type Tun = tun_rs::AsyncDevice;
    type Tunnel = TlsTunnel;
    type Lcp = crate::ppp::lcp::LcpState;

    fn setup_tun<'a>(
        &'a mut self,
        config: &'a TunnelConfig,
        shutdown: &'a Shutdown,
    ) -> DriverFuture<'a, Result<(Self::Tun, String)>> {
        Box::pin(vpn::setup_tun(config, shutdown))
    }

    fn cleanup_tun<'a>(
        &'a mut self,
        config: &'a TunnelConfig,
        iface_name: &'a str,
    ) -> DriverFuture<'a, ()> {
        Box::pin(vpn::cleanup_tun(config, iface_name))
    }

    fn start_monitors(
        &mut self,
        target: ReachabilityTarget,
    ) -> Result<(
        mpsc::UnboundedReceiver<NetworkEvent>,
        mpsc::UnboundedReceiver<PowerEvent>,
    )> {
        let (network_monitor, network_rx) = NetworkMonitor::start(target)
            .map_err(|error| FortiError::TunnelError(format!("network monitor failed: {error}")))?;
        self.network_monitor = Some(network_monitor);
        let (power_monitor, power_rx) = PowerMonitor::start()
            .map_err(|error| FortiError::TunnelError(format!("power monitor failed: {error}")))?;
        self.power_monitor = Some(power_monitor);
        Ok((network_rx, power_rx))
    }

    fn authenticate<'a>(&'a mut self, params: &'a AuthParams) -> DriverFuture<'a, Result<String>> {
        Box::pin(async move {
            let auth_client = params.auth_client()?;
            if params.saml {
                info!("Re-authenticating via SAML...");
                auth_client.authenticate_saml().await
            } else {
                let username = params
                    .username
                    .as_deref()
                    .ok_or_else(|| FortiError::AuthFailed("no username for re-auth".into()))?;
                let password = params
                    .password
                    .as_ref()
                    .ok_or_else(|| FortiError::AuthFailed("no password for re-auth".into()))?;
                info!("Re-authenticating with credentials...");
                auth_client
                    .authenticate_credentials(
                        username,
                        password.expose_secret(),
                        params.realm.as_deref(),
                    )
                    .await
            }
        })
    }

    fn fetch_tunnel_config<'a>(
        &'a mut self,
        params: &'a AuthParams,
        cookie: &'a str,
    ) -> DriverFuture<'a, Result<TunnelConfig>> {
        Box::pin(async move { params.auth_client()?.fetch_tunnel_config(cookie).await })
    }

    fn suspend_dns(&mut self) -> DriverFuture<'_, Result<()>> {
        Box::pin(crate::tun::dns::remove_dns())
    }

    fn resume_dns<'a>(
        &'a mut self,
        config: &'a TunnelConfig,
        shutdown: &'a Shutdown,
    ) -> DriverFuture<'a, Result<()>> {
        Box::pin(crate::tun::dns::configure_dns(
            &config.dns_servers,
            shutdown,
        ))
    }

    fn connect_tunnel<'a>(
        &'a mut self,
        params: &'a AuthParams,
        cookie: &'a str,
    ) -> DriverFuture<'a, DriverConnectResult<Self::Tunnel, Self::Lcp>> {
        Box::pin(async move {
            let mut tunnel = TlsTunnel::connect(
                &params.server,
                params.port,
                params.server_addr,
                cookie,
                params.tls_config.clone(),
            )
            .await
            .map_err(|source| ConnectFailure {
                kind: classify_tunnel_connect_error(&source),
                source,
            })?;

            let mut ppp = PppEngine::new(1500);
            let ipcp_config =
                ppp.negotiate(&mut tunnel)
                    .await
                    .map_err(|source| ConnectFailure {
                        kind: classify_tunnel_connect_error(&source),
                        source,
                    })?;
            Ok((tunnel, ppp.into_lcp(), ipcp_config.ip_address))
        })
    }

    fn event_loop<'a>(
        &'a mut self,
        tunnel: &'a mut Self::Tunnel,
        lcp: &'a mut Self::Lcp,
        tun: &'a Self::Tun,
        shutdown: &'a Shutdown,
        power_rx: &'a mut mpsc::UnboundedReceiver<PowerEvent>,
    ) -> DriverFuture<'a, DisconnectReason> {
        Box::pin(vpn::event_loop(tunnel, lcp, tun, shutdown, power_rx))
    }

    fn send_terminate<'a>(
        &'a mut self,
        tunnel: &'a mut Self::Tunnel,
        lcp: &'a mut Self::Lcp,
    ) -> DriverFuture<'a, Result<()>> {
        Box::pin(async move {
            let frame = PppFrame::new(PppProtocol::Lcp, lcp.build_terminate_request());
            tunnel.send_frame(frame.encode()).await
        })
    }
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

#[derive(Debug, Clone, Copy)]
struct RetryContext {
    current_operation: &'static str,
    retry_reason: &'static str,
    failure_class: &'static str,
}

fn connect_failure_class(kind: ConnectFailureKind) -> &'static str {
    match kind {
        ConnectFailureKind::TransportUnavailable => "transport_unavailable",
        ConnectFailureKind::CookieRejected => "cookie_rejected",
        ConnectFailureKind::PostUpgrade => "post_upgrade",
        ConnectFailureKind::LocalSetup => "local_setup",
        ConnectFailureKind::Cancelled => "cancelled",
    }
}

fn saml_failure_class(kind: SamlFailureKind) -> &'static str {
    match kind {
        SamlFailureKind::CallbackTimedOut => "callback_timed_out",
        SamlFailureKind::GatewayUnavailable => "gateway_unavailable",
        SamlFailureKind::CallbackInvalid => "callback_invalid",
        SamlFailureKind::UserCancelled => "user_cancelled",
        SamlFailureKind::LocalPortUnavailable => "local_port_unavailable",
        SamlFailureKind::TerminalConfiguration => "terminal_configuration",
    }
}

fn disconnect_failure_class(reason: &DisconnectReason) -> &'static str {
    match reason {
        DisconnectReason::DeadPeer => "dead_peer",
        DisconnectReason::TunnelClosed => "tunnel_closed",
        DisconnectReason::ServerTerminated => "server_terminated",
        DisconnectReason::IoError(_) => "io_error",
        DisconnectReason::SystemSleep => "system_sleep",
        DisconnectReason::UserQuit => "user_quit",
    }
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

/// Withdraw VPN DNS unless it has already been withdrawn. On failure the flag
/// is left unchanged: the controller keeps treating VPN DNS as installed (the
/// safe assumption for the SAML browser path) rather than recording a withdraw
/// that did not actually happen.
async fn suspend_vpn_dns<Driver: ControllerDriver>(driver: &mut Driver, dns_suspended: &mut bool) {
    if *dns_suspended {
        return;
    }
    match driver.suspend_dns().await {
        Ok(()) => *dns_suspended = true,
        Err(error) => warn!(
            error = %error,
            "Failed to withdraw VPN DNS; it may remain installed and black-hole the reconnect path"
        ),
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

    /// Run until shutdown or an unrecoverable local setup error.
    pub async fn run(&mut self) -> Result<()> {
        self.run_with_driver(&mut ProductionDriver::default()).await
    }

    async fn run_with_driver<Driver: ControllerDriver>(
        &mut self,
        driver: &mut Driver,
    ) -> Result<()> {
        let (initial_tun, mut iface_name) =
            match driver.setup_tun(&self.tunnel_config, &self.shutdown).await {
                Ok(setup) => setup,
                Err(_) if self.shutdown.is_cancelled() => return Ok(()),
                Err(error) => return Err(error),
            };
        let mut tun_dev = Some(initial_tun);
        let mut applied_config = self.tunnel_config.clone();
        let mut setup_active = true;
        info!("Press Ctrl+C to disconnect.");

        // Watch the gateway by its pinned IP when we have one. The hostname
        // path resolves via the system resolver, which by this point may be the
        // VPN's own DNS — that can pin the monitor to a VPN-internal address
        // that falsely reports unreachable once the tunnel drops, stalling every
        // reconnect until the 15s monitor fallback fires.
        let monitor_target = match self.auth_params.server_addr {
            Some(addr) => ReachabilityTarget::Address(addr),
            None => ReachabilityTarget::Host(self.auth_params.server.clone()),
        };
        let (mut network_rx, mut power_rx) = match driver.start_monitors(monitor_target) {
            Ok(receivers) => receivers,
            Err(error) => {
                driver.cleanup_tun(&applied_config, &iface_name).await;
                return Err(error);
            }
        };

        let shutdown = self.shutdown.clone();
        let mut terminal_error: Option<FortiError> = None;
        let mut pending_config_refresh = false;
        // VPN DNS servers are typically reachable only through the tunnel. While
        // no tunnel carries them they are withdrawn, otherwise every reconnect
        // attempt (and any SAML browser launch) resolves into a black hole.
        let mut dns_suspended = false;

        'reconnect: loop {
            if pending_config_refresh {
                self.state = ConnectionState::RefreshingConfig;
                match interruptible(
                    driver.fetch_tunnel_config(&self.auth_params, &self.svpn_cookie),
                    &shutdown,
                    &mut network_rx,
                    &mut power_rx,
                )
                .await
                {
                    Ok(Ok(config)) => {
                        self.tunnel_config = config;
                        pending_config_refresh = false;
                        self.policy.on_saml_success();
                        continue;
                    }
                    Ok(Err(FortiError::CookieRejected(status))) => {
                        warn!(
                            status,
                            "New session cookie was rejected while fetching config"
                        );
                        pending_config_refresh = false;
                        self.policy
                            .on_connect_failure(ConnectFailureKind::CookieRejected);
                        self.log_retry_transition(
                            RetryContext {
                                current_operation: "config_refresh",
                                retry_reason: "cookie_rejected",
                                failure_class: "cookie_rejected",
                            },
                            Duration::ZERO,
                            &ConnectionState::Authenticating,
                        );
                        continue;
                    }
                    Ok(Err(error)) => {
                        warn!(error = %error, "Tunnel config refresh failed; retrying without authentication");
                        let failure_kind = SamlFailureKind::classify(&error);
                        if self
                            .wait_for_retry(
                                RetryContext {
                                    current_operation: "config_refresh",
                                    retry_reason: "config_refresh_failed",
                                    failure_class: saml_failure_class(failure_kind),
                                },
                                &mut network_rx,
                                &mut power_rx,
                            )
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

            if let Some(attempt_kind) = self.policy.next_auth_attempt() {
                self.state = ConnectionState::Authenticating;
                info!(
                    state = ?self.state,
                    auth_requirement = ?self.policy.auth_requirement(),
                    saml_attempt = self.policy.saml_attempts(),
                    attempt_kind = ?attempt_kind,
                    "Starting reconnect authentication attempt"
                );
                prepare_cookie_for_auth(attempt_kind, &mut self.svpn_cookie);
                match interruptible(
                    driver.authenticate(&self.auth_params),
                    &shutdown,
                    &mut network_rx,
                    &mut power_rx,
                )
                .await
                {
                    Ok(Ok(cookie)) => {
                        // Save the cookie before config I/O. A transient config
                        // failure must retry with this cookie, not reopen SAML.
                        self.svpn_cookie = cookie;
                        pending_config_refresh = true;
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
                        if self
                            .wait_for_retry(
                                RetryContext {
                                    current_operation: "authentication",
                                    retry_reason: "authentication_failed",
                                    failure_class: saml_failure_class(failure_kind),
                                },
                                &mut network_rx,
                                &mut power_rx,
                            )
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
            self.policy.on_connect_attempt();
            info!(
                state = ?self.state,
                connect_attempt = self.policy.connect_attempts(),
                auth_requirement = ?self.policy.auth_requirement(),
                saml_attempt = self.policy.saml_attempts(),
                "Starting tunnel connection attempt"
            );
            let connect_result = match interruptible(
                driver.connect_tunnel(&self.auth_params, &self.svpn_cookie),
                &shutdown,
                &mut network_rx,
                &mut power_rx,
            )
            .await
            {
                Ok(result) => result,
                Err(Interrupt::Shutdown) => break,
                Err(Interrupt::Sleep) => {
                    // The first connect attempt can be interrupted before any
                    // tunnel exists, while setup_tun has already installed the
                    // VPN DNS. Withdraw it so the system resolver is usable
                    // again while we wait for wake.
                    suspend_vpn_dns(driver, &mut dns_suspended).await;
                    if self.wait_for_wake(&mut power_rx).await {
                        break;
                    }
                    continue;
                }
                Err(Interrupt::NetworkDown) => {
                    suspend_vpn_dns(driver, &mut dns_suspended).await;
                    if self.wait_for_network(&mut network_rx, &mut power_rx).await {
                        break;
                    }
                    continue;
                }
            };

            let (mut tunnel, mut lcp, negotiated_ip) = match connect_result {
                Ok(connected) => {
                    self.policy.on_tunnel_established();
                    connected
                }
                Err(connect_failure) => {
                    self.policy.on_connect_failure(connect_failure.kind);
                    suspend_vpn_dns(driver, &mut dns_suspended).await;
                    warn!(
                        state = ?self.state,
                        failure_class = ?connect_failure.kind,
                        connect_attempt = self.policy.connect_attempts(),
                        transport_failure_count = self.policy.transport_attempts(),
                        negotiation_failure_count = self.policy.negotiation_failures(),
                        auth_requirement = ?self.policy.auth_requirement(),
                        error = %connect_failure.source,
                        "Tunnel connection attempt failed"
                    );
                    if self.policy.auth_requirement() != AuthRequirement::NotRequired {
                        self.log_retry_transition(
                            RetryContext {
                                current_operation: "tunnel_connect",
                                retry_reason: "authentication_required",
                                failure_class: connect_failure_class(connect_failure.kind),
                            },
                            Duration::ZERO,
                            &ConnectionState::Authenticating,
                        );
                        continue;
                    }
                    if self
                        .wait_for_retry(
                            RetryContext {
                                current_operation: "tunnel_connect",
                                retry_reason: "connect_failed",
                                failure_class: connect_failure_class(connect_failure.kind),
                            },
                            &mut network_rx,
                            &mut power_rx,
                        )
                        .await
                        == RetryOutcome::Shutdown
                    {
                        break;
                    }
                    continue;
                }
            };

            if apply_negotiated_ip(&mut self.tunnel_config, negotiated_ip) {
                info!("IPCP assigned a new address: {}", negotiated_ip);
            }

            if network_config_changed(&applied_config, &self.tunnel_config) {
                warn!("VPN network configuration changed — recreating TUN device");
                driver.cleanup_tun(&applied_config, &iface_name).await;
                setup_active = false;
                drop(tun_dev.take());
                match driver.setup_tun(&self.tunnel_config, &shutdown).await {
                    Ok((new_tun, new_iface)) => {
                        tun_dev = Some(new_tun);
                        iface_name = new_iface;
                        applied_config = self.tunnel_config.clone();
                        setup_active = true;
                        // setup_tun reinstalls DNS for the new configuration.
                        dns_suspended = false;
                    }
                    Err(_) if shutdown.is_cancelled() => break 'reconnect,
                    Err(error) => {
                        terminal_error = Some(error);
                        break 'reconnect;
                    }
                }
            }

            if dns_suspended {
                if let Err(error) = driver.resume_dns(&self.tunnel_config, &shutdown).await {
                    warn!(error = %error, "Failed to reinstall VPN DNS after reconnect");
                } else {
                    dns_suspended = false;
                }
            }

            info!("Tunnel established, entering data plane");
            self.state = ConnectionState::Running;
            let reason = driver
                .event_loop(
                    &mut tunnel,
                    &mut lcp,
                    tun_dev.as_ref().expect("active setup has a TUN device"),
                    &shutdown,
                    &mut power_rx,
                )
                .await;

            if should_send_terminate(&reason) {
                let _ = tokio::time::timeout(
                    TERMINATE_TIMEOUT,
                    driver.send_terminate(&mut tunnel, &mut lcp),
                )
                .await;
            }
            drop(tunnel);

            // The tunnel is gone; withdraw its DNS servers before any wait.
            if reason != DisconnectReason::UserQuit {
                suspend_vpn_dns(driver, &mut dns_suspended).await;
            }

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
                    if self
                        .wait_for_retry(
                            RetryContext {
                                current_operation: "data_plane",
                                retry_reason: "data_plane_disconnected",
                                failure_class: disconnect_failure_class(&reason),
                            },
                            &mut network_rx,
                            &mut power_rx,
                        )
                        .await
                        == RetryOutcome::Shutdown
                    {
                        break;
                    }
                }
            }
        }

        self.state = ConnectionState::CleaningUp;
        if setup_active {
            driver.cleanup_tun(&applied_config, &iface_name).await;
        }
        info!("VPN disconnected.");
        match terminal_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
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
        loop {
            if self.shutdown.is_cancelled() {
                return true;
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => return true,
                _ = tokio::time::sleep(MONITOR_FALLBACK_TIMEOUT) => return false,
                event = next_power_event(power_rx) => {
                    if event == PowerEvent::HasPoweredOn {
                        self.policy.on_system_wake();
                        return false;
                    }
                }
            }
        }
    }

    fn log_retry_transition(
        &self,
        context: RetryContext,
        delay: Duration,
        next_state: &ConnectionState,
    ) {
        info!(
            state = ?next_state,
            backoff_ms = delay.as_millis() as u64,
            current_operation = context.current_operation,
            retry_reason = context.retry_reason,
            failure_class = context.failure_class,
            connect_attempt = self.policy.connect_attempts(),
            transport_failure_count = self.policy.transport_attempts(),
            saml_attempt = self.policy.saml_attempts(),
            auth_requirement = ?self.policy.auth_requirement(),
            "Reconnect retry transition"
        );
    }

    async fn wait_for_retry(
        &mut self,
        context: RetryContext,
        network_rx: &mut mpsc::UnboundedReceiver<NetworkEvent>,
        power_rx: &mut mpsc::UnboundedReceiver<PowerEvent>,
    ) -> RetryOutcome {
        self.state = ConnectionState::WaitingToRetry;
        let delay = self.policy.next_delay();
        self.log_retry_transition(context, delay, &self.state);
        if self.shutdown.is_cancelled() {
            return RetryOutcome::Shutdown;
        }
        tokio::select! {
            _ = self.shutdown.cancelled() => RetryOutcome::Shutdown,
            _ = tokio::time::sleep(delay) => RetryOutcome::Retry,
            event = next_network_event(network_rx) => {
                match event {
                    NetworkEvent::Reachable => {
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
        // A busy callback port must not strand the client: without a SAML
        // session there is no way back to a working tunnel, so giving up is
        // strictly worse than retrying behind the backoff.
        assert!(!auth_failure_is_terminal(
            AuthAttemptKind::Required,
            SamlFailureKind::LocalPortUnavailable
        ));
        assert_eq!(
            SamlFailureKind::classify(&FortiError::SamlCallbackPortUnavailable(
                "port 8020 busy".into()
            )),
            SamlFailureKind::LocalPortUnavailable
        );
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

    use crate::auth::xml::Route;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::{Arc as StdArc, Mutex};

    struct ScriptTun;
    struct ScriptTunnel;
    struct ScriptLcp;

    enum ScriptConnect {
        Failure(ConnectFailureKind),
        FailureThenSleepWake(ConnectFailureKind),
        Success(Ipv4Addr),
        Sleep,
    }

    enum ScriptAuth {
        Result(Result<String>),
        NetworkDown,
        SleepUntil(tokio::sync::oneshot::Receiver<()>),
        Pending,
    }

    struct ScriptDriver {
        log: StdArc<Mutex<Vec<String>>>,
        connects: VecDeque<ScriptConnect>,
        auth: VecDeque<ScriptAuth>,
        configs: VecDeque<Result<TunnelConfig>>,
        config_network_down: usize,
        events: VecDeque<DisconnectReason>,
        network_tx: Option<mpsc::UnboundedSender<NetworkEvent>>,
        power_tx: Option<mpsc::UnboundedSender<PowerEvent>>,
        setup_calls: usize,
        fail_setup_call: Option<usize>,
        fail_dns_suspend: usize,
    }

    impl Default for ScriptDriver {
        fn default() -> Self {
            Self {
                log: StdArc::new(Mutex::new(Vec::new())),
                connects: VecDeque::new(),
                auth: VecDeque::new(),
                configs: VecDeque::new(),
                config_network_down: 0,
                events: VecDeque::new(),
                network_tx: None,
                power_tx: None,
                setup_calls: 0,
                fail_setup_call: None,
                fail_dns_suspend: 0,
            }
        }
    }

    impl ScriptDriver {
        fn record(&self, value: impl Into<String>) {
            self.log.lock().unwrap().push(value.into());
        }

        fn snapshot(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    impl ControllerDriver for ScriptDriver {
        type Tun = ScriptTun;
        type Tunnel = ScriptTunnel;
        type Lcp = ScriptLcp;

        fn setup_tun<'a>(
            &'a mut self,
            config: &'a TunnelConfig,
            _shutdown: &'a Shutdown,
        ) -> DriverFuture<'a, Result<(Self::Tun, String)>> {
            self.setup_calls += 1;
            let call = self.setup_calls;
            self.record(format!(
                "setup:{}:{}:{}",
                config.ip_address,
                config
                    .routes
                    .first()
                    .map(|route| route.ip)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED),
                config
                    .dns_servers
                    .first()
                    .copied()
                    .unwrap_or(Ipv4Addr::UNSPECIFIED)
            ));
            let fail = self.fail_setup_call == Some(call);
            Box::pin(async move {
                if fail {
                    Err(FortiError::TunnelError("scripted setup failure".into()))
                } else {
                    Ok((ScriptTun, format!("utun{call}")))
                }
            })
        }

        fn cleanup_tun<'a>(
            &'a mut self,
            config: &'a TunnelConfig,
            iface_name: &'a str,
        ) -> DriverFuture<'a, ()> {
            self.record(format!(
                "cleanup:{iface_name}:{}:{}:{}",
                config.ip_address,
                config
                    .routes
                    .first()
                    .map(|route| route.ip)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED),
                config
                    .dns_servers
                    .first()
                    .copied()
                    .unwrap_or(Ipv4Addr::UNSPECIFIED)
            ));
            Box::pin(async {})
        }

        fn start_monitors(
            &mut self,
            _target: ReachabilityTarget,
        ) -> Result<(
            mpsc::UnboundedReceiver<NetworkEvent>,
            mpsc::UnboundedReceiver<PowerEvent>,
        )> {
            let (network_tx, network_rx) = mpsc::unbounded_channel();
            let (power_tx, power_rx) = mpsc::unbounded_channel();
            self.network_tx = Some(network_tx);
            self.power_tx = Some(power_tx);
            Ok((network_rx, power_rx))
        }

        fn authenticate<'a>(
            &'a mut self,
            _params: &'a AuthParams,
        ) -> DriverFuture<'a, Result<String>> {
            self.record("auth");
            match self.auth.pop_front().expect("missing scripted auth") {
                ScriptAuth::Result(result) => Box::pin(async move { result }),
                ScriptAuth::NetworkDown => {
                    let tx = self.network_tx.as_ref().unwrap().clone();
                    tx.send(NetworkEvent::Unreachable).unwrap();
                    tx.send(NetworkEvent::Reachable).unwrap();
                    Box::pin(std::future::pending())
                }
                ScriptAuth::SleepUntil(wake) => {
                    let tx = self.power_tx.as_ref().unwrap().clone();
                    tx.send(PowerEvent::WillSleep).unwrap();
                    tokio::spawn(async move {
                        if wake.await.is_ok() {
                            let _ = tx.send(PowerEvent::HasPoweredOn);
                        }
                    });
                    Box::pin(std::future::pending())
                }
                ScriptAuth::Pending => Box::pin(std::future::pending()),
            }
        }

        fn fetch_tunnel_config<'a>(
            &'a mut self,
            _params: &'a AuthParams,
            cookie: &'a str,
        ) -> DriverFuture<'a, Result<TunnelConfig>> {
            self.record(format!("config:{cookie}"));
            if self.config_network_down > 0 {
                self.config_network_down -= 1;
                let tx = self.network_tx.as_ref().unwrap().clone();
                tx.send(NetworkEvent::Unreachable).unwrap();
                tx.send(NetworkEvent::Reachable).unwrap();
                return Box::pin(std::future::pending());
            }
            let result = self.configs.pop_front().expect("missing scripted config");
            Box::pin(async move { result })
        }

        fn suspend_dns(&mut self) -> DriverFuture<'_, Result<()>> {
            self.record("dns_suspend");
            let fail = self.fail_dns_suspend > 0;
            if fail {
                self.fail_dns_suspend -= 1;
            }
            Box::pin(async move {
                if fail {
                    Err(FortiError::TunnelError(
                        "scripted DNS suspend failure".into(),
                    ))
                } else {
                    Ok(())
                }
            })
        }

        fn resume_dns<'a>(
            &'a mut self,
            config: &'a TunnelConfig,
            _shutdown: &'a Shutdown,
        ) -> DriverFuture<'a, Result<()>> {
            self.record(format!(
                "dns_resume:{}",
                config
                    .dns_servers
                    .first()
                    .copied()
                    .unwrap_or(Ipv4Addr::UNSPECIFIED)
            ));
            Box::pin(async { Ok(()) })
        }

        fn connect_tunnel<'a>(
            &'a mut self,
            _params: &'a AuthParams,
            cookie: &'a str,
        ) -> DriverFuture<'a, DriverConnectResult<Self::Tunnel, Self::Lcp>> {
            self.record(format!("connect:{cookie}"));
            match self.connects.pop_front().expect("missing scripted connect") {
                ScriptConnect::Failure(kind) => Box::pin(async move {
                    let source = match kind {
                        ConnectFailureKind::CookieRejected => FortiError::CookieRejected(403),
                        ConnectFailureKind::PostUpgrade => {
                            FortiError::PostUpgradeNegotiation("scripted".into())
                        }
                        _ => FortiError::TransportUnavailable(
                            "scripted HTTP 503/transport failure".into(),
                        ),
                    };
                    Err(ConnectFailure { kind, source })
                }),
                ScriptConnect::FailureThenSleepWake(kind) => {
                    let tx = self.power_tx.as_ref().unwrap().clone();
                    tokio::spawn(async move {
                        tokio::task::yield_now().await;
                        tx.send(PowerEvent::WillSleep).unwrap();
                        tx.send(PowerEvent::HasPoweredOn).unwrap();
                    });
                    Box::pin(async move {
                        Err(ConnectFailure {
                            kind,
                            source: FortiError::TransportUnavailable(
                                "scripted failure before sleep".into(),
                            ),
                        })
                    })
                }
                ScriptConnect::Success(ip) => {
                    Box::pin(async move { Ok((ScriptTunnel, ScriptLcp, ip)) })
                }
                ScriptConnect::Sleep => {
                    let tx = self.power_tx.as_ref().unwrap().clone();
                    tx.send(PowerEvent::WillSleep).unwrap();
                    tx.send(PowerEvent::HasPoweredOn).unwrap();
                    Box::pin(std::future::pending())
                }
            }
        }

        fn event_loop<'a>(
            &'a mut self,
            _tunnel: &'a mut Self::Tunnel,
            _lcp: &'a mut Self::Lcp,
            _tun: &'a Self::Tun,
            _shutdown: &'a Shutdown,
            _power_rx: &'a mut mpsc::UnboundedReceiver<PowerEvent>,
        ) -> DriverFuture<'a, DisconnectReason> {
            self.record("event_loop");
            let reason = self.events.pop_front().expect("missing scripted event");
            Box::pin(async move { reason })
        }

        fn send_terminate<'a>(
            &'a mut self,
            _tunnel: &'a mut Self::Tunnel,
            _lcp: &'a mut Self::Lcp,
        ) -> DriverFuture<'a, Result<()>> {
            self.record("terminate");
            Box::pin(async { Ok(()) })
        }
    }

    fn config(ip: [u8; 4], route: [u8; 4], dns: [u8; 4]) -> TunnelConfig {
        TunnelConfig {
            ip_address: Ipv4Addr::from(ip),
            dns_servers: vec![Ipv4Addr::from(dns)],
            routes: vec![Route {
                ip: Ipv4Addr::from(route),
                mask: Ipv4Addr::new(255, 255, 255, 0),
            }],
            idle_timeout: None,
            auth_timeout: None,
            dtls_port: None,
            fos_version: None,
            tunnel_method: "ppp".into(),
        }
    }

    fn controller(initial: TunnelConfig, shutdown: Shutdown) -> ReconnectController {
        controller_with_saml(initial, shutdown, true)
    }

    fn controller_with_saml(
        initial: TunnelConfig,
        shutdown: Shutdown,
        saml: bool,
    ) -> ReconnectController {
        let auth_client = AuthClient::new("vpn.example", 443, false).unwrap();
        ReconnectController::new(
            AuthParams {
                server: "vpn.example".into(),
                port: 443,
                server_addr: None,
                saml,
                username: None,
                password: None,
                realm: None,
                tls_config: auth_client.tls_config(),
                enable_keylog: false,
            },
            "old-cookie".into(),
            initial,
            shutdown,
        )
    }

    #[test]
    fn public_controller_run_future_is_send() {
        fn assert_send<T: Send>(_: T) {}

        let mut controller = controller(
            config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]),
            Shutdown::new(),
        );
        assert_send(controller.run());
    }

    #[tokio::test(start_paused = true)]
    async fn cookie_rejections_bypass_capped_backoff_without_advancing_time() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        for _ in 0..7 {
            controller.policy.next_delay();
        }
        assert_eq!(controller.policy.current_delay(), Duration::from_secs(60));

        let mut driver = ScriptDriver::default();
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("first-new-cookie".into())));
        driver
            .configs
            .push_back(Err(FortiError::CookieRejected(403)));
        driver.auth.push_back(ScriptAuth::Pending);

        let log = driver.log.clone();
        let started_at = tokio::time::Instant::now();
        {
            let run = controller.run_with_driver(&mut driver);
            tokio::pin!(run);
            let observe_second_auth = async {
                for _ in 0..1_000 {
                    if log
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|entry| *entry == "auth")
                        .count()
                        == 2
                    {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
                panic!("authentication was not called without waiting for capped backoff");
            };
            tokio::select! {
                result = &mut run => panic!("controller unexpectedly completed: {result:?}"),
                _ = observe_second_auth => {}
            }
        }

        assert_eq!(tokio::time::Instant::now(), started_at);
        assert_eq!(controller.policy.current_delay(), Duration::from_secs(60));
        assert_eq!(
            driver
                .snapshot()
                .iter()
                .filter(|entry| *entry == "auth")
                .count(),
            2
        );
    }

    #[tokio::test(start_paused = true)]
    async fn saml_sleep_waits_for_explicit_wake_before_retrying_authentication() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        let (wake_tx, wake_rx) = tokio::sync::oneshot::channel();
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver.auth.push_back(ScriptAuth::SleepUntil(wake_rx));
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("new-cookie".into())));
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        let log = driver.log.clone();
        let run = controller.run_with_driver(&mut driver);
        tokio::pin!(run);
        let prove_auth_is_blocked_before_wake = async {
            for _ in 0..1_000 {
                let auth_calls = log
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|entry| *entry == "auth")
                    .count();
                assert!(
                    auth_calls <= 1,
                    "authentication retried before HasPoweredOn"
                );
                tokio::task::yield_now().await;
            }
        };
        tokio::select! {
            result = &mut run => panic!("controller completed before explicit wake: {result:?}"),
            _ = prove_auth_is_blocked_before_wake => {}
        }
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|entry| *entry == "auth")
                .count(),
            1
        );

        wake_tx.send(()).expect("release scripted wake gate");
        (&mut run).await.unwrap();

        let log = log.lock().unwrap();
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 2);
        assert!(log.contains(&"connect:new-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn dead_peer_backoff_reconnects_with_cached_cookie_then_user_quits() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
        ]);
        driver
            .events
            .extend([DisconnectReason::DeadPeer, DisconnectReason::UserQuit]);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();
        assert_eq!(
            log.iter()
                .filter(|entry| *entry == "connect:old-cookie")
                .count(),
            2
        );
        assert_eq!(log.iter().filter(|entry| *entry == "event_loop").count(), 2);
        assert_eq!(controller.state, ConnectionState::CleaningUp);
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_sleep_waits_for_wake_before_cached_cookie_retry() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::FailureThenSleepWake(ConnectFailureKind::TransportUnavailable),
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
        ]);
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        assert_eq!(
            driver
                .snapshot()
                .iter()
                .filter(|entry| *entry == "connect:old-cookie")
                .count(),
            2
        );
    }

    #[tokio::test(start_paused = true)]
    async fn network_cycle_during_config_refresh_retries_only_config() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver {
            config_network_down: 1,
            ..ScriptDriver::default()
        };
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("new-cookie".into())));
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 1);
        assert_eq!(
            log.iter()
                .filter(|entry| *entry == "config:new-cookie")
                .count(),
            2
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_cancels_pending_saml_and_mfa_auth_and_cleans_up() {
        for saml in [true, false] {
            let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
            let shutdown = Shutdown::new();
            let trigger = shutdown.clone();
            let mut controller = controller_with_saml(initial, shutdown, saml);
            let mut driver = ScriptDriver::default();
            driver
                .connects
                .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
            driver.auth.push_back(ScriptAuth::Pending);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1100)).await;
                trigger.cancel();
            });

            controller.run_with_driver(&mut driver).await.unwrap();
            let log = driver.snapshot();
            assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 1);
            assert_eq!(
                log.iter()
                    .filter(|entry| entry.starts_with("cleanup:"))
                    .count(),
                1
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_transport_and_http_5xx_failures_never_open_saml() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let shutdown = Shutdown::new();
        let mut controller = controller(initial, shutdown);
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
        ]);
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 0);
        assert_eq!(
            log.iter()
                .filter(|entry| entry.starts_with("connect:"))
                .count(),
            6
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_old_cookie_and_saml_timeout_never_reuses_old_cookie() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        let mut controller = controller(initial, shutdown);
        let mut driver = ScriptDriver::default();
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver
            .auth
            .push_back(ScriptAuth::Result(Err(FortiError::SamlCallbackTimedOut)));
        driver
            .auth
            .push_back(ScriptAuth::Result(Err(FortiError::SamlCallbackTimedOut)));
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            trigger.cancel();
        });

        controller.run_with_driver(&mut driver).await.unwrap();
        let connects: Vec<_> = driver
            .snapshot()
            .into_iter()
            .filter(|entry| entry.starts_with("connect:"))
            .collect();
        assert_eq!(connects, ["connect:old-cookie"]);
        assert!(controller.svpn_cookie.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn new_cookie_survives_config_timeout_and_config_only_retry() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("new-cookie".into())));
        driver
            .configs
            .push_back(Err(FortiError::TransportUnavailable(
                "config timed out".into(),
            )));
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 1);
        assert_eq!(
            log.iter()
                .filter(|entry| *entry == "config:new-cookie")
                .count(),
            2
        );
        assert!(log.contains(&"connect:new-cookie".to_string()));
        assert_eq!(controller.svpn_cookie, "new-cookie");
    }

    #[tokio::test(start_paused = true)]
    async fn compatibility_probe_runs_once_per_reconnect_episode() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let mut driver = ScriptDriver::default();
        for _ in 0..5 {
            driver
                .connects
                .push_back(ScriptConnect::Failure(ConnectFailureKind::PostUpgrade));
        }
        driver
            .auth
            .push_back(ScriptAuth::Result(Err(FortiError::SamlCallbackTimedOut)));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        assert_eq!(
            driver
                .snapshot()
                .iter()
                .filter(|entry| *entry == "auth")
                .count(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn sleep_during_connect_and_network_loss_during_auth_are_interruptible() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::Sleep,
            ScriptConnect::Failure(ConnectFailureKind::CookieRejected),
        ]);
        driver.auth.push_back(ScriptAuth::NetworkDown);
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("new-cookie".into())));
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 2);
        assert!(log.contains(&"connect:new-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_during_backoff_runs_final_cleanup() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        let mut controller = controller(initial, shutdown);
        let mut driver = ScriptDriver::default();
        driver.connects.push_back(ScriptConnect::Failure(
            ConnectFailureKind::TransportUnavailable,
        ));
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            trigger.cancel();
        });

        controller.run_with_driver(&mut driver).await.unwrap();
        assert_eq!(
            driver
                .snapshot()
                .iter()
                .filter(|entry| entry.starts_with("cleanup:"))
                .count(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn each_network_config_component_change_rebuilds_and_cleans_new_setup() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let cases = [
            (
                "ip",
                config([10, 9, 0, 8], [10, 1, 0, 0], [10, 0, 0, 53]),
                Ipv4Addr::new(10, 9, 0, 8),
            ),
            (
                "route",
                config([10, 0, 0, 2], [172, 16, 0, 0], [10, 0, 0, 53]),
                Ipv4Addr::new(10, 0, 0, 2),
            ),
            (
                "dns",
                config([10, 0, 0, 2], [10, 1, 0, 0], [10, 9, 0, 53]),
                Ipv4Addr::new(10, 0, 0, 2),
            ),
        ];

        for (component, changed, negotiated_ip) in cases {
            let mut controller = controller(initial.clone(), Shutdown::new());
            let mut driver = ScriptDriver::default();
            driver
                .connects
                .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
            driver
                .auth
                .push_back(ScriptAuth::Result(Ok("new-cookie".into())));
            driver.configs.push_back(Ok(changed.clone()));
            driver
                .connects
                .push_back(ScriptConnect::Success(negotiated_ip));
            driver.events.push_back(DisconnectReason::UserQuit);

            controller.run_with_driver(&mut driver).await.unwrap();
            let log = driver.snapshot();
            assert_eq!(
                log.iter()
                    .filter(|entry| entry.starts_with("setup:"))
                    .count(),
                2,
                "{component} change must rebuild the setup"
            );
            let cleanups: Vec<_> = log
                .iter()
                .filter(|entry| entry.starts_with("cleanup:"))
                .collect();
            assert_eq!(
                cleanups.len(),
                2,
                "{component} change must clean old and replacement setups"
            );
            assert!(cleanups[0].contains("10.0.0.2"));
            assert!(cleanups[1].contains(&changed.ip_address.to_string()));
            assert!(cleanups[1].contains(&changed.routes[0].ip.to_string()));
            assert!(cleanups[1].contains(&changed.dns_servers[0].to_string()));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn config_cookie_rejection_returns_to_fresh_authentication() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("first-new-cookie".into())));
        driver
            .configs
            .push_back(Err(FortiError::CookieRejected(403)));
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("second-new-cookie".into())));
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 2);
        assert!(log.contains(&"config:first-new-cookie".to_string()));
        assert!(log.contains(&"config:second-new-cookie".to_string()));
        assert_eq!(controller.svpn_cookie, "second-new-cookie");
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_setup_failure_does_not_double_cleanup_old_setup() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let mut driver = ScriptDriver {
            fail_setup_call: Some(2),
            ..ScriptDriver::default()
        };
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 9)));

        assert!(controller.run_with_driver(&mut driver).await.is_err());
        let log = driver.snapshot();
        assert_eq!(
            log.iter()
                .filter(|entry| entry.starts_with("setup:"))
                .count(),
            2
        );
        assert_eq!(
            log.iter()
                .filter(|entry| entry.starts_with("cleanup:"))
                .count(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn data_plane_disconnect_withdraws_vpn_dns_until_tunnel_returns() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
        ]);
        driver
            .events
            .extend([DisconnectReason::DeadPeer, DisconnectReason::UserQuit]);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        // The VPN DNS servers are only reachable through the tunnel, so they
        // must be withdrawn while it is down and reinstalled once it is back.
        let suspend = log.iter().position(|entry| entry == "dns_suspend");
        let resume = log.iter().position(|entry| entry == "dns_resume:10.0.0.53");
        assert!(
            suspend.is_some(),
            "disconnect must withdraw VPN DNS: {log:?}"
        );
        assert!(
            resume.is_some(),
            "reconnect must reinstall VPN DNS: {log:?}"
        );
        assert!(suspend < resume, "withdraw must precede reinstall: {log:?}");

        // The retry wait must happen with DNS already withdrawn.
        let retry_connect = log
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.starts_with("connect:"))
            .nth(1)
            .map(|(index, _)| index);
        assert!(
            suspend < retry_connect,
            "DNS must be withdrawn before the retry connect: {log:?}"
        );

        assert_eq!(
            log.iter().filter(|entry| *entry == "dns_suspend").count(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_connect_failures_withdraw_vpn_dns_exactly_once() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let mut driver = ScriptDriver::default();
        for _ in 0..4 {
            driver.connects.push_back(ScriptConnect::Failure(
                ConnectFailureKind::TransportUnavailable,
            ));
        }
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        // Repeated failures must not re-run scutil on every attempt.
        assert_eq!(
            log.iter().filter(|entry| *entry == "dns_suspend").count(),
            1,
            "{log:?}"
        );
        assert_eq!(
            log.iter()
                .filter(|entry| *entry == "dns_resume:10.0.0.53")
                .count(),
            1,
            "{log:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn clean_user_quit_leaves_dns_to_final_cleanup() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let mut driver = ScriptDriver::default();
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        // A never-interrupted session installs DNS once via setup_tun and
        // removes it once via cleanup_tun; no mid-session churn.
        assert!(!log.iter().any(|entry| entry == "dns_suspend"), "{log:?}");
        assert!(
            !log.iter().any(|entry| entry.starts_with("dns_resume")),
            "{log:?}"
        );
        assert_eq!(
            log.iter()
                .filter(|entry| entry.starts_with("cleanup:"))
                .count(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn first_connect_sleep_interrupt_withdraws_vpn_dns() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        // The first connect is interrupted by sleep before any tunnel is up,
        // while setup_tun has already installed the VPN DNS.
        driver.connects.push_back(ScriptConnect::Sleep);
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        // setup_tun installs DNS; the first-iteration sleep must withdraw it
        // before the retry reconnects, then the reconnect reinstalls it.
        let suspend = log.iter().position(|entry| entry == "dns_suspend");
        let resume = log.iter().position(|entry| entry == "dns_resume:10.0.0.53");
        assert!(
            suspend.is_some(),
            "first-iteration sleep must withdraw VPN DNS: {log:?}"
        );
        assert!(
            resume.is_some(),
            "reconnect must reinstall VPN DNS: {log:?}"
        );
        assert!(suspend < resume, "withdraw must precede reinstall: {log:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn suspend_dns_failure_is_retried_not_skipped() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let mut driver = ScriptDriver {
            fail_dns_suspend: 1,
            ..ScriptDriver::default()
        };
        // The first suspend is scripted to fail; because the controller must
        // not record a withdraw that did not happen, it suspends again on the
        // next failure before finally resuming on connect success.
        driver.connects.extend([
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
        ]);
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        assert_eq!(
            log.iter().filter(|entry| *entry == "dns_suspend").count(),
            2,
            "a failed suspend must be retried on the next failure: {log:?}"
        );
        assert_eq!(
            log.iter()
                .filter(|entry| *entry == "dns_resume:10.0.0.53")
                .count(),
            1,
            "{log:?}"
        );
    }
}
