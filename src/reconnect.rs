use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::auth::xml::TunnelConfig;
use crate::auth::{AuthClient, SamlAttempt, SamlBrowserPresentation};
use crate::error::{AuthRequirement, ConnectFailureKind, FortiError, Result, SamlFailureKind};
use crate::network_monitor::{NetworkEvent, NetworkMonitor, ReachabilityTarget};
use crate::power_monitor::{PowerCapabilities, PowerEvent, PowerMonitor};
use crate::ppp::codec::{PppFrame, PppProtocol};
use crate::ppp::PppEngine;
use crate::shutdown::Shutdown;
use crate::tunnel::TlsTunnel;
use crate::vpn;
use crate::wifi_monitor::WifiEvent;

/// Reason the VPN event loop exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    DeadPeer,
    TunnelClosed,
    ServerTerminated,
    IoError(String),
    SystemSleep,
    /// The machine joined a trusted Wi-Fi network; the VPN must stay down
    /// until the network drifts off the whitelist again.
    TrustedNetwork,
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

fn saml_failure_is_terminal(failure: SamlFailureKind) -> bool {
    failure == SamlFailureKind::TerminalConfiguration
}

/// Detect a likely sleep gap from a delayed keepalive tick.
pub fn detect_sleep_gap(last_tick: Instant, expected_interval: Duration) -> bool {
    last_tick.elapsed() > expected_interval * 3
}

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(2);
const MONITOR_FALLBACK_TIMEOUT: Duration = Duration::from_secs(15);
/// Safety net for a wake notification that never arrives. Long enough that a
/// normally-delivered capability change always wins, short enough that a lost
/// one costs minutes rather than the rest of the session.
const WAKE_FALLBACK_TIMEOUT: Duration = Duration::from_secs(120);
const SAML_BACKGROUND_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const SAML_INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Tracks the latest authoritative power capability level while preserving the
/// existing single-consumer event stream. Unknown capabilities fail open only
/// before a real sleep edge; after `WillSleep`, a CPU+network capability update
/// is required before network work resumes.
pub(crate) struct PowerTracker {
    rx: mpsc::UnboundedReceiver<PowerEvent>,
    capabilities: PowerCapabilities,
    sleeping: bool,
}

impl PowerTracker {
    pub(crate) fn new(rx: mpsc::UnboundedReceiver<PowerEvent>) -> Self {
        let mut tracker = Self {
            rx,
            capabilities: PowerCapabilities::UNKNOWN,
            sleeping: false,
        };
        tracker.drain();
        tracker
    }

    fn drain(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            self.apply(event);
        }
    }

    fn apply(&mut self, event: PowerEvent) {
        match event {
            PowerEvent::WillSleep => self.sleeping = true,
            PowerEvent::HasPoweredOn => {
                // HasPoweredOn also fires for Dark Wake. Capability changes,
                // not this legacy edge, decide which work may resume.
            }
            PowerEvent::Capabilities(capabilities) => {
                self.capabilities = capabilities;
                if capabilities.known {
                    self.sleeping = !capabilities.cpu;
                }
            }
        }
    }

    /// Drop back to the fail-open level used before any capability arrived.
    /// Only for the wake fallback: it lets a bounded reconnect probe run when
    /// the authoritative signal is missing, without inventing a capability set.
    fn assume_awake(&mut self) {
        self.sleeping = false;
        self.capabilities = PowerCapabilities::UNKNOWN;
    }

    pub(crate) fn can_run_network(&self) -> bool {
        !self.sleeping
            && (!self.capabilities.known || (self.capabilities.cpu && self.capabilities.network))
    }

    fn can_interact(&self) -> bool {
        self.can_run_network() && (!self.capabilities.known || self.capabilities.graphics)
    }

    pub(crate) async fn next_event(&mut self) -> PowerEvent {
        let event = match self.rx.recv().await {
            Some(event) => event,
            None => std::future::pending().await,
        };
        self.apply(event);
        event
    }
}

/// Tracks the latest gateway reachability level so browser authentication is
/// not started from a stale or already-consumed `Unreachable` edge.
struct NetworkTracker {
    rx: mpsc::UnboundedReceiver<NetworkEvent>,
    reachable: Option<bool>,
}

impl NetworkTracker {
    fn new(rx: mpsc::UnboundedReceiver<NetworkEvent>) -> Self {
        let mut tracker = Self {
            rx,
            reachable: None,
        };
        tracker.drain();
        tracker
    }

    fn drain(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            self.apply(event);
        }
    }

    fn apply(&mut self, event: NetworkEvent) {
        self.reachable = Some(event == NetworkEvent::Reachable);
    }

    fn can_attempt(&self) -> bool {
        self.reachable != Some(false)
    }

    fn allow_fallback_probe(&mut self) {
        self.reachable = None;
    }

    async fn next_event(&mut self) -> NetworkEvent {
        let event = match self.rx.recv().await {
            Some(event) => event,
            None => std::future::pending().await,
        };
        self.apply(event);
        event
    }
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

/// When repeated reconnect failures escalate from cookie retries to full
/// re-authentication.
///
/// The gateway only sends a definitive cookie rejection (401/403) when it
/// considers the session gone. A zombie session left behind by an unclean
/// disconnect never produces one, so local failure evidence must be able to
/// escalate on its own.
#[derive(Debug, Clone, Copy)]
pub struct EscalationConfig {
    /// Consecutive failed cycles that force full re-authentication.
    pub max_failed_cycles: u32,
    /// A tunnel dying within this window after establishment counts as a
    /// failed cycle, not a success.
    pub flap_window: Duration,
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            max_failed_cycles: 5,
            flap_window: Duration::from_secs(120),
        }
    }
}

/// Pure reconnect decision state. An episode ends only after both TLS and PPP
/// negotiation succeed.
pub struct ReconnectPolicy {
    backoff: Backoff,
    auth_requirement: AuthRequirement,
    connect_attempts: u32,
    transport_attempts: u32,
    failed_cycles: u32,
    /// The failed-cycle count as it was when the current tunnel came up. A
    /// tunnel that dies within the flap window was never a real success, so
    /// the flap handler restores this evidence before counting the flap.
    failed_cycles_at_establishment: u32,
    escalation: EscalationConfig,
    saml_attempts: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl ReconnectPolicy {
    pub fn new() -> Self {
        Self::with_escalation(EscalationConfig::default())
    }

    pub fn with_escalation(escalation: EscalationConfig) -> Self {
        Self {
            backoff: Backoff::new(),
            auth_requirement: AuthRequirement::NotRequired,
            connect_attempts: 0,
            transport_attempts: 0,
            failed_cycles: 0,
            failed_cycles_at_establishment: 0,
            escalation,
            saml_attempts: 0,
        }
    }

    pub fn auth_requirement(&self) -> AuthRequirement {
        self.auth_requirement
    }

    /// The authentication gate: re-authentication only runs once the cookie is
    /// known or suspected to be unusable.
    pub fn next_auth_attempt(&mut self) -> bool {
        if self.auth_requirement != AuthRequirement::Required {
            return false;
        }
        self.saml_attempts = self.saml_attempts.saturating_add(1);
        true
    }

    /// Count one more cycle that failed to produce a healthy tunnel. Any failure
    /// kind counts: during unstable networking the failure modes interleave, and
    /// a counter that only tracks one kind consecutively never reaches its
    /// threshold. Past the configured threshold the only way back is a fresh
    /// session, so escalate to full re-authentication rather than retrying a
    /// possibly-zombie cookie forever.
    fn record_failed_cycle(&mut self) {
        self.failed_cycles = self.failed_cycles.saturating_add(1);
        if self.failed_cycles >= self.escalation.max_failed_cycles {
            self.auth_requirement = AuthRequirement::Required;
        }
    }

    pub fn on_connect_failure(&mut self, kind: ConnectFailureKind) {
        match kind {
            ConnectFailureKind::TransportUnavailable => {
                self.transport_attempts = self.transport_attempts.saturating_add(1);
                self.record_failed_cycle();
            }
            ConnectFailureKind::CookieRejected => {
                // A definitive rejection begins a new required-auth episode.
                self.transport_attempts = 0;
                self.failed_cycles = 0;
                self.auth_requirement = AuthRequirement::Required;
            }
            ConnectFailureKind::PostUpgrade => {
                self.record_failed_cycle();
            }
            ConnectFailureKind::LocalSetup | ConnectFailureKind::Cancelled => {}
        }
    }

    pub fn on_connect_attempt(&mut self) {
        self.connect_attempts = self.connect_attempts.saturating_add(1);
    }

    /// A SAML failure keeps the requirement sticky: without a fresh cookie
    /// there is no way back to a working tunnel.
    pub fn on_saml_failure(&mut self, _kind: SamlFailureKind) {
        self.auth_requirement = AuthRequirement::Required;
    }

    /// A pending attempt was shown to the user again. It is not a new attempt —
    /// the listener and IdP transaction are unchanged — but the counter has to
    /// advance so a stalled SAML does not read as a frozen attempt in the logs.
    pub fn on_saml_presented_again(&mut self) {
        self.saml_attempts = self.saml_attempts.saturating_add(1);
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

    /// The tunnel came up but died within the flap window for a non-user reason:
    /// the gateway accepted the cookie, yet the session cannot carry traffic.
    /// Establishment reset the failure evidence, but this tunnel was never a
    /// real success, so restore the count it wiped before counting the flap —
    /// otherwise repeated accept-then-drop flapping would never reach the
    /// escalation threshold.
    pub fn on_short_lived_tunnel(&mut self) {
        self.failed_cycles = self.failed_cycles.max(self.failed_cycles_at_establishment);
        self.record_failed_cycle();
    }

    pub fn on_tunnel_established(&mut self) {
        self.backoff.reset();
        self.auth_requirement = AuthRequirement::NotRequired;
        self.connect_attempts = 0;
        self.transport_attempts = 0;
        self.failed_cycles_at_establishment = self.failed_cycles;
        self.failed_cycles = 0;
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

    pub fn failed_cycles(&self) -> u32 {
        self.failed_cycles
    }

    pub fn flap_window(&self) -> Duration {
        self.escalation.flap_window
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
    WaitingForInteractiveAuth,
    SuspendedOnTrustedWifi,
    CleaningUp,
}

/// Whether the given SSID exactly matches a whitelisted trusted network.
/// `None` (no Wi-Fi, or the SSID could not be determined) is never trusted,
/// so wired networks and query failures fail open toward establishing the
/// VPN. An empty whitelist trusts nothing — the feature is disabled.
pub fn is_trusted_wifi(ssid: Option<&str>, whitelist: &[String]) -> bool {
    ssid.is_some_and(|current| whitelist.iter().any(|trusted| trusted == current))
}

/// Trusted Wi-Fi gating configuration. With no whitelisted SSIDs the
/// controller behaves exactly as before; `wifi_rx` carries events from a
/// [`crate::wifi_monitor::WifiMonitor`] started by the caller.
#[derive(Default)]
pub struct TrustedWifiConfig {
    pub ssids: Vec<String>,
    pub wifi_rx: Option<mpsc::UnboundedReceiver<WifiEvent>>,
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
    trusted_ssids: Vec<String>,
    wifi_rx: Option<mpsc::UnboundedReceiver<WifiEvent>>,
    wifi_trusted: bool,
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

trait ControllerSamlAttempt: Send {
    fn url(&self) -> &str;
    /// Borrows nothing, so the controller can keep polling one launch across
    /// select cancellations instead of dropping and respawning the browser.
    fn present(
        &self,
        presentation: SamlBrowserPresentation,
    ) -> DriverFuture<'static, std::io::Result<()>>;
    fn callback_received(&self) -> bool;
    fn wait_for_callback(&self) -> DriverFuture<'_, Result<()>>;
    fn wait_result(&mut self) -> DriverFuture<'_, Result<String>>;
}

impl ControllerSamlAttempt for SamlAttempt {
    fn url(&self) -> &str {
        SamlAttempt::url(self)
    }

    fn present(
        &self,
        presentation: SamlBrowserPresentation,
    ) -> DriverFuture<'static, std::io::Result<()>> {
        Box::pin(SamlAttempt::present(self, presentation))
    }

    fn callback_received(&self) -> bool {
        SamlAttempt::callback_received(self)
    }

    fn wait_for_callback(&self) -> DriverFuture<'_, Result<()>> {
        Box::pin(SamlAttempt::wait_for_callback(self))
    }

    fn wait_result(&mut self) -> DriverFuture<'_, Result<String>> {
        Box::pin(SamlAttempt::wait_result(self))
    }
}

trait ControllerDriver: Send {
    type Tun: Sync;
    type Tunnel: Send;
    type Lcp: Send;
    type SamlAttempt: ControllerSamlAttempt;

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
    fn begin_saml_attempt<'a>(
        &'a mut self,
        params: &'a AuthParams,
    ) -> DriverFuture<'a, Result<Self::SamlAttempt>>;
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
    #[allow(clippy::too_many_arguments)]
    fn event_loop<'a>(
        &'a mut self,
        tunnel: &'a mut Self::Tunnel,
        lcp: &'a mut Self::Lcp,
        tun: &'a Self::Tun,
        shutdown: &'a Shutdown,
        power: &'a mut PowerTracker,
        wifi_rx: &'a mut mpsc::UnboundedReceiver<WifiEvent>,
        trusted_ssids: &'a [String],
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
    type SamlAttempt = SamlAttempt;

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

    fn begin_saml_attempt<'a>(
        &'a mut self,
        params: &'a AuthParams,
    ) -> DriverFuture<'a, Result<Self::SamlAttempt>> {
        Box::pin(async move {
            info!("Re-authenticating via SAML...");
            params.auth_client()?.begin_saml_attempt().await
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
        power: &'a mut PowerTracker,
        wifi_rx: &'a mut mpsc::UnboundedReceiver<WifiEvent>,
        trusted_ssids: &'a [String],
    ) -> DriverFuture<'a, DisconnectReason> {
        Box::pin(vpn::event_loop(
            tunnel,
            lcp,
            tun,
            shutdown,
            power,
            wifi_rx,
            trusted_ssids,
        ))
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
    TrustedWifi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryOutcome {
    Retry,
    Shutdown,
}

enum SamlRunOutcome {
    Completed(Result<String>),
    BackgroundTimedOut,
    Interrupted(Interrupt),
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
        DisconnectReason::TrustedNetwork => "trusted_network",
        DisconnectReason::UserQuit => "user_quit",
    }
}

/// Poll a retained browser launch without consuming it, so a cancelled select
/// arm leaves the launcher running instead of killing its child on drop.
async fn poll_launch(
    launch: &mut Option<DriverFuture<'static, std::io::Result<()>>>,
) -> std::io::Result<()> {
    match launch.as_mut() {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

pub(crate) async fn next_wifi_event(rx: &mut mpsc::UnboundedReceiver<WifiEvent>) -> WifiEvent {
    match rx.recv().await {
        Some(event) => event,
        None => std::future::pending().await,
    }
}

/// A receiver whose sender is already gone: `next_wifi_event` pends on it
/// forever, so every Wi-Fi select arm is inert when the feature is disabled.
fn closed_wifi_receiver() -> mpsc::UnboundedReceiver<WifiEvent> {
    let (_tx, rx) = mpsc::unbounded_channel();
    rx
}

#[allow(clippy::too_many_arguments)]
async fn interruptible<T>(
    operation: impl Future<Output = T>,
    shutdown: &Shutdown,
    network: &mut NetworkTracker,
    power: &mut PowerTracker,
    wifi_rx: &mut mpsc::UnboundedReceiver<WifiEvent>,
    trusted_ssids: &[String],
) -> std::result::Result<T, Interrupt> {
    tokio::pin!(operation);
    loop {
        if shutdown.is_cancelled() {
            return Err(Interrupt::Shutdown);
        }
        if !power.can_run_network() {
            return Err(Interrupt::Sleep);
        }
        if !network.can_attempt() {
            return Err(Interrupt::NetworkDown);
        }
        tokio::select! {
            _ = shutdown.cancelled() => return Err(Interrupt::Shutdown),
            _ = power.next_event() => {
                if !power.can_run_network() {
                    return Err(Interrupt::Sleep);
                }
            }
            event = network.next_event() => {
                if event == NetworkEvent::Unreachable {
                    return Err(Interrupt::NetworkDown);
                }
            }
            wifi = next_wifi_event(wifi_rx) => {
                if is_trusted_wifi(wifi.ssid.as_deref(), trusted_ssids) {
                    return Err(Interrupt::TrustedWifi);
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
        escalation: EscalationConfig,
        trusted_wifi: TrustedWifiConfig,
    ) -> Self {
        Self {
            auth_params,
            svpn_cookie,
            tunnel_config,
            policy: ReconnectPolicy::with_escalation(escalation),
            state: ConnectionState::EstablishingTunnel,
            shutdown,
            trusted_ssids: trusted_wifi.ssids,
            wifi_rx: trusted_wifi.wifi_rx,
            // The caller only hands over control on an untrusted network; a
            // trusted SSID at startup is handled before the controller runs.
            wifi_trusted: false,
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
        let mut wifi_rx = self.wifi_rx.take().unwrap_or_else(closed_wifi_receiver);
        let trusted_ssids = self.trusted_ssids.clone();
        // A trusted SSID may already be queued before the first TUN setup
        // (the network flipped between the caller's startup gate and here).
        // Routes and DNS must never be installed on a trusted network, so
        // check before setting anything up rather than tearing it down again.
        while let Ok(event) = wifi_rx.try_recv() {
            self.wifi_trusted = is_trusted_wifi(event.ssid.as_deref(), &trusted_ssids);
        }

        let mut tun_dev = None;
        let mut iface_name = String::new();
        let mut setup_active = false;
        let mut applied_config = self.tunnel_config.clone();
        if !self.wifi_trusted {
            match driver.setup_tun(&self.tunnel_config, &self.shutdown).await {
                Ok((initial_tun, initial_iface)) => {
                    tun_dev = Some(initial_tun);
                    iface_name = initial_iface;
                    setup_active = true;
                }
                Err(_) if self.shutdown.is_cancelled() => return Ok(()),
                Err(error) => return Err(error),
            }
        }
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
        let (network_rx, power_rx) = match driver.start_monitors(monitor_target) {
            Ok(receivers) => receivers,
            Err(error) => {
                if setup_active {
                    driver.cleanup_tun(&applied_config, &iface_name).await;
                }
                return Err(error);
            }
        };
        let mut network_rx = NetworkTracker::new(network_rx);
        let mut power = PowerTracker::new(power_rx);

        let shutdown = self.shutdown.clone();
        let mut terminal_error: Option<FortiError> = None;
        let mut pending_config_refresh = false;
        let mut background_saml_attempted = false;
        // VPN DNS servers are typically reachable only through the tunnel. While
        // no tunnel carries them they are withdrawn, otherwise every reconnect
        // attempt (and any SAML browser launch) resolves into a black hole.
        let mut dns_suspended = false;

        'reconnect: loop {
            power.drain();
            // Trusted Wi-Fi gate: the single place that owns suspension. All
            // other observation points only set `wifi_trusted` and loop back
            // here, so the full local teardown exists exactly once.
            while let Ok(event) = wifi_rx.try_recv() {
                self.wifi_trusted = is_trusted_wifi(event.ssid.as_deref(), &trusted_ssids);
            }
            if self.wifi_trusted {
                if setup_active {
                    info!(
                        state = ?ConnectionState::SuspendedOnTrustedWifi,
                        "Trusted Wi-Fi detected — tearing down VPN locally"
                    );
                    driver.cleanup_tun(&applied_config, &iface_name).await;
                    setup_active = false;
                    drop(tun_dev.take());
                    // cleanup_tun withdrew the VPN DNS along with the routes.
                    dns_suspended = true;
                }
                if self
                    .wait_while_trusted(&mut wifi_rx, &mut power, &trusted_ssids)
                    .await
                {
                    break;
                }
                network_rx.drain();
                continue;
            }

            if !power.can_run_network() {
                if self.wait_for_wake(&mut power).await {
                    break;
                }
                continue;
            }

            if pending_config_refresh {
                self.state = ConnectionState::RefreshingConfig;
                match interruptible(
                    driver.fetch_tunnel_config(&self.auth_params, &self.svpn_cookie),
                    &shutdown,
                    &mut network_rx,
                    &mut power,
                    &mut wifi_rx,
                    &trusted_ssids,
                )
                .await
                {
                    Ok(Ok(config)) => {
                        self.tunnel_config = config;
                        pending_config_refresh = false;
                        self.policy.on_saml_success();
                        background_saml_attempted = false;
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
                                &mut power,
                                &mut wifi_rx,
                                &trusted_ssids,
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
                        if self.wait_for_wake(&mut power).await {
                            break;
                        }
                        continue;
                    }
                    Err(Interrupt::NetworkDown) => {
                        if self
                            .wait_for_network(
                                &mut network_rx,
                                &mut power,
                                &mut wifi_rx,
                                &trusted_ssids,
                            )
                            .await
                        {
                            break;
                        }
                        continue;
                    }
                    Err(Interrupt::TrustedWifi) => {
                        self.wifi_trusted = true;
                        continue;
                    }
                }
            }

            if self.policy.auth_requirement() == AuthRequirement::Required {
                if !power.can_run_network() {
                    if self.wait_for_wake(&mut power).await {
                        break;
                    }
                    continue;
                }

                if self.auth_params.saml && !power.can_interact() && background_saml_attempted {
                    if self
                        .wait_for_interactive_auth(
                            &mut network_rx,
                            &mut power,
                            &mut wifi_rx,
                            &trusted_ssids,
                            false,
                        )
                        .await
                    {
                        break;
                    }
                    if self.wifi_trusted {
                        continue;
                    }
                }

                let auth_gate_open = self.policy.next_auth_attempt();
                debug_assert!(auth_gate_open);
                self.state = ConnectionState::Authenticating;
                info!(
                    state = ?self.state,
                    auth_requirement = ?self.policy.auth_requirement(),
                    saml_attempt = self.policy.saml_attempts(),
                    "Starting reconnect authentication attempt"
                );
                // The cookie was rejected or the failure count escalated — it
                // must never be presented again.
                self.svpn_cookie.clear();

                let auth_outcome = if self.auth_params.saml {
                    self.run_saml_attempt(
                        driver,
                        &mut network_rx,
                        &mut power,
                        &mut wifi_rx,
                        &trusted_ssids,
                        &mut background_saml_attempted,
                    )
                    .await
                } else {
                    match interruptible(
                        driver.authenticate(&self.auth_params),
                        &shutdown,
                        &mut network_rx,
                        &mut power,
                        &mut wifi_rx,
                        &trusted_ssids,
                    )
                    .await
                    {
                        Ok(result) => SamlRunOutcome::Completed(result),
                        Err(interrupt) => SamlRunOutcome::Interrupted(interrupt),
                    }
                };

                match auth_outcome {
                    SamlRunOutcome::Completed(Ok(cookie)) => {
                        // Save the cookie before config I/O. A transient config
                        // failure must retry with this cookie, not reopen SAML.
                        self.svpn_cookie = cookie;
                        pending_config_refresh = true;
                        continue;
                    }
                    SamlRunOutcome::BackgroundTimedOut => {
                        background_saml_attempted = true;
                        info!(
                            state = ?ConnectionState::WaitingForInteractiveAuth,
                            saml_attempt = self.policy.saml_attempts(),
                            "Background SAML probe received no callback; waiting for interactive graphics"
                        );
                        if self
                            .wait_for_interactive_auth(
                                &mut network_rx,
                                &mut power,
                                &mut wifi_rx,
                                &trusted_ssids,
                                false,
                            )
                            .await
                        {
                            break;
                        }
                        continue;
                    }
                    SamlRunOutcome::Completed(Err(auth_error)) => {
                        let failure_kind = SamlFailureKind::classify(&auth_error);
                        error!(
                            state = ?self.state,
                            failure_class = ?failure_kind,
                            auth_requirement = ?self.policy.auth_requirement(),
                            error = %auth_error,
                            "Re-authentication failed"
                        );
                        if saml_failure_is_terminal(failure_kind) {
                            terminal_error = Some(auth_error);
                            break 'reconnect;
                        }
                        self.policy.on_saml_failure(failure_kind);
                        if failure_kind == SamlFailureKind::CallbackTimedOut
                            && self.auth_params.saml
                        {
                            if self
                                .wait_for_interactive_auth(
                                    &mut network_rx,
                                    &mut power,
                                    &mut wifi_rx,
                                    &trusted_ssids,
                                    true,
                                )
                                .await
                            {
                                break;
                            }
                            continue;
                        }
                        if self
                            .wait_for_retry(
                                RetryContext {
                                    current_operation: "authentication",
                                    retry_reason: "authentication_failed",
                                    failure_class: saml_failure_class(failure_kind),
                                },
                                &mut network_rx,
                                &mut power,
                                &mut wifi_rx,
                                &trusted_ssids,
                            )
                            .await
                            == RetryOutcome::Shutdown
                        {
                            break;
                        }
                        continue;
                    }
                    SamlRunOutcome::Interrupted(Interrupt::Shutdown) => break,
                    SamlRunOutcome::Interrupted(Interrupt::Sleep) => {
                        if self.wait_for_wake(&mut power).await {
                            break;
                        }
                        continue;
                    }
                    SamlRunOutcome::Interrupted(Interrupt::NetworkDown) => {
                        if self
                            .wait_for_network(
                                &mut network_rx,
                                &mut power,
                                &mut wifi_rx,
                                &trusted_ssids,
                            )
                            .await
                        {
                            break;
                        }
                        continue;
                    }
                    SamlRunOutcome::Interrupted(Interrupt::TrustedWifi) => {
                        self.wifi_trusted = true;
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
                &mut power,
                &mut wifi_rx,
                &trusted_ssids,
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
                    if self.wait_for_wake(&mut power).await {
                        break;
                    }
                    continue;
                }
                Err(Interrupt::NetworkDown) => {
                    suspend_vpn_dns(driver, &mut dns_suspended).await;
                    if self
                        .wait_for_network(&mut network_rx, &mut power, &mut wifi_rx, &trusted_ssids)
                        .await
                    {
                        break;
                    }
                    continue;
                }
                Err(Interrupt::TrustedWifi) => {
                    self.wifi_trusted = true;
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
                        failed_cycles = self.policy.failed_cycles(),
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
                            &mut power,
                            &mut wifi_rx,
                            &trusted_ssids,
                        )
                        .await
                        == RetryOutcome::Shutdown
                    {
                        break;
                    }
                    continue;
                }
            };
            let established_at = std::time::Instant::now();

            if apply_negotiated_ip(&mut self.tunnel_config, negotiated_ip) {
                info!("IPCP assigned a new address: {}", negotiated_ip);
            }

            // Rebuild when the config changed — or when there is no TUN at
            // all, i.e. resuming after a trusted-Wi-Fi suspension tore it down.
            if tun_dev.is_none() || network_config_changed(&applied_config, &self.tunnel_config) {
                if setup_active {
                    warn!("VPN network configuration changed — recreating TUN device");
                    driver.cleanup_tun(&applied_config, &iface_name).await;
                    setup_active = false;
                    drop(tun_dev.take());
                }
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
                    &mut power,
                    &mut wifi_rx,
                    &trusted_ssids,
                )
                .await;
            // Sample the lifetime immediately: teardown below (terminate up to
            // 2s, DNS withdrawal up to 5s) must not push a short-lived tunnel
            // past the flap window and suppress the escalation.
            let tunnel_alive = established_at.elapsed();

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

            // A tunnel that dies within the flap window for a non-user reason never
            // carried healthy traffic: count it as a failed cycle so repeated
            // accept-then-drop behavior escalates to re-authentication. Sleep,
            // trusted-Wi-Fi suspension, and user-initiated exits are excluded —
            // they say nothing about the cookie.
            if !matches!(
                reason,
                DisconnectReason::UserQuit
                    | DisconnectReason::SystemSleep
                    | DisconnectReason::TrustedNetwork
            ) && tunnel_alive < self.policy.flap_window()
            {
                warn!(
                    tunnel_alive_ms = tunnel_alive.as_millis() as u64,
                    "Tunnel died within the flap window; counting as a failed cycle"
                );
                self.policy.on_short_lived_tunnel();
            }

            if reason == DisconnectReason::SystemSleep {
                if self.wait_for_wake(&mut power).await {
                    break;
                }
                network_rx.drain();
                continue;
            }

            if reason == DisconnectReason::TrustedNetwork {
                // Terminate was sent and the tunnel dropped above; the gate at
                // the top of the loop completes the local teardown.
                self.wifi_trusted = true;
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
                            &mut power,
                            &mut wifi_rx,
                            &trusted_ssids,
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

    /// Put the SAML URL somewhere the user can actually see it. Logging alone
    /// is not enough: the launcher failing and the browser being closed are the
    /// two cases where the user has nothing to click, and both are invisible at
    /// the default log level.
    fn print_saml_url(&self, url: &str) {
        eprintln!("\nPlease open this URL in your browser:\n  {url}\n");
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_saml_attempt<Driver: ControllerDriver>(
        &mut self,
        driver: &mut Driver,
        network_rx: &mut NetworkTracker,
        power: &mut PowerTracker,
        wifi_rx: &mut mpsc::UnboundedReceiver<WifiEvent>,
        trusted_ssids: &[String],
        background_saml_attempted: &mut bool,
    ) -> SamlRunOutcome {
        power.drain();
        network_rx.drain();
        if self.shutdown.is_cancelled() {
            return SamlRunOutcome::Interrupted(Interrupt::Shutdown);
        }
        if !power.can_run_network() {
            return SamlRunOutcome::Interrupted(Interrupt::Sleep);
        }
        if !network_rx.can_attempt() {
            return SamlRunOutcome::Interrupted(Interrupt::NetworkDown);
        }

        let mut attempt = match driver.begin_saml_attempt(&self.auth_params).await {
            Ok(attempt) => attempt,
            Err(error) => return SamlRunOutcome::Completed(Err(error)),
        };

        // Capability and reachability loss may race listener creation. Consume
        // queued levels before the first browser side effect. Once the attempt
        // exists, keep its listener across later power/network changes.
        power.drain();
        network_rx.drain();

        let mut presentation = None;
        // An in-flight browser launch. Held across loop iterations so a power or
        // network event cannot cancel it: the launcher kills its child on drop,
        // which would silently lose the launch while the latches below still
        // recorded it as spent.
        let mut launch: Option<DriverFuture<'static, std::io::Result<()>>> = None;
        let mut presentation_started = false;
        let mut callback_received = attempt.callback_received();
        let mut deadline_remaining: Option<Duration> = None;
        let mut deadline_started: Option<tokio::time::Instant> = None;
        // Set once the interactive budget lapses with no callback. The attempt
        // stays alive for a late callback, and one re-present is allowed after a
        // full display off→on cycle so the user is not stuck with a stale tab.
        let mut soft_timed_out = false;
        let mut saw_noninteractive = false;
        let deadline = tokio::time::sleep(SAML_INTERACTIVE_TIMEOUT);
        tokio::pin!(deadline);
        // A gateway reported unreachable parks this loop with the attempt held,
        // and `NetworkTracker::next_event` pends forever once the monitor exits.
        // Because the attempt is deliberately kept alive, the controller never
        // reaches `wait_for_network`, so its bounded fallback cannot run here —
        // this timer is the floor that replaces it.
        let reachability_stall = tokio::time::sleep(MONITOR_FALLBACK_TIMEOUT);
        tokio::pin!(reachability_stall);
        let mut reachability_stall_armed = false;

        loop {
            let runnable = power.can_run_network() && network_rx.can_attempt();

            if presentation.is_none() && runnable && !callback_received {
                let selected = if power.can_interact() {
                    SamlBrowserPresentation::Foreground
                } else {
                    SamlBrowserPresentation::Background
                };
                presentation = Some(selected);
                launch = Some(attempt.present(selected));
                presentation_started = false;
                deadline_remaining = Some(match selected {
                    SamlBrowserPresentation::Background => SAML_BACKGROUND_PROBE_TIMEOUT,
                    SamlBrowserPresentation::Foreground => SAML_INTERACTIVE_TIMEOUT,
                });
                info!(
                    state = ?self.state,
                    auth_requirement = ?self.policy.auth_requirement(),
                    saml_attempt = self.policy.saml_attempts(),
                    presentation = ?selected,
                    "Presenting reconnect SAML attempt"
                );
            }

            if presentation == Some(SamlBrowserPresentation::Background)
                && power.can_interact()
                && !callback_received
            {
                // `open -g` already created this attempt's browser navigation.
                // Do not open the URL again: doing so can create a second tab
                // and a second FortiGate SAML transaction. The existing tab is
                // now available for user interaction.
                presentation = Some(SamlBrowserPresentation::Foreground);
                deadline_remaining = Some(SAML_INTERACTIVE_TIMEOUT);
                deadline_started = None;
                info!(
                    state = ?self.state,
                    saml_attempt = self.policy.saml_attempts(),
                    "Interactive graphics restored; continuing the existing SAML attempt"
                );
            }

            // Re-present only on a fresh interactive epoch: the display must
            // have gone dark and come back. Reachability alone must never
            // trigger this — it flaps during interface churn, which is exactly
            // the popup loop the soft timeout exists to avoid.
            if soft_timed_out && saw_noninteractive && runnable && power.can_interact() {
                soft_timed_out = false;
                saw_noninteractive = false;
                presentation = Some(SamlBrowserPresentation::Foreground);
                launch = Some(attempt.present(SamlBrowserPresentation::Foreground));
                presentation_started = false;
                deadline_remaining = Some(SAML_INTERACTIVE_TIMEOUT);
                deadline_started = None;
                self.policy.on_saml_presented_again();
                self.state = ConnectionState::Authenticating;
                info!(
                    state = ?self.state,
                    saml_attempt = self.policy.saml_attempts(),
                    "New interactive session; re-presenting the existing SAML attempt"
                );
            }

            // Arm only while reachability is the thing blocking progress. A
            // sleeping machine is a correct reason to wait, and rearming from
            // scratch on each event would let a busy event stream starve the
            // floor — so it is armed once per stall and reset on recovery.
            let reachability_stalled = !callback_received && !network_rx.can_attempt();
            if reachability_stalled {
                if !reachability_stall_armed {
                    reachability_stall
                        .as_mut()
                        .reset(tokio::time::Instant::now() + MONITOR_FALLBACK_TIMEOUT);
                    reachability_stall_armed = true;
                }
            } else {
                reachability_stall_armed = false;
            }

            if callback_received
                || deadline_remaining.is_none()
                || !runnable
                || !presentation_started
            {
                if let Some(started) = deadline_started.take() {
                    if let Some(remaining) = deadline_remaining.as_mut() {
                        *remaining = remaining.saturating_sub(started.elapsed());
                    }
                }
            } else if deadline_started.is_none() {
                if let Some(remaining) = deadline_remaining {
                    let now = tokio::time::Instant::now();
                    deadline.as_mut().reset(now + remaining);
                    deadline_started = Some(now);
                }
            }

            enum AttemptEvent {
                Shutdown,
                Wifi(WifiEvent),
                Presented(std::io::Result<()>),
                Callback(Result<()>),
                Result(Result<String>),
                Power,
                Network(NetworkEvent),
                Deadline,
                ReachabilityStalled,
            }

            let event = if callback_received {
                tokio::select! {
                    biased;
                    _ = self.shutdown.cancelled() => AttemptEvent::Shutdown,
                    wifi = next_wifi_event(wifi_rx) => AttemptEvent::Wifi(wifi),
                    result = attempt.wait_result() => AttemptEvent::Result(result),
                    _ = power.next_event() => AttemptEvent::Power,
                    network = network_rx.next_event() => AttemptEvent::Network(network),
                }
            } else {
                tokio::select! {
                    biased;
                    _ = self.shutdown.cancelled() => AttemptEvent::Shutdown,
                    wifi = next_wifi_event(wifi_rx) => AttemptEvent::Wifi(wifi),
                    callback = attempt.wait_for_callback() => AttemptEvent::Callback(callback),
                    // Borrows the retained future rather than consuming it, so
                    // losing this branch to a competing event leaves the
                    // launcher running and resumable on the next iteration.
                    result = poll_launch(&mut launch), if launch.is_some() => {
                        AttemptEvent::Presented(result)
                    }
                    _ = power.next_event() => AttemptEvent::Power,
                    network = network_rx.next_event() => AttemptEvent::Network(network),
                    _ = &mut deadline, if deadline_started.is_some() => AttemptEvent::Deadline,
                    _ = &mut reachability_stall, if reachability_stall_armed => {
                        AttemptEvent::ReachabilityStalled
                    }
                }
            };

            match event {
                AttemptEvent::Shutdown => return SamlRunOutcome::Interrupted(Interrupt::Shutdown),
                AttemptEvent::Wifi(event) => {
                    if is_trusted_wifi(event.ssid.as_deref(), trusted_ssids) {
                        return SamlRunOutcome::Interrupted(Interrupt::TrustedWifi);
                    }
                }
                AttemptEvent::Presented(result) => {
                    // The launcher ran to completion, so the browser
                    // opportunity is genuinely spent — including the one-shot
                    // headless probe, whose latch must not be charged for a
                    // launch that never finished.
                    launch = None;
                    presentation_started = true;
                    if presentation == Some(SamlBrowserPresentation::Background) {
                        *background_saml_attempted = true;
                    }
                    if let Err(error) = result {
                        warn!(
                            presentation = ?presentation,
                            error = %error,
                            "SAML browser launcher failed; callback listener remains active"
                        );
                        self.print_saml_url(attempt.url());
                    }
                }
                AttemptEvent::Callback(Ok(())) => {
                    callback_received = true;
                    deadline_remaining = None;
                    deadline_started = None;
                    soft_timed_out = false;
                    info!("SAML callback received; waiting for session cookie exchange");
                }
                AttemptEvent::Callback(Err(error)) => {
                    return SamlRunOutcome::Completed(Err(error));
                }
                AttemptEvent::Result(result) => {
                    network_rx.drain();
                    if result.is_err() && callback_received {
                        // The browser reached the IdP and the callback came
                        // back; only the exchange failed. The headless route is
                        // still viable, so do not spend the user's display on
                        // the retry.
                        *background_saml_attempted = false;
                    }
                    return SamlRunOutcome::Completed(result);
                }
                AttemptEvent::Power => {
                    if soft_timed_out && !power.can_interact() {
                        saw_noninteractive = true;
                    }
                }
                AttemptEvent::Network(event) => {
                    debug!(
                        ?event,
                        "Network changed during SAML; preserving single-flight callback listener"
                    );
                }
                AttemptEvent::ReachabilityStalled => {
                    warn!(
                        "No gateway reachability update in {}s while SAML is pending — allowing a bounded probe",
                        MONITOR_FALLBACK_TIMEOUT.as_secs()
                    );
                    network_rx.allow_fallback_probe();
                }
                AttemptEvent::Deadline => {
                    deadline_started = None;
                    deadline_remaining = None;
                    if presentation == Some(SamlBrowserPresentation::Background) {
                        return SamlRunOutcome::BackgroundTimedOut;
                    }
                    // Soft: the listener stays bound so a late callback still
                    // completes this attempt. The user may also have abandoned
                    // or closed the tab, so arm a single re-present for the next
                    // interactive epoch rather than waiting here forever.
                    self.state = ConnectionState::WaitingForInteractiveAuth;
                    soft_timed_out = true;
                    saw_noninteractive = !power.can_interact();
                    warn!(
                        state = ?self.state,
                        saml_attempt = self.policy.saml_attempts(),
                        "SAML is still pending after the interactive wait budget; keeping the listener and waiting for a new interactive session"
                    );
                    self.print_saml_url(attempt.url());
                }
            }
        }
    }

    /// Wait for a user-visible authentication epoch. When `require_new_epoch`
    /// is true, an already-lit display does not immediately reopen a browser;
    /// the controller first observes a non-interactive level and then a fresh
    /// graphics transition.
    async fn wait_for_interactive_auth(
        &mut self,
        network_rx: &mut NetworkTracker,
        power: &mut PowerTracker,
        wifi_rx: &mut mpsc::UnboundedReceiver<WifiEvent>,
        trusted_ssids: &[String],
        require_new_epoch: bool,
    ) -> bool {
        self.state = ConnectionState::WaitingForInteractiveAuth;
        let mut saw_noninteractive = !power.can_interact();
        info!(
            state = ?self.state,
            require_new_epoch,
            "Waiting for interactive graphics before presenting SAML again"
        );

        loop {
            if self.shutdown.is_cancelled() {
                return true;
            }
            if power.can_interact() && (!require_new_epoch || saw_noninteractive) {
                return false;
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => return true,
                _ = power.next_event() => {
                    if !power.can_interact() {
                        saw_noninteractive = true;
                    }
                }
                event = network_rx.next_event() => {
                    debug!(?event, "Network changed while waiting for interactive SAML");
                }
                event = next_wifi_event(wifi_rx) => {
                    self.wifi_trusted = is_trusted_wifi(event.ssid.as_deref(), trusted_ssids);
                    if self.wifi_trusted {
                        return false;
                    }
                }
            }
        }
    }

    /// Returns true when shutdown was requested.
    async fn wait_for_network(
        &mut self,
        network_rx: &mut NetworkTracker,
        power: &mut PowerTracker,
        wifi_rx: &mut mpsc::UnboundedReceiver<WifiEvent>,
        trusted_ssids: &[String],
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
                    network_rx.allow_fallback_probe();
                    return false;
                }
                event = network_rx.next_event() => {
                    if event == NetworkEvent::Reachable {
                        self.policy.on_network_reachable();
                        return false;
                    }
                }
                _ = power.next_event() => {
                    if !power.can_run_network() && self.wait_for_wake(power).await {
                        return true;
                    }
                }
                event = next_wifi_event(wifi_rx) => {
                    self.wifi_trusted = is_trusted_wifi(event.ssid.as_deref(), trusted_ssids);
                    if self.wifi_trusted {
                        // Let the loop-top gate take over the suspension.
                        return false;
                    }
                }
            }
        }
    }

    /// Block while the machine stays on a trusted Wi-Fi network. The VPN has
    /// already been torn down by the gate; suspension is indefinite by design,
    /// so unlike the other waits there is no fallback timeout. Returns true
    /// when shutdown was requested.
    async fn wait_while_trusted(
        &mut self,
        wifi_rx: &mut mpsc::UnboundedReceiver<WifiEvent>,
        power: &mut PowerTracker,
        trusted_ssids: &[String],
    ) -> bool {
        self.state = ConnectionState::SuspendedOnTrustedWifi;
        info!(
            state = ?self.state,
            "On trusted Wi-Fi — VPN suspended until the network changes"
        );
        loop {
            if self.shutdown.is_cancelled() {
                return true;
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => return true,
                // recv() directly, not next_wifi_event: this state is only
                // reachable through a real trusted event, so a closed channel
                // here means the active monitor died — without it no event
                // will ever end the suspension, so fail open and reconnect
                // rather than staying suspended until the process is killed.
                event = wifi_rx.recv() => match event {
                    Some(event) => {
                        if !is_trusted_wifi(event.ssid.as_deref(), trusted_ssids) {
                            info!(ssid = ?event.ssid, "Left trusted Wi-Fi — re-establishing VPN");
                            self.wifi_trusted = false;
                            self.policy.on_network_reachable();
                            return false;
                        }
                    }
                    None => {
                        warn!("Wi-Fi monitor stopped while suspended — failing open and re-establishing the VPN");
                        self.wifi_trusted = false;
                        return false;
                    }
                },
                event = power.next_event() => {
                    // Sleeping and waking on a trusted network changes nothing;
                    // waking on a different network fires a Wi-Fi event.
                    debug!("Ignoring power event while suspended on trusted Wi-Fi: {:?}", event);
                }
            }
        }
    }

    /// Returns true when shutdown was requested.
    async fn wait_for_wake(&mut self, power: &mut PowerTracker) -> bool {
        self.state = ConnectionState::WaitingForNetwork;
        // Waiting on capability events alone has no floor: a dropped
        // notification, or a power monitor thread that died and closed its
        // channel, would park the tunnel here for the rest of the process.
        // Built once so repeated events cannot keep pushing the floor back.
        let fallback = tokio::time::sleep(WAKE_FALLBACK_TIMEOUT);
        tokio::pin!(fallback);
        loop {
            if self.shutdown.is_cancelled() {
                return true;
            }
            if power.can_run_network() {
                self.policy.on_system_wake();
                return false;
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => return true,
                _ = power.next_event() => {}
                _ = &mut fallback => {
                    warn!(
                        "No power capability update in {}s — assuming the system is awake and retrying with bounded timeouts",
                        WAKE_FALLBACK_TIMEOUT.as_secs()
                    );
                    power.assume_awake();
                    self.policy.on_system_wake();
                    return false;
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
        network_rx: &mut NetworkTracker,
        power: &mut PowerTracker,
        wifi_rx: &mut mpsc::UnboundedReceiver<WifiEvent>,
        trusted_ssids: &[String],
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
            event = network_rx.next_event() => {
                match event {
                    NetworkEvent::Reachable => {
                        self.policy.on_network_reachable();
                        RetryOutcome::Retry
                    }
                    NetworkEvent::Unreachable => {
                        if self.wait_for_network(network_rx, power, wifi_rx, trusted_ssids).await {
                            RetryOutcome::Shutdown
                        } else {
                            RetryOutcome::Retry
                        }
                    }
                }
            }
            _ = power.next_event() => {
                if !power.can_run_network() && self.wait_for_wake(power).await {
                    RetryOutcome::Shutdown
                } else {
                    RetryOutcome::Retry
                }
            }
            event = next_wifi_event(wifi_rx) => {
                // Any Wi-Fi drift is fresh network evidence: retry right away.
                // A trusted SSID is picked up by the loop-top gate, which must
                // not be delayed behind a backoff while routes are installed.
                self.wifi_trusted = is_trusted_wifi(event.ssid.as_deref(), trusted_ssids);
                RetryOutcome::Retry
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
    fn only_terminal_configuration_auth_failure_stops_controller() {
        assert!(saml_failure_is_terminal(
            SamlFailureKind::TerminalConfiguration
        ));
        assert!(!saml_failure_is_terminal(SamlFailureKind::CallbackTimedOut));
        // A busy callback port must not strand the client: without a SAML
        // session there is no way back to a working tunnel, so giving up is
        // strictly worse than retrying behind the backoff.
        assert!(!saml_failure_is_terminal(
            SamlFailureKind::LocalPortUnavailable
        ));
        assert_eq!(
            SamlFailureKind::classify(&FortiError::SamlCallbackPortUnavailable(
                "port 8020 busy".into()
            )),
            SamlFailureKind::LocalPortUnavailable
        );
    }

    #[tokio::test]
    async fn interruptible_operation_observes_shutdown() {
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        let (_network_tx, network_rx) = mpsc::unbounded_channel();
        let mut network_rx = NetworkTracker::new(network_rx);
        let (_power_tx, power_rx) = mpsc::unbounded_channel();
        let mut power = PowerTracker::new(power_rx);
        let (_wifi_tx, mut wifi_rx) = mpsc::unbounded_channel();
        trigger.cancel();
        let result = interruptible(
            std::future::pending::<()>(),
            &shutdown,
            &mut network_rx,
            &mut power,
            &mut wifi_rx,
            &[],
        )
        .await;
        assert_eq!(result, Err(Interrupt::Shutdown));
    }

    #[tokio::test]
    async fn interruptible_operation_observes_network_loss() {
        let shutdown = Shutdown::new();
        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let mut network_rx = NetworkTracker::new(network_rx);
        let (_power_tx, power_rx) = mpsc::unbounded_channel();
        let mut power = PowerTracker::new(power_rx);
        let (_wifi_tx, mut wifi_rx) = mpsc::unbounded_channel();
        network_tx.send(NetworkEvent::Unreachable).unwrap();
        let result = interruptible(
            std::future::pending::<()>(),
            &shutdown,
            &mut network_rx,
            &mut power,
            &mut wifi_rx,
            &[],
        )
        .await;
        assert_eq!(result, Err(Interrupt::NetworkDown));
    }

    #[tokio::test(start_paused = true)]
    async fn network_monitor_fallback_allows_one_bounded_probe() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let (network_tx, network_rx) = mpsc::unbounded_channel();
        network_tx.send(NetworkEvent::Unreachable).unwrap();
        let mut network = NetworkTracker::new(network_rx);
        let (_power_tx, power_rx) = mpsc::unbounded_channel();
        let mut power = PowerTracker::new(power_rx);
        let (_wifi_tx, mut wifi_rx) = mpsc::unbounded_channel();
        let started = tokio::time::Instant::now();

        assert!(!network.can_attempt());
        assert!(
            !controller
                .wait_for_network(&mut network, &mut power, &mut wifi_rx, &[])
                .await
        );
        assert_eq!(started.elapsed(), MONITOR_FALLBACK_TIMEOUT);
        assert!(network.can_attempt());
    }

    #[tokio::test]
    async fn interruptible_operation_observes_sleep() {
        let shutdown = Shutdown::new();
        let (_network_tx, network_rx) = mpsc::unbounded_channel();
        let mut network_rx = NetworkTracker::new(network_rx);
        let (power_tx, power_rx) = mpsc::unbounded_channel();
        let mut power = PowerTracker::new(power_rx);
        let (_wifi_tx, mut wifi_rx) = mpsc::unbounded_channel();
        power_tx.send(PowerEvent::WillSleep).unwrap();
        let result = interruptible(
            std::future::pending::<()>(),
            &shutdown,
            &mut network_rx,
            &mut power,
            &mut wifi_rx,
            &[],
        )
        .await;
        assert_eq!(result, Err(Interrupt::Sleep));
    }

    #[test]
    fn legacy_powered_on_does_not_override_capability_gate() {
        let (_tx, rx) = mpsc::unbounded_channel();
        let mut power = PowerTracker::new(rx);
        power.apply(PowerEvent::WillSleep);
        power.apply(PowerEvent::HasPoweredOn);
        assert!(!power.can_run_network());

        power.apply(PowerEvent::Capabilities(background_power_capabilities()));
        assert!(power.can_run_network());
        assert!(!power.can_interact());
    }

    #[tokio::test]
    async fn graphics_loss_does_not_interrupt_network_operation() {
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        let (_network_tx, network_rx) = mpsc::unbounded_channel();
        let mut network_rx = NetworkTracker::new(network_rx);
        let (power_tx, power_rx) = mpsc::unbounded_channel();
        let mut power = PowerTracker::new(power_rx);
        let (_wifi_tx, mut wifi_rx) = mpsc::unbounded_channel();
        power_tx
            .send(PowerEvent::Capabilities(background_power_capabilities()))
            .unwrap();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            trigger.cancel();
        });

        let result = interruptible(
            std::future::pending::<()>(),
            &shutdown,
            &mut network_rx,
            &mut power,
            &mut wifi_rx,
            &[],
        )
        .await;
        assert_eq!(result, Err(Interrupt::Shutdown));
    }

    use crate::auth::xml::Route;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::{Arc as StdArc, Mutex};

    struct ScriptTun;
    struct ScriptTunnel;
    struct ScriptLcp;

    fn full_power_capabilities() -> PowerEvent {
        PowerEvent::Capabilities(PowerCapabilities {
            known: true,
            cpu: true,
            network: true,
            graphics: true,
        })
    }

    fn background_power_capabilities() -> PowerCapabilities {
        PowerCapabilities {
            known: true,
            cpu: true,
            network: true,
            graphics: false,
        }
    }

    enum ScriptConnect {
        Failure(ConnectFailureKind),
        FailureThenSleepWake(ConnectFailureKind),
        FailureThenNetworkPause {
            kind: ConnectFailureKind,
            resume: tokio::sync::oneshot::Receiver<()>,
        },
        Success(Ipv4Addr),
        Sleep,
        TrustedWifiPending(WifiEvent),
    }

    enum ScriptAuth {
        Result(Result<String>),
        NetworkDown,
        SleepUntil(tokio::sync::oneshot::Receiver<()>),
        PowerThenResult {
            event: PowerEvent,
            release: tokio::sync::oneshot::Receiver<()>,
            result: Result<String>,
        },
        CallbackThenResult {
            release: tokio::sync::oneshot::Receiver<()>,
            result: Result<String>,
        },
        Pending,
    }

    struct ScriptSamlAttempt {
        log: StdArc<Mutex<Vec<String>>>,
        _callback_tx: tokio::sync::watch::Sender<bool>,
        callback_rx: tokio::sync::watch::Receiver<bool>,
        presentation_tx: tokio::sync::watch::Sender<Option<SamlBrowserPresentation>>,
        launch_gate: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        #[allow(clippy::type_complexity)]
        launch_preempt: Mutex<
            Option<(
                mpsc::UnboundedSender<PowerEvent>,
                mpsc::UnboundedSender<NetworkEvent>,
            )>,
        >,
        result: DriverFuture<'static, Result<String>>,
    }

    impl ControllerSamlAttempt for ScriptSamlAttempt {
        fn url(&self) -> &str {
            "https://vpn.example:10443/remote/saml/start?redirect=1"
        }

        fn present(
            &self,
            presentation: SamlBrowserPresentation,
        ) -> DriverFuture<'static, std::io::Result<()>> {
            let log = self.log.clone();
            let presentation_tx = self.presentation_tx.clone();
            let gate = self.launch_gate.lock().unwrap().take();
            let preempt = self.launch_preempt.lock().unwrap().take();
            Box::pin(async move {
                // `auth_launch` records that a launcher process was started and
                // `auth_present` that it finished, so a test can tell a retained
                // launch from a dropped-and-respawned one.
                log.lock()
                    .unwrap()
                    .push(format!("auth_launch:{presentation:?}"));
                if let Some((power_tx, network_tx)) = preempt {
                    // Make competing select arms ready while this launcher is
                    // still running, which is exactly when a dropped future
                    // would kill the browser process.
                    let _ = power_tx.send(full_power_capabilities());
                    let _ = network_tx.send(NetworkEvent::Reachable);
                }
                if let Some(gate) = gate {
                    let _ = gate.await;
                }
                log.lock()
                    .unwrap()
                    .push(format!("auth_present:{presentation:?}"));
                let _ = presentation_tx.send(Some(presentation));
                Ok(())
            })
        }

        fn callback_received(&self) -> bool {
            *self.callback_rx.borrow()
        }

        fn wait_for_callback(&self) -> DriverFuture<'_, Result<()>> {
            let mut rx = self.callback_rx.clone();
            Box::pin(async move {
                if *rx.borrow() {
                    return Ok(());
                }
                rx.changed().await.map_err(|_| {
                    FortiError::SamlCallbackInvalid(
                        "scripted callback source closed before callback".into(),
                    )
                })?;
                Ok(())
            })
        }

        fn wait_result(&mut self) -> DriverFuture<'_, Result<String>> {
            Box::pin(async move { self.result.as_mut().await })
        }
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
        wifi_tx: Option<mpsc::UnboundedSender<WifiEvent>>,
        setup_calls: usize,
        fail_setup_call: Option<usize>,
        fail_dns_suspend: usize,
        initial_power: Option<PowerCapabilities>,
        initial_network: Option<NetworkEvent>,
        auth_wifi_event: Option<WifiEvent>,
        /// Delivered as the SAML attempt begins, i.e. after the loop's initial
        /// drain, so it lands while the attempt is already in flight.
        auth_network_event: Option<NetworkEvent>,
        /// Holds the first browser launch pending until released, modelling an
        /// `open` process that is still running when other events arrive.
        launch_gate: Option<tokio::sync::oneshot::Receiver<()>>,
        /// Fire power and network events from inside the launcher.
        preempt_launch: bool,
        /// Hands the power sender to the test so it can drive capability
        /// changes after the controller is already running.
        power_tap: Option<tokio::sync::oneshot::Sender<mpsc::UnboundedSender<PowerEvent>>>,
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
                wifi_tx: None,
                setup_calls: 0,
                fail_setup_call: None,
                fail_dns_suspend: 0,
                initial_power: None,
                initial_network: None,
                auth_wifi_event: None,
                auth_network_event: None,
                launch_gate: None,
                preempt_launch: false,
                power_tap: None,
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
        type SamlAttempt = ScriptSamlAttempt;

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
            if let Some(event) = self.initial_network {
                network_tx.send(event).unwrap();
            }
            if let Some(capabilities) = self.initial_power {
                power_tx
                    .send(PowerEvent::Capabilities(capabilities))
                    .unwrap();
            }
            if let Some(tap) = self.power_tap.take() {
                let _ = tap.send(power_tx.clone());
            }
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
                            let _ = tx.send(full_power_capabilities());
                        }
                    });
                    Box::pin(std::future::pending())
                }
                ScriptAuth::PowerThenResult {
                    event,
                    release,
                    result,
                } => {
                    let tx = self.power_tx.as_ref().unwrap().clone();
                    Box::pin(async move {
                        tx.send(event).unwrap();
                        let _ = release.await;
                        result
                    })
                }
                ScriptAuth::CallbackThenResult { release, result } => Box::pin(async move {
                    let _ = release.await;
                    result
                }),
                ScriptAuth::Pending => Box::pin(std::future::pending()),
            }
        }

        fn begin_saml_attempt<'a>(
            &'a mut self,
            _params: &'a AuthParams,
        ) -> DriverFuture<'a, Result<Self::SamlAttempt>> {
            self.record("auth");
            if let Some(event) = self.auth_wifi_event.take() {
                self.wifi_tx.as_ref().unwrap().send(event).unwrap();
            }
            if let Some(event) = self.auth_network_event.take() {
                self.network_tx.as_ref().unwrap().send(event).unwrap();
            }
            let behavior = self.auth.pop_front().expect("missing scripted auth");
            let network_tx = self.network_tx.as_ref().unwrap().clone();
            let power_tx = self.power_tx.as_ref().unwrap().clone();
            let (callback_tx, callback_rx) = tokio::sync::watch::channel(false);
            let (presentation_tx, presentation_rx) = tokio::sync::watch::channel(None);
            let result: DriverFuture<'static, Result<String>> = match behavior {
                ScriptAuth::Result(result) => {
                    let callback_tx = callback_tx.clone();
                    let mut presentation_rx = presentation_rx.clone();
                    tokio::spawn(async move {
                        if presentation_rx.changed().await.is_ok() {
                            let _ = callback_tx.send(true);
                        }
                    });
                    Box::pin(async move { result })
                }
                ScriptAuth::NetworkDown => {
                    let callback_tx = callback_tx.clone();
                    let mut presentation_rx = presentation_rx.clone();
                    tokio::spawn(async move {
                        if presentation_rx.changed().await.is_err() {
                            return;
                        }
                        network_tx.send(NetworkEvent::Unreachable).unwrap();
                        tokio::task::yield_now().await;
                        network_tx.send(NetworkEvent::Reachable).unwrap();
                        let _ = callback_tx.send(true);
                    });
                    Box::pin(async { Ok("new-cookie".to_string()) })
                }
                ScriptAuth::SleepUntil(wake) => {
                    power_tx.send(PowerEvent::WillSleep).unwrap();
                    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
                    let callback_tx = callback_tx.clone();
                    tokio::spawn(async move {
                        if wake.await.is_ok() {
                            let _ = power_tx.send(full_power_capabilities());
                            let _ = callback_tx.send(true);
                            let _ = result_tx.send(Ok("new-cookie".to_string()));
                        }
                    });
                    Box::pin(async move {
                        result_rx.await.unwrap_or_else(|_| {
                            Err(FortiError::AuthFailed(
                                "scripted result sender dropped".into(),
                            ))
                        })
                    })
                }
                ScriptAuth::PowerThenResult {
                    event,
                    release,
                    result,
                } => {
                    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
                    let callback_tx = callback_tx.clone();
                    let mut presentation_rx = presentation_rx.clone();
                    tokio::spawn(async move {
                        if presentation_rx.changed().await.is_err() {
                            return;
                        }
                        power_tx.send(event).unwrap();
                        let _ = release.await;
                        let _ = callback_tx.send(true);
                        let _ = result_tx.send(result);
                    });
                    Box::pin(async move {
                        result_rx.await.unwrap_or_else(|_| {
                            Err(FortiError::AuthFailed(
                                "scripted result sender dropped".into(),
                            ))
                        })
                    })
                }
                ScriptAuth::CallbackThenResult { release, result } => {
                    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
                    let callback_tx = callback_tx.clone();
                    let mut presentation_rx = presentation_rx.clone();
                    tokio::spawn(async move {
                        if presentation_rx.changed().await.is_err() {
                            return;
                        }
                        let _ = callback_tx.send(true);
                        let _ = release.await;
                        let _ = result_tx.send(result);
                    });
                    Box::pin(async move {
                        result_rx.await.unwrap_or_else(|_| {
                            Err(FortiError::AuthFailed(
                                "scripted result sender dropped".into(),
                            ))
                        })
                    })
                }
                ScriptAuth::Pending => Box::pin(std::future::pending()),
            };
            let attempt = ScriptSamlAttempt {
                log: self.log.clone(),
                _callback_tx: callback_tx,
                callback_rx,
                presentation_tx,
                launch_gate: Mutex::new(self.launch_gate.take()),
                launch_preempt: Mutex::new(self.preempt_launch.then(|| {
                    (
                        self.power_tx.as_ref().unwrap().clone(),
                        self.network_tx.as_ref().unwrap().clone(),
                    )
                })),
                result,
            };
            Box::pin(async move { Ok(attempt) })
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
                        tx.send(full_power_capabilities()).unwrap();
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
                ScriptConnect::FailureThenNetworkPause { kind, resume } => {
                    let tx = self.network_tx.as_ref().unwrap().clone();
                    Box::pin(async move {
                        tx.send(NetworkEvent::Unreachable).unwrap();
                        tokio::spawn(async move {
                            if resume.await.is_ok() {
                                let _ = tx.send(NetworkEvent::Reachable);
                            }
                        });
                        Err(ConnectFailure {
                            kind,
                            source: FortiError::CookieRejected(403),
                        })
                    })
                }
                ScriptConnect::Success(ip) => {
                    Box::pin(async move { Ok((ScriptTunnel, ScriptLcp, ip)) })
                }
                ScriptConnect::Sleep => {
                    let tx = self.power_tx.as_ref().unwrap().clone();
                    tx.send(PowerEvent::WillSleep).unwrap();
                    tx.send(full_power_capabilities()).unwrap();
                    Box::pin(std::future::pending())
                }
                ScriptConnect::TrustedWifiPending(event) => {
                    self.wifi_tx.as_ref().unwrap().send(event).unwrap();
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
            _power: &'a mut PowerTracker,
            _wifi_rx: &'a mut mpsc::UnboundedReceiver<WifiEvent>,
            _trusted_ssids: &'a [String],
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
        controller_with_escalation(initial, shutdown, EscalationConfig::default())
    }

    fn controller_with_saml(
        initial: TunnelConfig,
        shutdown: Shutdown,
        saml: bool,
    ) -> ReconnectController {
        controller_with_saml_and_escalation(initial, shutdown, saml, EscalationConfig::default())
    }

    fn controller_with_escalation(
        initial: TunnelConfig,
        shutdown: Shutdown,
        escalation: EscalationConfig,
    ) -> ReconnectController {
        controller_with_saml_and_escalation(initial, shutdown, true, escalation)
    }

    fn controller_with_saml_and_escalation(
        initial: TunnelConfig,
        shutdown: Shutdown,
        saml: bool,
        escalation: EscalationConfig,
    ) -> ReconnectController {
        controller_full(
            initial,
            shutdown,
            saml,
            escalation,
            TrustedWifiConfig::default(),
        )
    }

    fn controller_full(
        initial: TunnelConfig,
        shutdown: Shutdown,
        saml: bool,
        escalation: EscalationConfig,
        trusted_wifi: TrustedWifiConfig,
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
            escalation,
            trusted_wifi,
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
    async fn saml_sleep_preserves_the_same_attempt_until_explicit_wake() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        let (wake_tx, wake_rx) = tokio::sync::oneshot::channel();
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver.auth.push_back(ScriptAuth::SleepUntil(wake_rx));
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
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 1);
        assert!(log.contains(&"connect:new-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn headless_sso_callback_restores_vpn_without_foreground_browser() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver {
            initial_power: Some(background_power_capabilities()),
            ..ScriptDriver::default()
        };
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("headless-cookie".into())));
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
                .filter(|entry| *entry == "auth_present:Background")
                .count(),
            1
        );
        assert!(!log.contains(&"auth_present:Foreground".to_string()));
        assert!(log.contains(&"connect:headless-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn known_unreachable_gateway_defers_saml_browser_until_recovery() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        driver
            .connects
            .push_back(ScriptConnect::FailureThenNetworkPause {
                kind: ConnectFailureKind::CookieRejected,
                resume: resume_rx,
            });
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("recovered-cookie".into())));
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        let log = driver.log.clone();
        let run = controller.run_with_driver(&mut driver);
        tokio::pin!(run);
        for _ in 0..100 {
            tokio::select! {
                result = &mut run => panic!("controller completed before network recovery: {result:?}"),
                _ = tokio::task::yield_now() => {}
            }
        }
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|entry| *entry == "auth")
                .count(),
            0
        );

        resume_tx.send(()).unwrap();
        (&mut run).await.unwrap();
        let snapshot = log.lock().unwrap().clone();
        assert_eq!(
            snapshot
                .iter()
                .filter(|entry| entry.starts_with("auth_present:"))
                .count(),
            1,
            "{snapshot:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn queued_untrusted_wifi_event_does_not_consume_background_launch() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        let (mut controller, wifi_tx) =
            trusted_controller(initial, shutdown, EscalationConfig::default());
        let mut driver = ScriptDriver {
            initial_power: Some(background_power_capabilities()),
            wifi_tx: Some(wifi_tx),
            auth_wifi_event: Some(trusted("Office")),
            ..ScriptDriver::default()
        };
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver.auth.push_back(ScriptAuth::Pending);

        let log = driver.log.clone();
        let run = controller.run_with_driver(&mut driver);
        tokio::pin!(run);
        for _ in 0..1_000 {
            if log
                .lock()
                .unwrap()
                .contains(&"auth_present:Background".to_string())
            {
                break;
            }
            tokio::select! {
                result = &mut run => panic!("controller unexpectedly completed: {result:?}"),
                _ = tokio::task::yield_now() => {}
            }
        }
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|entry| *entry == "auth_present:Background")
                .count(),
            1
        );

        trigger.cancel();
        (&mut run).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn graphics_restore_continues_the_same_saml_attempt_without_reopening_url() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver {
            initial_power: Some(background_power_capabilities()),
            ..ScriptDriver::default()
        };
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver.auth.push_back(ScriptAuth::PowerThenResult {
            event: full_power_capabilities(),
            release: release_rx,
            result: Ok("promoted-cookie".into()),
        });
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        let log = driver.log.clone();
        let run = controller.run_with_driver(&mut driver);
        tokio::pin!(run);
        let wait_for_background_presentation = async {
            for _ in 0..1_000 {
                if log
                    .lock()
                    .unwrap()
                    .contains(&"auth_present:Background".to_string())
                {
                    tokio::task::yield_now().await;
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("background attempt was not presented");
        };
        tokio::select! {
            result = &mut run => panic!("controller finished before callback: {result:?}"),
            _ = wait_for_background_presentation => {}
        }
        release_tx.send(()).unwrap();
        (&mut run).await.unwrap();

        let log = log.lock().unwrap();
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 1);
        assert_eq!(
            log.iter()
                .filter(|entry| *entry == "auth_present:Background")
                .count(),
            1
        );
        assert!(!log.contains(&"auth_present:Foreground".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn headless_saml_timeout_waits_for_graphics_without_popup_loop() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        let mut controller = controller(initial, shutdown);
        let mut driver = ScriptDriver {
            initial_power: Some(background_power_capabilities()),
            ..ScriptDriver::default()
        };
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver.auth.push_back(ScriptAuth::Pending);

        let log = driver.log.clone();
        let run = controller.run_with_driver(&mut driver);
        tokio::pin!(run);
        let wait_for_background_launch = async {
            for _ in 0..1_000 {
                if log
                    .lock()
                    .unwrap()
                    .contains(&"auth_present:Background".to_string())
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("background SAML did not start");
        };
        tokio::select! {
            result = &mut run => panic!("controller unexpectedly completed: {result:?}"),
            _ = wait_for_background_launch => {}
        }
        tokio::select! {
            result = &mut run => panic!("controller unexpectedly completed: {result:?}"),
            _ = tokio::time::advance(Duration::from_secs(10 * 60)) => {}
        }
        for _ in 0..100 {
            tokio::select! {
                result = &mut run => panic!("controller unexpectedly completed: {result:?}"),
                _ = tokio::task::yield_now() => {}
            }
        }

        {
            let log = log.lock().unwrap();
            assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 1);
            assert_eq!(
                log.iter()
                    .filter(|entry| *entry == "auth_present:Background")
                    .count(),
                1
            );
            assert!(!log.contains(&"auth_present:Foreground".to_string()));
        }

        trigger.cancel();
        (&mut run).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn background_callback_stops_probe_deadline_while_exchange_finishes() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver {
            initial_power: Some(background_power_capabilities()),
            ..ScriptDriver::default()
        };
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver.auth.push_back(ScriptAuth::CallbackThenResult {
            release: release_rx,
            result: Ok("headless-cookie".into()),
        });
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        let log = driver.log.clone();
        let run = controller.run_with_driver(&mut driver);
        tokio::pin!(run);
        for _ in 0..100 {
            tokio::select! {
                result = &mut run => panic!("controller finished before exchange: {result:?}"),
                _ = tokio::task::yield_now() => {}
            }
        }
        tokio::select! {
            result = &mut run => panic!("controller finished before exchange: {result:?}"),
            _ = tokio::time::advance(Duration::from_secs(10 * 60)) => {}
        }
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|entry| *entry == "auth")
                .count(),
            1
        );

        release_tx.send(()).unwrap();
        (&mut run).await.unwrap();
        assert!(log
            .lock()
            .unwrap()
            .contains(&"connect:headless-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_background_saml_cookie_does_not_open_another_tab() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        let mut controller = controller(initial, shutdown);
        let mut driver = ScriptDriver {
            initial_power: Some(background_power_capabilities()),
            ..ScriptDriver::default()
        };
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("rejected-new-cookie".into())));
        driver
            .configs
            .push_back(Err(FortiError::CookieRejected(403)));

        let log = driver.log.clone();
        let run = controller.run_with_driver(&mut driver);
        tokio::pin!(run);
        for _ in 0..200 {
            tokio::select! {
                result = &mut run => panic!("controller unexpectedly completed: {result:?}"),
                _ = tokio::task::yield_now() => {}
            }
        }
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|entry| *entry == "auth_present:Background")
                .count(),
            1
        );

        trigger.cancel();
        (&mut run).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn interactive_timeout_keeps_listener_for_late_callback() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver.auth.push_back(ScriptAuth::PowerThenResult {
            event: full_power_capabilities(),
            release: release_rx,
            result: Ok("late-cookie".into()),
        });
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        let log = driver.log.clone();
        let run = controller.run_with_driver(&mut driver);
        tokio::pin!(run);
        for _ in 0..100 {
            tokio::select! {
                result = &mut run => panic!("controller finished before callback: {result:?}"),
                _ = tokio::task::yield_now() => {}
            }
        }
        tokio::select! {
            result = &mut run => panic!("controller finished before callback: {result:?}"),
            _ = tokio::time::advance(Duration::from_secs(10 * 60)) => {}
        }
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|entry| *entry == "auth")
                .count(),
            1
        );

        release_tx.send(()).unwrap();
        (&mut run).await.unwrap();
        assert!(log
            .lock()
            .unwrap()
            .contains(&"connect:late-cookie".to_string()));
    }

    fn count_entries(log: &StdArc<Mutex<Vec<String>>>, entry: &str) -> usize {
        log.lock().unwrap().iter().filter(|e| *e == entry).count()
    }

    /// Poll the controller without letting it finish, so a test can observe an
    /// intermediate state.
    macro_rules! spin {
        ($run:expr, $rounds:expr) => {
            for _ in 0..$rounds {
                tokio::select! {
                    result = &mut $run => panic!("controller completed early: {result:?}"),
                    _ = tokio::task::yield_now() => {}
                }
            }
        };
    }

    #[tokio::test(start_paused = true)]
    async fn power_and_network_events_do_not_cancel_a_running_browser_launch() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let mut driver = ScriptDriver {
            launch_gate: Some(release_rx),
            preempt_launch: true,
            ..ScriptDriver::default()
        };
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("survived-cookie".into())));
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        let log = driver.log.clone();
        let run = controller.run_with_driver(&mut driver);
        tokio::pin!(run);
        spin!(run, 100);

        assert_eq!(
            count_entries(&log, "auth_launch:Foreground"),
            1,
            "a preempted launch must never be respawned: {:?}",
            log.lock().unwrap()
        );
        assert_eq!(
            count_entries(&log, "auth_present:Foreground"),
            0,
            "the launcher is still running"
        );

        release_tx.send(()).unwrap();
        (&mut run).await.unwrap();

        let snapshot = log.lock().unwrap().clone();
        assert_eq!(count_entries(&log, "auth_launch:Foreground"), 1);
        assert_eq!(
            count_entries(&log, "auth_present:Foreground"),
            1,
            "the retained launch must complete: {snapshot:?}"
        );
        assert!(snapshot.contains(&"connect:survived-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn foreground_soft_timeout_re_presents_on_the_next_interactive_session() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        let mut controller = controller(initial, shutdown);
        let (tap_tx, tap_rx) = tokio::sync::oneshot::channel();
        let mut driver = ScriptDriver {
            initial_power: Some(PowerCapabilities {
                known: true,
                cpu: true,
                network: true,
                graphics: true,
            }),
            power_tap: Some(tap_tx),
            ..ScriptDriver::default()
        };
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        // The user never completes the login, so no callback ever arrives.
        driver.auth.push_back(ScriptAuth::Pending);

        let log = driver.log.clone();
        let run = controller.run_with_driver(&mut driver);
        tokio::pin!(run);
        spin!(run, 100);
        let power_tx = tap_rx.await.expect("power sender");
        assert_eq!(count_entries(&log, "auth_present:Foreground"), 1);

        // The interactive budget lapses with the display still lit.
        tokio::select! {
            result = &mut run => panic!("controller completed early: {result:?}"),
            _ = tokio::time::advance(SAML_INTERACTIVE_TIMEOUT + Duration::from_secs(1)) => {}
        }
        spin!(run, 100);
        assert_eq!(
            count_entries(&log, "auth_present:Foreground"),
            1,
            "a lit display must not re-present on its own"
        );
        assert_eq!(count_entries(&log, "auth"), 1);

        // Display off, then on: a genuinely new interactive session.
        power_tx
            .send(PowerEvent::Capabilities(background_power_capabilities()))
            .unwrap();
        spin!(run, 20);
        assert_eq!(
            count_entries(&log, "auth_present:Foreground"),
            1,
            "losing graphics must not re-present"
        );
        power_tx.send(full_power_capabilities()).unwrap();
        spin!(run, 20);

        assert_eq!(
            count_entries(&log, "auth_present:Foreground"),
            2,
            "a new interactive session must re-present: {:?}",
            log.lock().unwrap()
        );
        assert_eq!(
            count_entries(&log, "auth"),
            1,
            "re-presenting must reuse the same attempt and its callback listener"
        );

        trigger.cancel();
        (&mut run).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn exchange_failure_after_a_callback_keeps_the_headless_route() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver {
            initial_power: Some(background_power_capabilities()),
            ..ScriptDriver::default()
        };
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        release_tx.send(()).unwrap();
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        // The browser reached the IdP and the callback came back; only the
        // cookie exchange failed.
        driver.auth.push_back(ScriptAuth::CallbackThenResult {
            release: release_rx,
            result: Err(FortiError::TunnelError("transient exchange failure".into())),
        });
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("retried-cookie".into())));
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();

        let log = driver.snapshot();
        assert_eq!(
            log.iter()
                .filter(|entry| *entry == "auth_present:Background")
                .count(),
            2,
            "the headless route proved itself, so the retry must not need the display: {log:?}"
        );
        assert!(!log.contains(&"auth_present:Foreground".to_string()));
        assert!(log.contains(&"connect:retried-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_reachability_during_saml_still_allows_a_bounded_probe() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver {
            // Unreachable lands while the attempt is in flight, and no recovery
            // edge ever follows — the monitor missed it or exited.
            auth_network_event: Some(NetworkEvent::Unreachable),
            ..ScriptDriver::default()
        };
        driver
            .connects
            .push_back(ScriptConnect::Failure(ConnectFailureKind::CookieRejected));
        driver
            .auth
            .push_back(ScriptAuth::Result(Ok("probe-cookie".into())));
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        let log = driver.log.clone();
        let run = controller.run_with_driver(&mut driver);
        tokio::pin!(run);
        spin!(run, 100);
        assert_eq!(
            count_entries(&log, "auth_launch:Foreground"),
            0,
            "a known-unreachable gateway must still defer the browser"
        );

        tokio::select! {
            result = &mut run => panic!("controller completed before the floor: {result:?}"),
            _ = tokio::time::advance(MONITOR_FALLBACK_TIMEOUT + Duration::from_secs(1)) => {}
        }
        // Bounded so a regression reports a stalled controller instead of
        // hanging the suite: without the floor this never resolves.
        tokio::time::timeout(Duration::from_secs(600), &mut run)
            .await
            .expect("a stalled reachability signal must not park SAML forever")
            .unwrap();

        let snapshot = log.lock().unwrap().clone();
        assert_eq!(
            count_entries(&log, "auth"),
            1,
            "the single SAML attempt must survive the stall: {snapshot:?}"
        );
        assert_eq!(count_entries(&log, "auth_present:Foreground"), 1);
        assert!(snapshot.contains(&"connect:probe-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn wake_without_a_capability_update_resumes_after_the_fallback() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let (_power_tx, power_rx) = mpsc::unbounded_channel();
        let mut power = PowerTracker::new(power_rx);
        power.apply(PowerEvent::WillSleep);
        assert!(!power.can_run_network());
        let started = tokio::time::Instant::now();

        assert!(!controller.wait_for_wake(&mut power).await);
        assert_eq!(started.elapsed(), WAKE_FALLBACK_TIMEOUT);
        assert!(
            power.can_run_network(),
            "the fallback must leave the tracker able to run a bounded probe"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dark_wake_capabilities_allow_cached_cookie_reconnect() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let mut driver = ScriptDriver {
            initial_power: Some(background_power_capabilities()),
            ..ScriptDriver::default()
        };
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();
        assert!(log.contains(&"connect:old-cookie".to_string()));
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 0);
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
    async fn transport_failures_below_threshold_never_open_saml() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let shutdown = Shutdown::new();
        let mut controller = controller(initial, shutdown);
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
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
            5
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
    async fn failed_cycles_escalate_to_full_reauthentication() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        for _ in 0..5 {
            driver
                .connects
                .push_back(ScriptConnect::Failure(ConnectFailureKind::PostUpgrade));
        }
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
        assert!(log.contains(&"connect:new-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn mixed_failure_kinds_escalate_to_reauthentication() {
        // Regression test for the zombie-cookie incident: during unstable
        // networking transport and post-upgrade failures interleave, and a
        // counter that only tracks one kind consecutively never escalates.
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
            ScriptConnect::Failure(ConnectFailureKind::PostUpgrade),
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
            ScriptConnect::Failure(ConnectFailureKind::PostUpgrade),
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
        ]);
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
        assert!(log.contains(&"connect:new-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn short_lived_tunnels_escalate_to_reauthentication() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        // With paused time each tunnel lives ~0s, well under the 120s default
        // flap window, so every death counts as a failed cycle.
        for _ in 0..5 {
            driver
                .connects
                .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
            driver.events.push_back(DisconnectReason::DeadPeer);
        }
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
        assert!(log.contains(&"connect:new-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn long_lived_tunnels_do_not_escalate() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        // A zero flap window means no elapsed time is ever below it, so no
        // tunnel death counts as a failed cycle.
        let mut controller = controller_with_escalation(
            initial,
            Shutdown::new(),
            EscalationConfig {
                max_failed_cycles: 5,
                flap_window: Duration::ZERO,
            },
        );
        let mut driver = ScriptDriver::default();
        for _ in 0..5 {
            driver
                .connects
                .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
            driver.events.push_back(DisconnectReason::DeadPeer);
        }
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn system_sleep_cycles_never_escalate() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial, Shutdown::new());
        let mut driver = ScriptDriver::default();
        // A laptop that keeps sleeping shortly after each reconnect must never
        // march toward re-authentication: sleep deaths say nothing about the
        // cookie. Six sleep cycles exceed the default threshold of five, so an
        // escalation would hit the empty auth queue and fail this test loudly.
        for _ in 0..6 {
            driver
                .connects
                .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
            driver.events.push_back(DisconnectReason::SystemSleep);
        }
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 0);
        assert_eq!(
            log.iter()
                .filter(|entry| *entry == "connect:old-cookie")
                .count(),
            7
        );
    }

    #[tokio::test(start_paused = true)]
    async fn escalation_threshold_is_configurable() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller_with_escalation(
            initial.clone(),
            Shutdown::new(),
            EscalationConfig {
                max_failed_cycles: 2,
                ..EscalationConfig::default()
            },
        );
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
            ScriptConnect::Failure(ConnectFailureKind::TransportUnavailable),
        ]);
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
        assert!(log.contains(&"connect:new-cookie".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn sleep_interrupts_connect_but_network_flap_preserves_saml_single_flight() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let mut controller = controller(initial.clone(), Shutdown::new());
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::Sleep,
            ScriptConnect::Failure(ConnectFailureKind::CookieRejected),
        ]);
        driver.auth.push_back(ScriptAuth::NetworkDown);
        driver.configs.push_back(Ok(initial));
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 1);
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

    fn trusted_controller(
        initial: TunnelConfig,
        shutdown: Shutdown,
        escalation: EscalationConfig,
    ) -> (ReconnectController, mpsc::UnboundedSender<WifiEvent>) {
        let (wifi_tx, wifi_rx) = mpsc::unbounded_channel();
        let controller = controller_full(
            initial,
            shutdown,
            true,
            escalation,
            TrustedWifiConfig {
                ssids: vec!["Home".into()],
                wifi_rx: Some(wifi_rx),
            },
        );
        (controller, wifi_tx)
    }

    fn trusted(ssid: &str) -> WifiEvent {
        WifiEvent {
            ssid: Some(ssid.into()),
        }
    }

    fn no_wifi() -> WifiEvent {
        WifiEvent { ssid: None }
    }

    #[tokio::test(start_paused = true)]
    async fn trusted_wifi_disconnect_tears_down_and_resumes_off_trusted_network() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let (mut controller, wifi_tx) =
            trusted_controller(initial, Shutdown::new(), EscalationConfig::default());
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
        ]);
        driver
            .events
            .extend([DisconnectReason::TrustedNetwork, DisconnectReason::UserQuit]);
        // Once the controller suspends, drift to a non-Wi-Fi (untrusted)
        // network so it resumes.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = wifi_tx.send(no_wifi());
        });

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        // Full local teardown: LCP terminate (network is fine, unlike sleep),
        // DNS withdrawal, then routes/TUN cleanup — before any reconnect.
        let position = |needle: &str| log.iter().position(|entry| entry.starts_with(needle));
        let terminate = position("terminate").expect("terminate must be sent");
        let dns_suspend = position("dns_suspend").expect("DNS must be withdrawn");
        let cleanup = position("cleanup:").expect("routes/TUN must be cleaned up");
        let second_connect = log
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.starts_with("connect:"))
            .nth(1)
            .map(|(index, _)| index)
            .expect("must reconnect after leaving trusted Wi-Fi");
        assert!(terminate < dns_suspend, "{log:?}");
        assert!(dns_suspend < cleanup, "{log:?}");
        assert!(cleanup < second_connect, "{log:?}");

        // The cookie survives suspension: no re-authentication, and the
        // reconnect presents the old cookie.
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 0);
        assert!(log[second_connect].ends_with(":old-cookie"), "{log:?}");
        // setup_tun reinstalls DNS on resume; no separate dns_resume runs.
        assert!(
            !log.iter().any(|entry| entry.starts_with("dns_resume")),
            "{log:?}"
        );
        let second_setup = log
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.starts_with("setup:"))
            .nth(1)
            .map(|(index, _)| index)
            .expect("TUN must be rebuilt on resume");
        assert!(second_connect < second_setup, "{log:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn trusted_wifi_interrupt_during_connect_suspends_without_failure_accounting() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let (mut controller, wifi_tx) =
            trusted_controller(initial, Shutdown::new(), EscalationConfig::default());
        let mut driver = ScriptDriver {
            wifi_tx: Some(wifi_tx.clone()),
            ..ScriptDriver::default()
        };
        driver.connects.extend([
            ScriptConnect::TrustedWifiPending(trusted("Home")),
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
        ]);
        driver.events.push_back(DisconnectReason::UserQuit);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = wifi_tx.send(no_wifi());
        });

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        // Suspension is not a failure: no re-auth, no backoff advance.
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 0);
        assert_eq!(controller.policy.current_delay(), Duration::from_secs(1));
        assert_eq!(controller.policy.failed_cycles(), 0);
        let cleanup = log
            .iter()
            .position(|entry| entry.starts_with("cleanup:"))
            .expect("interrupted connect must still tear down the eager setup");
        let second_connect = log
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.starts_with("connect:"))
            .nth(1)
            .map(|(index, _)| index)
            .expect("must reconnect after resume");
        assert!(cleanup < second_connect, "{log:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn startup_trusted_wifi_event_defers_first_connect() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let (mut controller, wifi_tx) =
            trusted_controller(initial, Shutdown::new(), EscalationConfig::default());
        let mut driver = ScriptDriver::default();
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::UserQuit);
        // A trusted SSID is already queued when the controller starts (e.g.
        // the network flipped between main's gate and the controller run).
        wifi_tx.send(trusted("Home")).unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = wifi_tx.send(no_wifi());
        });

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        // The queued trusted event is consumed before the first TUN setup:
        // routes and DNS are never installed on the trusted network, so the
        // suspension has nothing to tear down. Setup happens only on resume,
        // after the reconnect succeeds; the only cleanup is the final one.
        let first_connect = log
            .iter()
            .position(|entry| entry.starts_with("connect:"))
            .expect("must connect after leaving trusted Wi-Fi");
        let first_setup = log
            .iter()
            .position(|entry| entry.starts_with("setup:"))
            .expect("TUN must be set up on resume");
        assert!(first_connect < first_setup, "{log:?}");
        assert_eq!(
            log.iter()
                .filter(|entry| entry.starts_with("setup:"))
                .count(),
            1,
            "{log:?}"
        );
        assert_eq!(
            log.iter()
                .filter(|entry| entry.starts_with("cleanup:"))
                .count(),
            1,
            "{log:?}"
        );
        assert_eq!(
            log.iter()
                .filter(|entry| entry.starts_with("connect:"))
                .count(),
            1,
            "{log:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_death_while_suspended_fails_open_and_reconnects() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let (mut controller, wifi_tx) =
            trusted_controller(initial, Shutdown::new(), EscalationConfig::default());
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
        ]);
        driver
            .events
            .extend([DisconnectReason::TrustedNetwork, DisconnectReason::UserQuit]);
        // The monitor dies while the controller sits suspended. Without an
        // event source nothing can ever end the suspension, so the controller
        // must fail open and reconnect instead of hanging until killed.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(wifi_tx);
        });

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        let second_connect = log
            .iter()
            .filter(|entry| entry.starts_with("connect:"))
            .count();
        assert_eq!(second_connect, 2, "monitor death must resume: {log:?}");
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn trusted_network_disconnect_is_excluded_from_flap_escalation() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let (mut controller, wifi_tx) = trusted_controller(
            initial,
            Shutdown::new(),
            EscalationConfig {
                max_failed_cycles: 1,
                flap_window: Duration::from_secs(120),
            },
        );
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
        ]);
        driver
            .events
            .extend([DisconnectReason::TrustedNetwork, DisconnectReason::UserQuit]);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = wifi_tx.send(no_wifi());
        });

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        // The tunnel lived well under the flap window, but a trusted-network
        // disconnect says nothing about the cookie: even with the escalation
        // threshold at 1 no re-authentication may run.
        assert_eq!(log.iter().filter(|entry| *entry == "auth").count(), 0);
        let connects: Vec<_> = log
            .iter()
            .filter(|entry| entry.starts_with("connect:"))
            .collect();
        assert_eq!(connects, ["connect:old-cookie", "connect:old-cookie"]);
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_trusted_untrusted_cycles_are_stable() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let (mut controller, wifi_tx) =
            trusted_controller(initial, Shutdown::new(), EscalationConfig::default());
        let mut driver = ScriptDriver::default();
        driver.connects.extend([
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
            ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)),
        ]);
        driver.events.extend([
            DisconnectReason::TrustedNetwork,
            DisconnectReason::TrustedNetwork,
            DisconnectReason::UserQuit,
        ]);
        // Resume the controller out of each of the two suspensions.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = wifi_tx.send(no_wifi());
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = wifi_tx.send(no_wifi());
        });

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        let count = |needle: &str| log.iter().filter(|entry| entry.starts_with(needle)).count();
        // Two suspensions plus the final shutdown cleanup; a fresh setup and
        // tunnel for every resume. Suspend/resume must repeat indefinitely.
        // Terminate fires on both trusted-network disconnects and on UserQuit.
        assert_eq!(count("terminate"), 3, "{log:?}");
        assert_eq!(count("cleanup:"), 3, "{log:?}");
        assert_eq!(count("setup:"), 3, "{log:?}");
        assert_eq!(count("connect:"), 3, "{log:?}");
        assert_eq!(count("event_loop"), 3, "{log:?}");
        assert_eq!(count("auth"), 0, "{log:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_while_suspended_on_trusted_wifi_exits_without_double_cleanup() {
        let initial = config([10, 0, 0, 2], [10, 1, 0, 0], [10, 0, 0, 53]);
        let shutdown = Shutdown::new();
        let trigger = shutdown.clone();
        let (mut controller, _wifi_tx) =
            trusted_controller(initial, shutdown, EscalationConfig::default());
        let mut driver = ScriptDriver::default();
        driver
            .connects
            .push_back(ScriptConnect::Success(Ipv4Addr::new(10, 0, 0, 2)));
        driver.events.push_back(DisconnectReason::TrustedNetwork);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            trigger.cancel();
        });

        controller.run_with_driver(&mut driver).await.unwrap();
        let log = driver.snapshot();

        // The suspension already tore everything down; the final cleanup pass
        // must not run again against a dead interface.
        assert_eq!(
            log.iter()
                .filter(|entry| entry.starts_with("cleanup:"))
                .count(),
            1,
            "{log:?}"
        );
    }
}
