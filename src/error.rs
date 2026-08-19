use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFailureKind {
    TransportUnavailable,
    CookieRejected,
    PostUpgrade,
    LocalSetup,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlFailureKind {
    CallbackTimedOut,
    GatewayUnavailable,
    CallbackInvalid,
    UserCancelled,
    /// The local callback port could not be bound. Recoverable: the occupying
    /// socket may be in TIME_WAIT, or the other process may exit.
    LocalPortUnavailable,
    TerminalConfiguration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRequirement {
    NotRequired,
    Required,
}

#[derive(Error, Debug)]
pub enum FortiError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("SAML callback timed out while waiting for browser or IdP")]
    SamlCallbackTimedOut,

    #[error("invalid SAML callback: {0}")]
    SamlCallbackInvalid(String),

    #[error("SAML callback port unavailable: {0}")]
    SamlCallbackPortUnavailable(String),

    #[error("SAML terminal configuration error: {0}")]
    SamlTerminalConfiguration(String),

    #[error("VPN cookie rejected by server (HTTP {0})")]
    CookieRejected(u16),

    #[error("transport unavailable: {0}")]
    TransportUnavailable(String),

    #[error("post-upgrade negotiation failed: {0}")]
    PostUpgradeNegotiation(String),

    #[error("tunnel closed by peer")]
    TunnelClosed,

    #[error("tunnel error: {0}")]
    TunnelError(String),

    /// A local network-setup command (route/scutil) exceeded its deadline.
    /// This is a busy-system condition — typically configd stalled by the same
    /// interface churn that triggered the reconnect — so callers should retry
    /// rather than treat it as unrecoverable.
    #[error("local setup timed out: {0}")]
    LocalSetupTimedOut(String),

    #[error("PPP negotiation failed: {0}")]
    PppError(String),

    #[error("protocol error: {0}")]
    ProtocolError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
}

impl SamlFailureKind {
    pub fn classify(error: &FortiError) -> Self {
        match error {
            FortiError::SamlCallbackTimedOut => Self::CallbackTimedOut,
            FortiError::SamlCallbackInvalid(_) => Self::CallbackInvalid,
            FortiError::SamlCallbackPortUnavailable(_) => Self::LocalPortUnavailable,
            FortiError::SamlTerminalConfiguration(_) => Self::TerminalConfiguration,
            FortiError::Io(_)
            | FortiError::Tls(_)
            | FortiError::TransportUnavailable(_)
            | FortiError::PostUpgradeNegotiation(_)
            | FortiError::TunnelClosed
            | FortiError::TunnelError(_)
            // A busy local system is not a SAML configuration problem; treat
            // it like an unreachable gateway so auth retries rather than stops.
            | FortiError::LocalSetupTimedOut(_)
            | FortiError::ProtocolError(_) => Self::GatewayUnavailable,
            FortiError::AuthFailed(_)
            | FortiError::CookieRejected(_)
            | FortiError::PppError(_)
            | FortiError::Http(_) => Self::TerminalConfiguration,
        }
    }
}

pub type Result<T> = std::result::Result<T, FortiError>;
