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
    TerminalConfiguration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRequirement {
    NotRequired,
    Required,
    CompatibilityProbeAllowed,
}

#[derive(Error, Debug)]
pub enum FortiError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("SAML callback timed out while waiting for browser or IdP")]
    SamlCallbackTimedOut,

    #[error("invalid SAML callback: {0}")]
    SamlCallbackInvalid(String),

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
            FortiError::SamlTerminalConfiguration(_) => Self::TerminalConfiguration,
            FortiError::Io(_)
            | FortiError::Tls(_)
            | FortiError::TransportUnavailable(_)
            | FortiError::PostUpgradeNegotiation(_)
            | FortiError::TunnelClosed
            | FortiError::TunnelError(_)
            | FortiError::ProtocolError(_) => Self::GatewayUnavailable,
            FortiError::AuthFailed(_)
            | FortiError::CookieRejected(_)
            | FortiError::PppError(_)
            | FortiError::Http(_) => Self::TerminalConfiguration,
        }
    }
}

pub type Result<T> = std::result::Result<T, FortiError>;
