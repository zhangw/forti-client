use thiserror::Error;

#[derive(Error, Debug)]
pub enum FortiError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

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

pub type Result<T> = std::result::Result<T, FortiError>;
