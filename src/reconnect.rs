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
