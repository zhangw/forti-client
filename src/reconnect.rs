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

use std::time::Duration;

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Exponential backoff timer: 1s, 2s, 4s, 8s, ..., capped at 60s.
pub struct Backoff {
    current: Duration,
}

impl Backoff {
    pub fn new() -> Self {
        Self { current: BACKOFF_INITIAL }
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
