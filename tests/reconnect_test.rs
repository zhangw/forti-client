use forti_client::reconnect::{DisconnectReason, ReconnectAction, classify_disconnect};
use forti_client::reconnect::Backoff;
use std::time::Duration;

#[test]
fn test_dead_peer_is_recoverable() {
    assert_eq!(
        classify_disconnect(&DisconnectReason::DeadPeer),
        ReconnectAction::RetryWithCookie,
    );
}

#[test]
fn test_tunnel_closed_is_recoverable() {
    assert_eq!(
        classify_disconnect(&DisconnectReason::TunnelClosed),
        ReconnectAction::RetryWithCookie,
    );
}

#[test]
fn test_server_terminated_is_recoverable() {
    assert_eq!(
        classify_disconnect(&DisconnectReason::ServerTerminated),
        ReconnectAction::RetryWithCookie,
    );
}

#[test]
fn test_io_error_is_recoverable() {
    assert_eq!(
        classify_disconnect(&DisconnectReason::IoError("TUN read error".into())),
        ReconnectAction::RetryWithCookie,
    );
}

#[test]
fn test_user_quit_exits() {
    assert_eq!(
        classify_disconnect(&DisconnectReason::UserQuit),
        ReconnectAction::Exit,
    );
}

#[test]
fn test_backoff_initial() {
    let backoff = Backoff::new();
    assert_eq!(backoff.current(), Duration::from_secs(1));
}

#[test]
fn test_backoff_exponential() {
    let mut backoff = Backoff::new();
    assert_eq!(backoff.current(), Duration::from_secs(1));
    backoff.next();
    assert_eq!(backoff.current(), Duration::from_secs(2));
    backoff.next();
    assert_eq!(backoff.current(), Duration::from_secs(4));
    backoff.next();
    assert_eq!(backoff.current(), Duration::from_secs(8));
}

#[test]
fn test_backoff_caps_at_60s() {
    let mut backoff = Backoff::new();
    for _ in 0..10 {
        backoff.next();
    }
    assert_eq!(backoff.current(), Duration::from_secs(60));
}

#[test]
fn test_backoff_reset() {
    let mut backoff = Backoff::new();
    backoff.next();
    backoff.next();
    assert_eq!(backoff.current(), Duration::from_secs(4));
    backoff.reset();
    assert_eq!(backoff.current(), Duration::from_secs(1));
}
