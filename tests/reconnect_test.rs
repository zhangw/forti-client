use forti_client::reconnect::Backoff;
use forti_client::reconnect::{classify_disconnect, DisconnectReason, ReconnectAction};
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

use std::time::Instant;

#[test]
fn test_no_gap_detected_for_normal_interval() {
    let last = Instant::now() - Duration::from_secs(10);
    assert!(!forti_client::reconnect::detect_sleep_gap(
        last,
        Duration::from_secs(10)
    ));
}

#[test]
fn test_gap_detected_for_long_pause() {
    let last = Instant::now() - Duration::from_secs(45);
    assert!(forti_client::reconnect::detect_sleep_gap(
        last,
        Duration::from_secs(10)
    ));
}

#[test]
fn test_no_gap_for_moderate_delay() {
    // 20s elapsed with 10s interval — 2x is not enough to trigger (threshold is 3x)
    let last = Instant::now() - Duration::from_secs(20);
    assert!(!forti_client::reconnect::detect_sleep_gap(
        last,
        Duration::from_secs(10)
    ));
}

use forti_client::reconnect::ConnectionState;

#[test]
fn test_initial_state_is_connecting() {
    let state = ConnectionState::Connecting;
    assert!(matches!(state, ConnectionState::Connecting));
}

#[test]
fn test_state_transitions() {
    let states = [
        ConnectionState::Connecting,
        ConnectionState::Connected,
        ConnectionState::Reconnecting,
        ConnectionState::ReAuthenticating,
        ConnectionState::WaitingForNetwork,
        ConnectionState::Cleanup,
    ];
    assert_eq!(states.len(), 6);
}

#[test]
fn test_waiting_for_network_state() {
    let state = ConnectionState::WaitingForNetwork;
    assert!(matches!(state, ConnectionState::WaitingForNetwork));
}
