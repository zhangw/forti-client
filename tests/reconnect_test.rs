use forti_client::reconnect::{DisconnectReason, ReconnectAction, classify_disconnect};

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
