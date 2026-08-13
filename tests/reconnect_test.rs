use std::time::{Duration, Instant};

use forti_client::error::{AuthRequirement, ConnectFailureKind, SamlFailureKind};
use forti_client::reconnect::{
    classify_disconnect, is_trusted_wifi, Backoff, ConnectionState, DisconnectReason,
    ReconnectAction, ReconnectPolicy,
};

#[test]
fn disconnect_reasons_preserve_existing_behavior() {
    for reason in [
        DisconnectReason::DeadPeer,
        DisconnectReason::TunnelClosed,
        DisconnectReason::ServerTerminated,
        DisconnectReason::IoError("TUN read error".into()),
        DisconnectReason::SystemSleep,
    ] {
        assert_eq!(
            classify_disconnect(&reason),
            ReconnectAction::RetryWithCookie
        );
    }
    assert_eq!(
        classify_disconnect(&DisconnectReason::UserQuit),
        ReconnectAction::Exit
    );
}

#[test]
fn backoff_sequence_is_one_through_capped_sixty() {
    let mut policy = ReconnectPolicy::new();
    let delays: Vec<_> = (0..9).map(|_| policy.next_delay().as_secs()).collect();
    assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
}

#[test]
fn standalone_backoff_reset_is_preserved() {
    let mut backoff = Backoff::new();
    backoff.next();
    backoff.next();
    assert_eq!(backoff.current(), Duration::from_secs(4));
    backoff.reset();
    assert_eq!(backoff.current(), Duration::from_secs(1));
}

#[test]
fn failures_below_threshold_never_permit_saml() {
    let mut policy = ReconnectPolicy::new();
    for _ in 0..4 {
        policy.on_connect_failure(ConnectFailureKind::TransportUnavailable);
        assert_eq!(policy.auth_requirement(), AuthRequirement::NotRequired);
        assert!(!policy.next_auth_attempt());
    }
}

#[test]
fn mixed_failure_kinds_accumulate_toward_escalation() {
    let mut policy = ReconnectPolicy::new();
    for _ in 0..2 {
        policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
        policy.on_connect_failure(ConnectFailureKind::TransportUnavailable);
    }
    assert_eq!(policy.auth_requirement(), AuthRequirement::NotRequired);
    assert!(!policy.next_auth_attempt());

    policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
    assert_eq!(policy.auth_requirement(), AuthRequirement::Required);
    assert!(policy.next_auth_attempt());
}

#[test]
fn cookie_rejection_requires_immediate_sticky_authentication() {
    let mut policy = ReconnectPolicy::new();
    policy.on_connect_failure(ConnectFailureKind::CookieRejected);

    assert_eq!(policy.auth_requirement(), AuthRequirement::Required);
    assert!(policy.next_auth_attempt());

    policy.on_saml_failure(SamlFailureKind::TerminalConfiguration);
    assert_eq!(policy.auth_requirement(), AuthRequirement::Required);
    assert!(policy.next_auth_attempt());

    policy.on_saml_failure(SamlFailureKind::GatewayUnavailable);
    assert_eq!(policy.auth_requirement(), AuthRequirement::Required);
    assert!(policy.next_auth_attempt());
}

#[test]
fn escalated_auth_requirement_is_sticky_until_saml_success() {
    let mut policy = ReconnectPolicy::new();
    for _ in 0..5 {
        policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
    }
    assert!(policy.next_auth_attempt());

    policy.on_saml_failure(SamlFailureKind::GatewayUnavailable);
    assert!(policy.next_auth_attempt());

    policy.on_saml_success();
    assert!(!policy.next_auth_attempt());
}

#[test]
fn post_escalation_failures_reescalate_immediately() {
    let mut policy = ReconnectPolicy::new();
    for _ in 0..5 {
        policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
    }
    assert!(policy.next_auth_attempt());

    policy.on_saml_success();
    assert!(!policy.next_auth_attempt());

    // SAML success deliberately does not reset failed_cycles, so one more
    // connect failure pushes the count back over the threshold at once.
    policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
    assert!(policy.next_auth_attempt());
}

#[test]
fn tunnel_establishment_resets_failed_cycles() {
    let mut policy = ReconnectPolicy::new();
    for _ in 0..5 {
        policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
    }
    policy.on_tunnel_established();

    for _ in 0..4 {
        policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
        assert!(!policy.next_auth_attempt());
    }
}

#[test]
fn short_lived_tunnels_count_toward_escalation() {
    let mut policy = ReconnectPolicy::new();
    for _ in 0..4 {
        policy.on_short_lived_tunnel();
        assert!(!policy.next_auth_attempt());
    }
    policy.on_short_lived_tunnel();
    assert!(policy.next_auth_attempt());
}

#[test]
fn flap_and_connect_failures_share_one_escalation_budget() {
    // A flapping tunnel and the failed retry that follows it are two failed
    // cycles from one physical outage. Pin the shared budget so a future
    // refactor cannot silently double or halve the effective threshold.
    let mut policy = ReconnectPolicy::new();
    for pair in 0..2 {
        policy.on_short_lived_tunnel();
        policy.on_connect_failure(ConnectFailureKind::TransportUnavailable);
        assert!(
            !policy.next_auth_attempt(),
            "escalated after only {} flap+failure pairs",
            pair + 1
        );
    }
    policy.on_short_lived_tunnel();
    assert!(policy.next_auth_attempt());
}

#[test]
fn only_tls_plus_ppp_success_resets_backoff() {
    let mut policy = ReconnectPolicy::new();
    policy.on_connect_attempt();
    policy.on_connect_attempt();
    assert_eq!(policy.connect_attempts(), 2);
    assert_eq!(policy.next_delay(), Duration::from_secs(1));
    assert_eq!(policy.current_delay(), Duration::from_secs(2));

    policy.on_network_reachable();
    assert_eq!(policy.current_delay(), Duration::from_secs(2));
    policy.on_system_wake();
    assert_eq!(policy.current_delay(), Duration::from_secs(2));

    policy.on_connect_failure(ConnectFailureKind::CookieRejected);
    assert!(policy.next_auth_attempt());
    policy.on_saml_success();
    assert_eq!(policy.current_delay(), Duration::from_secs(2));

    policy.on_tunnel_established();
    assert_eq!(policy.current_delay(), Duration::from_secs(1));
    assert_eq!(policy.connect_attempts(), 0);
}

#[test]
fn sleep_gap_detection_behavior_is_preserved() {
    let interval = Duration::from_secs(10);
    assert!(!forti_client::reconnect::detect_sleep_gap(
        Instant::now() - Duration::from_secs(10),
        interval
    ));
    assert!(!forti_client::reconnect::detect_sleep_gap(
        Instant::now() - Duration::from_secs(20),
        interval
    ));
    assert!(forti_client::reconnect::detect_sleep_gap(
        Instant::now() - Duration::from_secs(45),
        interval
    ));
}

#[test]
fn connection_states_name_actual_controller_phases() {
    let states = [
        ConnectionState::EstablishingTunnel,
        ConnectionState::Authenticating,
        ConnectionState::RefreshingConfig,
        ConnectionState::Running,
        ConnectionState::WaitingToRetry,
        ConnectionState::WaitingForNetwork,
        ConnectionState::SuspendedOnTrustedWifi,
        ConnectionState::CleaningUp,
    ];
    assert_eq!(states.len(), 8);
}

#[test]
fn is_trusted_wifi_matches_exactly() {
    let whitelist = vec!["Home".to_string(), "Office-5G".to_string()];
    // Strict, byte-exact matching only.
    assert!(is_trusted_wifi(Some("Home"), &whitelist));
    assert!(is_trusted_wifi(Some("Office-5G"), &whitelist));
    assert!(!is_trusted_wifi(Some("home"), &whitelist));
    assert!(!is_trusted_wifi(Some("Home "), &whitelist));
    assert!(!is_trusted_wifi(Some("Homestead"), &whitelist));
    // No Wi-Fi (wired, hotspot without SSID, failed query) is never trusted.
    assert!(!is_trusted_wifi(None, &whitelist));
    // An empty whitelist disables the feature entirely.
    assert!(!is_trusted_wifi(Some("Home"), &[]));
    assert!(!is_trusted_wifi(None, &[]));
}
