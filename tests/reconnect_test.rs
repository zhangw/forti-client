use std::time::{Duration, Instant};

use forti_client::error::{AuthRequirement, ConnectFailureKind, SamlFailureKind};
use forti_client::reconnect::{
    classify_disconnect, AuthAttemptKind, Backoff, ConnectionState, DisconnectReason,
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
fn transport_unavailable_never_permits_saml() {
    let mut policy = ReconnectPolicy::new();
    for _ in 0..10_000 {
        policy.on_connect_failure(ConnectFailureKind::TransportUnavailable);
        assert_eq!(policy.auth_requirement(), AuthRequirement::NotRequired);
        assert_eq!(policy.next_auth_attempt(), None);
    }
}

#[test]
fn transport_failure_breaks_consecutive_post_upgrade_count() {
    let mut policy = ReconnectPolicy::new();
    for _ in 0..3 {
        policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
        policy.on_connect_failure(ConnectFailureKind::TransportUnavailable);
    }
    assert_eq!(policy.auth_requirement(), AuthRequirement::NotRequired);
    assert_eq!(policy.next_auth_attempt(), None);

    for _ in 0..3 {
        policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
    }
    assert_eq!(
        policy.next_auth_attempt(),
        Some(AuthAttemptKind::CompatibilityProbe)
    );
}

#[test]
fn cookie_rejection_requires_immediate_sticky_authentication() {
    let mut policy = ReconnectPolicy::new();
    policy.on_connect_failure(ConnectFailureKind::CookieRejected);

    assert_eq!(policy.auth_requirement(), AuthRequirement::Required);
    assert_eq!(policy.next_auth_attempt(), Some(AuthAttemptKind::Required));

    policy.on_saml_failure(
        AuthAttemptKind::Required,
        SamlFailureKind::TerminalConfiguration,
    );
    assert_eq!(policy.auth_requirement(), AuthRequirement::Required);
    assert_eq!(policy.next_auth_attempt(), Some(AuthAttemptKind::Required));

    policy.on_saml_failure(
        AuthAttemptKind::Required,
        SamlFailureKind::GatewayUnavailable,
    );
    assert_eq!(policy.auth_requirement(), AuthRequirement::Required);
    assert_eq!(policy.next_auth_attempt(), Some(AuthAttemptKind::Required));
}

#[derive(Clone, Copy)]
enum ScenarioStep {
    PostUpgradeFailure,
    SamlFailure,
    SamlSuccess,
}

fn run_post_upgrade_script(
    policy: &mut ReconnectPolicy,
    script: &[ScenarioStep],
) -> Vec<Option<AuthAttemptKind>> {
    script
        .iter()
        .map(|step| {
            match step {
                ScenarioStep::PostUpgradeFailure => {
                    policy.on_connect_failure(ConnectFailureKind::PostUpgrade)
                }
                ScenarioStep::SamlFailure => policy.on_saml_failure(
                    AuthAttemptKind::CompatibilityProbe,
                    SamlFailureKind::TerminalConfiguration,
                ),
                ScenarioStep::SamlSuccess => policy.on_saml_success(),
            }
            policy.next_auth_attempt()
        })
        .collect()
}

#[test]
fn third_post_upgrade_failure_gets_only_one_probe_in_episode() {
    let mut policy = ReconnectPolicy::new();
    let attempts = run_post_upgrade_script(
        &mut policy,
        &[
            ScenarioStep::PostUpgradeFailure,
            ScenarioStep::PostUpgradeFailure,
            ScenarioStep::PostUpgradeFailure,
            ScenarioStep::SamlFailure,
            ScenarioStep::SamlSuccess,
            ScenarioStep::PostUpgradeFailure,
            ScenarioStep::PostUpgradeFailure,
        ],
    );

    assert_eq!(
        attempts,
        [
            None,
            None,
            Some(AuthAttemptKind::CompatibilityProbe),
            None,
            None,
            None,
            None,
        ]
    );
}

#[test]
fn successful_tunnel_starts_a_new_probe_episode() {
    let mut policy = ReconnectPolicy::new();
    for _ in 0..3 {
        policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
    }
    assert_eq!(
        policy.next_auth_attempt(),
        Some(AuthAttemptKind::CompatibilityProbe)
    );
    policy.on_saml_success();
    policy.on_tunnel_established();

    for _ in 0..2 {
        policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
        assert_eq!(policy.next_auth_attempt(), None);
    }
    policy.on_connect_failure(ConnectFailureKind::PostUpgrade);
    assert_eq!(
        policy.next_auth_attempt(),
        Some(AuthAttemptKind::CompatibilityProbe)
    );
}

#[test]
fn only_tls_plus_ppp_success_resets_backoff() {
    let mut policy = ReconnectPolicy::new();
    assert_eq!(policy.next_delay(), Duration::from_secs(1));
    assert_eq!(policy.current_delay(), Duration::from_secs(2));

    policy.on_network_reachable();
    assert_eq!(policy.current_delay(), Duration::from_secs(2));
    policy.on_system_wake();
    assert_eq!(policy.current_delay(), Duration::from_secs(2));

    policy.on_connect_failure(ConnectFailureKind::CookieRejected);
    assert_eq!(policy.next_auth_attempt(), Some(AuthAttemptKind::Required));
    policy.on_saml_success();
    assert_eq!(policy.current_delay(), Duration::from_secs(2));

    policy.on_tunnel_established();
    assert_eq!(policy.current_delay(), Duration::from_secs(1));
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
        ConnectionState::Running,
        ConnectionState::WaitingToRetry,
        ConnectionState::WaitingForNetwork,
        ConnectionState::CleaningUp,
    ];
    assert_eq!(states.len(), 6);
}
