use forti_client::power_monitor::{PowerCapabilities, PowerEvent, PowerMonitor};

#[test]
fn test_power_event_variants() {
    let capabilities = PowerCapabilities {
        known: true,
        cpu: true,
        network: true,
        graphics: false,
    };
    let events = [
        PowerEvent::WillSleep,
        PowerEvent::HasPoweredOn,
        PowerEvent::Capabilities(capabilities),
    ];
    assert_eq!(events.len(), 3);
    assert!(matches!(events[0], PowerEvent::WillSleep));
    assert!(matches!(events[1], PowerEvent::HasPoweredOn));
    assert_eq!(events[2], PowerEvent::Capabilities(capabilities));
}

#[test]
fn initial_capabilities_are_explicitly_unknown() {
    let initial = PowerCapabilities::default();
    assert_eq!(initial, PowerCapabilities::UNKNOWN);
    assert!(!initial.known);
}

#[test]
fn monitor_start_waits_for_registration_and_publishes_initial_level() {
    let (_monitor, mut events) = PowerMonitor::start().expect("power monitor must register");
    assert_eq!(
        events.try_recv().expect("initial capability level"),
        PowerEvent::Capabilities(PowerCapabilities::UNKNOWN)
    );
}
