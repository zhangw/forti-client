use forti_client::power_monitor::PowerEvent;

#[test]
fn test_power_event_variants() {
    let events = vec![
        PowerEvent::WillSleep,
        PowerEvent::HasPoweredOn,
    ];
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PowerEvent::WillSleep));
    assert!(matches!(events[1], PowerEvent::HasPoweredOn));
}
