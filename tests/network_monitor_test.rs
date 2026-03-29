use forti_client::network_monitor::NetworkEvent;

#[test]
fn test_network_event_variants() {
    let events = vec![
        NetworkEvent::Reachable,
        NetworkEvent::Unreachable,
    ];
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], NetworkEvent::Reachable));
    assert!(matches!(events[1], NetworkEvent::Unreachable));
}
