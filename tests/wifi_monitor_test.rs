use forti_client::wifi_monitor::WifiEvent;

#[test]
fn test_wifi_event_shape() {
    let on_wifi = WifiEvent {
        ssid: Some("OfficeNet".into()),
    };
    let off_wifi = WifiEvent { ssid: None };
    assert_ne!(on_wifi, off_wifi);
    assert_eq!(on_wifi.clone(), on_wifi);
}
