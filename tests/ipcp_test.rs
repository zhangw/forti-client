use forti_client::ppp::ipcp::{IpcpCode, IpcpOption, IpcpPacket, IpcpState};
use std::net::Ipv4Addr;

#[test]
fn test_encode_initial_request() {
    let state = IpcpState::new();
    let req = state.build_configure_request();
    let pkt = IpcpPacket::decode(&req).unwrap();
    assert_eq!(pkt.code(), IpcpCode::ConfigureRequest);
    let ip_opt = pkt
        .options()
        .iter()
        .find(|o| matches!(o, IpcpOption::IpAddress(_)));
    assert!(ip_opt.is_some());
    if let Some(IpcpOption::IpAddress(addr)) = ip_opt {
        assert_eq!(*addr, Ipv4Addr::UNSPECIFIED);
    }
}

#[test]
fn test_decode_configure_nak_with_assigned_addresses() {
    let data = vec![
        0x03, 0x01, 0x00, 0x22, // ConfigureNak, id=1, length=34
        0x03, 0x06, 10, 0, 0, 5, // IpAddress 10.0.0.5
        0x81, 0x06, 10, 0, 0, 1, // PrimaryDns 10.0.0.1
        0x82, 0x06, 8, 8, 8, 8, // SecondaryDns 8.8.8.8
        0x83, 0x06, 10, 0, 0, 2, // PrimaryNbns 10.0.0.2
        0x84, 0x06, 10, 0, 0, 3, // SecondaryNbns 10.0.0.3
    ];
    let pkt = IpcpPacket::decode(&data).unwrap();
    assert_eq!(pkt.code(), IpcpCode::ConfigureNak);
    let opts = pkt.options();
    assert_eq!(opts[0], IpcpOption::IpAddress(Ipv4Addr::new(10, 0, 0, 5)));
    assert_eq!(opts[1], IpcpOption::PrimaryDns(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(opts[2], IpcpOption::SecondaryDns(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(opts[3], IpcpOption::PrimaryNbns(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(
        opts[4],
        IpcpOption::SecondaryNbns(Ipv4Addr::new(10, 0, 0, 3))
    );
}

#[test]
fn test_handle_nak_then_resend_with_assigned_values() {
    let mut state = IpcpState::new();
    let nak = vec![
        0x03, 0x01, 0x00, 0x16, // ConfigureNak, id=1, length=22
        0x03, 0x06, 10, 0, 0, 5, // IpAddress 10.0.0.5
        0x81, 0x06, 10, 0, 0, 1, // PrimaryDns 10.0.0.1
        0x82, 0x06, 8, 8, 8, 8, // SecondaryDns 8.8.8.8
    ];
    let responses = state.handle_packet(&nak);
    assert_eq!(responses.len(), 1);
    let pkt = IpcpPacket::decode(&responses[0]).unwrap();
    assert_eq!(pkt.code(), IpcpCode::ConfigureRequest);
    let ip_opt = pkt
        .options()
        .iter()
        .find(|o| matches!(o, IpcpOption::IpAddress(_)));
    if let Some(IpcpOption::IpAddress(addr)) = ip_opt {
        assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 5));
    }
}

#[test]
fn test_handle_ack_completes_negotiation() {
    let mut state = IpcpState::new();
    // First handle a Nak to set assigned addresses
    let nak = vec![
        0x03, 0x01, 0x00, 0x16, // ConfigureNak, id=1, length=22
        0x03, 0x06, 10, 0, 0, 5, // IpAddress 10.0.0.5
        0x81, 0x06, 10, 0, 0, 1, // PrimaryDns 10.0.0.1
        0x82, 0x06, 8, 8, 8, 8, // SecondaryDns 8.8.8.8
    ];
    let _ = state.handle_packet(&nak);
    // Then handle Ack to complete negotiation
    let ack = vec![
        0x02, 0x02, 0x00, 0x16, // ConfigureAck, id=2, length=22
        0x03, 0x06, 10, 0, 0, 5, // IpAddress 10.0.0.5
        0x81, 0x06, 10, 0, 0, 1, // PrimaryDns 10.0.0.1
        0x82, 0x06, 8, 8, 8, 8, // SecondaryDns 8.8.8.8
    ];
    let responses = state.handle_packet(&ack);
    assert!(responses.is_empty());
    let config = state.config().unwrap();
    assert_eq!(config.ip_address, Ipv4Addr::new(10, 0, 0, 5));
    assert_eq!(config.primary_dns, Some(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(config.secondary_dns, Some(Ipv4Addr::new(8, 8, 8, 8)));
}

#[test]
fn test_handle_server_configure_request() {
    let mut state = IpcpState::new();
    let server_req = vec![
        0x01, 0x03, 0x00, 0x0A, // ConfigureRequest, id=3, length=10
        0x03, 0x06, 192, 168, 1, 1, // IpAddress 192.168.1.1
    ];
    let responses = state.handle_packet(&server_req);
    assert_eq!(responses.len(), 1);
    let pkt = IpcpPacket::decode(&responses[0]).unwrap();
    assert_eq!(pkt.code(), IpcpCode::ConfigureAck);
    assert_eq!(pkt.identifier(), 0x03);
}
