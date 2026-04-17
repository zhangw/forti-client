use forti_client::ppp::lcp::{LcpCode, LcpOption, LcpPacket, LcpState};

#[test]
fn test_encode_configure_request_mru_magic() {
    let options = vec![LcpOption::Mru(1500), LcpOption::MagicNumber(0xDEADBEEF)];
    let pkt = LcpPacket::new(LcpCode::ConfigureRequest, 1, options);
    let encoded = pkt.encode();

    assert_eq!(encoded[0], 0x01);
    assert_eq!(encoded[1], 0x01);
    assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 14);
    assert_eq!(encoded[4..8], [0x01, 0x04, 0x05, 0xDC]);
    assert_eq!(encoded[8], 0x05);
    assert_eq!(encoded[9], 0x06);
    assert_eq!(encoded[10..14], 0xDEADBEEFu32.to_be_bytes());
}

#[test]
fn test_decode_configure_request() {
    let data = vec![
        0x01, 0x42, 0x00, 0x0E, 0x01, 0x04, 0x05, 0xDC, 0x05, 0x06, 0x12, 0x34, 0x56, 0x78,
    ];
    let pkt = LcpPacket::decode(&data).unwrap();
    assert_eq!(pkt.code(), LcpCode::ConfigureRequest);
    assert_eq!(pkt.identifier(), 0x42);
    assert_eq!(pkt.options().len(), 2);
    assert_eq!(pkt.options()[0], LcpOption::Mru(1500));
    assert_eq!(pkt.options()[1], LcpOption::MagicNumber(0x12345678));
}

#[test]
fn test_decode_configure_request_with_pfcomp_accomp() {
    let data = vec![
        0x01, 0x01, 0x00, 0x0C, 0x01, 0x04, 0x05, 0xDC, 0x07, 0x02, 0x08, 0x02,
    ];
    let pkt = LcpPacket::decode(&data).unwrap();
    assert_eq!(pkt.options().len(), 3);
    assert_eq!(pkt.options()[1], LcpOption::ProtocolFieldCompression);
    assert_eq!(pkt.options()[2], LcpOption::AddressControlFieldCompression);
}

#[test]
fn test_lcp_state_handle_server_config_request() {
    let mut state = LcpState::new(1500);
    let server_req = vec![
        0x01, 0x01, 0x00, 0x10, 0x01, 0x04, 0x05, 0xDC, 0x05, 0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0x07,
        0x02,
    ];
    let responses = state.handle_packet(&server_req);
    assert!(!responses.is_empty());
    let reject = LcpPacket::decode(&responses[0]).unwrap();
    assert_eq!(reject.code(), LcpCode::ConfigureReject);
    assert_eq!(reject.identifier(), 0x01);
    assert_eq!(reject.options().len(), 1);
    assert_eq!(reject.options()[0], LcpOption::ProtocolFieldCompression);
}

#[test]
fn test_lcp_state_handle_server_config_request_all_acceptable() {
    let mut state = LcpState::new(1500);
    let server_req = vec![
        0x01, 0x01, 0x00, 0x0E, 0x01, 0x04, 0x05, 0xDC, 0x05, 0x06, 0xAA, 0xBB, 0xCC, 0xDD,
    ];
    let responses = state.handle_packet(&server_req);
    assert_eq!(responses.len(), 1);
    let ack = LcpPacket::decode(&responses[0]).unwrap();
    assert_eq!(ack.code(), LcpCode::ConfigureAck);
    assert_eq!(ack.identifier(), 0x01);
}

#[test]
fn test_lcp_echo_request_produces_reply() {
    let mut state = LcpState::new(1500);
    state.set_peer_magic(0x12345678);
    let echo_req = vec![0x09, 0x05, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78];
    let responses = state.handle_packet(&echo_req);
    assert_eq!(responses.len(), 1);
    let reply = &responses[0];
    assert_eq!(reply[0], 0x0A); // Echo-Reply
    assert_eq!(reply[1], 0x05); // same identifier
}

#[test]
fn test_lcp_build_initial_config_request() {
    let state = LcpState::new(1400);
    let req = state.build_configure_request();
    let pkt = LcpPacket::decode(&req).unwrap();
    assert_eq!(pkt.code(), LcpCode::ConfigureRequest);
    let mru = pkt
        .options()
        .iter()
        .find(|o| matches!(o, LcpOption::Mru(_)));
    assert!(mru.is_some());
    if let Some(LcpOption::Mru(val)) = mru {
        assert_eq!(*val, 1400);
    }
    let magic = pkt
        .options()
        .iter()
        .find(|o| matches!(o, LcpOption::MagicNumber(_)));
    assert!(magic.is_some());
}
