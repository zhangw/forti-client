use forti_client::ppp::codec::{PppFrame, PppProtocol};

#[test]
fn test_ppp_protocol_values() {
    assert_eq!(PppProtocol::Lcp.to_u16(), 0xC021);
    assert_eq!(PppProtocol::Ipcp.to_u16(), 0x8021);
    assert_eq!(PppProtocol::Ipv4.to_u16(), 0x0021);
    assert_eq!(PppProtocol::Ip6cp.to_u16(), 0x8057);
    assert_eq!(PppProtocol::Ipv6.to_u16(), 0x0057);
    assert_eq!(PppProtocol::Ccp.to_u16(), 0x80FD);
}

#[test]
fn test_encode_ipv4_data_frame() {
    let ip_packet = vec![0x45, 0x00, 0x00, 0x14];
    let frame = PppFrame::new(PppProtocol::Ipv4, ip_packet.clone());
    let encoded = frame.encode();
    assert_eq!(encoded[0], 0xFF);
    assert_eq!(encoded[1], 0x03);
    assert_eq!(encoded[2..4], [0x00, 0x21]);
    assert_eq!(encoded[4..], ip_packet[..]);
}

#[test]
fn test_decode_lcp_frame() {
    let wire = vec![
        0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x08, 0x01, 0x04, 0x05, 0xDC,
    ];
    let frame = PppFrame::decode(&wire).unwrap();
    assert_eq!(frame.protocol(), PppProtocol::Lcp);
    assert_eq!(
        frame.data(),
        &[0x01, 0x01, 0x00, 0x08, 0x01, 0x04, 0x05, 0xDC]
    );
}

#[test]
fn test_decode_unknown_protocol() {
    let wire = vec![0xFF, 0x03, 0xAA, 0xBB, 0x01, 0x02];
    let frame = PppFrame::decode(&wire).unwrap();
    assert_eq!(frame.protocol(), PppProtocol::Unknown(0xAABB));
    assert_eq!(frame.data(), &[0x01, 0x02]);
}

#[test]
fn test_decode_without_address_control() {
    // Compressed PPP frame: no FF 03 prefix, protocol starts directly
    let wire = vec![0xC0, 0x21, 0x01, 0x01, 0x00, 0x04];
    let frame = PppFrame::decode(&wire).unwrap();
    assert_eq!(frame.protocol(), PppProtocol::Lcp);
    assert_eq!(frame.data(), &[0x01, 0x01, 0x00, 0x04]);
}

#[test]
fn test_decode_too_short() {
    let wire = vec![0xFF, 0x03];
    assert!(PppFrame::decode(&wire).is_err());
}

#[test]
fn test_roundtrip() {
    let original = PppFrame::new(PppProtocol::Ipcp, vec![0x01, 0x02, 0x00, 0x04]);
    let encoded = original.encode();
    let decoded = PppFrame::decode(&encoded).unwrap();
    assert_eq!(decoded.protocol(), original.protocol());
    assert_eq!(decoded.data(), original.data());
}
