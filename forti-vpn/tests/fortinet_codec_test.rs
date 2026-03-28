use forti_vpn::tunnel::codec::{FortinetCodec, FortinetFrame};

#[test]
fn test_encode_fortinet_frame() {
    let ppp_payload = vec![0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14];
    let frame = FortinetFrame::new(ppp_payload.clone());
    let encoded = frame.encode();
    assert_eq!(encoded[0..2], [0x00, 0x0E]);
    assert_eq!(encoded[2..4], [0x50, 0x50]);
    assert_eq!(encoded[4..6], [0x00, 0x08]);
    assert_eq!(encoded[6..], ppp_payload[..]);
}

#[test]
fn test_decode_fortinet_frame() {
    let wire = vec![
        0x00, 0x0E, 0x50, 0x50, 0x00, 0x08, 0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14,
    ];
    let frame = FortinetFrame::decode(&wire).unwrap();
    assert_eq!(
        frame.payload(),
        &[0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14]
    );
}

#[test]
fn test_decode_invalid_magic() {
    let wire = vec![0x00, 0x0A, 0x51, 0x50, 0x00, 0x04, 0xFF, 0x03, 0x00, 0x21];
    assert!(FortinetFrame::decode(&wire).is_err());
}

#[test]
fn test_decode_truncated_frame() {
    let wire = vec![0x00, 0x0E, 0x50, 0x50];
    assert!(FortinetFrame::decode(&wire).is_err());
}

#[test]
fn test_codec_extract_frame_from_stream() {
    let mut buf = vec![
        0x00, 0x0A, 0x50, 0x50, 0x00, 0x04, 0xFF, 0x03, 0x00, 0x21, // complete frame
        0x00, 0x0E, 0x50, 0x50, // incomplete second frame
    ];
    let mut codec = FortinetCodec::new();
    let frame1 = codec.try_decode(&mut buf);
    assert!(frame1.is_some());
    assert_eq!(frame1.unwrap().payload(), &[0xFF, 0x03, 0x00, 0x21]);
    let frame2 = codec.try_decode(&mut buf);
    assert!(frame2.is_none());
}

#[test]
fn test_encode_empty_payload() {
    let frame = FortinetFrame::new(vec![]);
    let encoded = frame.encode();
    assert_eq!(encoded, vec![0x00, 0x06, 0x50, 0x50, 0x00, 0x00]);
}
