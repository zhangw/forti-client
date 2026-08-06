use forti_client::tunnel::codec::{FortinetCodec, FortinetFrame};

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

/// A valid single frame carrying a 4-byte PPP payload.
fn valid_frame() -> Vec<u8> {
    vec![0x00, 0x0A, 0x50, 0x50, 0x00, 0x04, 0xFF, 0x03, 0x00, 0x21]
}

/// Drain the codec until it stops producing frames, with a hard iteration cap
/// so a non-progressing codec fails the test instead of hanging it.
fn drain_frames(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut codec = FortinetCodec::new();
    let mut frames = Vec::new();
    for _ in 0..1_000 {
        match codec.try_decode(buf) {
            Some(frame) => frames.push(frame.payload().to_vec()),
            None => return frames,
        }
    }
    panic!("codec did not settle within 1000 iterations; buffer left: {buf:?}");
}

#[test]
fn magic_at_buffer_start_does_not_livelock() {
    // "PP" is ordinary IP payload data and can land at offset 0 after a
    // desync. A frame header would put the magic at offset 2, so a magic at 0
    // is never a header. Treating it as one used to drain zero bytes and
    // return None with the buffer unchanged, so the caller appended more data
    // and re-entered the same state forever while memory grew without bound.
    let mut buf = vec![0x50, 0x50, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22];
    let before = buf.len();

    assert!(drain_frames(&mut buf).is_empty());
    assert!(
        buf.len() < before,
        "undecodable bytes must be consumed to guarantee progress"
    );
}

#[test]
fn frame_is_recovered_after_leading_magic_garbage() {
    let mut buf = vec![0x50, 0x50];
    buf.extend(valid_frame());

    let frames = drain_frames(&mut buf);
    assert_eq!(frames, vec![vec![0xFF, 0x03, 0x00, 0x21]]);
    assert!(buf.is_empty());
}

#[test]
fn implausible_length_is_skipped_instead_of_awaited() {
    // Magic in the right position but a 64 KiB length: without a bound the
    // codec would stall waiting for bytes that never arrive.
    let mut buf = vec![0xFF, 0xFF, 0x50, 0x50, 0xFF, 0xFF];
    buf.extend(valid_frame());

    let frames = drain_frames(&mut buf);
    assert_eq!(frames, vec![vec![0xFF, 0x03, 0x00, 0x21]]);
}

#[test]
fn inconsistent_header_lengths_cost_one_byte_not_a_whole_frame() {
    // total_len disagrees with payload_len + 6, so this is a chance "PP" and
    // not a header. Consuming the claimed frame length would swallow the real
    // frame that follows; only one byte may be discarded.
    let mut buf = vec![0x00, 0xFF, 0x50, 0x50, 0x00, 0x04];
    buf.extend(valid_frame());

    let frames = drain_frames(&mut buf);
    assert_eq!(frames, vec![vec![0xFF, 0x03, 0x00, 0x21]]);
}

#[test]
fn header_split_across_reads_is_retained_and_then_decoded() {
    let frame = valid_frame();
    // Deliver the frame one byte at a time. A header candidate must survive
    // the resync tail trim, otherwise a frame straddling reads is lost.
    let mut codec = FortinetCodec::new();
    let mut buf = Vec::new();
    let mut decoded = None;
    for byte in frame {
        buf.push(byte);
        if let Some(f) = codec.try_decode(&mut buf) {
            decoded = Some(f.payload().to_vec());
        }
    }

    assert_eq!(decoded, Some(vec![0xFF, 0x03, 0x00, 0x21]));
}

#[test]
fn back_to_back_frames_are_all_decoded() {
    let mut buf = valid_frame();
    buf.extend(valid_frame());
    buf.extend(valid_frame());

    let frames = drain_frames(&mut buf);
    assert_eq!(frames.len(), 3);
    assert!(frames.iter().all(|p| p == &[0xFF, 0x03, 0x00, 0x21]));
    assert!(buf.is_empty());
}
