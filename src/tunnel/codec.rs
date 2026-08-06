use crate::error::{FortiError, Result};

const FORTINET_MAGIC: [u8; 2] = [0x50, 0x50];
const HEADER_LEN: usize = 6;

/// Upper bound on a single frame's PPP payload.
///
/// The negotiated MRU is 1500, so this sits far above anything a correct peer
/// sends while leaving room for a raised MTU. It exists to stop us waiting on a
/// bogus 64 KiB length, not to enforce the MRU.
const MAX_PAYLOAD_LEN: usize = 8192;

/// Bytes retained when no usable magic is found yet.
///
/// A frame header is `[len:2][magic:2][payload_len:2]`, so a frame start at
/// offset `s` is only confirmable once `s + 4` bytes are present. Keeping the
/// last 3 bytes preserves a header whose magic straddles two reads.
const RESYNC_TAIL_KEEP: usize = 3;

#[derive(Debug, Clone)]
pub struct FortinetFrame {
    payload: Vec<u8>,
}

impl FortinetFrame {
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u16;
        let total_len = payload_len + HEADER_LEN as u16;
        let mut buf = Vec::with_capacity(HEADER_LEN + self.payload.len());
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&FORTINET_MAGIC);
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(FortiError::ProtocolError(
                "frame too short for header".into(),
            ));
        }
        if buf[2..4] != FORTINET_MAGIC {
            return Err(FortiError::ProtocolError(format!(
                "invalid magic: {:02X}{:02X}, expected 5050",
                buf[2], buf[3]
            )));
        }
        let total_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        if total_len != payload_len + HEADER_LEN {
            return Err(FortiError::ProtocolError(format!(
                "frame length mismatch: total_len={} but payload_len+6={}",
                total_len,
                payload_len + HEADER_LEN,
            )));
        }
        if buf.len() < HEADER_LEN + payload_len {
            return Err(FortiError::ProtocolError(format!(
                "frame truncated: have {} bytes, need {}",
                buf.len(),
                HEADER_LEN + payload_len,
            )));
        }
        Ok(Self {
            payload: buf[HEADER_LEN..HEADER_LEN + payload_len].to_vec(),
        })
    }
}

pub struct FortinetCodec;

impl Default for FortinetCodec {
    fn default() -> Self {
        Self
    }
}

impl FortinetCodec {
    pub fn new() -> Self {
        Self
    }

    pub fn try_decode(&mut self, buf: &mut Vec<u8>) -> Option<FortinetFrame> {
        loop {
            if buf.len() < HEADER_LEN {
                return None;
            }

            if buf[2..4] != FORTINET_MAGIC {
                if resync(buf) {
                    continue;
                }
                return None;
            }

            let total_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;

            // Validate the whole header before consuming anything. A "PP" pair
            // inside an IP payload can land at the magic offset by chance, and
            // consuming a bogus frame length would swallow part of the real
            // frame that follows. Dropping a single byte keeps the cost of a
            // false positive at one byte and still guarantees progress.
            if payload_len > MAX_PAYLOAD_LEN || total_len != payload_len + HEADER_LEN {
                buf.drain(..1);
                continue;
            }

            let frame_len = HEADER_LEN + payload_len;
            if buf.len() < frame_len {
                return None;
            }
            let frame_bytes: Vec<u8> = buf.drain(..frame_len).collect();
            match FortinetFrame::decode(&frame_bytes) {
                Ok(frame) => return Some(frame),
                // Not reachable in practice, since the header was validated
                // above. The bytes are consumed either way, so the loop still
                // makes forward progress.
                Err(_) => continue,
            }
        }
    }
}

/// Realign `buf` so a frame header candidate starts at offset 0.
///
/// Returns true when the caller should retry decoding. Always either makes
/// forward progress or leaves a buffer too short to decide, so a desynchronized
/// stream can never spin without consuming bytes.
fn resync(buf: &mut Vec<u8>) -> bool {
    // A frame starting at `s` puts its magic at `s + 2`, so only a magic at
    // offset >= 2 can be a header. A magic at offset 0 or 1 is payload data and
    // must be skipped rather than aligned to, which is what previously let a
    // buffer beginning with "PP" spin forever without consuming anything.
    let magic_at = buf
        .windows(2)
        .enumerate()
        .skip(2)
        .find(|(_, window)| *window == FORTINET_MAGIC)
        .map(|(offset, _)| offset);

    match magic_at {
        Some(offset) => {
            // `offset` cannot be 2 here, because the caller only resyncs after
            // rejecting a magic at that position, so `offset - 2` is at least 1.
            // The `max(1)` makes forward progress independent of that caller
            // invariant rather than silently reintroducing a livelock if it
            // ever changes.
            let discard = (offset - 2).max(1);
            buf.drain(..discard);
            true
        }
        None => {
            // No header candidate anywhere. Discard everything that cannot
            // still be the start of one.
            if buf.len() > RESYNC_TAIL_KEEP {
                buf.drain(..buf.len() - RESYNC_TAIL_KEEP);
            }
            false
        }
    }
}
