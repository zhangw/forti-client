use crate::error::{FortiError, Result};

const FORTINET_MAGIC: [u8; 2] = [0x50, 0x50];
const HEADER_LEN: usize = 6;

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
        if buf.len() < HEADER_LEN {
            return None;
        }

        if buf[2..4] != FORTINET_MAGIC {
            // Protocol desync — scan forward for magic bytes
            if let Some(pos) = buf.windows(2).position(|w| w == FORTINET_MAGIC) {
                // The magic is at offset `pos`, but it should be at offset 2.
                // So the frame header starts at `pos - 2` if pos >= 2.
                if pos >= 2 {
                    let _discarded: Vec<u8> = buf.drain(..pos - 2).collect();
                    // Try again with the realigned buffer
                    return self.try_decode(buf);
                } else {
                    // Magic too close to start, discard up to magic position
                    let _discarded: Vec<u8> = buf.drain(..pos).collect();
                    return None;
                }
            } else {
                // No magic found anywhere — discard all but last byte
                // (magic could straddle reads)
                let keep = 1;
                if buf.len() > keep {
                    buf.drain(..buf.len() - keep);
                }
                return None;
            }
        }

        let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let frame_len = HEADER_LEN + payload_len;
        if buf.len() < frame_len {
            return None;
        }
        let frame_bytes: Vec<u8> = buf.drain(..frame_len).collect();
        FortinetFrame::decode(&frame_bytes).ok()
    }
}
