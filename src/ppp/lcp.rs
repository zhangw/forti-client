use crate::error::{FortiError, Result};

/// LCP packet codes per RFC 1661 Section 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcpCode {
    ConfigureRequest,
    ConfigureAck,
    ConfigureNak,
    ConfigureReject,
    TerminateRequest,
    TerminateAck,
    CodeReject,
    ProtocolReject,
    EchoRequest,
    EchoReply,
    DiscardRequest,
    Unknown(u8),
}

impl LcpCode {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::ConfigureRequest,
            2 => Self::ConfigureAck,
            3 => Self::ConfigureNak,
            4 => Self::ConfigureReject,
            5 => Self::TerminateRequest,
            6 => Self::TerminateAck,
            7 => Self::CodeReject,
            8 => Self::ProtocolReject,
            9 => Self::EchoRequest,
            10 => Self::EchoReply,
            11 => Self::DiscardRequest,
            other => Self::Unknown(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::ConfigureRequest => 1,
            Self::ConfigureAck => 2,
            Self::ConfigureNak => 3,
            Self::ConfigureReject => 4,
            Self::TerminateRequest => 5,
            Self::TerminateAck => 6,
            Self::CodeReject => 7,
            Self::ProtocolReject => 8,
            Self::EchoRequest => 9,
            Self::EchoReply => 10,
            Self::DiscardRequest => 11,
            Self::Unknown(v) => v,
        }
    }
}

/// LCP configuration options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LcpOption {
    /// Maximum Receive Unit (type 1, length 4).
    Mru(u16),
    /// Magic Number for loop detection (type 5, length 6).
    MagicNumber(u32),
    /// Protocol Field Compression (type 7, length 2). Always rejected for FortiGate.
    ProtocolFieldCompression,
    /// Address-and-Control Field Compression (type 8, length 2). Always rejected for FortiGate.
    AddressControlFieldCompression,
    /// Unknown option preserved for round-tripping.
    Unknown { option_type: u8, data: Vec<u8> },
}

impl LcpOption {
    /// Returns true if this option must be rejected (FortiGate requires no compression).
    pub fn is_rejectable(&self) -> bool {
        matches!(
            self,
            LcpOption::ProtocolFieldCompression | LcpOption::AddressControlFieldCompression
        )
    }

    /// Encode this option into its wire representation.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            LcpOption::Mru(mru) => {
                let mut buf = vec![0x01, 0x04];
                buf.extend_from_slice(&mru.to_be_bytes());
                buf
            }
            LcpOption::MagicNumber(magic) => {
                let mut buf = vec![0x05, 0x06];
                buf.extend_from_slice(&magic.to_be_bytes());
                buf
            }
            LcpOption::ProtocolFieldCompression => {
                vec![0x07, 0x02]
            }
            LcpOption::AddressControlFieldCompression => {
                vec![0x08, 0x02]
            }
            LcpOption::Unknown { option_type, data } => {
                let mut buf = vec![*option_type, (2 + data.len()) as u8];
                buf.extend_from_slice(data);
                buf
            }
        }
    }

    /// Decode a single option from a byte slice, returning the option and bytes consumed.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 2 {
            return Err(FortiError::ProtocolError(
                "LCP option too short, need at least 2 bytes".into(),
            ));
        }
        let option_type = buf[0];
        let length = buf[1] as usize;
        if length < 2 || buf.len() < length {
            return Err(FortiError::ProtocolError(format!(
                "LCP option type {} has invalid length {}",
                option_type, length
            )));
        }

        let option = match option_type {
            0x01 => {
                if length != 4 {
                    return Err(FortiError::ProtocolError(format!(
                        "MRU option must be 4 bytes, got {}",
                        length
                    )));
                }
                let mru = u16::from_be_bytes([buf[2], buf[3]]);
                LcpOption::Mru(mru)
            }
            0x05 => {
                if length != 6 {
                    return Err(FortiError::ProtocolError(format!(
                        "Magic-Number option must be 6 bytes, got {}",
                        length
                    )));
                }
                let magic = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
                LcpOption::MagicNumber(magic)
            }
            0x07 => LcpOption::ProtocolFieldCompression,
            0x08 => LcpOption::AddressControlFieldCompression,
            _ => LcpOption::Unknown {
                option_type,
                data: buf[2..length].to_vec(),
            },
        };

        Ok((option, length))
    }
}

/// An LCP packet (code + identifier + length + body).
#[derive(Debug, Clone)]
pub struct LcpPacket {
    code: LcpCode,
    identifier: u8,
    options: Vec<LcpOption>,
    /// Raw data payload for Echo/Discard/Terminate packets (not parsed as options).
    raw_data: Vec<u8>,
}

impl LcpPacket {
    /// Create a new LCP packet with options (for Configure-Request/Ack/Nak/Reject).
    pub fn new(code: LcpCode, identifier: u8, options: Vec<LcpOption>) -> Self {
        Self {
            code,
            identifier,
            options,
            raw_data: Vec::new(),
        }
    }

    /// Create a new LCP packet with raw data (for Echo/Discard/Terminate).
    pub fn new_raw(code: LcpCode, identifier: u8, raw_data: Vec<u8>) -> Self {
        Self {
            code,
            identifier,
            options: Vec::new(),
            raw_data,
        }
    }

    pub fn code(&self) -> LcpCode {
        self.code
    }

    pub fn identifier(&self) -> u8 {
        self.identifier
    }

    pub fn options(&self) -> &[LcpOption] {
        &self.options
    }

    pub fn raw_data(&self) -> &[u8] {
        &self.raw_data
    }

    /// Returns true if this code type uses raw_data instead of parsed options.
    fn is_raw_body_code(code: LcpCode) -> bool {
        matches!(
            code,
            LcpCode::EchoRequest
                | LcpCode::EchoReply
                | LcpCode::DiscardRequest
                | LcpCode::TerminateRequest
                | LcpCode::TerminateAck
        )
    }

    /// Encode the packet to wire format.
    pub fn encode(&self) -> Vec<u8> {
        let body = if Self::is_raw_body_code(self.code) {
            self.raw_data.clone()
        } else {
            let mut buf = Vec::new();
            for opt in &self.options {
                buf.extend_from_slice(&opt.encode());
            }
            buf
        };

        // Total length = 4 (header) + body length
        let length = (4 + body.len()) as u16;
        let mut pkt = Vec::with_capacity(length as usize);
        pkt.push(self.code.to_u8());
        pkt.push(self.identifier);
        pkt.extend_from_slice(&length.to_be_bytes());
        pkt.extend_from_slice(&body);
        pkt
    }

    /// Decode a packet from wire format.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(FortiError::ProtocolError(
                "LCP packet too short, need at least 4 bytes".into(),
            ));
        }

        let code = LcpCode::from_u8(buf[0]);
        let identifier = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;

        if length < 4 || buf.len() < length {
            return Err(FortiError::ProtocolError(format!(
                "LCP packet length {} is invalid (buf len {})",
                length,
                buf.len()
            )));
        }

        let body = &buf[4..length];

        if Self::is_raw_body_code(code) {
            Ok(Self {
                code,
                identifier,
                options: Vec::new(),
                raw_data: body.to_vec(),
            })
        } else {
            let mut options = Vec::new();
            let mut offset = 0;
            while offset < body.len() {
                let (opt, consumed) = LcpOption::decode(&body[offset..])?;
                options.push(opt);
                offset += consumed;
            }
            Ok(Self {
                code,
                identifier,
                options,
                raw_data: Vec::new(),
            })
        }
    }
}

/// LCP state machine for negotiating link parameters with FortiGate.
pub struct LcpState {
    our_mru: u16,
    our_magic: u32,
    peer_magic: Option<u32>,
    next_identifier: u8,
}

impl LcpState {
    /// Create a new LCP state with the given MRU and a random magic number.
    pub fn new(mru: u16) -> Self {
        Self {
            our_mru: mru,
            our_magic: rand::random(),
            peer_magic: None,
            next_identifier: 1,
        }
    }

    /// Set the peer's magic number (for testing or after learning it from a Configure-Request).
    pub fn set_peer_magic(&mut self, magic: u32) {
        self.peer_magic = Some(magic);
    }

    /// Get our magic number.
    pub fn our_magic(&self) -> u32 {
        self.our_magic
    }

    /// Allocate and return the next identifier.
    fn next_id(&mut self) -> u8 {
        let id = self.next_identifier;
        self.next_identifier = self.next_identifier.wrapping_add(1);
        id
    }

    /// Build our initial Configure-Request with MRU and Magic-Number.
    pub fn build_configure_request(&self) -> Vec<u8> {
        let pkt = LcpPacket::new(
            LcpCode::ConfigureRequest,
            self.next_identifier,
            vec![
                LcpOption::Mru(self.our_mru),
                LcpOption::MagicNumber(self.our_magic),
            ],
        );
        pkt.encode()
    }

    /// Build an Echo-Request with our magic number.
    pub fn build_echo_request(&mut self) -> Vec<u8> {
        let id = self.next_id();
        let pkt = LcpPacket::new_raw(
            LcpCode::EchoRequest,
            id,
            self.our_magic.to_be_bytes().to_vec(),
        );
        pkt.encode()
    }

    /// Handle an incoming LCP packet. Returns zero or more response packets to send.
    pub fn handle_packet(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let pkt = match LcpPacket::decode(data) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };

        match pkt.code() {
            LcpCode::ConfigureRequest => self.handle_configure_request(&pkt),
            LcpCode::ConfigureAck => {
                // Our request was accepted; nothing to send back.
                Vec::new()
            }
            LcpCode::ConfigureNak => {
                // Server wants different values; we could re-negotiate but for now ignore.
                Vec::new()
            }
            LcpCode::ConfigureReject => {
                // Server rejected some of our options; we could re-negotiate.
                Vec::new()
            }
            LcpCode::EchoRequest => self.handle_echo_request(&pkt),
            LcpCode::TerminateRequest => {
                let reply = LcpPacket::new_raw(
                    LcpCode::TerminateAck,
                    pkt.identifier(),
                    Vec::new(),
                );
                vec![reply.encode()]
            }
            _ => Vec::new(),
        }
    }

    /// Handle a Configure-Request from the peer.
    /// Splits options into acceptable and rejectable. If any are rejectable, sends
    /// ConfigureReject with just those. Otherwise sends ConfigureAck.
    fn handle_configure_request(&mut self, pkt: &LcpPacket) -> Vec<Vec<u8>> {
        let mut rejected = Vec::new();
        let mut acceptable = Vec::new();

        for opt in pkt.options() {
            if opt.is_rejectable() {
                rejected.push(opt.clone());
            } else {
                acceptable.push(opt.clone());
                // Remember peer's magic number
                if let LcpOption::MagicNumber(magic) = opt {
                    self.peer_magic = Some(*magic);
                }
            }
        }

        if !rejected.is_empty() {
            let reject = LcpPacket::new(
                LcpCode::ConfigureReject,
                pkt.identifier(),
                rejected,
            );
            vec![reject.encode()]
        } else {
            let ack = LcpPacket::new(
                LcpCode::ConfigureAck,
                pkt.identifier(),
                acceptable,
            );
            vec![ack.encode()]
        }
    }

    /// Handle an Echo-Request from the peer. Responds with Echo-Reply using our magic.
    fn handle_echo_request(&self, pkt: &LcpPacket) -> Vec<Vec<u8>> {
        let reply = LcpPacket::new_raw(
            LcpCode::EchoReply,
            pkt.identifier(),
            self.our_magic.to_be_bytes().to_vec(),
        );
        vec![reply.encode()]
    }
}
