use crate::error::{FortiError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PppProtocol {
    Lcp,
    Ipcp,
    Ip6cp,
    Ccp,
    Ipv4,
    Ipv6,
    Unknown(u16),
}

impl PppProtocol {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0xC021 => Self::Lcp,
            0x8021 => Self::Ipcp,
            0x8057 => Self::Ip6cp,
            0x80FD => Self::Ccp,
            0x0021 => Self::Ipv4,
            0x0057 => Self::Ipv6,
            other => Self::Unknown(other),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Self::Lcp => 0xC021,
            Self::Ipcp => 0x8021,
            Self::Ip6cp => 0x8057,
            Self::Ccp => 0x80FD,
            Self::Ipv4 => 0x0021,
            Self::Ipv6 => 0x0057,
            Self::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PppFrame {
    protocol: PppProtocol,
    data: Vec<u8>,
}

impl PppFrame {
    pub fn new(protocol: PppProtocol, data: Vec<u8>) -> Self {
        Self { protocol, data }
    }

    pub fn protocol(&self) -> PppProtocol {
        self.protocol
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    pub fn encode(&self) -> Vec<u8> {
        let proto_bytes = self.protocol.to_u16().to_be_bytes();
        let mut buf = Vec::with_capacity(4 + self.data.len());
        buf.push(0xFF);
        buf.push(0x03);
        buf.extend_from_slice(&proto_bytes);
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(FortiError::ProtocolError(
                "PPP frame too short, need at least 4 bytes".into(),
            ));
        }
        if buf[0] != 0xFF || buf[1] != 0x03 {
            return Err(FortiError::ProtocolError(format!(
                "invalid PPP address/control: {:02X}{:02X}, expected FF03",
                buf[0], buf[1]
            )));
        }
        let protocol = PppProtocol::from_u16(u16::from_be_bytes([buf[2], buf[3]]));
        let data = buf[4..].to_vec();
        Ok(Self { protocol, data })
    }
}
