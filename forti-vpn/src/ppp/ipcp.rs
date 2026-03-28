use crate::error::{FortiError, Result};
use std::net::Ipv4Addr;
use tracing::debug;

// ---------------------------------------------------------------------------
// IpcpCode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcpCode {
    ConfigureRequest,
    ConfigureAck,
    ConfigureNak,
    ConfigureReject,
    Unknown(u8),
}

impl IpcpCode {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::ConfigureRequest,
            2 => Self::ConfigureAck,
            3 => Self::ConfigureNak,
            4 => Self::ConfigureReject,
            other => Self::Unknown(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::ConfigureRequest => 1,
            Self::ConfigureAck => 2,
            Self::ConfigureNak => 3,
            Self::ConfigureReject => 4,
            Self::Unknown(v) => v,
        }
    }
}

// ---------------------------------------------------------------------------
// IpcpOption
// ---------------------------------------------------------------------------

/// IPCP configuration option (RFC 1332 + vendor extensions for DNS/NBNS).
///
/// Each option is encoded as: `[type:u8][length:u8=6][addr:4 bytes]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcpOption {
    /// Option type 3 — negotiated IPv4 address
    IpAddress(Ipv4Addr),
    /// Option type 0x81 (129) — primary DNS server
    PrimaryDns(Ipv4Addr),
    /// Option type 0x82 (130) — secondary DNS server
    SecondaryDns(Ipv4Addr),
    /// Option type 0x83 (131) — primary NBNS server
    PrimaryNbns(Ipv4Addr),
    /// Option type 0x84 (132) — secondary NBNS server
    SecondaryNbns(Ipv4Addr),
    /// Any unrecognised option (type + raw data, excluding type/length bytes)
    Unknown { option_type: u8, data: Vec<u8> },
}

impl IpcpOption {
    /// Encode a single option into its wire representation.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::IpAddress(addr) => Self::encode_addr(3, addr),
            Self::PrimaryDns(addr) => Self::encode_addr(0x81, addr),
            Self::SecondaryDns(addr) => Self::encode_addr(0x82, addr),
            Self::PrimaryNbns(addr) => Self::encode_addr(0x83, addr),
            Self::SecondaryNbns(addr) => Self::encode_addr(0x84, addr),
            Self::Unknown { option_type, data } => {
                let len = 2 + data.len() as u8;
                let mut buf = Vec::with_capacity(len as usize);
                buf.push(*option_type);
                buf.push(len);
                buf.extend_from_slice(data);
                buf
            }
        }
    }

    fn encode_addr(opt_type: u8, addr: &Ipv4Addr) -> Vec<u8> {
        let octets = addr.octets();
        vec![opt_type, 6, octets[0], octets[1], octets[2], octets[3]]
    }

    /// Decode options from raw bytes (the options portion of an IPCP packet,
    /// i.e. everything after the 4-byte code/id/length header).
    pub fn decode_all(mut buf: &[u8]) -> Result<Vec<Self>> {
        let mut opts = Vec::new();
        while buf.len() >= 2 {
            let opt_type = buf[0];
            let opt_len = buf[1] as usize;
            if opt_len < 2 || opt_len > buf.len() {
                return Err(FortiError::ProtocolError(format!(
                    "IPCP option type {} has invalid length {}",
                    opt_type, opt_len
                )));
            }
            let opt = match opt_type {
                3 | 0x81 | 0x82 | 0x83 | 0x84 if opt_len == 6 => {
                    let addr = Ipv4Addr::new(buf[2], buf[3], buf[4], buf[5]);
                    match opt_type {
                        3 => Self::IpAddress(addr),
                        0x81 => Self::PrimaryDns(addr),
                        0x82 => Self::SecondaryDns(addr),
                        0x83 => Self::PrimaryNbns(addr),
                        0x84 => Self::SecondaryNbns(addr),
                        _ => unreachable!(),
                    }
                }
                _ => Self::Unknown {
                    option_type: opt_type,
                    data: buf[2..opt_len].to_vec(),
                },
            };
            opts.push(opt);
            buf = &buf[opt_len..];
        }
        Ok(opts)
    }
}

// ---------------------------------------------------------------------------
// IpcpPacket
// ---------------------------------------------------------------------------

/// A decoded IPCP packet (code + identifier + options).
#[derive(Debug, Clone)]
pub struct IpcpPacket {
    code: IpcpCode,
    identifier: u8,
    options: Vec<IpcpOption>,
}

impl IpcpPacket {
    pub fn new(code: IpcpCode, identifier: u8, options: Vec<IpcpOption>) -> Self {
        Self {
            code,
            identifier,
            options,
        }
    }

    pub fn code(&self) -> IpcpCode {
        self.code
    }

    pub fn identifier(&self) -> u8 {
        self.identifier
    }

    pub fn options(&self) -> &[IpcpOption] {
        &self.options
    }

    /// Decode an IPCP packet from raw bytes (starting at the code byte).
    ///
    /// Wire format: `[code:u8][identifier:u8][length:BE16][options...]`
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(FortiError::ProtocolError(
                "IPCP packet too short, need at least 4 bytes".into(),
            ));
        }
        let code = IpcpCode::from_u8(buf[0]);
        let identifier = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if length < 4 || length > buf.len() {
            return Err(FortiError::ProtocolError(format!(
                "IPCP packet length {} invalid (buf len {})",
                length,
                buf.len()
            )));
        }
        let options = IpcpOption::decode_all(&buf[4..length])?;
        Ok(Self {
            code,
            identifier,
            options,
        })
    }

    /// Encode this packet to its wire representation.
    pub fn encode(&self) -> Vec<u8> {
        let mut opts_buf = Vec::new();
        for opt in &self.options {
            opts_buf.extend_from_slice(&opt.encode());
        }
        let length = (4 + opts_buf.len()) as u16;
        let mut buf = Vec::with_capacity(length as usize);
        buf.push(self.code.to_u8());
        buf.push(self.identifier);
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&opts_buf);
        buf
    }
}

// ---------------------------------------------------------------------------
// IpcpConfig — final negotiated configuration
// ---------------------------------------------------------------------------

/// The result of a successful IPCP negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcpConfig {
    pub ip_address: Ipv4Addr,
    pub primary_dns: Option<Ipv4Addr>,
    pub secondary_dns: Option<Ipv4Addr>,
    pub primary_nbns: Option<Ipv4Addr>,
    pub secondary_nbns: Option<Ipv4Addr>,
}

// ---------------------------------------------------------------------------
// IpcpState — negotiation state machine
// ---------------------------------------------------------------------------

/// Tracks the client-side IPCP negotiation state.
///
/// Typical flow:
/// 1. Client sends `ConfigureRequest` with all-zero addresses.
/// 2. Server replies `ConfigureNak` with assigned addresses.
/// 3. Client re-sends `ConfigureRequest` with the assigned addresses.
/// 4. Server replies `ConfigureAck` — negotiation complete.
///
/// The server may also send its own `ConfigureRequest`; we always ACK it.
pub struct IpcpState {
    ip_address: Ipv4Addr,
    primary_dns: Option<Ipv4Addr>,
    secondary_dns: Option<Ipv4Addr>,
    primary_nbns: Option<Ipv4Addr>,
    secondary_nbns: Option<Ipv4Addr>,
    negotiation_complete: bool,
    next_identifier: u8,
}

impl IpcpState {
    pub fn new() -> Self {
        Self {
            ip_address: Ipv4Addr::UNSPECIFIED,
            primary_dns: None,
            secondary_dns: None,
            primary_nbns: None,
            secondary_nbns: None,
            negotiation_complete: false,
            next_identifier: 1,
        }
    }

    /// Build the initial Configure-Request with all-zero addresses to solicit
    /// address assignment from the server.
    pub fn build_configure_request(&self) -> Vec<u8> {
        let options = vec![
            IpcpOption::IpAddress(self.ip_address),
            IpcpOption::PrimaryDns(self.primary_dns.unwrap_or(Ipv4Addr::UNSPECIFIED)),
            IpcpOption::SecondaryDns(self.secondary_dns.unwrap_or(Ipv4Addr::UNSPECIFIED)),
        ];
        let pkt = IpcpPacket::new(IpcpCode::ConfigureRequest, self.next_identifier, options);
        pkt.encode()
    }

    /// Process an incoming IPCP packet and return zero or more response packets.
    pub fn handle_packet(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let pkt = match IpcpPacket::decode(data) {
            Ok(p) => p,
            Err(e) => {
                debug!("failed to decode IPCP packet: {}", e);
                return vec![];
            }
        };

        match pkt.code() {
            IpcpCode::ConfigureRequest => {
                // Server is requesting its own configuration — ACK it.
                debug!(
                    "IPCP: received ConfigureRequest (id={}), sending ACK",
                    pkt.identifier()
                );
                let ack = IpcpPacket::new(
                    IpcpCode::ConfigureAck,
                    pkt.identifier(),
                    pkt.options().to_vec(),
                );
                vec![ack.encode()]
            }
            IpcpCode::ConfigureNak => {
                // Server is telling us what addresses to use.
                debug!("IPCP: received ConfigureNak, updating addresses");
                for opt in pkt.options() {
                    match opt {
                        IpcpOption::IpAddress(addr) => self.ip_address = *addr,
                        IpcpOption::PrimaryDns(addr) => self.primary_dns = Some(*addr),
                        IpcpOption::SecondaryDns(addr) => self.secondary_dns = Some(*addr),
                        IpcpOption::PrimaryNbns(addr) => self.primary_nbns = Some(*addr),
                        IpcpOption::SecondaryNbns(addr) => self.secondary_nbns = Some(*addr),
                        IpcpOption::Unknown { .. } => {}
                    }
                }
                // Re-send ConfigureRequest with the assigned values.
                self.next_identifier = self.next_identifier.wrapping_add(1);
                let req = self.build_configure_request();
                vec![req]
            }
            IpcpCode::ConfigureAck => {
                debug!("IPCP: received ConfigureAck — negotiation complete");
                self.negotiation_complete = true;
                vec![]
            }
            IpcpCode::ConfigureReject => {
                debug!("IPCP: received ConfigureReject — ignoring for now");
                vec![]
            }
            IpcpCode::Unknown(code) => {
                debug!("IPCP: received unknown code {}", code);
                vec![]
            }
        }
    }

    /// Returns the negotiated configuration if the IP address has been
    /// assigned (non-zero), regardless of whether the ACK has been received.
    pub fn config(&self) -> Option<IpcpConfig> {
        if self.ip_address.is_unspecified() {
            return None;
        }
        Some(IpcpConfig {
            ip_address: self.ip_address,
            primary_dns: self.primary_dns,
            secondary_dns: self.secondary_dns,
            primary_nbns: self.primary_nbns,
            secondary_nbns: self.secondary_nbns,
        })
    }

    /// Whether the negotiation has completed (ACK received).
    pub fn is_complete(&self) -> bool {
        self.negotiation_complete
    }
}

impl Default for IpcpState {
    fn default() -> Self {
        Self::new()
    }
}
