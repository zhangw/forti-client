# FortiVPN Rust Client — Phase 1: Feasibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the three hardest components work end-to-end: PPP codec, HTTP authentication, and TLS tunnel upgrade — culminating in a CLI that can authenticate to a FortiGate, establish a PPP-over-TLS tunnel, and complete IP negotiation.

**Architecture:** A Rust binary (`forti-vpn`) structured as a library + CLI. The PPP engine is a standalone module with no network dependencies (testable in isolation). The auth module handles HTTP login and cookie extraction. The tunnel module upgrades the HTTP connection to raw TLS and bridges it with the PPP engine. Phase 1 does NOT include TUN device, DNS, routes, or SAML — those are Phase 2/3.

**Tech Stack:** Rust 2021 edition, tokio 1.x, hyper 1.8, rustls 0.23, tokio-rustls 0.26, clap 4.6, serde 1.0, tracing 0.1, bytes 1.x

**Spec Reference:** `docs/superpowers/specs/2026-03-28-rust-fortigate-vpn-client-design.md`

**Wire Protocol Reference:** `docs/fortigate_sslvpn_wire_protocol.md`

---

## File Structure

```
forti-vpn/
├── Cargo.toml
├── src/
│   ├── main.rs              # CLI entry point, tokio bootstrap
│   ├── lib.rs               # Re-exports for library use
│   ├── config.rs            # CLI args via clap (minimal for phase 1)
│   ├── error.rs             # Error types (thiserror)
│   ├── auth/
│   │   ├── mod.rs           # Auth trait + credential auth implementation
│   │   └── xml.rs           # Tunnel config XML parser
│   ├── tunnel/
│   │   ├── mod.rs           # Transport trait + TLS tunnel implementation
│   │   └── codec.rs         # Fortinet wire frame codec (6-byte header)
│   └── ppp/
│       ├── mod.rs           # PPP engine public API + frame types
│       ├── codec.rs         # PPP frame encode/decode (FF 03 + protocol)
│       ├── lcp.rs           # LCP state machine (MRU, Magic, Echo)
│       └── ipcp.rs          # IPCP negotiation (IPv4 + DNS assignment)
└── tests/
    ├── ppp_codec_test.rs    # PPP frame encode/decode tests
    ├── lcp_test.rs          # LCP negotiation tests
    ├── ipcp_test.rs         # IPCP negotiation tests
    └── fortinet_codec_test.rs  # Fortinet wire frame tests
```

---

### Task 1: Project Scaffold

**Files:**
- Create: `forti-vpn/Cargo.toml`
- Create: `forti-vpn/src/main.rs`
- Create: `forti-vpn/src/lib.rs`
- Create: `forti-vpn/src/error.rs`

- [ ] **Step 1: Create project directory and Cargo.toml**

```bash
mkdir -p forti-vpn/src
```

Create `forti-vpn/Cargo.toml`:

```toml
[package]
name = "forti-vpn"
version = "0.1.0"
edition = "2021"
description = "A Rust CLI client for FortiGate SSL VPN"

[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# TLS
rustls = "0.23"
tokio-rustls = "0.26"
rustls-pemfile = "2"
webpki-roots = "0.26"

# HTTP (auth + tunnel upgrade)
hyper = { version = "1", features = ["http1", "client"] }
hyper-util = { version = "0.1", features = ["tokio", "http1"] }
http = "1"
http-body-util = "0.1"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# CLI
clap = { version = "4", features = ["derive"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Error handling
thiserror = "2"
anyhow = "1"

# Utilities
bytes = "1"
rand = "0.8"

[dev-dependencies]
tokio-test = "0.4"
```

- [ ] **Step 2: Create error.rs**

Create `forti-vpn/src/error.rs`:

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FortiError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("tunnel error: {0}")]
    TunnelError(String),

    #[error("PPP negotiation failed: {0}")]
    PppError(String),

    #[error("protocol error: {0}")]
    ProtocolError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
}

pub type Result<T> = std::result::Result<T, FortiError>;
```

- [ ] **Step 3: Create lib.rs**

Create `forti-vpn/src/lib.rs`:

```rust
pub mod error;
pub mod ppp;
pub mod auth;
pub mod tunnel;
```

- [ ] **Step 4: Create main.rs**

Create `forti-vpn/src/main.rs`:

```rust
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "forti-vpn", about = "FortiGate SSL VPN client")]
struct Cli {
    /// VPN gateway hostname or IP
    #[arg(short, long)]
    server: String,

    /// VPN gateway port
    #[arg(short, long, default_value = "443")]
    port: u16,

    /// Username
    #[arg(short, long)]
    username: String,

    /// Password (if omitted, will prompt)
    #[arg(short = 'P', long)]
    password: Option<String>,

    /// Realm (optional)
    #[arg(long)]
    realm: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    tracing::info!("Connecting to {}:{}", cli.server, cli.port);

    // Phase 1: auth → tunnel → PPP negotiation
    // Implementation follows in subsequent tasks

    Ok(())
}
```

- [ ] **Step 5: Verify it builds**

Run: `cd forti-vpn && cargo build 2>&1`
Expected: Compiles successfully with no errors.

- [ ] **Step 6: Commit**

```bash
git add forti-vpn/
git commit -m "feat: scaffold forti-vpn Rust project with dependencies"
```

---

### Task 2: Fortinet Wire Frame Codec

The Fortinet header wraps every PPP frame on the TLS connection. This is the lowest-level codec and has zero external dependencies — pure bytes in, bytes out.

**Wire format (spec section 2.4):**
```
[total_len:BE16] [0x50 0x50] [payload_len:BE16] [PPP payload...]
```

**Files:**
- Create: `forti-vpn/src/tunnel/mod.rs`
- Create: `forti-vpn/src/tunnel/codec.rs`
- Create: `forti-vpn/tests/fortinet_codec_test.rs`

- [ ] **Step 1: Write failing tests for Fortinet frame encode/decode**

Create `forti-vpn/tests/fortinet_codec_test.rs`:

```rust
use forti_vpn::tunnel::codec::{FortinetFrame, FortinetCodec};

#[test]
fn test_encode_fortinet_frame() {
    // A PPP frame: FF 03 00 21 + 4 bytes of "IP data"
    let ppp_payload = vec![0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14];

    let frame = FortinetFrame::new(ppp_payload.clone());
    let encoded = frame.encode();

    // total_len = payload_len + 6 = 8 + 6 = 14
    // Wire: [00 0E] [50 50] [00 08] [FF 03 00 21 45 00 00 14]
    assert_eq!(encoded[0..2], [0x00, 0x0E]); // total_len = 14
    assert_eq!(encoded[2..4], [0x50, 0x50]); // magic
    assert_eq!(encoded[4..6], [0x00, 0x08]); // payload_len = 8
    assert_eq!(encoded[6..], ppp_payload[..]);
}

#[test]
fn test_decode_fortinet_frame() {
    let wire = vec![
        0x00, 0x0E, // total_len = 14
        0x50, 0x50, // magic
        0x00, 0x08, // payload_len = 8
        0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14, // PPP payload
    ];

    let frame = FortinetFrame::decode(&wire).unwrap();
    assert_eq!(frame.payload(), &[0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14]);
}

#[test]
fn test_decode_invalid_magic() {
    let wire = vec![
        0x00, 0x0A, // total_len
        0x51, 0x50, // wrong magic
        0x00, 0x04, // payload_len
        0xFF, 0x03, 0x00, 0x21,
    ];

    assert!(FortinetFrame::decode(&wire).is_err());
}

#[test]
fn test_decode_truncated_frame() {
    let wire = vec![0x00, 0x0E, 0x50, 0x50]; // only 4 bytes, need at least 6 + payload
    assert!(FortinetFrame::decode(&wire).is_err());
}

#[test]
fn test_codec_extract_frame_from_stream() {
    // Simulate a stream buffer with one complete frame and a partial second frame
    let mut buf = vec![
        // Frame 1: complete
        0x00, 0x0A, 0x50, 0x50, 0x00, 0x04, 0xFF, 0x03, 0x00, 0x21,
        // Frame 2: partial (only header, missing payload)
        0x00, 0x0E, 0x50, 0x50,
    ];

    let mut codec = FortinetCodec::new();

    let frame1 = codec.try_decode(&mut buf);
    assert!(frame1.is_some());
    assert_eq!(frame1.unwrap().payload(), &[0xFF, 0x03, 0x00, 0x21]);

    // Second call should return None (incomplete frame)
    let frame2 = codec.try_decode(&mut buf);
    assert!(frame2.is_none());
}

#[test]
fn test_encode_empty_payload() {
    // Keepalive / zero-length frames
    let frame = FortinetFrame::new(vec![]);
    let encoded = frame.encode();
    assert_eq!(encoded, vec![0x00, 0x06, 0x50, 0x50, 0x00, 0x00]);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd forti-vpn && cargo test --test fortinet_codec_test 2>&1`
Expected: Compilation error — `tunnel::codec` module doesn't exist yet.

- [ ] **Step 3: Implement tunnel/mod.rs stub**

Create `forti-vpn/src/tunnel/mod.rs`:

```rust
pub mod codec;
```

- [ ] **Step 4: Implement Fortinet wire frame codec**

Create `forti-vpn/src/tunnel/codec.rs`:

```rust
use crate::error::{FortiError, Result};

const FORTINET_MAGIC: [u8; 2] = [0x50, 0x50];
const HEADER_LEN: usize = 6;

/// A decoded Fortinet wire frame containing a PPP payload.
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

    /// Encode into wire format: [total_len:BE16][0x5050][payload_len:BE16][payload]
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

    /// Decode from a complete wire frame buffer.
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

        let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;

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

/// Streaming codec that extracts complete Fortinet frames from a byte buffer.
///
/// Call `try_decode` repeatedly with a mutable buffer. It will consume complete
/// frames and leave incomplete data in the buffer for the next read.
pub struct FortinetCodec;

impl FortinetCodec {
    pub fn new() -> Self {
        Self
    }

    /// Try to extract one complete frame from the front of `buf`.
    /// On success, the consumed bytes are drained from `buf`.
    /// Returns `None` if the buffer doesn't contain a complete frame.
    pub fn try_decode(&mut self, buf: &mut Vec<u8>) -> Option<FortinetFrame> {
        if buf.len() < HEADER_LEN {
            return None;
        }

        // Validate magic before reading length
        if buf[2..4] != FORTINET_MAGIC {
            // Protocol desync — caller should handle this
            return None;
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd forti-vpn && cargo test --test fortinet_codec_test 2>&1`
Expected: All 6 tests pass.

- [ ] **Step 6: Commit**

```bash
cd forti-vpn && git add src/tunnel/ tests/fortinet_codec_test.rs
git commit -m "feat: implement Fortinet wire frame codec with streaming decoder"
```

---

### Task 3: PPP Frame Codec

The PPP frame sits inside the Fortinet payload. Every PPP frame has a 4-byte header: `[FF][03][protocol:BE16]`, followed by the protocol-specific data.

**Files:**
- Create: `forti-vpn/src/ppp/mod.rs`
- Create: `forti-vpn/src/ppp/codec.rs`
- Create: `forti-vpn/tests/ppp_codec_test.rs`

- [ ] **Step 1: Write failing tests for PPP frame codec**

Create `forti-vpn/tests/ppp_codec_test.rs`:

```rust
use forti_vpn::ppp::codec::{PppFrame, PppProtocol};

#[test]
fn test_ppp_protocol_values() {
    assert_eq!(PppProtocol::Lcp as u16, 0xC021);
    assert_eq!(PppProtocol::Ipcp as u16, 0x8021);
    assert_eq!(PppProtocol::Ipv4 as u16, 0x0021);
    assert_eq!(PppProtocol::Ip6cp as u16, 0x8057);
    assert_eq!(PppProtocol::Ipv6 as u16, 0x0057);
    assert_eq!(PppProtocol::Ccp as u16, 0x80FD);
}

#[test]
fn test_encode_ipv4_data_frame() {
    let ip_packet = vec![0x45, 0x00, 0x00, 0x14]; // minimal IP header
    let frame = PppFrame::new(PppProtocol::Ipv4, ip_packet.clone());
    let encoded = frame.encode();

    assert_eq!(encoded[0], 0xFF); // address
    assert_eq!(encoded[1], 0x03); // control
    assert_eq!(encoded[2..4], [0x00, 0x21]); // protocol
    assert_eq!(encoded[4..], ip_packet[..]);
}

#[test]
fn test_decode_lcp_frame() {
    let wire = vec![
        0xFF, 0x03, // address, control
        0xC0, 0x21, // LCP protocol
        0x01,       // Configure-Request code
        0x01,       // identifier
        0x00, 0x08, // length = 8
        0x01, 0x04, 0x05, 0xDC, // MRU option: type=1, len=4, value=1500
    ];

    let frame = PppFrame::decode(&wire).unwrap();
    assert_eq!(frame.protocol(), PppProtocol::Lcp);
    assert_eq!(frame.data(), &[0x01, 0x01, 0x00, 0x08, 0x01, 0x04, 0x05, 0xDC]);
}

#[test]
fn test_decode_unknown_protocol() {
    let wire = vec![0xFF, 0x03, 0xAA, 0xBB, 0x01, 0x02];
    let frame = PppFrame::decode(&wire).unwrap();
    assert_eq!(frame.protocol(), PppProtocol::Unknown(0xAABB));
    assert_eq!(frame.data(), &[0x01, 0x02]);
}

#[test]
fn test_decode_invalid_address_control() {
    // Wrong address byte
    let wire = vec![0xFE, 0x03, 0x00, 0x21, 0x45];
    assert!(PppFrame::decode(&wire).is_err());
}

#[test]
fn test_decode_too_short() {
    let wire = vec![0xFF, 0x03]; // only 2 bytes, need at least 4
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd forti-vpn && cargo test --test ppp_codec_test 2>&1`
Expected: Compilation error — `ppp::codec` module doesn't exist yet.

- [ ] **Step 3: Implement PPP frame types and codec**

Create `forti-vpn/src/ppp/mod.rs`:

```rust
pub mod codec;
pub mod lcp;
pub mod ipcp;
```

Create `forti-vpn/src/ppp/codec.rs`:

```rust
use crate::error::{FortiError, Result};

/// PPP protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PppProtocol {
    Lcp,         // 0xC021 - Link Control Protocol
    Ipcp,        // 0x8021 - IP Control Protocol
    Ip6cp,       // 0x8057 - IPv6 Control Protocol
    Ccp,         // 0x80FD - Compression Control Protocol
    Ipv4,        // 0x0021 - IPv4 data
    Ipv6,        // 0x0057 - IPv6 data
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

/// A decoded PPP frame with protocol and data payload.
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

    /// Encode to wire format: [FF][03][protocol:BE16][data...]
    pub fn encode(&self) -> Vec<u8> {
        let proto_bytes = self.protocol.to_u16().to_be_bytes();
        let mut buf = Vec::with_capacity(4 + self.data.len());
        buf.push(0xFF); // address
        buf.push(0x03); // control
        buf.extend_from_slice(&proto_bytes);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode from wire bytes: [FF][03][protocol:BE16][data...]
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd forti-vpn && cargo test --test ppp_codec_test 2>&1`
Expected: All 7 tests pass.

- [ ] **Step 5: Commit**

```bash
cd forti-vpn && git add src/ppp/ tests/ppp_codec_test.rs
git commit -m "feat: implement PPP frame codec with protocol type parsing"
```

---

### Task 4: LCP State Machine

LCP (Link Control Protocol, RFC 1661) negotiates link parameters. For FortiGate, we need:
- Send Configure-Request with MRU and Magic-Number
- Handle server's Configure-Request: accept MRU and Magic-Number, reject PFCOMP and ACCOMP
- Echo-Request/Reply for keepalive

**LCP packet format:** `[code:u8][identifier:u8][length:BE16][options...]`

**Files:**
- Create: `forti-vpn/src/ppp/lcp.rs`
- Create: `forti-vpn/tests/lcp_test.rs`

- [ ] **Step 1: Write failing tests for LCP**

Create `forti-vpn/tests/lcp_test.rs`:

```rust
use forti_vpn::ppp::lcp::{LcpPacket, LcpCode, LcpOption, LcpState};
use forti_vpn::ppp::codec::PppProtocol;

#[test]
fn test_encode_configure_request_mru_magic() {
    let options = vec![
        LcpOption::Mru(1500),
        LcpOption::MagicNumber(0xDEADBEEF),
    ];
    let pkt = LcpPacket::new(LcpCode::ConfigureRequest, 1, options);
    let encoded = pkt.encode();

    assert_eq!(encoded[0], 0x01); // Configure-Request
    assert_eq!(encoded[1], 0x01); // identifier
    // length = 4 (header) + 4 (MRU) + 6 (Magic) = 14
    assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 14);
    // MRU option: type=1, len=4, value=1500 (0x05DC)
    assert_eq!(encoded[4..8], [0x01, 0x04, 0x05, 0xDC]);
    // Magic: type=5, len=6, value=0xDEADBEEF
    assert_eq!(encoded[8], 0x05);
    assert_eq!(encoded[9], 0x06);
    assert_eq!(encoded[10..14], 0xDEADBEEFu32.to_be_bytes());
}

#[test]
fn test_decode_configure_request() {
    let data = vec![
        0x01, // Configure-Request
        0x42, // identifier
        0x00, 0x0E, // length = 14
        0x01, 0x04, 0x05, 0xDC, // MRU = 1500
        0x05, 0x06, 0x12, 0x34, 0x56, 0x78, // Magic = 0x12345678
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
    // FortiGate sends PFCOMP (type=7) and ACCOMP (type=8) — we must reject these
    let data = vec![
        0x01, 0x01, 0x00, 0x0C,
        0x01, 0x04, 0x05, 0xDC, // MRU = 1500
        0x07, 0x02,             // PFCOMP (type=7, len=2, no data)
        0x08, 0x02,             // ACCOMP (type=8, len=2, no data)
    ];
    let pkt = LcpPacket::decode(&data).unwrap();
    assert_eq!(pkt.options().len(), 3);
    assert_eq!(pkt.options()[1], LcpOption::ProtocolFieldCompression);
    assert_eq!(pkt.options()[2], LcpOption::AddressControlFieldCompression);
}

#[test]
fn test_lcp_state_handle_server_config_request() {
    let mut state = LcpState::new(1500);

    // Server sends Configure-Request with MRU, Magic, PFCOMP, ACCOMP
    let server_req = vec![
        0x01, 0x01, 0x00, 0x10,
        0x01, 0x04, 0x05, 0xDC, // MRU = 1500
        0x05, 0x06, 0xAA, 0xBB, 0xCC, 0xDD, // Magic = 0xAABBCCDD
        0x07, 0x02, // PFCOMP
    ];

    let responses = state.handle_packet(&server_req);

    // Should produce:
    // 1. Configure-Reject for PFCOMP (type=7)
    // Because we accept MRU and Magic, but reject compression options
    assert!(!responses.is_empty());

    let reject = LcpPacket::decode(&responses[0]).unwrap();
    assert_eq!(reject.code(), LcpCode::ConfigureReject);
    assert_eq!(reject.identifier(), 0x01); // same id as request
    // Rejected options should only contain PFCOMP
    assert_eq!(reject.options().len(), 1);
    assert_eq!(reject.options()[0], LcpOption::ProtocolFieldCompression);
}

#[test]
fn test_lcp_state_handle_server_config_request_all_acceptable() {
    let mut state = LcpState::new(1500);

    // Server sends Configure-Request with only MRU and Magic (no compression)
    let server_req = vec![
        0x01, 0x01, 0x00, 0x0E,
        0x01, 0x04, 0x05, 0xDC,
        0x05, 0x06, 0xAA, 0xBB, 0xCC, 0xDD,
    ];

    let responses = state.handle_packet(&server_req);

    // Should produce Configure-Ack (accept all)
    assert_eq!(responses.len(), 1);
    let ack = LcpPacket::decode(&responses[0]).unwrap();
    assert_eq!(ack.code(), LcpCode::ConfigureAck);
    assert_eq!(ack.identifier(), 0x01);
}

#[test]
fn test_lcp_echo_request_produces_reply() {
    let mut state = LcpState::new(1500);
    state.set_peer_magic(0x12345678);

    // Echo-Request: code=9, id=5, length=8, magic=0x12345678
    let echo_req = vec![
        0x09, 0x05, 0x00, 0x08,
        0x12, 0x34, 0x56, 0x78,
    ];

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
    let mru = pkt.options().iter().find(|o| matches!(o, LcpOption::Mru(_)));
    assert!(mru.is_some());
    if let Some(LcpOption::Mru(val)) = mru {
        assert_eq!(*val, 1400);
    }
    // Should also have a magic number
    let magic = pkt.options().iter().find(|o| matches!(o, LcpOption::MagicNumber(_)));
    assert!(magic.is_some());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd forti-vpn && cargo test --test lcp_test 2>&1`
Expected: Compilation error — `ppp::lcp` module is empty.

- [ ] **Step 3: Implement LCP types and state machine**

Create `forti-vpn/src/ppp/lcp.rs`:

```rust
use crate::error::{FortiError, Result};

/// LCP packet codes (RFC 1661 section 5)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcpCode {
    ConfigureRequest,  // 1
    ConfigureAck,      // 2
    ConfigureNak,      // 3
    ConfigureReject,   // 4
    TerminateRequest,  // 5
    TerminateAck,      // 6
    CodeReject,        // 7
    ProtocolReject,    // 8
    EchoRequest,       // 9
    EchoReply,         // 10
    DiscardRequest,    // 11
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

/// LCP configuration options
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LcpOption {
    Mru(u16),                           // type 1, len 4
    MagicNumber(u32),                   // type 5, len 6
    ProtocolFieldCompression,           // type 7, len 2
    AddressControlFieldCompression,     // type 8, len 2
    Unknown { option_type: u8, data: Vec<u8> },
}

impl LcpOption {
    fn option_type(&self) -> u8 {
        match self {
            Self::Mru(_) => 1,
            Self::MagicNumber(_) => 5,
            Self::ProtocolFieldCompression => 7,
            Self::AddressControlFieldCompression => 8,
            Self::Unknown { option_type, .. } => *option_type,
        }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Mru(val) => {
                vec![0x01, 0x04, (val >> 8) as u8, *val as u8]
            }
            Self::MagicNumber(val) => {
                let mut buf = vec![0x05, 0x06];
                buf.extend_from_slice(&val.to_be_bytes());
                buf
            }
            Self::ProtocolFieldCompression => vec![0x07, 0x02],
            Self::AddressControlFieldCompression => vec![0x08, 0x02],
            Self::Unknown { option_type, data } => {
                let mut buf = vec![*option_type, (data.len() + 2) as u8];
                buf.extend_from_slice(data);
                buf
            }
        }
    }

    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 2 {
            return Err(FortiError::ProtocolError("LCP option too short".into()));
        }

        let opt_type = buf[0];
        let opt_len = buf[1] as usize;

        if opt_len < 2 || buf.len() < opt_len {
            return Err(FortiError::ProtocolError(format!(
                "LCP option type {} invalid length {}",
                opt_type, opt_len,
            )));
        }

        let option = match opt_type {
            1 if opt_len == 4 => {
                Self::Mru(u16::from_be_bytes([buf[2], buf[3]]))
            }
            5 if opt_len == 6 => {
                Self::MagicNumber(u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]))
            }
            7 => Self::ProtocolFieldCompression,
            8 => Self::AddressControlFieldCompression,
            _ => Self::Unknown {
                option_type: opt_type,
                data: buf[2..opt_len].to_vec(),
            },
        };

        Ok((option, opt_len))
    }

    /// Returns true if this option should be rejected (not supported)
    fn is_rejectable(&self) -> bool {
        matches!(
            self,
            Self::ProtocolFieldCompression | Self::AddressControlFieldCompression
        )
    }
}

/// A decoded LCP packet.
#[derive(Debug)]
pub struct LcpPacket {
    code: LcpCode,
    identifier: u8,
    options: Vec<LcpOption>,
    /// Raw data for non-option packets (Echo-Request/Reply, Terminate, etc.)
    raw_data: Vec<u8>,
}

impl LcpPacket {
    pub fn new(code: LcpCode, identifier: u8, options: Vec<LcpOption>) -> Self {
        Self {
            code,
            identifier,
            options,
            raw_data: Vec::new(),
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

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        match self.code {
            LcpCode::EchoRequest | LcpCode::EchoReply | LcpCode::DiscardRequest => {
                payload.extend_from_slice(&self.raw_data);
            }
            _ => {
                for opt in &self.options {
                    payload.extend_from_slice(&opt.encode());
                }
            }
        }

        let length = (4 + payload.len()) as u16;
        let mut buf = Vec::with_capacity(4 + payload.len());
        buf.push(self.code.to_u8());
        buf.push(self.identifier);
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(FortiError::ProtocolError("LCP packet too short".into()));
        }

        let code = LcpCode::from_u8(buf[0]);
        let identifier = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;

        if buf.len() < length {
            return Err(FortiError::ProtocolError("LCP packet truncated".into()));
        }

        let data = &buf[4..length];

        match code {
            LcpCode::EchoRequest | LcpCode::EchoReply | LcpCode::DiscardRequest
            | LcpCode::TerminateRequest | LcpCode::TerminateAck => {
                Ok(Self {
                    code,
                    identifier,
                    options: Vec::new(),
                    raw_data: data.to_vec(),
                })
            }
            _ => {
                let mut options = Vec::new();
                let mut offset = 0;
                while offset < data.len() {
                    let (opt, consumed) = LcpOption::decode(&data[offset..])?;
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
}

/// LCP state machine.
pub struct LcpState {
    our_mru: u16,
    our_magic: u32,
    peer_magic: u32,
    next_identifier: u8,
}

impl LcpState {
    pub fn new(mru: u16) -> Self {
        Self {
            our_mru: mru,
            our_magic: rand::random(),
            peer_magic: 0,
            next_identifier: 1,
        }
    }

    pub fn set_peer_magic(&mut self, magic: u32) {
        self.peer_magic = magic;
    }

    pub fn our_magic(&self) -> u32 {
        self.our_magic
    }

    fn next_id(&mut self) -> u8 {
        let id = self.next_identifier;
        self.next_identifier = self.next_identifier.wrapping_add(1);
        id
    }

    /// Build our initial Configure-Request.
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

    /// Build an Echo-Request for keepalive.
    pub fn build_echo_request(&mut self) -> Vec<u8> {
        let id = self.next_id();
        let mut pkt = LcpPacket {
            code: LcpCode::EchoRequest,
            identifier: id,
            options: Vec::new(),
            raw_data: self.our_magic.to_be_bytes().to_vec(),
        };
        // Unused field but needed for encode
        let _ = &mut pkt;
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
            LcpCode::ConfigureAck => Vec::new(), // our request was accepted
            LcpCode::ConfigureNak => Vec::new(), // FortiGate accepts MRU + Magic; Nak not expected
            LcpCode::ConfigureReject => Vec::new(), // FortiGate accepts MRU + Magic; Reject not expected
            LcpCode::EchoRequest => self.handle_echo_request(&pkt),
            LcpCode::EchoReply => Vec::new(), // keepalive response received
            LcpCode::TerminateRequest => {
                let ack = LcpPacket::new(LcpCode::TerminateAck, pkt.identifier(), Vec::new());
                vec![ack.encode()]
            }
            _ => Vec::new(),
        }
    }

    fn handle_configure_request(&mut self, pkt: &LcpPacket) -> Vec<Vec<u8>> {
        let mut acceptable = Vec::new();
        let mut rejected = Vec::new();

        for opt in pkt.options() {
            if opt.is_rejectable() {
                rejected.push(opt.clone());
            } else {
                acceptable.push(opt.clone());
                // Remember peer's magic
                if let LcpOption::MagicNumber(m) = opt {
                    self.peer_magic = *m;
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

    fn handle_echo_request(&self, pkt: &LcpPacket) -> Vec<Vec<u8>> {
        let reply = LcpPacket {
            code: LcpCode::EchoReply,
            identifier: pkt.identifier(),
            options: Vec::new(),
            raw_data: self.our_magic.to_be_bytes().to_vec(),
        };
        vec![reply.encode()]
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd forti-vpn && cargo test --test lcp_test 2>&1`
Expected: All 7 tests pass.

- [ ] **Step 5: Commit**

```bash
cd forti-vpn && git add src/ppp/lcp.rs tests/lcp_test.rs
git commit -m "feat: implement LCP state machine with Configure-Request/Ack/Reject and Echo"
```

---

### Task 5: IPCP Negotiation

IPCP (IP Control Protocol, RFC 1332) negotiates IPv4 address and DNS server assignment. The client sends a Configure-Request with all-zeros addresses; the server responds with Configure-Nak containing the assigned values.

**IPCP option types:**
- 3: IP address (4 bytes)
- 129: Primary DNS (4 bytes)
- 130: Secondary DNS (4 bytes)
- 131: Primary NBNS (4 bytes)
- 132: Secondary NBNS (4 bytes)

**Files:**
- Create: `forti-vpn/src/ppp/ipcp.rs`
- Create: `forti-vpn/tests/ipcp_test.rs`

- [ ] **Step 1: Write failing tests for IPCP**

Create `forti-vpn/tests/ipcp_test.rs`:

```rust
use forti_vpn::ppp::ipcp::{IpcpPacket, IpcpCode, IpcpOption, IpcpState, IpcpConfig};
use std::net::Ipv4Addr;

#[test]
fn test_encode_initial_request() {
    let state = IpcpState::new();
    let req = state.build_configure_request();
    let pkt = IpcpPacket::decode(&req).unwrap();

    assert_eq!(pkt.code(), IpcpCode::ConfigureRequest);

    // Should request all-zero addresses
    let ip_opt = pkt.options().iter().find(|o| matches!(o, IpcpOption::IpAddress(_)));
    assert!(ip_opt.is_some());
    if let Some(IpcpOption::IpAddress(addr)) = ip_opt {
        assert_eq!(*addr, Ipv4Addr::UNSPECIFIED);
    }
}

#[test]
fn test_decode_configure_nak_with_assigned_addresses() {
    // Server sends Nak with the addresses we should use
    let data = vec![
        0x03, // Configure-Nak
        0x01, // identifier
        0x00, 0x22, // length = 34
        // IP address: 10.0.0.5
        0x03, 0x06, 10, 0, 0, 5,
        // Primary DNS: 10.0.0.1
        0x81, 0x06, 10, 0, 0, 1,
        // Secondary DNS: 8.8.8.8
        0x82, 0x06, 8, 8, 8, 8,
        // Primary NBNS: 10.0.0.2
        0x83, 0x06, 10, 0, 0, 2,
        // Secondary NBNS: 10.0.0.3
        0x84, 0x06, 10, 0, 0, 3,
    ];

    let pkt = IpcpPacket::decode(&data).unwrap();
    assert_eq!(pkt.code(), IpcpCode::ConfigureNak);

    let opts = pkt.options();
    assert_eq!(opts[0], IpcpOption::IpAddress(Ipv4Addr::new(10, 0, 0, 5)));
    assert_eq!(opts[1], IpcpOption::PrimaryDns(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(opts[2], IpcpOption::SecondaryDns(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(opts[3], IpcpOption::PrimaryNbns(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(opts[4], IpcpOption::SecondaryNbns(Ipv4Addr::new(10, 0, 0, 3)));
}

#[test]
fn test_handle_nak_then_resend_with_assigned_values() {
    let mut state = IpcpState::new();

    let nak = vec![
        0x03, 0x01, 0x00, 0x16,
        0x03, 0x06, 10, 0, 0, 5,       // IP: 10.0.0.5
        0x81, 0x06, 10, 0, 0, 1,       // DNS1: 10.0.0.1
        0x82, 0x06, 8, 8, 8, 8,        // DNS2: 8.8.8.8
    ];

    let responses = state.handle_packet(&nak);

    // Should send a new Configure-Request with the assigned values
    assert_eq!(responses.len(), 1);
    let pkt = IpcpPacket::decode(&responses[0]).unwrap();
    assert_eq!(pkt.code(), IpcpCode::ConfigureRequest);

    let ip_opt = pkt.options().iter().find(|o| matches!(o, IpcpOption::IpAddress(_)));
    if let Some(IpcpOption::IpAddress(addr)) = ip_opt {
        assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 5));
    }
}

#[test]
fn test_handle_ack_completes_negotiation() {
    let mut state = IpcpState::new();

    // First, handle a Nak to learn our addresses
    let nak = vec![
        0x03, 0x01, 0x00, 0x16,
        0x03, 0x06, 10, 0, 0, 5,
        0x81, 0x06, 10, 0, 0, 1,
        0x82, 0x06, 8, 8, 8, 8,
    ];
    let _ = state.handle_packet(&nak);

    // Then handle the Ack
    let ack = vec![
        0x02, 0x02, 0x00, 0x16,
        0x03, 0x06, 10, 0, 0, 5,
        0x81, 0x06, 10, 0, 0, 1,
        0x82, 0x06, 8, 8, 8, 8,
    ];
    let responses = state.handle_packet(&ack);
    assert!(responses.is_empty()); // Ack needs no response

    let config = state.config().unwrap();
    assert_eq!(config.ip_address, Ipv4Addr::new(10, 0, 0, 5));
    assert_eq!(config.primary_dns, Some(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(config.secondary_dns, Some(Ipv4Addr::new(8, 8, 8, 8)));
}

#[test]
fn test_handle_server_configure_request() {
    let mut state = IpcpState::new();

    // Server sends its own Configure-Request (we just Ack it)
    let server_req = vec![
        0x01, 0x03, 0x00, 0x0A,
        0x03, 0x06, 192, 168, 1, 1, // Server's IP
    ];

    let responses = state.handle_packet(&server_req);
    assert_eq!(responses.len(), 1);

    let pkt = IpcpPacket::decode(&responses[0]).unwrap();
    assert_eq!(pkt.code(), IpcpCode::ConfigureAck);
    assert_eq!(pkt.identifier(), 0x03);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd forti-vpn && cargo test --test ipcp_test 2>&1`
Expected: Compilation error — `ppp::ipcp` module doesn't exist yet.

- [ ] **Step 3: Implement IPCP negotiation**

Create `forti-vpn/src/ppp/ipcp.rs`:

```rust
use crate::error::{FortiError, Result};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcpCode {
    ConfigureRequest,  // 1
    ConfigureAck,      // 2
    ConfigureNak,      // 3
    ConfigureReject,   // 4
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcpOption {
    IpAddress(Ipv4Addr),       // type 3
    PrimaryDns(Ipv4Addr),      // type 129 (0x81)
    SecondaryDns(Ipv4Addr),    // type 130 (0x82)
    PrimaryNbns(Ipv4Addr),     // type 131 (0x83)
    SecondaryNbns(Ipv4Addr),   // type 132 (0x84)
    Unknown { option_type: u8, data: Vec<u8> },
}

impl IpcpOption {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::IpAddress(addr) => {
                let mut buf = vec![0x03, 0x06];
                buf.extend_from_slice(&addr.octets());
                buf
            }
            Self::PrimaryDns(addr) => {
                let mut buf = vec![0x81, 0x06];
                buf.extend_from_slice(&addr.octets());
                buf
            }
            Self::SecondaryDns(addr) => {
                let mut buf = vec![0x82, 0x06];
                buf.extend_from_slice(&addr.octets());
                buf
            }
            Self::PrimaryNbns(addr) => {
                let mut buf = vec![0x83, 0x06];
                buf.extend_from_slice(&addr.octets());
                buf
            }
            Self::SecondaryNbns(addr) => {
                let mut buf = vec![0x84, 0x06];
                buf.extend_from_slice(&addr.octets());
                buf
            }
            Self::Unknown { option_type, data } => {
                let mut buf = vec![*option_type, (data.len() + 2) as u8];
                buf.extend_from_slice(data);
                buf
            }
        }
    }

    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 2 {
            return Err(FortiError::ProtocolError("IPCP option too short".into()));
        }

        let opt_type = buf[0];
        let opt_len = buf[1] as usize;

        if opt_len < 2 || buf.len() < opt_len {
            return Err(FortiError::ProtocolError(format!(
                "IPCP option type {} invalid length {}",
                opt_type, opt_len,
            )));
        }

        let addr_from = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);

        let option = match (opt_type, opt_len) {
            (0x03, 6) => Self::IpAddress(addr_from(&buf[2..6])),
            (0x81, 6) => Self::PrimaryDns(addr_from(&buf[2..6])),
            (0x82, 6) => Self::SecondaryDns(addr_from(&buf[2..6])),
            (0x83, 6) => Self::PrimaryNbns(addr_from(&buf[2..6])),
            (0x84, 6) => Self::SecondaryNbns(addr_from(&buf[2..6])),
            _ => Self::Unknown {
                option_type: opt_type,
                data: buf[2..opt_len].to_vec(),
            },
        };

        Ok((option, opt_len))
    }
}

#[derive(Debug)]
pub struct IpcpPacket {
    code: IpcpCode,
    identifier: u8,
    options: Vec<IpcpOption>,
}

impl IpcpPacket {
    pub fn new(code: IpcpCode, identifier: u8, options: Vec<IpcpOption>) -> Self {
        Self { code, identifier, options }
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

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        for opt in &self.options {
            payload.extend_from_slice(&opt.encode());
        }

        let length = (4 + payload.len()) as u16;
        let mut buf = Vec::with_capacity(4 + payload.len());
        buf.push(self.code.to_u8());
        buf.push(self.identifier);
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(FortiError::ProtocolError("IPCP packet too short".into()));
        }

        let code = IpcpCode::from_u8(buf[0]);
        let identifier = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;

        if buf.len() < length {
            return Err(FortiError::ProtocolError("IPCP packet truncated".into()));
        }

        let data = &buf[4..length];
        let mut options = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let (opt, consumed) = IpcpOption::decode(&data[offset..])?;
            options.push(opt);
            offset += consumed;
        }

        Ok(Self { code, identifier, options })
    }
}

/// Negotiated IPCP configuration.
#[derive(Debug, Clone)]
pub struct IpcpConfig {
    pub ip_address: Ipv4Addr,
    pub primary_dns: Option<Ipv4Addr>,
    pub secondary_dns: Option<Ipv4Addr>,
    pub primary_nbns: Option<Ipv4Addr>,
    pub secondary_nbns: Option<Ipv4Addr>,
}

/// IPCP state machine.
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

    fn next_id(&mut self) -> u8 {
        let id = self.next_identifier;
        self.next_identifier = self.next_identifier.wrapping_add(1);
        id
    }

    /// Returns the negotiated config, or None if negotiation is not complete.
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

    /// Build our initial Configure-Request with all-zero addresses.
    pub fn build_configure_request(&self) -> Vec<u8> {
        let options = vec![
            IpcpOption::IpAddress(self.ip_address),
            IpcpOption::PrimaryDns(self.primary_dns.unwrap_or(Ipv4Addr::UNSPECIFIED)),
            IpcpOption::SecondaryDns(self.secondary_dns.unwrap_or(Ipv4Addr::UNSPECIFIED)),
        ];
        let pkt = IpcpPacket::new(IpcpCode::ConfigureRequest, self.next_identifier, options);
        pkt.encode()
    }

    /// Handle an incoming IPCP packet. Returns zero or more response packets.
    pub fn handle_packet(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let pkt = match IpcpPacket::decode(data) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };

        match pkt.code() {
            IpcpCode::ConfigureRequest => {
                // Server sends its own request — just Ack it
                let ack = IpcpPacket::new(
                    IpcpCode::ConfigureAck,
                    pkt.identifier(),
                    pkt.options().to_vec(),
                );
                vec![ack.encode()]
            }
            IpcpCode::ConfigureNak => {
                // Server tells us the correct values — update and resend
                for opt in pkt.options() {
                    match opt {
                        IpcpOption::IpAddress(addr) => self.ip_address = *addr,
                        IpcpOption::PrimaryDns(addr) => self.primary_dns = Some(*addr),
                        IpcpOption::SecondaryDns(addr) => self.secondary_dns = Some(*addr),
                        IpcpOption::PrimaryNbns(addr) => self.primary_nbns = Some(*addr),
                        IpcpOption::SecondaryNbns(addr) => self.secondary_nbns = Some(*addr),
                        _ => {}
                    }
                }
                // Resend Configure-Request with the new values
                let id = self.next_id();
                let options = vec![
                    IpcpOption::IpAddress(self.ip_address),
                    IpcpOption::PrimaryDns(self.primary_dns.unwrap_or(Ipv4Addr::UNSPECIFIED)),
                    IpcpOption::SecondaryDns(self.secondary_dns.unwrap_or(Ipv4Addr::UNSPECIFIED)),
                ];
                let req = IpcpPacket::new(IpcpCode::ConfigureRequest, id, options);
                vec![req.encode()]
            }
            IpcpCode::ConfigureAck => {
                self.negotiation_complete = true;
                Vec::new()
            }
            IpcpCode::ConfigureReject => {
                // Remove rejected options and resend
                Vec::new()
            }
            _ => Vec::new(),
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd forti-vpn && cargo test --test ipcp_test 2>&1`
Expected: All 5 tests pass.

- [ ] **Step 5: Commit**

```bash
cd forti-vpn && git add src/ppp/ipcp.rs tests/ipcp_test.rs
git commit -m "feat: implement IPCP negotiation for IPv4 + DNS address assignment"
```

---

### Task 6: HTTP Authentication Client

Implements credential-based auth: `POST /remote/logincheck` to obtain `SVPNCOOKIE`, then `GET /remote/fortisslvpn_xml` to fetch tunnel configuration.

**Files:**
- Create: `forti-vpn/src/auth/mod.rs`
- Create: `forti-vpn/src/auth/xml.rs`

- [ ] **Step 1: Create auth module with the AuthClient struct**

Create `forti-vpn/src/auth/mod.rs`:

```rust
pub mod xml;

use crate::error::{FortiError, Result};
use std::sync::Arc;
use tracing::{info, debug, warn};

/// Result of a successful authentication.
#[derive(Debug)]
pub struct AuthResult {
    pub svpn_cookie: String,
    pub tunnel_config: xml::TunnelConfig,
}

/// HTTP authentication client for FortiGate SSL VPN.
pub struct AuthClient {
    server: String,
    port: u16,
    tls_config: Arc<rustls::ClientConfig>,
}

impl AuthClient {
    pub fn new(server: &str, port: u16) -> Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            server: server.to_string(),
            port,
            tls_config: Arc::new(tls_config),
        })
    }

    /// Authenticate with username/password and retrieve tunnel configuration.
    pub async fn login(&self, username: &str, password: &str, realm: Option<&str>) -> Result<AuthResult> {
        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        let server_name = rustls::pki_types::ServerName::try_from(self.server.clone())
            .map_err(|e| FortiError::TunnelError(format!("invalid server name: {}", e)))?;

        let tcp = tokio::net::TcpStream::connect(format!("{}:{}", self.server, self.port)).await?;
        let tls = connector.connect(server_name.clone(), tcp).await
            .map_err(|e| FortiError::Tls(e.into()))?;

        let io = hyper_util::rt::TokioIo::new(tls);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await
            .map_err(|e| FortiError::TunnelError(format!("HTTP handshake failed: {}", e)))?;

        tokio::spawn(conn);

        // Step 1: POST /remote/logincheck
        let body = if let Some(realm) = realm {
            format!(
                "ajax=1&username={}&credential={}&realm={}",
                urlencoded(username),
                urlencoded(password),
                urlencoded(realm),
            )
        } else {
            format!(
                "ajax=1&username={}&credential={}",
                urlencoded(username),
                urlencoded(password),
            )
        };

        let req = hyper::Request::builder()
            .method("POST")
            .uri("/remote/logincheck")
            .header("Host", &self.server)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", body.len())
            .body(http_body_util::Full::new(bytes::Bytes::from(body)))
            .map_err(|e| FortiError::Http(e))?;

        info!("Sending login request");
        let resp = sender.send_request(req).await
            .map_err(|e| FortiError::TunnelError(format!("login request failed: {}", e)))?;

        debug!("Login response status: {}", resp.status());

        // Extract SVPNCOOKIE from Set-Cookie headers
        let svpn_cookie = resp.headers()
            .get_all("set-cookie")
            .iter()
            .find_map(|v| {
                let s = v.to_str().ok()?;
                if s.starts_with("SVPNCOOKIE=") {
                    let val = s.split(';').next()?;
                    Some(val.trim_start_matches("SVPNCOOKIE=").to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                FortiError::AuthFailed("no SVPNCOOKIE in login response".into())
            })?;

        info!("Authentication successful, got SVPNCOOKIE");

        // Step 2: GET /remote/fortisslvpn_xml
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/remote/fortisslvpn_xml?dual_stack=1")
            .header("Host", &self.server)
            .header("Cookie", format!("SVPNCOOKIE={}", svpn_cookie))
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .map_err(|e| FortiError::Http(e))?;

        debug!("Fetching tunnel configuration");
        let resp = sender.send_request(req).await
            .map_err(|e| FortiError::TunnelError(format!("XML config request failed: {}", e)))?;

        let body = http_body_util::BodyExt::collect(resp.into_body()).await
            .map_err(|e| FortiError::TunnelError(format!("failed to read XML body: {}", e)))?;
        let xml_text = String::from_utf8_lossy(&body.to_bytes());

        let tunnel_config = xml::TunnelConfig::parse(&xml_text)?;
        info!("Tunnel config: IP={}, DNS={:?}", tunnel_config.ip_address, tunnel_config.dns_servers);

        Ok(AuthResult {
            svpn_cookie,
            tunnel_config,
        })
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn tls_config(&self) -> Arc<rustls::ClientConfig> {
        self.tls_config.clone()
    }
}

fn urlencoded(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}
```

- [ ] **Step 2: Implement XML tunnel config parser**

Create `forti-vpn/src/auth/xml.rs`:

```rust
use crate::error::{FortiError, Result};
use std::net::Ipv4Addr;

/// Parsed tunnel configuration from /remote/fortisslvpn_xml.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub ip_address: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub routes: Vec<Route>,
    pub idle_timeout: Option<u32>,
    pub auth_timeout: Option<u32>,
    pub dtls_port: Option<u16>,
    pub fos_version: Option<String>,
    pub tunnel_method: String,
}

#[derive(Debug, Clone)]
pub struct Route {
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl TunnelConfig {
    /// Parse the XML response from /remote/fortisslvpn_xml.
    ///
    /// This is a lightweight parser that extracts the fields we need
    /// without pulling in a full XML library.
    pub fn parse(xml: &str) -> Result<Self> {
        let ip_address = extract_tag_attr(xml, "assigned-addr", "ipv4")
            .or_else(|| extract_text(xml, "assigned-addr"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(Ipv4Addr::UNSPECIFIED);

        let mut dns_servers = Vec::new();
        if let Some(dns1) = extract_text(xml, "dns") {
            if let Ok(addr) = dns1.parse() {
                dns_servers.push(addr);
            }
        }
        if let Some(dns2) = extract_text(xml, "dns2") {
            if let Ok(addr) = dns2.parse() {
                dns_servers.push(addr);
            }
        }

        let mut routes = Vec::new();
        for addr_match in find_all_tag_attrs(xml, "addr") {
            if let (Some(ip_str), Some(mask_str)) = (addr_match.get("ip"), addr_match.get("mask")) {
                if let (Ok(ip), Ok(mask)) = (ip_str.parse(), mask_str.parse()) {
                    routes.push(Route { ip, mask });
                }
            }
        }

        let idle_timeout = extract_text(xml, "idle-timeout")
            .and_then(|s| s.parse().ok());

        let auth_timeout = extract_text(xml, "auth-timeout")
            .and_then(|s| s.parse().ok());

        let dtls_port = extract_text(xml, "dtls-config")
            .and_then(|s| extract_text(&s, "port"))
            .and_then(|s| s.parse().ok());

        let fos_version = extract_text(xml, "fos");

        let tunnel_method = extract_tag_attr(xml, "tunnel-method", "value")
            .unwrap_or_else(|| "ppp".to_string());

        Ok(Self {
            ip_address,
            dns_servers,
            routes,
            idle_timeout,
            auth_timeout,
            dtls_port,
            fos_version,
            tunnel_method,
        })
    }
}

/// Extract text content between <tag>...</tag>
fn extract_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let start_idx = xml.find(&open)?;
    let after_open = &xml[start_idx + open.len()..];
    // Skip to end of opening tag
    let content_start = after_open.find('>')? + 1;
    let content = &after_open[content_start..];
    let end_idx = content.find(&close)?;
    let text = content[..end_idx].trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Extract a specific attribute value from a tag: <tag attr="value"/>
fn extract_tag_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let start_idx = xml.find(&open)?;
    let after_open = &xml[start_idx + open.len()..];
    let tag_end = after_open.find('>')?;
    let tag_content = &after_open[..tag_end];

    let attr_pattern = format!("{}=\"", attr);
    let attr_start = tag_content.find(&attr_pattern)?;
    let value_start = attr_start + attr_pattern.len();
    let value_end = tag_content[value_start..].find('"')?;
    Some(tag_content[value_start..value_start + value_end].to_string())
}

/// Find all occurrences of a tag and extract their attributes.
fn find_all_tag_attrs(xml: &str, tag: &str) -> Vec<std::collections::HashMap<String, String>> {
    let open = format!("<{}", tag);
    let mut results = Vec::new();
    let mut search_from = 0;

    while let Some(pos) = xml[search_from..].find(&open) {
        let abs_pos = search_from + pos;
        let after_open = &xml[abs_pos + open.len()..];
        if let Some(tag_end) = after_open.find('>') {
            let tag_content = &after_open[..tag_end];
            let mut attrs = std::collections::HashMap::new();

            let mut remaining = tag_content;
            while let Some(eq_pos) = remaining.find("=\"") {
                // Find attribute name (word before =")
                let before_eq = &remaining[..eq_pos];
                let attr_name = before_eq.rsplit_once(char::is_whitespace)
                    .map(|(_, name)| name)
                    .unwrap_or(before_eq)
                    .trim();
                let value_start = eq_pos + 2;
                if let Some(value_end) = remaining[value_start..].find('"') {
                    let value = &remaining[value_start..value_start + value_end];
                    attrs.insert(attr_name.to_string(), value.to_string());
                    remaining = &remaining[value_start + value_end + 1..];
                } else {
                    break;
                }
            }

            if !attrs.is_empty() {
                results.push(attrs);
            }
            search_from = abs_pos + open.len() + tag_end;
        } else {
            break;
        }
    }

    results
}
```

- [ ] **Step 3: Verify project builds**

Run: `cd forti-vpn && cargo build 2>&1`
Expected: Compiles successfully. (Auth is tested via integration, not unit tests, since it requires a real FortiGate.)

- [ ] **Step 4: Commit**

```bash
cd forti-vpn && git add src/auth/
git commit -m "feat: implement HTTP auth client and XML tunnel config parser"
```

---

### Task 7: TLS Tunnel Establishment

After authentication, the client sends `GET /remote/sslvpn-tunnel` to upgrade the HTTP connection to a raw binary tunnel. This is the critical "connection hijack" — extracting the raw TLS stream from hyper.

**Files:**
- Modify: `forti-vpn/src/tunnel/mod.rs`

- [ ] **Step 1: Implement TLS tunnel that reuses the auth connection**

Replace `forti-vpn/src/tunnel/mod.rs` with:

```rust
pub mod codec;

use crate::error::{FortiError, Result};
use crate::auth::AuthClient;
use codec::{FortinetFrame, FortinetCodec};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

/// A raw TLS tunnel to the FortiGate, carrying Fortinet-framed PPP data.
pub struct TlsTunnel {
    tls_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    codec: FortinetCodec,
    read_buf: Vec<u8>,
}

impl TlsTunnel {
    /// Establish the tunnel: connect, send GET /remote/sslvpn-tunnel, then
    /// use the raw TLS stream for PPP framing.
    pub async fn connect(
        server: &str,
        port: u16,
        svpn_cookie: &str,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<Self> {
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let server_name = rustls::pki_types::ServerName::try_from(server.to_string())
            .map_err(|e| FortiError::TunnelError(format!("invalid server name: {}", e)))?;

        let tcp = tokio::net::TcpStream::connect(format!("{}:{}", server, port)).await?;
        let mut tls = connector.connect(server_name, tcp).await
            .map_err(|e| FortiError::Tls(e.into()))?;

        // Send the HTTP request manually on the raw TLS stream.
        // This avoids the hyper connection hijack complexity entirely —
        // we just write raw HTTP bytes and then switch to binary mode.
        let http_req = format!(
            "GET /remote/sslvpn-tunnel HTTP/1.1\r\n\
             Host: {}\r\n\
             Cookie: SVPNCOOKIE={}\r\n\
             \r\n",
            server, svpn_cookie,
        );

        tls.write_all(http_req.as_bytes()).await?;
        tls.flush().await?;

        info!("Sent tunnel upgrade request");

        // Read the HTTP response. The server responds with "HTTP/1.1 200 OK"
        // and then immediately switches to binary Fortinet framing.
        let mut response_buf = vec![0u8; 4096];
        let n = tls.read(&mut response_buf).await?;
        let response_str = String::from_utf8_lossy(&response_buf[..n]);

        if !response_str.contains("200") {
            return Err(FortiError::TunnelError(format!(
                "tunnel upgrade failed: {}",
                response_str.lines().next().unwrap_or("empty response"),
            )));
        }

        debug!("Tunnel upgrade response: {}", response_str.lines().next().unwrap_or(""));

        // Any data after the HTTP headers is the start of the binary stream.
        // Find the end of HTTP headers (\r\n\r\n) and keep the remainder.
        let header_end = response_str.find("\r\n\r\n")
            .map(|i| i + 4)
            .unwrap_or(n);

        let leftover = if header_end < n {
            response_buf[header_end..n].to_vec()
        } else {
            Vec::new()
        };

        info!("TLS tunnel established, {} bytes of initial data", leftover.len());

        Ok(Self {
            tls_stream: tls,
            codec: FortinetCodec::new(),
            read_buf: leftover,
        })
    }

    /// Send a Fortinet-framed PPP packet.
    pub async fn send_frame(&mut self, ppp_payload: Vec<u8>) -> Result<()> {
        let frame = FortinetFrame::new(ppp_payload);
        let wire = frame.encode();
        self.tls_stream.write_all(&wire).await?;
        self.tls_stream.flush().await?;
        Ok(())
    }

    /// Receive the next complete Fortinet frame. Blocks until a full frame arrives.
    pub async fn recv_frame(&mut self) -> Result<FortinetFrame> {
        loop {
            // Try to decode from existing buffer
            if let Some(frame) = self.codec.try_decode(&mut self.read_buf) {
                return Ok(frame);
            }

            // Read more data from TLS
            let mut tmp = vec![0u8; 4096];
            let n = self.tls_stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(FortiError::TunnelError("tunnel closed by peer".into()));
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
    }
}
```

- [ ] **Step 2: Verify project builds**

Run: `cd forti-vpn && cargo build 2>&1`
Expected: Compiles successfully.

- [ ] **Step 3: Commit**

```bash
cd forti-vpn && git add src/tunnel/mod.rs
git commit -m "feat: implement TLS tunnel with raw HTTP upgrade for PPP framing"
```

---

### Task 8: PPP Engine — Orchestrating LCP + IPCP over the Tunnel

This task ties the PPP codec, LCP, and IPCP together into a single PPP engine that drives negotiation over the TLS tunnel.

**Files:**
- Modify: `forti-vpn/src/ppp/mod.rs`

- [ ] **Step 1: Implement the PPP engine**

Replace `forti-vpn/src/ppp/mod.rs` with:

```rust
pub mod codec;
pub mod lcp;
pub mod ipcp;

use crate::error::{FortiError, Result};
use crate::tunnel::TlsTunnel;
use codec::{PppFrame, PppProtocol};
use ipcp::IpcpConfig;
use tracing::{debug, info, warn};
use std::time::Duration;

/// PPP engine that drives LCP and IPCP negotiation over a TLS tunnel.
pub struct PppEngine {
    lcp: lcp::LcpState,
    ipcp: ipcp::IpcpState,
    mru: u16,
}

impl PppEngine {
    pub fn new(mru: u16) -> Self {
        Self {
            lcp: lcp::LcpState::new(mru),
            ipcp: ipcp::IpcpState::new(),
            mru,
        }
    }

    /// Run full PPP negotiation: LCP → IPCP.
    /// Returns the negotiated IP configuration on success.
    pub async fn negotiate(&mut self, tunnel: &mut TlsTunnel) -> Result<IpcpConfig> {
        // Phase 1: LCP
        info!("Starting LCP negotiation");
        let lcp_req = self.lcp.build_configure_request();
        self.send_ppp(tunnel, PppProtocol::Lcp, lcp_req).await?;

        let mut lcp_done = false;
        let mut our_lcp_acked = false;
        let mut peer_lcp_acked = false;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        while !lcp_done {
            if tokio::time::Instant::now() > deadline {
                return Err(FortiError::PppError("LCP negotiation timeout".into()));
            }

            let frame = tokio::time::timeout(Duration::from_secs(10), tunnel.recv_frame())
                .await
                .map_err(|_| FortiError::PppError("timeout waiting for LCP response".into()))?
                ?;

            let ppp = PppFrame::decode(frame.payload())?;

            match ppp.protocol() {
                PppProtocol::Lcp => {
                    let responses = self.lcp.handle_packet(ppp.data());
                    for resp in &responses {
                        self.send_ppp(tunnel, PppProtocol::Lcp, resp.clone()).await?;
                    }

                    let code = ppp.data().first().copied().unwrap_or(0);
                    match code {
                        2 => { // Configure-Ack for our request
                            debug!("LCP: our Configure-Request accepted");
                            our_lcp_acked = true;
                        }
                        1 => { // Configure-Request from peer (we sent Ack or Reject)
                            if responses.iter().any(|r| r.first() == Some(&2)) {
                                debug!("LCP: peer Configure-Request accepted");
                                peer_lcp_acked = true;
                            }
                        }
                        _ => {}
                    }
                }
                PppProtocol::Ccp => {
                    // Reject CCP (compression) — send Protocol-Reject via LCP
                    debug!("Rejecting CCP Configure-Request");
                    let ccp_reject = build_protocol_reject(
                        PppProtocol::Ccp.to_u16(),
                        ppp.data(),
                        self.lcp.our_magic(),
                    );
                    self.send_ppp(tunnel, PppProtocol::Lcp, ccp_reject).await?;
                }
                other => {
                    debug!("LCP phase: ignoring {:?} packet", other);
                }
            }

            lcp_done = our_lcp_acked && peer_lcp_acked;
        }

        info!("LCP negotiation complete");

        // Phase 2: IPCP
        info!("Starting IPCP negotiation");
        let ipcp_req = self.ipcp.build_configure_request();
        self.send_ppp(tunnel, PppProtocol::Ipcp, ipcp_req).await?;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(FortiError::PppError("IPCP negotiation timeout".into()));
            }

            let frame = tokio::time::timeout(Duration::from_secs(10), tunnel.recv_frame())
                .await
                .map_err(|_| FortiError::PppError("timeout waiting for IPCP response".into()))?
                ?;

            let ppp = PppFrame::decode(frame.payload())?;

            match ppp.protocol() {
                PppProtocol::Ipcp => {
                    let responses = self.ipcp.handle_packet(ppp.data());
                    for resp in &responses {
                        self.send_ppp(tunnel, PppProtocol::Ipcp, resp.clone()).await?;
                    }

                    if let Some(config) = self.ipcp.config() {
                        info!("IPCP negotiation complete: IP={}", config.ip_address);
                        return Ok(config);
                    }
                }
                PppProtocol::Lcp => {
                    // Handle LCP packets during IPCP phase (keepalive, etc.)
                    let responses = self.lcp.handle_packet(ppp.data());
                    for resp in &responses {
                        self.send_ppp(tunnel, PppProtocol::Lcp, resp.clone()).await?;
                    }
                }
                other => {
                    debug!("IPCP phase: ignoring {:?} packet", other);
                }
            }
        }
    }

    /// Send a PPP frame wrapped in a Fortinet frame.
    async fn send_ppp(
        &self,
        tunnel: &mut TlsTunnel,
        protocol: PppProtocol,
        data: Vec<u8>,
    ) -> Result<()> {
        let ppp_frame = PppFrame::new(protocol, data);
        tunnel.send_frame(ppp_frame.encode()).await
    }
}

/// Build an LCP Protocol-Reject packet (code 8).
fn build_protocol_reject(rejected_protocol: u16, rejected_data: &[u8], magic: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&rejected_protocol.to_be_bytes());
    payload.extend_from_slice(rejected_data);

    // Truncate to fit within MRU if needed
    if payload.len() > 1492 {
        payload.truncate(1492);
    }

    let length = (4 + payload.len()) as u16;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.push(8); // Protocol-Reject code
    buf.push(0); // identifier (will be overwritten if we track IDs)
    buf.extend_from_slice(&length.to_be_bytes());
    buf.extend_from_slice(&payload);
    buf
}
```

- [ ] **Step 2: Verify project builds**

Run: `cd forti-vpn && cargo build 2>&1`
Expected: Compiles successfully.

- [ ] **Step 3: Commit**

```bash
cd forti-vpn && git add src/ppp/mod.rs
git commit -m "feat: implement PPP engine orchestrating LCP + IPCP negotiation"
```

---

### Task 9: Wire It Together — End-to-End CLI

Connect everything in `main.rs`: authenticate, establish tunnel, run PPP negotiation.

**Files:**
- Modify: `forti-vpn/src/main.rs`

- [ ] **Step 1: Update main.rs with full connect flow**

Replace `forti-vpn/src/main.rs` with:

```rust
use clap::Parser;
use tracing_subscriber::EnvFilter;
use forti_vpn::auth::AuthClient;
use forti_vpn::tunnel::TlsTunnel;
use forti_vpn::ppp::PppEngine;
use std::io::Write;

#[derive(Parser, Debug)]
#[command(name = "forti-vpn", about = "FortiGate SSL VPN client")]
struct Cli {
    /// VPN gateway hostname or IP
    #[arg(short, long)]
    server: String,

    /// VPN gateway port
    #[arg(short, long, default_value = "443")]
    port: u16,

    /// Username
    #[arg(short, long)]
    username: String,

    /// Password (if omitted, will prompt)
    #[arg(short = 'P', long)]
    password: Option<String>,

    /// Realm (optional)
    #[arg(long)]
    realm: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let password = match cli.password {
        Some(p) => p,
        None => {
            eprint!("Password: ");
            std::io::stderr().flush()?;
            let mut p = String::new();
            std::io::stdin().read_line(&mut p)?;
            p.trim().to_string()
        }
    };

    // Step 1: Authenticate
    tracing::info!("Authenticating to {}:{}", cli.server, cli.port);
    let auth_client = AuthClient::new(&cli.server, cli.port)?;
    let auth_result = auth_client
        .login(&cli.username, &password, cli.realm.as_deref())
        .await?;

    tracing::info!(
        "Authenticated. Tunnel config: IP={}, DNS={:?}, {} routes",
        auth_result.tunnel_config.ip_address,
        auth_result.tunnel_config.dns_servers,
        auth_result.tunnel_config.routes.len(),
    );

    // Step 2: Establish TLS tunnel
    tracing::info!("Establishing TLS tunnel");
    let mut tunnel = TlsTunnel::connect(
        &cli.server,
        cli.port,
        &auth_result.svpn_cookie,
        auth_client.tls_config(),
    )
    .await?;

    // Step 3: PPP negotiation
    tracing::info!("Running PPP negotiation");
    let mut ppp = PppEngine::new(1500);
    let ipcp_config = ppp.negotiate(&mut tunnel).await?;

    tracing::info!("PPP negotiation complete!");
    tracing::info!("  Assigned IP:    {}", ipcp_config.ip_address);
    if let Some(dns) = ipcp_config.primary_dns {
        tracing::info!("  Primary DNS:    {}", dns);
    }
    if let Some(dns) = ipcp_config.secondary_dns {
        tracing::info!("  Secondary DNS:  {}", dns);
    }

    tracing::info!("Phase 1 feasibility validated — tunnel is up and negotiated.");
    tracing::info!("Press Ctrl+C to disconnect.");

    // Keep the tunnel alive with LCP Echo
    tokio::signal::ctrl_c().await?;
    tracing::info!("Disconnecting...");

    Ok(())
}
```

- [ ] **Step 2: Verify project builds**

Run: `cd forti-vpn && cargo build 2>&1`
Expected: Compiles successfully.

- [ ] **Step 3: Commit**

```bash
cd forti-vpn && git add src/main.rs
git commit -m "feat: wire up end-to-end CLI: auth → tunnel → PPP negotiation"
```

---

### Task 10: Run All Tests and Final Verification

- [ ] **Step 1: Run the full test suite**

Run: `cd forti-vpn && cargo test 2>&1`
Expected: All tests pass (fortinet_codec_test, ppp_codec_test, lcp_test, ipcp_test).

- [ ] **Step 2: Run clippy**

Run: `cd forti-vpn && cargo clippy 2>&1`
Expected: No errors. Fix any warnings.

- [ ] **Step 3: Verify release build**

Run: `cd forti-vpn && cargo build --release 2>&1`
Expected: Compiles successfully.

- [ ] **Step 4: Verify CLI help output**

Run: `cd forti-vpn && cargo run -- --help 2>&1`
Expected output includes:
```
FortiGate SSL VPN client

Usage: forti-vpn [OPTIONS] --server <SERVER> --username <USERNAME>

Options:
  -s, --server <SERVER>      VPN gateway hostname or IP
  -p, --port <PORT>          VPN gateway port [default: 443]
  -u, --username <USERNAME>  Username
  -P, --password <PASSWORD>  Password (if omitted, will prompt)
      --realm <REALM>        Realm (optional)
  -h, --help                 Print help
```

- [ ] **Step 5: Final commit**

```bash
cd forti-vpn && git add -A
git commit -m "chore: phase 1 complete — all tests pass, clippy clean"
```

---

## Scope Notes

**What Phase 1 does NOT include** (deferred to Phase 2/3):
- TUN device integration (no actual packet routing)
- DNS configuration
- Route management
- SAML authentication
- DTLS data channel
- Sleep/wake handling
- Auto-reconnect
- Config file support (TOML)

**How to test Phase 1 against a real FortiGate:**
```bash
cd forti-vpn
RUST_LOG=debug cargo run -- --server vpn.example.com --username user@domain.com
# Enter password when prompted
# Expected: LCP and IPCP negotiation completes, assigned IP is printed
```
