# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Rust CLI client (`forti-vpn`) that speaks the FortiGate SSL VPN wire protocol directly, targeting macOS. This fills a gap where no existing client provides macOS-native networking (utun + SystemConfiguration DNS) + SAML/SSO + DTLS + userspace PPP together.

The project is in early development. Phase 1 (feasibility) covers PPP codec, HTTP authentication, and TLS tunnel upgrade. Phase 2/3 will add TUN device, DNS/routes, SAML, and DTLS.

## Build and Test Commands

```bash
cd forti-vpn

# Build
cargo build

# Run all tests
cargo test

# Run a single test file
cargo test --test fortinet_codec_test
cargo test --test ppp_codec_test
cargo test --test lcp_test
cargo test --test ipcp_test

# Run a specific test by name
cargo test test_encode_fortinet_frame

# Run with logging
RUST_LOG=debug cargo run -- --server vpn.example.com --username user

# Check without building
cargo check

# Lint
cargo clippy
```

## Architecture

### Protocol Stack (bottom-up)

```
TLS Connection (rustls/tokio-rustls)
  -> Fortinet Wire Frame (6-byte header: [total_len:BE16][0x5050][payload_len:BE16])
    -> PPP Frame (4-byte header: [FF 03][protocol:BE16])
      -> LCP / IPCP / IP6CP / CCP / IPv4 data / IPv6 data
```

### Module Layout (`forti-vpn/src/`)

- **`ppp/`** — Standalone PPP engine with no network dependencies (testable in isolation)
  - `codec.rs` — PPP frame encode/decode (`FF 03` + 2-byte protocol + payload)
  - `lcp.rs` — LCP state machine (MRU, Magic-Number, Echo keepalive; rejects PFCOMP/ACCOMP)
  - `ipcp.rs` — IPCP negotiation (IPv4 + DNS assignment from server)
- **`tunnel/`** — Transport layer
  - `codec.rs` — Fortinet wire frame codec (6-byte header with `0x5050` magic), including streaming `FortinetCodec` for extracting frames from a byte buffer
  - `mod.rs` — TLS tunnel establishment (upgrades HTTP connection to raw PPP-over-TLS)
- **`auth/`** — HTTP authentication against FortiGate
  - `mod.rs` — Credential auth (`POST /remote/logincheck` with `credential` field, not `password`)
  - `xml.rs` — Tunnel config XML parser (`GET /remote/fortisslvpn_xml`)
- **`main.rs`** — CLI entry point and args via clap
- **`error.rs`** — Error types via thiserror

### Key Protocol Details

- The password field in login POST is named `credential`, not `password`
- FortiGate sends LCP Configure-Request with PFCOMP (type 7) and ACCOMP (type 8) — always reject both; the server rejects compressed frames
- PPP address/control field is always `FF 03` — no compression negotiated
- IPCP: client sends all-zeros to request assignment; server assigns IPv4, DNS (options 129/130), NBNS (options 131/132)
- After `GET /remote/sslvpn-tunnel`, the server sends NO HTTP response on success — it silently transitions to raw binary PPP framing. If the first bytes look like `HTTP/`, it's an error. The tunnel module writes raw HTTP on the TLS stream (not via hyper) then switches to binary mode
- Fortinet wire frame `total_len` = `payload_len + 6` (counts from byte 2 onward)

### Tech Stack

Rust 2021 edition, tokio 1.x (full), hyper 1.8, rustls 0.23, tokio-rustls 0.26, clap 4, tracing 0.1, thiserror 2, bytes 1.x. DTLS will use `openssl` crate (only mature DTLS option in Rust).

### macOS-Specific Design Decisions

- **TUN**: Uses `tun-rs` crate (utun). Every packet has a mandatory 4-byte AF header on macOS
- **DNS**: `/etc/resolver/` files for split DNS + `scutil` for full tunnel (not `/etc/resolv.conf` — macOS ignores it)
- **Routes**: Shell out to `/sbin/route` or use `net-route` crate (PF_ROUTE socket)
- **No pppd**: Userspace PPP eliminates Apple's broken pppd (kernel panics on Apple Silicon, route hijacking, DNS races)
- **No Network Extension**: Raw utun + routes + scutil (like Tailscale's `tailscaled`); NE requires app bundle + Apple Developer entitlement
- **Privilege**: Runs as root via `sudo` in Phase 1; future: split into privileged launchd daemon + unprivileged CLI

## Reference Documents

- `docs/fortigate_sslvpn_wire_protocol.md` — Complete wire protocol spec (reverse-engineered from OpenConnect + openfortivpn)
- `docs/superpowers/specs/2026-03-28-rust-fortigate-vpn-client-design.md` — Full design spec with crate ecosystem analysis and macOS platform details
- `docs/superpowers/plans/2026-03-28-forti-vpn-phase1-feasibility.md` — Phase 1 implementation plan (10 tasks, TDD approach with test-first for each module)
