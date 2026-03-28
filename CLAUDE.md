# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Rust CLI client (`forti-vpn`) that speaks the FortiGate SSL VPN wire protocol directly, targeting macOS. This fills a gap where no existing client provides macOS-native networking (utun + SystemConfiguration DNS) + SAML/SSO + DTLS + userspace PPP together.

**Status:** Phase 1 (feasibility) is complete and validated against a real FortiGate. SAML auth, TLS tunnel, and PPP negotiation all work end-to-end. Phase 2 will add TUN device, DNS/routes, keepalive, and DTLS.

## Build and Test Commands

```bash
cd forti-vpn

# Build
cargo build

# Run all tests (25 tests across 4 test files)
cargo test

# Run a single test file
cargo test --test fortinet_codec_test
cargo test --test ppp_codec_test
cargo test --test lcp_test
cargo test --test ipcp_test

# Run a specific test by name
cargo test test_encode_fortinet_frame

# Run with SAML auth against a real FortiGate
RUST_LOG=debug cargo run -- --server vpn.example.com --port 10443 --saml

# Run with credential auth
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
    -> PPP Frame ([FF 03][protocol:BE16] or just [protocol:BE16] without address/control)
      -> LCP / IPCP / IP6CP / CCP / IPv4 data / IPv6 data
```

### Module Layout (`forti-vpn/src/`)

- **`ppp/`** — Standalone PPP engine with no network dependencies (testable in isolation)
  - `mod.rs` — `PppEngine` orchestrating LCP + IPCP negotiation over the tunnel
  - `codec.rs` — PPP frame encode/decode (supports both with and without `FF 03` prefix)
  - `lcp.rs` — LCP state machine (MRU, Magic-Number, Echo keepalive; rejects PFCOMP/ACCOMP)
  - `ipcp.rs` — IPCP negotiation (IPv4 + DNS assignment; handles Configure-Reject by removing rejected options)
- **`tunnel/`** — Transport layer
  - `codec.rs` — Fortinet wire frame codec (6-byte header with `0x5050` magic), including streaming `FortinetCodec` with desync recovery
  - `mod.rs` — TLS tunnel establishment (raw HTTP/1.1 upgrade to binary PPP-over-TLS)
- **`auth/`** — HTTP authentication against FortiGate
  - `mod.rs` — Credential auth, SAML/SSO auth (browser-based with localhost callback on port 8020), 2FA support (tokeninfo + HTML form + FortiToken Mobile push)
  - `xml.rs` — Tunnel config XML parser (supports both single and double-quoted attributes)
- **`main.rs`** — CLI entry point with `--saml` flag for SSO, `--username`/`--password` for credential auth
- **`error.rs`** — Error types via thiserror

### Key Protocol Details (learned from real-server testing)

- The password field in login POST is named `credential`, not `password`
- FortiGate sends LCP Configure-Request with PFCOMP (type 7) and ACCOMP (type 8) — always reject both
- PPP frames from the server may omit the `FF 03` address/control prefix — the codec handles both formats
- IPCP: server may Configure-Reject DNS options (0x81/0x82) — must resend without them. DNS is assigned via XML config instead.
- After `GET /remote/sslvpn-tunnel`, the server sends NO HTTP response on success — silently transitions to binary PPP. Some servers wait for the client to send the first LCP packet before responding.
- `GET /remote/fortisslvpn` resource reservation is required before XML config fetch or tunnel upgrade
- The server may close the TCP connection between HTTP requests — each step (login, reservation, XML, tunnel) should use a fresh TLS connection
- Real FortiGate XML uses single-quoted attributes (`ipv4='10.8.2.6'`), not double quotes
- Fortinet wire frame `total_len` = `payload_len + 6`

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
