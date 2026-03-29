# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Rust CLI client (`forti-client`) that speaks the FortiGate SSL VPN wire protocol directly, targeting macOS. This fills a gap where no existing client provides macOS-native networking (utun + SystemConfiguration DNS) + SAML/SSO + DTLS + userspace PPP together.

**Status:** Phases 1–3 complete + security hardening. SAML auth, TLS tunnel, PPP negotiation, TUN device, split-tunnel routing, DNS, keepalive, packet forwarding, auto-reconnect with exponential backoff, network change detection (SCNetworkReachability), and macOS sleep/wake handling (IOKit) all work end-to-end. Security review completed: log redaction, SAML callback hardening, credential memory protection (`secrecy`), TLS keylog opt-in. Phase 4 will add DTLS and IPv6.

## Build and Test Commands

```bash
# Build
cargo build

# Run all tests (50 tests across 8 test files + auth unit tests)
cargo test

# Run a single test file
cargo test --test fortinet_codec_test
cargo test --test ppp_codec_test
cargo test --test lcp_test
cargo test --test ipcp_test
cargo test --test routes_test
cargo test --test reconnect_test
cargo test --test network_monitor_test
cargo test --test power_monitor_test

# Run a specific test by name
cargo test test_encode_fortinet_frame

# Run with SAML auth (requires sudo for TUN/routes/DNS)
cargo build && sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml

# Run with credential auth
cargo build && sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --username user

# Run with TLS key logging for Wireshark analysis (requires explicit opt-in flag)
cargo build && sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml --tls-keylog-file ~/.ssl-key.log

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
        -> Raw IP packets read/written to macOS utun device
```

### Module Layout (`src/`)

- **`ppp/`** — Standalone PPP engine with no network dependencies (testable in isolation)
  - `mod.rs` — `PppEngine` orchestrating LCP + IPCP negotiation; `into_lcp()` exposes LCP state for post-negotiation keepalive
  - `codec.rs` — PPP frame encode/decode (supports both with and without `FF 03` prefix)
  - `lcp.rs` — LCP state machine (MRU, Magic-Number, Echo keepalive, Terminate-Request; rejects PFCOMP/ACCOMP)
  - `ipcp.rs` — IPCP negotiation (IPv4 + DNS assignment; handles Configure-Reject by removing rejected options)
- **`tunnel/`** — Transport layer
  - `codec.rs` — Fortinet wire frame codec (6-byte header with `0x5050` magic), including streaming `FortinetCodec` with desync recovery
  - `mod.rs` — TLS tunnel establishment (raw HTTP/1.1 upgrade to binary PPP-over-TLS)
- **`auth/`** — HTTP authentication against FortiGate
  - `mod.rs` — Credential auth, SAML/SSO auth (browser-based with localhost callback on port 8020, hardened with request validation + 5-min timeout + 5-sec per-connection read timeout), 2FA support (tokeninfo + HTML form + FortiToken Mobile push). Debug logs redact SVPNCOOKIE and session IDs.
  - `xml.rs` — Tunnel config XML parser (supports both single and double-quoted attributes)
- **`tun/`** — macOS network configuration
  - `mod.rs` — TUN device creation via `tun-rs` (utun)
  - `routes.rs` — Split-tunnel route install/remove via `/sbin/route`
  - `dns.rs` — DNS configuration via `scutil` (supplemental resolver)
- **`vpn.rs`** — Data plane event loop: `tokio::select!` multiplexing TUN reads, tunnel reads, LCP keepalive timer, timing gap heuristic, and Ctrl+C. Provides `setup_tun()`, `cleanup_tun()`, and `event_loop()` (returns `DisconnectReason`).
- **`reconnect.rs`** — `ReconnectController` state machine wrapping the event loop. Owns TUN/routes/DNS lifetime (persist across reconnects). Handles `DisconnectReason`/`ReconnectAction` classification, `Backoff` (exponential, 1s–60s cap), cookie reuse fast path, automatic SAML re-auth, `WaitingForNetwork` state for sleep/wake, and `detect_sleep_gap` timing heuristic.
- **`network_monitor.rs`** — `NetworkMonitor` using `system-configuration` crate for SCNetworkReachability callbacks. Dedicated thread with CFRunLoop, sends `NetworkEvent::Reachable`/`Unreachable` via tokio channel. Cancels backoff on network return.
- **`power_monitor.rs`** — `PowerMonitor` using IOKit FFI for macOS sleep/wake notifications (`WillSleep`, `HasPoweredOn`). Dedicated thread with CFRunLoop, sends `PowerEvent` via tokio channel. Acknowledges sleep via `IOAllowPowerChange`.
- **`main.rs`** — CLI entry point with `--saml` flag for SSO, `--username`/`--password` for credential auth, `--tls-keylog-file` for opt-in TLS key logging (with path validation). Password stored as `SecretString` (zeroized on drop). Delegates to `ReconnectController` after initial authentication.
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

### macOS Platform Details (learned from live testing)

- **TUN (tun-rs 2.8.1)**: Uses `DeviceBuilder::new().ipv4(ip, 32, None).build_async()`. tun-rs handles AF headers internally — read/write raw IP packets directly (no 4-byte AF prefix). Detect IP version from first nibble (`0x4`=IPv4, `0x6`=IPv6).
- **DNS**: `scutil` input must have no leading whitespace. Stdin must be closed after writing for scutil to process commands. Use `SupplementalMatchDomains * ""` for catch-all supplemental resolver.
- **Routes**: `/sbin/route add -net <ip>/<prefix> -interface <utun>` for subnets, `-host <ip>` for /32. Tolerate "File exists" errors.
- **Privilege**: Requires `sudo` — build first, then `sudo ./target/debug/forti-client`. Don't use `sudo cargo run` (interferes with terminal input for SAML).

### Known Accepted Risks

- **SAML callback local race (medium):** The localhost SAML callback server (port 8020) validates request structure (GET + non-empty `id=`) and has timeouts, but cannot bind a cryptographic nonce to the browser session. FortiGate controls the callback URL (`http://127.0.0.1:8020/`) and `/remote/saml/start` does not accept a custom `state` parameter. A local attacker who knows the protocol can still race a valid-looking `id=` request. Mitigation: the `id` is validated server-side during the cookie exchange — a forged `id` will fail, producing an auth error rather than a hijacked session. This is a protocol-level limitation shared with openfortivpn.
- **Transitive unmaintained crate (`paste`, RUSTSEC-2024-0436):** No CVE, dependency is deep-transitive via the networking stack. Tracked for upstream migration.

### Tech Stack

Rust 2021 edition, tokio 1.x (full), hyper 1.8, rustls 0.23, tokio-rustls 0.26, tun-rs 2.8, clap 4, tracing 0.1, thiserror 2, bytes 1.x, secrecy 0.10 (credential zeroization), system-configuration 0.6 (SCNetworkReachability), core-foundation 0.9 (CFRunLoop), IOKit (FFI). DTLS will use `openssl` crate (only mature DTLS option in Rust).

## Reference Documents

- `docs/fortigate_sslvpn_wire_protocol.md` — Complete wire protocol spec (reverse-engineered from OpenConnect + openfortivpn)
- `docs/phase1-findings.md` — Phase 1 real-server findings: protocol deviations, negotiation trace, SAML flow
- `docs/phase2-findings.md` — Phase 2 real-server findings: tun-rs AF header behavior, DNS scutil format, live test results
- `docs/phase2-architecture.md` — Phase 2 data plane architecture design
- `docs/superpowers/specs/2026-03-28-rust-fortigate-vpn-client-design.md` — Full design spec with crate ecosystem analysis
- `docs/superpowers/plans/2026-03-28-forti-vpn-phase1-feasibility.md` — Phase 1 implementation plan
- `docs/superpowers/plans/2026-03-29-forti-client-phase2-data-plane.md` — Phase 2 implementation plan
- `docs/superpowers/specs/2026-03-29-phase3-reconnect-sleep-wake-design.md` — Phase 3 design spec (reconnect, network detection, sleep/wake)
- `docs/superpowers/plans/2026-03-29-phase3-reconnect-sleep-wake.md` — Phase 3 implementation plan
- `docs/security-review-plan.md` — Security review plan for Codex agent (9 review areas)
- `docs/security-review/2026-03-29-security-findings.md` — Security audit findings (6 findings)
- `docs/security-review/2026-03-29-security-remediation-roadmap.md` — Remediation roadmap (all fixed)
- `docs/superpowers/plans/2026-03-29-security-remediation.md` — Security remediation implementation plan
