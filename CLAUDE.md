# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Rust CLI client (`forti-client`) that speaks the FortiGate SSL VPN wire protocol directly, targeting macOS. This fills a gap where no existing client provides macOS-native networking (utun + SystemConfiguration DNS) + SAML/SSO + DTLS + userspace PPP together.

**Status:** Phases 1-3 complete + security hardening. Phase 4 will add DTLS and IPv6.

## Quick Commands

```bash
cargo build                # Build
cargo test                 # Run all 50 tests
cargo clippy               # Lint

# Run with SAML (requires sudo)
cargo build && sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml
```

See `docs/build-and-test.md` for full command reference.

## Key Details

- Architecture and module layout: `docs/architecture.md`
- Wire protocol spec: `docs/fortigate_sslvpn_wire_protocol.md`
- Accepted security risks: `docs/security-review/accepted-risks.md`

## Reference Documents

### Design and Findings
- `docs/phase1-findings.md` — Phase 1 real-server findings
- `docs/phase2-findings.md` — Phase 2 real-server findings
- `docs/phase2-architecture.md` — Phase 2 data plane architecture
- `docs/superpowers/specs/2026-03-28-rust-fortigate-vpn-client-design.md` — Full design spec
- `docs/superpowers/specs/2026-03-29-phase3-reconnect-sleep-wake-design.md` — Phase 3 design spec

### Implementation Plans
- `docs/superpowers/plans/2026-03-28-forti-vpn-phase1-feasibility.md` — Phase 1
- `docs/superpowers/plans/2026-03-29-forti-client-phase2-data-plane.md` — Phase 2
- `docs/superpowers/plans/2026-03-29-phase3-reconnect-sleep-wake.md` — Phase 3
- `docs/superpowers/plans/2026-03-29-security-remediation.md` — Security remediation

### Security Review
- `docs/security-review-plan.md` — Review plan (9 areas)
- `docs/security-review/2026-03-29-security-findings.md` — Findings (6 issues, all fixed)
- `docs/security-review/2026-03-29-security-remediation-roadmap.md` — Remediation roadmap
- `docs/security-review/accepted-risks.md` — Residual risks
