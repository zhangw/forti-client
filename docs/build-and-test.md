# Build and Test Commands

## Quick Reference

```bash
cargo build
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
git diff --check
```

The reconnect backoff is `1, 2, 4, 8, 16, 32, 60, ...` seconds. It is preserved across transport failures, network/wake notifications, and SAML attempts, and resets only after TLS plus PPP negotiation succeeds.

Bounded operations:

- FortiGate HTTP/TLS connect: 30 seconds
- Tunnel write: 10 seconds
- SAML callback connection I/O: 5 seconds
- Whole interactive SAML callback wait: 5 minutes
- Best-effort LCP terminate: 2 seconds
- Route + DNS cleanup: one shared 10-second budget

A first Ctrl+C starts graceful shutdown. A second Ctrl+C is an explicit force-exit and returns status 130.

## Running the Client

```bash
# SAML auth (requires sudo for TUN/routes/DNS)
cargo build && sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml

# Credential auth
cargo build && sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --username user

# TLS key logging for Wireshark (requires explicit opt-in flag)
cargo build && sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml --tls-keylog-file ~/.ssl-key.log
```

**Note:** Build first, then `sudo` the binary. Don't use `sudo cargo run` (interferes with terminal input for SAML).

## Running Tests

```bash
# All tests
cargo test

# Single test file
cargo test --test fortinet_codec_test
cargo test --test ppp_codec_test
cargo test --test lcp_test
cargo test --test ipcp_test
cargo test --test routes_test
cargo test --test reconnect_test
cargo test --test network_monitor_test
cargo test --test power_monitor_test

# Specific test by name
cargo test test_encode_fortinet_frame
```


## Reconnect and Shutdown Regression Tests

```bash
cargo test --test reconnect_test
cargo test --lib auth::tests
cargo test --lib reconnect::tests
cargo test --lib tunnel::tests
cargo test --lib vpn::tests
cargo test --test signal_test
```

These tests cover typed failure policy, sticky rejected cookies, failed-cycle escalation to full re-authentication, backoff reset timing, callback fragmentation/size/deadline handling, tunnel HTTP rejection, level-triggered shutdown, unbiased ready-source progress, UserQuit termination policy, and the shared cleanup deadline.

## Manual release blockers

The automated suite does not substitute for a root-enabled macOS test gateway and IdP. Before treating this checkpoint as merge-ready, capture timestamped logs for:

1. FortiGate dead-peer/firewall block and recovery with cookie reuse and no SAML.
2. Wi-Fi off/on and sleep/wake in connect, backoff, SAML, and connected states.
3. Expired cookie with a valid IdP session, changed MFA/password, and an unavailable IdP.
4. Ctrl+C in every controller state, including a deliberately stalled cleanup and second Ctrl+C exit 130.
5. Route/DNS/IP changes and partial setup failure; verify no stale routes or `State:/Network/Service/forti-client/DNS` entry after exit.

Until this evidence exists, the real FortiGate/IdP and privileged TUN/route/DNS scenarios remain release blockers rather than silently waived checks.
