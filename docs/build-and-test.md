# Build and Test Commands

## Quick Reference

```bash
cargo build                # Build
cargo test                 # Run all 50 tests
cargo check                # Check without building
cargo clippy               # Lint
```

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
