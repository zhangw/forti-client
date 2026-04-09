# forti-client

A Rust CLI client for FortiGate SSL VPN on macOS. Connects to FortiGate gateways using the native PPP-over-TLS protocol with userspace networking — no pppd, no kernel extensions, no FortiClient required.

## Features

- **SAML/SSO authentication** — opens your default browser for IdP login (Okta, Azure AD, etc.)
- **Credential authentication** — username/password with 2FA support (OTP, FortiToken Mobile push)
- **Split-tunnel routing** — installs only the routes pushed by the FortiGate
- **DNS configuration** — configures macOS resolver via `scutil`
- **LCP keepalive** — automatic dead peer detection
- **Auto-reconnect** — exponential backoff, network change detection, sleep/wake handling
- **Graceful cleanup** — removes routes, DNS, and TUN device on disconnect

## Requirements

- macOS (uses utun kernel interface)
- Rust toolchain (stable)
- Root privileges (`sudo`) for TUN device, routes, and DNS

## Build

```bash
git clone <repo-url>
cd forti-client
cargo build --release
```

The binary is at `target/release/forti-client`.

## Usage

### SAML/SSO (most common)

```bash
sudo ./target/release/forti-client --server sslvpn.example.com --port 10443 --saml
```

This will:
1. Open your browser for SAML login
2. Complete authentication via your IdP
3. Negotiate a PPP tunnel
4. Create a utun interface with your assigned IP
5. Install split-tunnel routes
6. Configure DNS

Press **Ctrl+C** to disconnect cleanly.

### Username/Password

```bash
sudo ./target/release/forti-client --server sslvpn.example.com --username user@domain.com
```

You'll be prompted for your password. If 2FA is enabled, you'll be prompted for the verification code.

### Options

```
  -s, --server <SERVER>              VPN gateway hostname or IP (required)
  -p, --port <PORT>                  VPN gateway port [default: 443]
  -u, --username <USERNAME>          Username (not needed for --saml)
  -P, --password <PASSWORD>          Password (if omitted, will prompt)
      --realm <REALM>                Realm/user-group (optional)
      --saml                         Use SAML/SSO authentication
      --tls-keylog-file <PATH>       TLS key logging for Wireshark (opt-in)
```

### Verbose logging

```bash
sudo RUST_LOG=debug ./target/release/forti-client --server sslvpn.example.com --saml
```

### TLS key logging (for Wireshark)

```bash
sudo ./target/release/forti-client --server sslvpn.example.com --saml --tls-keylog-file ~/.ssl-key.log
```

Then in Wireshark: **Preferences > Protocols > TLS > (Pre)-Master-Secret log filename** → point to `~/.ssl-key.log`.

**Note:** TLS key logging is disabled by default and requires the explicit `--tls-keylog-file` flag. The path is validated (symlinks and world-writable directories are rejected).

## Verify it's working

While connected, in another terminal:

```bash
# Check the TUN interface
ifconfig utun4

# Check installed routes
netstat -rn | grep utun4 | head -10

# Check DNS configuration
scutil --dns | grep -A 5 forti-client

# Test connectivity to an internal host
ping 10.0.0.1
```

## How it works

```
App traffic → macOS routing table → utun device
  → forti-client reads IP packet
    → wraps in PPP frame → wraps in Fortinet frame
      → sends over TLS to FortiGate
        → FortiGate routes to internal network

Reply from internal network → FortiGate
  → Fortinet frame over TLS → forti-client decodes
    → writes IP packet to utun
      → macOS delivers to app
```

The protocol stack:

```
TLS (rustls) → Fortinet Wire Frame (0x5050 magic)
  → PPP (LCP/IPCP/IPv4) → Raw IP packets → utun
```

## Limitations

- macOS only (uses utun kernel interface)
- TLS tunnel only (no DTLS/UDP acceleration yet)
- No IPv6 support yet
- Requires `sudo` (no privilege separation yet)
- SAML callback listens on port 8020 (must be free)

## License

Apache-2.0
