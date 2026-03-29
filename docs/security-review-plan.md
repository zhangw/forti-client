# Security Review Plan for forti-client

**Target:** forti-client — a Rust CLI VPN client that speaks the FortiGate SSL VPN wire protocol on macOS. Runs as root (sudo) to create TUN devices, manage routes, and configure DNS.

**Reviewer:** Codex security review agent

---

## Codebase Overview

| Module | Path | Risk Level | Description |
|--------|------|------------|-------------|
| Auth | `src/auth/mod.rs` | High | HTTP auth, SAML/SSO, 2FA, cookie handling, localhost HTTP server |
| Auth XML | `src/auth/xml.rs` | Medium | Parses server-provided XML config |
| TLS Tunnel | `src/tunnel/mod.rs` | High | TLS connection, HTTP upgrade, binary framing |
| Tunnel Codec | `src/tunnel/codec.rs` | Medium | Fortinet wire frame parsing (untrusted input) |
| PPP | `src/ppp/` | Medium | PPP frame codec, LCP/IPCP state machines (untrusted input) |
| TUN | `src/tun/mod.rs` | Medium | Creates macOS utun device (runs as root) |
| Routes | `src/tun/routes.rs` | High | Executes `/sbin/route` as root via `Command` |
| DNS | `src/tun/dns.rs` | High | Writes to system DNS config via `scutil` as root |
| VPN | `src/vpn.rs` | Medium | Event loop, packet forwarding |
| Reconnect | `src/reconnect.rs` | Medium | State machine, re-auth flow, credential storage |
| Network Monitor | `src/network_monitor.rs` | Low | SCNetworkReachability (read-only) |
| Power Monitor | `src/power_monitor.rs` | Medium | IOKit FFI (unsafe code) |
| Main | `src/main.rs` | Medium | CLI args, password handling |
| Build | `build.rs` | Low | Links IOKit framework |

---

## Review Areas

### 1. Command Injection (Critical)

**Files:** `src/tun/routes.rs`, `src/tun/dns.rs`

The client runs as root and executes system commands. Check:

- `routes.rs`: Uses `Command::new("/sbin/route")` with args from server-provided XML config (`Route.ip`, `Route.mask`). Can a malicious server inject shell commands via crafted IP/mask values?
  - How are `Route.ip` and `Route.mask` parsed? (Check `src/auth/xml.rs`)
  - Are they validated as `Ipv4Addr` before being passed to `Command`?
  - Is `Command` used with `.arg()` (safe) or string interpolation (unsafe)?

- `dns.rs`: Uses `scutil` with stdin piped input. Check:
  - Can server-provided DNS server addresses inject scutil commands?
  - Is the scutil input constructed safely (no string interpolation of untrusted data)?
  - Are DNS server addresses validated as `Ipv4Addr`?

### 2. TLS Configuration (Critical)

**Files:** `src/auth/mod.rs`, `src/tunnel/mod.rs`

- Is certificate verification enabled? Check `rustls::ClientConfig` setup.
- Is there any `danger_accept_invalid_certs` or equivalent?
- Is the server name validated against the certificate?
- Is TLS 1.2+ enforced (no SSLv3/TLS 1.0/1.1)?
- Is `SSLKEYLOGFILE` support safe? (Only writes when env var is set — check it doesn't write to unexpected locations)

### 3. Credential Handling (Critical)

**Files:** `src/main.rs`, `src/auth/mod.rs`, `src/reconnect.rs`

- Password is read from stdin in `main.rs`. Is it stored securely?
- `AuthParams` in `reconnect.rs` stores `password: Option<String>` in plain text for re-auth. Is this acceptable? Is it zeroed on drop?
- `SVPNCOOKIE` is stored as `String`. Is it logged anywhere? (Check all `debug!`/`info!` calls)
- Does the SAML callback server (`127.0.0.1:8020`) validate the origin of requests? Could a local attacker inject a fake SAML response?

### 4. Untrusted Input Parsing (High)

**Files:** `src/tunnel/codec.rs`, `src/ppp/codec.rs`, `src/ppp/lcp.rs`, `src/ppp/ipcp.rs`, `src/auth/xml.rs`

All data from the FortiGate server is untrusted (could be a MITM or malicious server).

- **Fortinet codec** (`tunnel/codec.rs`): Parses 6-byte headers with length fields. Check for:
  - Integer overflow in length calculations
  - Buffer overread if `payload_len` exceeds actual data
  - Allocation based on untrusted length (denial of service via huge allocation)

- **PPP codec** (`ppp/codec.rs`): Parses PPP frames. Check for:
  - Length validation before slicing
  - Panic on malformed packets (unwrap/expect on untrusted data)

- **LCP/IPCP** (`ppp/lcp.rs`, `ppp/ipcp.rs`): State machines processing server packets. Check for:
  - Bounds checking on option parsing
  - State machine confusion attacks (unexpected packet sequences)

- **XML parser** (`auth/xml.rs`): Hand-rolled XML parsing. Check for:
  - Does it handle malicious XML (deeply nested, huge attributes, entity expansion)?
  - Can crafted XML produce invalid `Ipv4Addr` values that bypass route/DNS validation?

### 5. Unsafe Code (High)

**Files:** `src/power_monitor.rs`

- Review all `unsafe` blocks in `power_monitor.rs`:
  - `Box::into_raw` / `Box::from_raw` lifecycle — is the raw pointer always reclaimed?
  - `IORegisterForSystemPower` callback — is the function pointer ABI correct (`extern "C"`)?
  - Is the `PowerCallbackContext` valid for the entire callback lifetime?
  - Can `IOAllowPowerChange` be called with an invalid `root_port` (the two-phase init pattern)?
  - Are all error paths cleaning up the raw pointer?

### 6. Network Exposure (High)

**Files:** `src/auth/mod.rs`

- The SAML callback runs an HTTP server on `127.0.0.1:8020`:
  - Is it bound to localhost only? (not `0.0.0.0`)
  - Does it accept only one connection then stop?
  - Could a race condition allow a local attacker to connect before the real SAML callback?
  - Is the session ID validated before exchanging for SVPNCOOKIE?
  - Is the HTTP response sanitized (no XSS in the auto-close HTML)?

### 7. Privilege Escalation (Medium)

**Files:** `src/auth/mod.rs`, `src/tun/routes.rs`, `src/tun/dns.rs`

- The binary runs as root. Check:
  - Does it drop privileges after creating TUN/routes/DNS? (Currently: no)
  - SAML browser open uses `sudo -u $SUDO_USER open` — can `SUDO_USER` be spoofed?
  - Are there any `Command::new()` calls that use user-controlled paths?

### 8. Denial of Service (Medium)

**Files:** `src/tunnel/codec.rs`, `src/vpn.rs`, `src/reconnect.rs`

- Can the server send a frame with a huge length, causing OOM?
- Can the server flood with packets faster than the client can process?
- Reconnect loop retries indefinitely — is the backoff sufficient to prevent resource exhaustion?
- Channel capacities (16 for network, 8 for power) — can they be overwhelmed?

### 9. Information Disclosure (Medium)

**Files:** All files with `debug!`/`info!`/`warn!`/`error!` logging

- Are credentials, cookies, or session IDs logged at any log level?
- Is the SSLKEYLOGFILE path validated?
- Are server error responses logged in full (could contain sensitive info)?

---

## How to Run the Review

### Step 1: Read the high-risk files

Read each file listed above, focusing on the specific checks described.

### Step 2: Search for dangerous patterns

```
# Search for all Command::new usage (shell execution)
grep -rn "Command::new" src/

# Search for unsafe blocks
grep -rn "unsafe" src/

# Search for unwrap/expect on potentially untrusted data
grep -rn "\.unwrap()" src/
grep -rn "\.expect(" src/

# Search for credential/cookie logging
grep -rn "cookie\|SVPNCOOKIE\|password\|credential" src/ | grep -i "debug\|info\|warn\|error"

# Search for format! used in Command args (injection risk)
grep -rn "format!" src/tun/

# Search for string indexing without bounds check
grep -rn "\[.*\.\." src/ppp/ src/tunnel/
```

### Step 3: Check dependencies for known vulnerabilities

```bash
# Install cargo-audit if not present
cargo install cargo-audit

# Run audit
cargo audit
```

### Step 4: Report findings

For each finding, report:
- **Severity:** Critical / High / Medium / Low / Informational
- **File:Line:** Exact location
- **Issue:** What the vulnerability is
- **Impact:** What an attacker could do
- **Fix:** Recommended remediation
