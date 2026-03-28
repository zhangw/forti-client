# Tech Stack Analysis: Rust FortiGate SSL VPN Client

A feasibility study and architectural design for a standalone Rust CLI client that speaks the FortiGate SSL VPN wire protocol directly, with first-class SAML/SSO support on macOS.

---

## 1. Existing Landscape

### 1.1 openfortivpn

An open-source C client (~210KB) that implements the FortiGate SSL VPN v1 protocol.

**What it got right:**
- Full SSL VPN v1 protocol (HTTP auth, PPP-over-TLS, LCP/IPCP keepalive)
- SAML support via built-in HTTP server on port 8020 (`--saml-login`)
- `--cookie-on-stdin` for external SAML cookie injection
- Simple, self-contained codebase
- Available on macOS via Homebrew

**What it got wrong on macOS:**
- Depends on Apple's ancient, divergent pppd (v2.4.2) — causes kernel panics on Apple Silicon (issue #1278), route hijacking ignoring `nodefaultroute` (issue #1310), DNS configuration races
- DNS via `/etc/resolv.conf` — macOS ignores this file entirely; needs SystemConfiguration framework (issue #534, open since 2019)
- No DTLS — TCP-over-TCP performance penalty (issue #473, open since 2019)
- No IPv6 support
- No userspace PPP (PR #1048 open since 2022, never merged)
- pppd is a dead end on macOS — Apple deprecated kernel extensions and pppd's route/DNS integration is fundamentally broken

### 1.2 OpenConnect (`--protocol=fortinet`)

A mature multi-protocol C VPN client with experimental Fortinet support (added March 2021).

**What it got right:**
- Userspace PPP stack (~1800 lines in `ppp.c`) — no pppd dependency
- Own TUN device management
- DTLS support for Fortinet (PPP-over-DTLS)
- Embedded PPP eliminates all pppd-related macOS issues

**What it got wrong:**
- **No SAML support for Fortinet** — dealbreaker for SSO environments (GitLab issue #356)
- DTLS broken on macOS for Fortinet (GitLab issue #637)
- Fortinet support still marked "experimental"
- DTLS performance lower than expected (~100Mbps vs openfortivpn's ~320Mbps over TLS)

### 1.3 Rust-Based Alternatives

**None exist.** No Rust implementation of the FortiGate SSL VPN or IPsec protocol was found. The closest Rust VPN projects are:
- `GlobalProtect-openconnect` (Rust + Tauri) — Palo Alto GlobalProtect, not Fortinet
- `tun-rs` — cross-platform TUN/TAP crate (useful as a building block)
- `EasyTier`, `vnt` — mesh VPNs, not Fortinet-compatible

### 1.4 The Gap

No existing client provides: macOS-native networking (utun + SystemConfiguration DNS) + SAML/SSO + DTLS + userspace PPP. That is the gap this project fills.

---

## 2. Protocol Reference — FortiGate SSL VPN

### 2.1 Authentication Phase (HTTPS)

```
Client                                    FortiGate
  |  POST /remote/logincheck              |
  |  credential=user&ajax=1               |
  |  &just_logged_in=1                    |
  |  ────────────────────────────────►    |
  |                                        |
  |  Set-Cookie: SVPNCOOKIE=xxx           |
  |  ◄────────────────────────────────    |
  |                                        |
  |  GET /remote/fortisslvpn              |
  |  Cookie: SVPNCOOKIE=xxx               |
  |  ────────────────────────────────►    |  (reserve resources)
  |                                        |
  |  GET /remote/fortisslvpn_xml          |
  |  ────────────────────────────────►    |  (IP, DNS, routes, DTLS config)
  |                                        |
  |  GET /remote/sslvpn-tunnel            |
  |  ────────────────────────────────►    |  (upgrade to binary tunnel)
  |                                        |
  |  ═══ PPP-over-TLS begins ═══         |
```

Key details:
- The credential field name is literally `credential`, not `password`
- Response codes: 200 + cookie = success, 200 without cookie = 2FA needed, 401 = HTML 2FA form, 405 = bad credentials
- 2FA flow: second `POST /remote/logincheck` with `code=<OTP>&code2=<backup_code>`
- Client certificate auth: presented during TLS handshake, server validates before logincheck

### 2.2 SAML/SSO Authentication

```
Client                     Browser              IdP              FortiGate
  |                          |                    |                  |
  |  Start HTTP server       |                    |                  |
  |  on 127.0.0.1:8020       |                    |                  |
  |                          |                    |                  |
  |  Open browser ───────►   |                    |                  |
  |  https://gw/remote/      |                    |                  |
  |  saml/start?redirect=1   |  ──────────────►   |                  |
  |                          |                    |  SAML challenge  |
  |                          |  ◄──────────────   |                  |
  |                          |  User logs in      |                  |
  |                          |  ──────────────►   |                  |
  |                          |                    |  SAML assertion  |
  |                          |                    |  ──────────────► |
  |                          |  Redirect to       |                  |
  |  ◄─────────────────────  |  127.0.0.1:8020    |                  |
  |  ?id=<session_id>        |  /?id=<id>         |                  |
  |                          |                    |                  |
  |  GET /remote/saml/auth_id?id=<id>             |                  |
  |  ─────────────────────────────────────────────────────────────►  |
  |  Set-Cookie: SVPNCOOKIE=xxx                                      |
  |  ◄─────────────────────────────────────────────────────────────  |
```

The SAML callback URL pattern is `127.0.0.1:8020` (FortiClient's default). After receiving the `?id=` parameter, the client exchanges it for an `SVPNCOOKIE` via `GET /remote/saml/auth_id?id=<id>`. From this point the flow is identical to credential auth.

Known variation: some FortiGate configurations use a different redirect path (openfortivpn issue #1284). The client should accept any request to the callback server containing an `id` parameter.

### 2.3 Tunnel Configuration (XML)

`GET /remote/fortisslvpn_xml?dual_stack=1` returns:

```xml
<sslvpn-tunnel>
  <dtls-config>          <!-- DTLS port, CipherSuite -->
  <fos>7.2.9</fos>       <!-- FortiOS version -->
  <tunnel-method value="ppp"/>  <!-- "ppp" = v1, "tun" = v2 -->
  <auth-ses/>             <!-- session token for reconnect -->
  <ipv4>
    <assigned-addr/>      <!-- client IP -->
    <dns/><dns2/>         <!-- DNS servers -->
    <nbns/>               <!-- WINS servers (legacy) -->
    <split-tunneling-info>
      <addr ip="x.x.x.x" mask="y.y.y.y"/>  <!-- routes to push -->
    </split-tunneling-info>
  </ipv4>
  <ipv6>
    <assigned-addr6/>
    <dns6/>
  </ipv6>
  <idle-timeout/>
  <auth-timeout/>
  <tun-connect-without-reauth/>  <!-- session resumption support -->
</sslvpn-tunnel>
```

### 2.4 PPP-over-TLS Wire Format

Each frame on the TLS connection:

```
Bytes:  [0..1]     [2..3]     [4..5]     [6..9]       [10+]
        total_len  0x50 0x50  payload_len FF 03 PP PP  PPP payload
        (BE16)     (magic)    (BE16)     (HDLC hdr)
```

- `total_len` = `payload_len + 6` (i.e., the total frame size on the wire minus the first 2 bytes of `total_len` itself; equivalently, `total_len` counts from byte 2 onward)
- PPP header is always 4 bytes (`FF 03` address/control + 2-byte big-endian protocol) — FortiGate rejects protocol/address-control field compression
- Protocol values: `0xC021` = LCP, `0x8021` = IPCP, `0x0021` = IPv4 data, `0x8057` = IP6CP, `0x0057` = IPv6 data
- Maximum frame size: negotiated via LCP MRU (typically 1500)

### 2.5 PPP Negotiation

| Phase | What happens |
|-------|-------------|
| **LCP** | Negotiate MRU and Magic-Number. FortiGate sends Configure-Request with PFCOMP/ACCOMP; we reject both. Exchange Magic-Numbers. |
| **IPCP** | Server assigns IPv4 address (option 3), primary DNS (option 129), secondary DNS (option 130), primary NBNS (option 131), secondary NBNS (option 132). Client sends Configure-Request with 0.0.0.0 to request assignment. |
| **IP6CP** | Interface identifier exchange (8 bytes each). |
| **CCP** | FortiGate may send Configure-Request for compression. Reject with Configure-Reject (no compression needed). |
| **Keepalive** | LCP Echo-Request/Reply for dead peer detection. Interval typically 10-30s. Missing 3+ echoes = dead peer. |

### 2.6 DTLS Data Channel

After the TLS tunnel is established, the client may optionally open a DTLS session on the same gateway port (typically UDP/443):

```
Standard DTLS 1.0/1.2 handshake
  → Application data: "GFtype\0clthello\0SVPNCOOKIE\0<cookie>\0"
  ← Application data: "GFtype\0svrhello\0handshake\0ok\0"
```

Once established, PPP data frames move to DTLS (same 6-byte Fortinet header + PPP framing). The TLS tunnel remains open as fallback/control channel. If DTLS fails or times out, the client falls back to TLS transparently.

Benefits: avoids TCP-over-TCP performance degradation for bulk data transfer.

### 2.7 SSL VPN Deprecation Timeline

| FortiOS Version | SSL VPN Status |
|----------------|----------------|
| < 7.6 | Full support |
| 7.6.0 | Removed from 2GB RAM models (FG-40F, FG-60F, etc.) |
| 7.6.3+ | **Removed from ALL models**, replaced by IPsec VPN |

Many enterprises will remain on FortiOS < 7.6 for years. SSL VPN implementation remains viable and necessary for the foreseeable future.

---

## 3. macOS Platform Challenges

### 3.1 TUN Device (utun)

macOS uses a kernel control socket mechanism (not `/dev/net/tun` like Linux):

```c
socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
  → ioctl(CTLIOCGINFO, "com.apple.net.utun_control")
  → connect(sockaddr_ctl { sc_unit = N+1 })  // N=0 → utun0
  → getsockopt(UTUN_OPT_IFNAME)              // get assigned name
```

Critical differences from Linux:
- Every packet has a mandatory 4-byte AF header (`AF_INET=2` for IPv4, `AF_INET6=30` for IPv6) — cannot be disabled
- Interface names are always `utunN` (kernel-assigned or explicit)
- **Requires root** — no capability-based alternative like Linux's `CAP_NET_ADMIN`

The PPP layer must handle this: strip the 4-byte AF header when reading from utun (before PPP-encoding), prepend it when writing to utun (after PPP-decoding).

### 3.2 DNS — The Biggest macOS Trap

`/etc/resolv.conf` is a dead file on macOS. The system resolver uses SystemConfiguration framework (`configd` daemon). This is why openfortivpn's DNS is broken (issue #534, open since 2019).

Three approaches, ranked by practicality:

| Approach | Mechanism | Split DNS | Complexity |
|----------|-----------|-----------|------------|
| `/etc/resolver/<domain>` files | Drop file per domain, macOS auto-reads | Yes (by domain) | Low |
| `scutil` shell-out | Write to SCDynamicStore via CLI | Yes | Medium |
| `SCDynamicStore` API | Programmatic via SystemConfiguration.framework | Yes | High |

Recommended strategy:
- `/etc/resolver/` for split DNS (one file per VPN domain, containing `nameserver <ip>`)
- `scutil` for the default resolver override if full tunnel mode is used
- This is what Tailscale and WireGuard-Go do in practice

### 3.3 Route Management

Routes require root per `route(4)`: "only carried out by the super user".

Two options:
- Shell out to `/sbin/route` — simple, debuggable, proven
- `PF_ROUTE` socket — programmatic, async-friendly, can also monitor route changes

For split tunneling, the FortiGate XML config pushes a route list under `<split-tunneling-info>`. The client iterates and adds each via `route add -net <dest>/<prefix> -interface <utun>`.

By implementing PPP in userspace and using utun directly, the pppd route hijack problem (Apple's pppd ignores `nodefaultroute`) disappears entirely.

### 3.4 Sleep/Wake

Two notification mechanisms:

| API | Events | Notes |
|-----|--------|-------|
| `IORegisterForSystemPower` (IOKit) | `WillSleep`, `WillPowerOn`, `HasPoweredOn` | Can delay sleep acknowledgment up to 30s |
| `SCNetworkReachability` (SystemConfiguration) | Network status changes | Fires when WiFi reassociates after wake |

Correct reconnection sequence:
1. `WillSleep` → gracefully close tunnel, save session state
2. `HasPoweredOn` → mark "needs reconnect", don't act yet
3. `SCNetworkReachability` callback → network is actually back, now reconnect
4. If reconnect fails, exponential backoff (1s, 2s, 4s)

This avoids the race where the system is "awake" but WiFi hasn't reconnected yet.

### 3.5 Network Extension Framework

Apple's official VPN path. Manages utun, DNS, routes automatically via `NEPacketTunnelNetworkSettings`.

| Aspect | Reality |
|--------|---------|
| Required? | No — utun + routes + scutil works without it |
| CLI-compatible? | No — must be packaged in an app bundle as a system extension |
| Entitlement | Restricted — requires Apple Developer Program ($99/yr) |
| Benefit | Automatic DNS/route management, macOS VPN UI integration |

For a Rust CLI tool: skip Network Extension. Tailscale's open-source `tailscaled` uses raw utun + routes + scutil and runs as a launchd daemon. This is the proven CLI-compatible path. Network Extension can be added later as an optional distribution mode.

### 3.6 Privilege Model

| Operation | Root Required? |
|-----------|---------------|
| Create utun | Yes |
| Modify routes | Yes |
| Write DNS config (scutil / /etc/resolver/) | Yes |
| Bind port 8020 (SAML callback) | No (> 1024) |
| Read network state | No |

Recommended approach:
- **Phase 1:** Run entire binary as root via `sudo` (like openfortivpn, OpenConnect, WireGuard-Go)
- **Phase 2:** Split into privileged launchd daemon + unprivileged CLI front-end over Unix socket

### 3.7 Code Signing and Distribution

| Requirement | Needed for CLI? |
|-------------|----------------|
| Code signing | Recommended (Gatekeeper) |
| Notarization | Practically required on macOS Sequoia+ |
| Hardened Runtime | Required for notarization |
| Developer ID | $99/yr Apple Developer Program |

Without notarization on macOS Sequoia, users must manually allow the binary in System Settings > Privacy & Security. Homebrew formulae that build from source avoid this issue.

---

## 4. Rust Crate Ecosystem

### 4.1 TLS + DTLS

| Component | Crate | Version | Rationale |
|-----------|-------|---------|-----------|
| TLS (auth + tunnel) | `rustls` | 0.23 | Pure Rust, TLS 1.2/1.3, client certs, session resumption |
| DTLS (data channel) | `openssl` | 0.10 | Only mature DTLS option in Rust. `SslMethod::dtls()` |
| Tokio integration | `tokio-rustls` / `tokio-openssl` | latest | Async wrappers |

Why two TLS libraries: `rustls` has no DTLS support and none is planned. `openssl` is the only production-ready DTLS in Rust. Split: rustls for HTTPS auth + TLS tunnel, openssl for optional DTLS data channel.

### 4.2 TUN Device

| Crate | Version | macOS | Async | Recommendation |
|-------|---------|-------|-------|----------------|
| `tun-rs` | 2.8.2 | Yes (utun) | Tokio + async-io | **Use this** |
| `tun` (meh/rust-tun) | 0.8.6 | Yes | Limited | Less active |
| Raw via `nix` | 0.31.2 | Yes | Manual | Fallback only |

`tun-rs` is the clear winner — actively maintained, cross-platform, handles the 4-byte utun AF header transparently, tokio-native async.

### 4.3 HTTP (Auth + Tunnel Upgrade)

| Crate | Version | Connection Hijack | Cookie Jar |
|-------|---------|-------------------|------------|
| `hyper` | 1.8 | **Yes** — `conn::http1::handshake()` → `into_parts()` | No (add `cookie_store`) |
| `reqwest` | 0.13 | No — abstracts away the connection | Yes |

Critical choice: after `GET /remote/sslvpn-tunnel`, the HTTP connection must transition to raw binary PPP framing on the same TLS socket. `reqwest` hides the socket; `hyper` exposes it.

Recommendation: `hyper` directly, with `cookie_store` (0.22) for SVPNCOOKIE management, and `hyper` also for the SAML callback server on `127.0.0.1:8020`.

### 4.4 PPP Implementation

**No Rust PPP crate exists** (the `ppp` crate on crates.io is HAProxy Proxy Protocol).

| Option | Effort | Recommendation |
|--------|--------|----------------|
| Implement in Rust from OpenConnect's `ppp.c` | ~1500-2000 lines | **Yes** |
| Spawn system pppd | Low | No — all the macOS problems |
| FFI to OpenConnect's ppp.c | Medium | No — mixes C into build |

The PPP subset needed is small: LCP (MRU, Magic-Number, Echo), IPCP (IPv4 + DNS assignment), IP6CP (interface identifier), CCP (reject). Frame codec: 6-byte Fortinet header + 4-byte PPP header. OpenConnect's `ppp.c` serves as the reference implementation.

### 4.5 Async Runtime

**`tokio`** with `features = ["full"]`. No realistic alternative — `async-std` is discontinued (March 2025), `smol` has a tiny ecosystem. Every crate above integrates natively with tokio.

Core features used:
- `tokio::select!` — multiplex TUN reads, TLS/DTLS reads, timers, signals
- `tokio::signal` — SIGINT/SIGTERM for graceful shutdown
- `tokio::time::interval` — keepalive timers
- `tokio::net::UdpSocket` — DTLS transport

### 4.6 System Integration (macOS)

| Component | Crate / Approach | Notes |
|-----------|-----------------|-------|
| Routes | `net-route` 0.4.6 | Cross-platform async, PF_ROUTE on macOS |
| DNS | Shell out to `scutil` + `/etc/resolver/` files | Proven (Tailscale, WireGuard-Go) |
| Sleep/wake | IOKit via raw FFI (~30 lines `unsafe`) | `IORegisterForSystemPower` |
| Network reachability | `system-configuration` 0.7.0 | `SCNetworkReachability` callbacks, by Mullvad team |
| Privilege | `nix` 0.31.2 | `setuid()`, fd passing |
| Keychain certs | `security-framework` 3.7.0 | Client certificate access |

### 4.7 CLI + Config + Logging

| Role | Crate | Version |
|------|-------|---------|
| CLI | `clap` | 4.6 |
| Config | `toml` + `serde` | 1.1 / 1.0 |
| Logging | `tracing` + `tracing-subscriber` | 0.1 / 0.3 |
| Signals | `tokio::signal` | (part of tokio) |

### 4.8 macOS FFI Integration Patterns

Three patterns are used for macOS system integration:

**Pattern 1 — Crate wraps the C framework (most components):**
Crates like `system-configuration` and `security-framework` provide safe Rust APIs. The `-sys` subcrate handles `#[link(name = "SystemConfiguration", kind = "framework")]`. No `unsafe` in your code.

**Pattern 2 — Shell out to system CLI tools (DNS, routes fallback):**
`std::process::Command` calls `scutil` or `/sbin/route`. No FFI, no `unsafe`. Simple and debuggable.

**Pattern 3 — Raw FFI (IOKit sleep/wake only):**
~30-50 lines of `extern "C"` declarations + `unsafe` calls to `IORegisterForSystemPower`. Requires `println!("cargo:rustc-link-lib=framework=IOKit")` in `build.rs`.

Total hand-written `unsafe` FFI: ~30-50 lines for IOKit only. Everything else is handled by crates or shell-out.

### 4.9 Consolidated Dependency Set

```toml
[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# TLS (auth + TLS tunnel)
rustls = "0.23"
tokio-rustls = "0.26"

# DTLS (data tunnel, phase 2)
openssl = "0.10"
tokio-openssl = "0.6"

# TUN device
tun-rs = { version = "2.8", features = ["async"] }

# HTTP (auth flow + SAML server + tunnel upgrade)
hyper = { version = "1.8", features = ["http1", "client", "server"] }
hyper-util = "0.1"
hyper-rustls = "0.27"
http = "1"
cookie_store = "0.22"
cookie = "0.18"

# Routes
net-route = "0.4"

# DNS / network reachability (macOS)
system-configuration = "0.7"

# CLI + config
clap = { version = "4.6", features = ["derive"] }
toml = "1.1"
serde = { version = "1.0", features = ["derive"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# System / privilege
nix = { version = "0.31", features = ["socket", "user", "signal"] }
security-framework = "3.7"
```

---

## 5. Recommended Architecture

### 5.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        forti-vpn CLI                            │
│  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ clap CLI  │  │  Config  │  │ tracing  │  │  Signal      │  │
│  │ parser    │  │  (TOML)  │  │ logging  │  │  handler     │  │
│  └─────┬─────┘  └────┬─────┘  └──────────┘  └──────┬───────┘  │
│        │              │                              │          │
│        ▼              ▼                              ▼          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Session Manager                       │  │
│  │  Orchestrates connect/disconnect/reconnect lifecycle     │  │
│  │  Owns state machine: Idle → Auth → Tunnel → Connected   │  │
│  └──────┬──────────┬──────────┬──────────────┬──────────────┘  │
│         │          │          │              │                  │
│         ▼          ▼          ▼              ▼                  │
│  ┌──────────┐ ┌─────────┐ ┌────────┐ ┌─────────────────────┐  │
│  │   Auth   │ │  SAML   │ │  PPP   │ │  Platform Layer     │  │
│  │  Client  │ │  Server │ │ Engine │ │  ┌───────────────┐  │  │
│  │          │ │         │ │        │ │  │ TUN (tun-rs)  │  │  │
│  │  hyper + │ │  hyper  │ │  LCP   │ │  ├───────────────┤  │  │
│  │  rustls  │ │  on     │ │  IPCP  │ │  │ DNS (scutil)  │  │  │
│  │  cookie  │ │  :8020  │ │  IP6CP │ │  ├───────────────┤  │  │
│  │          │ │         │ │  Codec │ │  │ Routes        │  │  │
│  └────┬─────┘ └────┬────┘ └───┬────┘ │  │ (net-route)   │  │  │
│       │            │          │      │  ├───────────────┤  │  │
│       │            │          │      │  │ Sleep/Wake    │  │  │
│       │            │          │      │  │ (IOKit FFI)   │  │  │
│       │            │          │      │  ├───────────────┤  │  │
│       │            │          │      │  │ Reachability  │  │  │
│       │            │          │      │  │ (SC framework)│  │  │
│       │            │          │      │  └───────────────┘  │  │
│       ▼            ▼          ▼      └─────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                  Transport Layer                          │  │
│  │  ┌─────────────────────┐  ┌────────────────────────────┐ │  │
│  │  │ TLS Tunnel          │  │ DTLS Tunnel (optional)     │ │  │
│  │  │ tokio-rustls        │  │ tokio-openssl              │ │  │
│  │  │ (fallback/control)  │  │ (preferred data path)      │ │  │
│  │  └─────────────────────┘  └────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│                        tokio runtime                            │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Connection State Machine

```
         ┌──────┐
         │ Idle │◄──────────────────────────────────┐
         └──┬───┘                                    │
            │ connect()                              │
            ▼                                        │
    ┌───────────────┐   auth failed /          ┌─────┴──────┐
    │ Authenticating │   SAML timeout         │ Disconnected│
    │ (HTTPS auth   │──────────────────────►  └─────────────┘
    │  or SAML)     │                                ▲
    └───────┬───────┘                                │
            │ SVPNCOOKIE acquired                    │
            ▼                                        │
    ┌───────────────┐                                │
    │ Configuring   │   XML parse / tunnel           │
    │ (fetch XML,   │   upgrade failed               │
    │  open tunnel) ├────────────────────────────────┤
    └───────┬───────┘                                │
            │ TLS tunnel open                        │
            ▼                                        │
    ┌───────────────┐                                │
    │ Negotiating   │   PPP negotiation              │
    │ (LCP → IPCP)  │   failed / timeout             │
    │               ├────────────────────────────────┤
    └───────┬───────┘                                │
            │ IP assigned, routes/DNS configured     │
            ▼                                        │
    ┌───────────────┐   peer dead / sleep /          │
    │  Connected    │   signal / user disconnect     │
    │  (forwarding  ├────────────────────────────────┘
    │   packets)    │
    └───────────────┘
            │ network restored (reachability callback)
            │ auto-reconnect enabled
            ▼
    (back to Authenticating, reuse session cookie if valid)
```

### 5.3 Data Flow (Connected State)

```
Outbound:
  App → utun read() → strip 4-byte AF header
    → PPP frame: [FF][03][00][21] + IP packet
    → Fortinet header: [total_len:BE16][50 50][payload_len:BE16]
    → TLS/DTLS write to FortiGate

Inbound:
  TLS/DTLS read from FortiGate → parse Fortinet header (validate 0x5050 magic)
    → extract PPP payload → strip 4-byte PPP header
    → prepend 4-byte AF header (AF_INET or AF_INET6)
    → utun write()
```

### 5.4 Concurrency Model

Single tokio task, no threads. `tokio::select!` multiplexes all I/O:

```rust
loop {
    tokio::select! {
        // Packet from TUN → encode → send to gateway
        pkt = tun_device.recv() => { ... }

        // Packet from gateway → decode → inject to TUN
        frame = transport.recv() => { ... }

        // Keepalive timer (LCP Echo-Request)
        _ = keepalive_interval.tick() => { ... }

        // Sleep/wake event (from IOKit via mpsc channel)
        event = sleep_wake_rx.recv() => { ... }

        // Graceful shutdown (SIGINT/SIGTERM)
        _ = shutdown_signal.recv() => { break; }
    }
}
```

### 5.5 Module Layout

```
src/
├── main.rs              # CLI entry point, tokio bootstrap
├── config.rs            # TOML config + clap args merged
├── session.rs           # Connection state machine, lifecycle orchestration
├── auth/
│   ├── mod.rs           # Auth trait (returns SVPNCOOKIE)
│   ├── credential.rs    # Username/password POST /remote/logincheck
│   └── saml.rs          # SAML flow: HTTP callback server + browser open
├── tunnel/
│   ├── mod.rs           # Transport trait: send(frame), recv() -> frame
│   ├── tls.rs           # TLS tunnel via tokio-rustls
│   └── dtls.rs          # DTLS tunnel via tokio-openssl (phase 2)
├── ppp/
│   ├── mod.rs           # PPP engine public API
│   ├── codec.rs         # Fortinet header + PPP frame encode/decode
│   ├── lcp.rs           # LCP: MRU, Magic-Number, Echo-Request/Reply
│   ├── ipcp.rs          # IPCP: IPv4 + DNS address assignment
│   └── ip6cp.rs         # IP6CP: interface identifier
├── platform/
│   ├── mod.rs           # Platform trait: configure_dns(), add_route(), etc.
│   ├── macos/
│   │   ├── mod.rs
│   │   ├── dns.rs       # scutil shell-out + /etc/resolver/ files
│   │   ├── routes.rs    # net-route crate or /sbin/route shell-out
│   │   ├── sleep.rs     # IOKit FFI: IORegisterForSystemPower
│   │   └── reachability.rs  # SCNetworkReachability callbacks
│   └── linux/
│       ├── mod.rs
│       ├── dns.rs       # systemd-resolved or /etc/resolv.conf
│       └── routes.rs    # rtnetlink
└── tun.rs               # TUN device wrapper around tun-rs
```

### 5.6 Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| PPP | Userspace, custom Rust | Avoid pppd entirely (macOS kernel panics, route hijack, DNS race) |
| TUN | Direct utun via tun-rs | No pppd means no ppp0 — use utun directly |
| HTTP library | hyper (not reqwest) | Need raw TLS socket after tunnel upgrade |
| DNS | scutil + /etc/resolver/ | Correct on macOS, proven by Tailscale/WireGuard-Go |
| Reconnect trigger | SCNetworkReachability | Event-driven, not polling — react to network restoration |
| DTLS | Phase 2 | TLS-only is fully functional; DTLS improves throughput later |
| Privilege | sudo (phase 1) | Simple. Daemon split is phase 2 |
| Config format | TOML | Idiomatic for Rust CLI tools, familiar syntax |

---

## 6. Risk Assessment

### 6.1 High Risk — Must Solve

| Risk | Why it's hard | Mitigation |
|------|---------------|------------|
| **PPP implementation correctness** | No Rust crate. Must implement LCP/IPCP/IP6CP state machines from scratch. Subtle bugs cause silent packet loss or negotiation hangs. | Port directly from OpenConnect's `ppp.c` (~1800 lines). Write property-based tests against captured PPP traces from a real FortiGate. |
| **HTTP-to-tunnel upgrade** | After `GET /remote/sslvpn-tunnel`, the HTTP connection must transition to raw binary framing on the same TLS socket. hyper's client-side upgrade path is not well-documented. | hyper's `http1::handshake()` returns `Connection` → `into_parts()` gives raw IO. Prototype this first. Fallback: use raw `tokio-rustls` without hyper for the tunnel request. |
| **FortiGate version differences** | Undocumented per-version quirks in cookie names, XML schema, PPP options. openfortivpn has years of accumulated workarounds. | Start with one known FortiOS version (7.2.x). Use openfortivpn's git blame to find version-specific fixes and port as needed. |

### 6.2 Medium Risk — Solvable with Effort

| Risk | Why it's hard | Mitigation |
|------|---------------|------------|
| **SAML flow variations** | Redirect URL path varies by server config (openfortivpn issue #1284). Some IdPs do multi-step redirects. | Accept any request to callback server containing `id` parameter. Support `--cookie-on-stdin` as manual fallback. |
| **DNS configuration correctness** | Split DNS on macOS is subtle. Wrong setup breaks VPN or internet resolution. | Test with `scutil --dns` and `dig` against both VPN and public domains. |
| **Sleep/wake reconnection timing** | Race between "system awake" and "network available". | Chain IOKit `HasPoweredOn` → `SCNetworkReachability` → reconnect. Exponential backoff on failure. |
| **DTLS implementation** | Bespoke application-layer key exchange inside standard DTLS. | Defer to phase 2. TLS-only works. OpenConnect's `fortinet.c` is the reference. |

### 6.3 Low Risk — Prior Art Exists

| Risk | Why it's fine |
|------|---------------|
| utun creation | `tun-rs` handles it. WireGuard-Go, Tailscale prove the approach. |
| Route management | FortiGate pushes route list in XML. Iterate and `route add`. |
| TLS client certificates | `rustls` has `with_client_auth_cert()`. Well-documented. |
| Privilege escalation | Phase 1 is just `sudo`. Every open-source VPN client does this. |

### 6.4 Unknowns — Need Investigation

| Unknown | How to resolve |
|---------|---------------|
| **Wire protocol v2** (non-PPP, raw IP, indicated by `<tunnel-method value="tun"/>`) | Capture traffic from FortiClient with Wireshark on a v2 server. Not blocking — v1 works on all current servers. |
| **Session resumption** (`tun-connect-without-reauth`) | Test by reconnecting with same SVPNCOOKIE. openfortivpn says "doesn't work very well". Full re-auth is the safe fallback. |
| **FortiOS 7.6.3 IPsec** | Out of scope. The `session.rs` / `tunnel/` abstraction allows adding IPsec transport later without rewriting auth or platform layers. |

### 6.5 Recommended Build Order (Risk-First)

```
Phase 1 — Prove feasibility (validate the three hardest components)
  1. PPP codec + LCP/IPCP state machine
  2. HTTP auth → SVPNCOOKIE acquisition
  3. TLS tunnel upgrade (hyper connection hijack)
  4. PPP-over-TLS end-to-end: auth → tunnel → negotiate → first ping

Phase 2 — Make it usable
  5. TUN device integration (tun-rs)
  6. Full packet forwarding loop (tokio::select!)
  7. DNS + route configuration
  8. SAML authentication flow

Phase 3 — Make it robust
  9. Sleep/wake handling (IOKit + SCNetworkReachability)
  10. Auto-reconnect state machine
  11. DTLS data channel
  12. Config file, CLI polish, logging
```

Phase 1 validates the three hardest pieces before investing in platform integration. If the PPP engine or tunnel upgrade doesn't work, you find out in days, not weeks.
