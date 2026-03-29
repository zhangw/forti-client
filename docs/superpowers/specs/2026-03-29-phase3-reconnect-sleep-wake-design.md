# Phase 3 Design: Reconnect, Network Detection, and Sleep/Wake

**Date:** 2026-03-29
**Status:** Approved design
**Scope:** Auto-reconnect on dead peer/tunnel close, network change detection, macOS sleep/wake handling, automatic SAML re-auth with browser auto-close

---

## 1. Overview

Phase 3 adds resilience to the VPN client through three incrementally delivered layers:

| Layer | Feature | Complexity | FFI Required |
|-------|---------|------------|-------------|
| 1 | Reconnect state machine | ~200 lines, pure Rust | No |
| 2 | Network change detection | ~50 lines + `system-configuration` crate | No unsafe |
| 3 | Sleep/wake handling | ~100 lines IOKit FFI + 5-line timing heuristic | Yes |

Each layer is independently shippable and testable. Layer 1 works standalone. Layer 2 adds smarter triggers. Layer 3 adds sleep/wake awareness.

### Design Decisions

- **Retry indefinitely** with exponential backoff (cap 60s). Client stays resident until user presses Ctrl+C.
- **TUN device, routes, DNS persist** across reconnects. Only the TLS tunnel and PPP session are re-established. This gives existing TCP connections a chance to survive short reconnects (kernel TCP retransmit buys ~15-120s).
- **Automatic SAML re-auth** when cookie expires — browser opens automatically, tab auto-closes after auth completes.

---

## 2. Architecture: Reconnect Controller

### Current Structure (Phase 2)

```
main.rs
  → authenticate() → SVPNCOOKIE + TunnelConfig
  → TlsTunnel::connect()
  → PppEngine::negotiate()
  → vpn::run(tunnel, lcp, config)
      creates TUN, routes, DNS
      runs event_loop()
      cleans up on exit
```

### New Structure (Phase 3)

```
main.rs
  → authenticate() → SVPNCOOKIE + TunnelConfig
  → ReconnectController::new(config, cookie, auth_params)
      owns: TUN device, routes, DNS (created once)
      → loop:
          connect_tunnel(cookie) → TLS + PPP negotiation
          event_loop(tunnel, lcp, tun_dev) → runs until error/signal
          on error:
            classify → Recoverable | AuthExpired | UserQuit
            Recoverable → backoff, retry with same cookie
            AuthExpired → re_authenticate() (auto SAML with browser close)
            UserQuit → break, cleanup
```

### What Changes in Existing Code

- `vpn::run()` splits: TUN/routes/DNS setup moves to the controller, `event_loop()` becomes a standalone async fn that borrows the TUN device
- `main.rs` orchestration moves into the controller
- `event_loop()` returns a typed enum (`DisconnectReason`) instead of `Result<()>`

### What Stays the Same

- `event_loop()` internals (the 4-way `tokio::select!`) are untouched
- Auth, tunnel, PPP modules unchanged
- All existing tests pass without modification

---

## 3. Layer 1: Reconnect State Machine (Pure Rust)

### Error Classification

```rust
enum DisconnectReason {
    DeadPeer,           // 3+ missed LCP echoes
    TunnelClosed,       // peer sent EOF
    ServerTerminated,   // server sent LCP Terminate-Request
    IoError(String),    // TUN or TLS read/write failure
    UserQuit,           // Ctrl+C
}

enum ReconnectAction {
    RetryWithCookie,    // fast path — reuse SVPNCOOKIE
    ReAuthenticate,     // cookie expired or rejected — full auth
    Exit,               // user requested quit
}
```

**Classification logic:**

- `DeadPeer` / `TunnelClosed` / `ServerTerminated` / `IoError` → `RetryWithCookie` (first attempt)
- If `RetryWithCookie` fails with HTTP 403 or tunnel rejected → `ReAuthenticate`
- `UserQuit` → `Exit`

### Backoff Strategy

- Exponential: 1s, 2s, 4s, 8s, 16s, 32s, capped at 60s
- Reset to 1s on successful reconnect
- During backoff wait, Ctrl+C still exits immediately (`select!` on signal + sleep)

### Cookie Reuse Fast Path

Per the protocol doc (Section 4.5), re-fetching `/remote/fortisslvpn_xml` after reconnect can invalidate the cookie. The fast path:

1. Skip `/remote/fortisslvpn` (resource reservation)
2. Skip `/remote/fortisslvpn_xml` (config fetch)
3. Go straight to `TlsTunnel::connect()` with saved SVPNCOOKIE
4. Reuse previously fetched `TunnelConfig` (same IP, routes, DNS)
5. If tunnel connect returns HTTP 403 → cookie expired → fall through to re-auth

### SAML Re-Auth Flow

- Same `AuthClient::login_saml()` path as initial auth
- Localhost callback server returns `<script>window.close()</script>` with fallback "You may close this tab" message
- New SVPNCOOKIE replaces the old one
- New `TunnelConfig` replaces old (in case server assigns different IP)
- If IP changed: tear down old routes/DNS, reconfigure TUN, install new routes/DNS

### Trade-Offs Considered

| Approach | Description | Verdict |
|----------|-------------|---------|
| **A: Flat retry loop** | Wrap existing flow in a loop in `main.rs` | Rejected — would need refactoring when adding Layer 2/3 triggers |
| **B: Explicit state machine** | Dedicated `ReconnectController` with typed states | **Selected** — clean separation, testable, extends naturally for Layer 2/3 |
| **C: Actor/channel model** | Separate tokio tasks communicating via channels | Rejected — overkill, channel coordination adds subtle bugs |

### Testing Scenarios

- **Dead peer:** Run VPN, block server with firewall (`sudo pfctl`), wait 30s for 3 missed echoes → verify reconnect attempt, verify reconnect succeeds after unblocking
- **Tunnel close:** Run VPN, server sends LCP Terminate-Request → verify reconnect
- **Cookie expiry:** Run VPN, disconnect, wait > 30s, reconnect → verify SAML re-auth triggers and browser tab auto-closes
- **Ctrl+C during backoff:** Disconnect server, wait for backoff, press Ctrl+C → verify clean exit (no hang)

---

## 4. Layer 2: Network Change Detection (SCNetworkReachability)

### Module: `src/network_monitor.rs`

A dedicated `std::thread` runs a `CFRunLoop` with an `SCNetworkReachability` callback targeting the VPN server address. Events are sent via `tokio::sync::mpsc` channel.

```rust
enum NetworkEvent {
    Reachable,      // network came back (WiFi associated, DNS resolving)
    Unreachable,    // network lost
}
```

### Integration with Reconnect Controller

- **During `Connected`:** `Unreachable` is logged but no action — LCP keepalive handles actual disconnect detection
- **During `Reconnecting` with backoff:** `Reachable` **cancels the backoff timer** and triggers immediate reconnect. This is the key win — instead of waiting up to 60s, reconnect starts the instant WiFi is back.
- **`Unreachable` during `Reconnecting`:** Reset backoff to initial (no point hammering a dead network)

### Why Not Primary Disconnect Trigger

Network reachability can flap (brief drops during WiFi roaming). LCP keepalive is a more reliable signal that the *tunnel* is dead. The network monitor supplements keepalive, it doesn't replace it.

### Trade-Offs Considered

| Approach | Description | Verdict |
|----------|-------------|---------|
| **A: `system-configuration` crate** | Safe Rust wrappers around SCNetworkReachability | **Selected** — no unsafe code, production-proven (Hickory DNS uses it), ~20-line callback bridge |
| **B: Raw FFI** | Direct calls to SCNetworkReachability C API | Rejected — ~80-100 lines unsafe for no real benefit over the crate |
| **C: Poll-based** | Periodic TCP connect to server every 5s | Rejected — up to 5s latency, wastes connections, doesn't compose with Layer 3 |

### Testing Scenarios

- Toggle WiFi off/on in System Preferences while VPN is running → verify reconnect within 2-3s of network return
- Switch between WiFi networks → verify reconnect
- Unplug/replug Ethernet → verify reconnect
- WiFi flap (brief 1-2s drop) → verify LCP keepalive rides through without unnecessary reconnect

---

## 5. Layer 3: Sleep/Wake Handling (IOKit)

### Module: `src/power_monitor.rs`

A dedicated `std::thread` calls `IORegisterForSystemPower` and runs a `CFRunLoop`. Events are sent via `tokio::sync::mpsc` channel.

```rust
enum PowerEvent {
    WillSleep,      // system about to sleep — up to 30s to acknowledge
    HasPoweredOn,   // system woke — network may not be ready
}
```

### Sleep Sequence

1. `WillSleep` received → send LCP Terminate-Request (graceful close)
2. Close TLS connection (don't wait for response — system is sleeping)
3. Acknowledge sleep to IOKit (`IOAllowPowerChange`) — must call or system hangs for 30s
4. TUN device + routes + DNS stay in place
5. Controller enters `WaitingForNetwork` state

### Wake Sequence

1. `HasPoweredOn` received → controller enters `WaitingForNetwork` state
2. **Do NOT attempt reconnect yet** — WiFi hasn't reassociated
3. Wait for `NetworkEvent::Reachable` from the network monitor (Layer 2)
4. Once reachable → attempt reconnect with cookie reuse (fast path)
5. If cookie expired (30-second `tun-user-ses-timeout` likely exceeded during sleep) → automatic SAML re-auth

### Timing Gap Heuristic (Safety Net)

In the event loop keepalive tick: if `Instant::now() - last_tick_time > 30s`, the system likely slept without IOKit notification reaching us. Treat as implicit wake → enter `Reconnecting` state. Five lines of code, zero dependencies, catches edge cases.

### IOKit FFI Scope (~80 lines unsafe)

- `IORegisterForSystemPower` — register callback
- `IOAllowPowerChange` — acknowledge sleep
- `IODeregisterForSystemPower` — cleanup on exit
- `CFRunLoopRun` / `CFRunLoopStop` — drive the callback thread

All wrapped in a safe `PowerMonitor` struct: `fn new() -> Result<(PowerMonitor, mpsc::Receiver<PowerEvent>)>`

### Trade-Offs Considered

| Approach | Description | Verdict |
|----------|-------------|---------|
| **A: IOKit FFI** | Direct `IORegisterForSystemPower` | **Selected** — the only way to get `WillSleep` for graceful shutdown |
| **B: kqueue / file descriptors** | Detect sleep via kernel events | Not viable — macOS doesn't expose sleep/wake this way |
| **C: Timing gap heuristic only** | Detect sleep from keepalive timer skew | Added as supplement — but can't do graceful pre-sleep shutdown |

### Testing Scenarios

- Close laptop lid, reopen → verify reconnect after WiFi returns
- `pmset sleepnow` from terminal → verify graceful close + reconnect on wake
- Disconnect WiFi before sleep, reconnect after wake → verify client waits for network, then reconnects
- Long sleep (> 30s cookie timeout) → verify SAML re-auth triggers automatically and browser tab auto-closes

---

## 6. Combined State Machine

### State Graph

```
                    ┌─────────────┐
                    │ Connecting  │ (initial auth + tunnel + PPP)
                    └──────┬──────┘
                           │ success
                    ┌──────▼──────┐
              ┌─────│  Connected  │◄──────────────────┐
              │     └──────┬──────┘                    │
              │            │ error / WillSleep         │ success
              │     ┌──────▼──────┐                    │
              │     │Disconnecting│ (close TLS,        │
              │     │             │  send LCP Term)    │
              │     └──────┬──────┘                    │
              │            │                           │
              │     ┌──────▼──────────┐                │
              │     │WaitingForNetwork│ (sleep/wake    │
              │     │ (optional)      │  path only)    │
              │     └──────┬──────────┘                │
              │            │ NetworkEvent::Reachable    │
              │     ┌──────▼──────┐                    │
              │     │ Reconnecting │──── success ──────┘
              │     │              │
              │     └──────┬──────┘
              │            │ cookie rejected (HTTP 403)
              │     ┌──────▼──────────┐
              │     │ReAuthenticating │ (SAML browser / creds)
              │     └──────┬──────────┘
              │            │ new cookie
              │            └───────► Reconnecting (retry with new cookie)
              │
              │ Ctrl+C (from any state)
       ┌──────▼──────┐
       │   Cleanup   │ (remove routes, DNS, drop TUN)
       └──────┬──────┘
              │
            exit
```

### Event Sources

```rust
tokio::select! {
    // Only active during Connected state:
    result = event_loop(...), if state == Connected => { ... }

    // Active in Reconnecting state:
    _ = backoff_timer, if state == Reconnecting => { attempt_reconnect() }

    // Always active:
    event = network_rx.recv() => { handle_network_event(event) }
    event = power_rx.recv() => { handle_power_event(event) }
    _ = tokio::signal::ctrl_c() => { state = Cleanup }
}
```

### Key Invariants

- TUN device, routes, DNS created once at startup, destroyed only at final cleanup (or IP change on re-auth)
- Only one TLS tunnel exists at a time — old is dropped before new is created
- Ctrl+C respected from any state, including mid-backoff and mid-re-auth
- Backoff resets to 1s on any successful connection
- `NetworkEvent::Reachable` cancels backoff and triggers immediate retry
- `WaitingForNetwork` is only entered via sleep/wake path — network-drop reconnects go straight to `Reconnecting` with backoff

### What Each Layer Adds

| Layer | States Added | Event Sources Added | Can Ship Without Others |
|-------|-------------|-------------------|------------------------|
| 1. Reconnect | Reconnecting, ReAuthenticating, Cleanup | backoff timer | Yes |
| 2. Network | (modifies Reconnecting behavior) | `network_rx` | Requires Layer 1 |
| 3. Sleep/wake | Disconnecting, WaitingForNetwork | `power_rx`, timing heuristic | Requires Layer 1 + 2 |

---

## 7. TCP Connection Survival Across Reconnects

A key design choice: TUN device + routes + DNS persist across reconnects. This gives existing TCP connections a chance to survive.

### What Happens During Reconnect

1. TLS tunnel drops → utun interface stays up, routes stay
2. Apps keep sending → packets enter utun → silently dropped (no tunnel)
3. Kernel TCP retransmits with exponential backoff (1s, 2s, 4s...)
4. Reconnect re-establishes TLS + PPP with same SVPNCOOKIE → same VPN IP assigned
5. TUN starts forwarding again → retransmitted packets flow through

### Survival Conditions

- Reconnect completes within TCP retransmit window (~15-120s depending on OS sysctls)
- Same VPN IP assigned (guaranteed with same SVPNCOOKIE)
- FortiGate doesn't NAT VPN traffic (common for SSL VPN — assigned IP is directly routable)

### If IP Changes (Re-Auth Scenario)

When SAML re-auth produces a new `TunnelConfig` with a different IP:
- Remove old routes, remove old DNS config
- Reconfigure TUN device with new IP
- Install new routes and DNS
- All existing TCP connections break (different source IP)

### Trade-Off: Persist vs Tear Down

| | Persist (selected) | Tear down |
|---|---|---|
| App sees error? | Not immediately — TCP retransmits | Immediately — RST/EHOSTUNREACH |
| Connection survival | Possible if reconnect < ~15s | Never |
| Stale state risk | Possible (utun up but tunnel dead) | None |

---

## 8. New Dependencies

| Crate | Purpose | Layer |
|-------|---------|-------|
| `system-configuration` | SCNetworkReachability wrappers | 2 |
| `core-foundation` | CFRunLoop types (likely transitive) | 2, 3 |

IOKit FFI in Layer 3 uses `libc` (already a dependency) and raw `extern "C"` bindings — no additional crate needed.

---

## 9. New Modules

| Module | Layer | Description |
|--------|-------|-------------|
| `src/reconnect.rs` | 1 | `ReconnectController`, state machine, backoff, error classification |
| `src/network_monitor.rs` | 2 | SCNetworkReachability watcher, `NetworkEvent` channel |
| `src/power_monitor.rs` | 3 | IOKit sleep/wake listener, `PowerEvent` channel |

### Changes to Existing Modules

| Module | Change |
|--------|--------|
| `src/vpn.rs` | `event_loop()` returns `DisconnectReason` enum instead of `Result<()>`. TUN/routes/DNS setup extracted. |
| `src/main.rs` | Orchestration moves to `ReconnectController`. `main()` becomes: parse args → initial auth → controller.run() |
| `src/auth/mod.rs` | SAML callback returns HTML with `<script>window.close()</script>` for browser tab auto-close |
| `src/error.rs` | Add variants or keep existing — `DisconnectReason` is a separate enum in `reconnect.rs` |
