# Phase 3: Reconnect, Network Detection, and Sleep/Wake — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add automatic reconnect with exponential backoff, network change detection via SCNetworkReachability, and macOS sleep/wake handling via IOKit FFI — delivered in three incremental layers.

**Architecture:** A new `ReconnectController` wraps the existing event loop, owns TUN/routes/DNS lifetime (persist across reconnects), and drives a state machine with transitions triggered by tunnel errors, network events, power events, and Ctrl+C. Each layer adds new event sources to the controller's `tokio::select!`.

**Tech Stack:** Rust 2021, tokio 1.x, `system-configuration` crate (Layer 2), IOKit FFI via `libc` + raw `extern "C"` (Layer 3)

**Spec:** `docs/superpowers/specs/2026-03-29-phase3-reconnect-sleep-wake-design.md`

---

## File Structure

### New Files

| File | Layer | Responsibility |
|------|-------|---------------|
| `src/reconnect.rs` | 1 | `ReconnectController`, `DisconnectReason`, `ReconnectAction`, backoff logic, state machine |
| `tests/reconnect_test.rs` | 1 | Unit tests for error classification, backoff calculation, state transitions |
| `src/network_monitor.rs` | 2 | `NetworkMonitor`, `NetworkEvent`, SCNetworkReachability watcher |
| `tests/network_monitor_test.rs` | 2 | Unit tests for network event handling |
| `src/power_monitor.rs` | 3 | `PowerMonitor`, `PowerEvent`, IOKit FFI, timing gap heuristic |
| `tests/power_monitor_test.rs` | 3 | Unit tests for power event handling and timing gap detection |

### Modified Files

| File | Layer | Change |
|------|-------|--------|
| `src/lib.rs` | 1 | Add `pub mod reconnect;` (Layer 2: `pub mod network_monitor;`, Layer 3: `pub mod power_monitor;`) |
| `src/vpn.rs` | 1 | Extract `event_loop()` as pub, return `DisconnectReason`, remove TUN/routes/DNS setup/cleanup |
| `src/main.rs` | 1 | Replace direct orchestration with `ReconnectController::run()` |
| `src/auth/mod.rs` | 1 | Add SAML browser auto-close HTML response; expose `AuthClient` fields for reconnect |
| `src/error.rs` | 1 | No changes — `DisconnectReason` lives in `reconnect.rs` |
| `Cargo.toml` | 2 | Add `system-configuration` dependency |

---

## Layer 1: Reconnect State Machine

### Task 1: Define `DisconnectReason` and `ReconnectAction` enums

**Files:**
- Create: `src/reconnect.rs`
- Create: `tests/reconnect_test.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write the failing test for error classification**

Create `tests/reconnect_test.rs`:

```rust
use forti_client::reconnect::{DisconnectReason, ReconnectAction, classify_disconnect};

#[test]
fn test_dead_peer_is_recoverable() {
    assert_eq!(
        classify_disconnect(&DisconnectReason::DeadPeer),
        ReconnectAction::RetryWithCookie,
    );
}

#[test]
fn test_tunnel_closed_is_recoverable() {
    assert_eq!(
        classify_disconnect(&DisconnectReason::TunnelClosed),
        ReconnectAction::RetryWithCookie,
    );
}

#[test]
fn test_server_terminated_is_recoverable() {
    assert_eq!(
        classify_disconnect(&DisconnectReason::ServerTerminated),
        ReconnectAction::RetryWithCookie,
    );
}

#[test]
fn test_io_error_is_recoverable() {
    assert_eq!(
        classify_disconnect(&DisconnectReason::IoError("TUN read error".into())),
        ReconnectAction::RetryWithCookie,
    );
}

#[test]
fn test_user_quit_exits() {
    assert_eq!(
        classify_disconnect(&DisconnectReason::UserQuit),
        ReconnectAction::Exit,
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test reconnect_test 2>&1`
Expected: Compile error — `reconnect` module not found

- [ ] **Step 3: Write minimal implementation**

Create `src/reconnect.rs`:

```rust
/// Reason the VPN event loop exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// 3+ missed LCP echo replies.
    DeadPeer,
    /// Peer sent EOF (TCP close).
    TunnelClosed,
    /// Server sent LCP Terminate-Request.
    ServerTerminated,
    /// TUN or TLS I/O failure.
    IoError(String),
    /// User pressed Ctrl+C.
    UserQuit,
}

/// What the reconnect controller should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconnectAction {
    /// Attempt reconnect reusing the existing SVPNCOOKIE.
    RetryWithCookie,
    /// Cookie expired or rejected — full re-authentication needed.
    ReAuthenticate,
    /// User requested exit — clean up and terminate.
    Exit,
}

/// Classify a disconnect reason into a reconnect action.
pub fn classify_disconnect(reason: &DisconnectReason) -> ReconnectAction {
    match reason {
        DisconnectReason::UserQuit => ReconnectAction::Exit,
        _ => ReconnectAction::RetryWithCookie,
    }
}
```

Add to `src/lib.rs`:

```rust
pub mod reconnect;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test reconnect_test 2>&1`
Expected: All 5 tests PASS

- [ ] **Step 5: Run full test suite to confirm no regressions**

Run: `cargo test 2>&1`
Expected: All 34 tests pass (29 existing + 5 new)

- [ ] **Step 6: Commit**

```bash
git add src/reconnect.rs src/lib.rs tests/reconnect_test.rs
git commit -m "feat(reconnect): add DisconnectReason, ReconnectAction, and classify_disconnect"
```

---

### Task 2: Add exponential backoff logic

**Files:**
- Modify: `src/reconnect.rs`
- Modify: `tests/reconnect_test.rs`

- [ ] **Step 1: Write failing tests for backoff**

Append to `tests/reconnect_test.rs`:

```rust
use forti_client::reconnect::Backoff;
use std::time::Duration;

#[test]
fn test_backoff_initial() {
    let backoff = Backoff::new();
    assert_eq!(backoff.current(), Duration::from_secs(1));
}

#[test]
fn test_backoff_exponential() {
    let mut backoff = Backoff::new();
    assert_eq!(backoff.current(), Duration::from_secs(1));
    backoff.next();
    assert_eq!(backoff.current(), Duration::from_secs(2));
    backoff.next();
    assert_eq!(backoff.current(), Duration::from_secs(4));
    backoff.next();
    assert_eq!(backoff.current(), Duration::from_secs(8));
}

#[test]
fn test_backoff_caps_at_60s() {
    let mut backoff = Backoff::new();
    for _ in 0..10 {
        backoff.next();
    }
    assert_eq!(backoff.current(), Duration::from_secs(60));
}

#[test]
fn test_backoff_reset() {
    let mut backoff = Backoff::new();
    backoff.next();
    backoff.next();
    assert_eq!(backoff.current(), Duration::from_secs(4));
    backoff.reset();
    assert_eq!(backoff.current(), Duration::from_secs(1));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test reconnect_test 2>&1`
Expected: Compile error — `Backoff` not found

- [ ] **Step 3: Implement Backoff**

Append to `src/reconnect.rs`:

```rust
use std::time::Duration;

const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Exponential backoff timer: 1s, 2s, 4s, 8s, ..., capped at 60s.
pub struct Backoff {
    current: Duration,
}

impl Backoff {
    pub fn new() -> Self {
        Self { current: BACKOFF_INITIAL }
    }

    /// Return the current backoff duration.
    pub fn current(&self) -> Duration {
        self.current
    }

    /// Advance to the next backoff interval.
    pub fn next(&mut self) {
        self.current = (self.current * 2).min(BACKOFF_MAX);
    }

    /// Reset backoff to initial value (after successful reconnect).
    pub fn reset(&mut self) {
        self.current = BACKOFF_INITIAL;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test reconnect_test 2>&1`
Expected: All 9 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/reconnect.rs tests/reconnect_test.rs
git commit -m "feat(reconnect): add exponential backoff with 60s cap"
```

---

### Task 3: Refactor `vpn.rs` — extract `event_loop()` to return `DisconnectReason`

**Files:**
- Modify: `src/vpn.rs`

This is a refactor of existing code. The goal is:
1. `event_loop()` becomes `pub` and returns `DisconnectReason` instead of `Result<()>`
2. TUN/routes/DNS setup and cleanup are removed from `vpn.rs` (they'll move to the controller later)
3. A new `pub async fn setup_tun(...)` function extracts the TUN/routes/DNS creation
4. A new `pub fn cleanup(...)` function extracts the route/DNS teardown

- [ ] **Step 1: Refactor `vpn.rs`**

Replace the entire `src/vpn.rs` with:

```rust
use crate::auth::xml::TunnelConfig;
use crate::error::{FortiError, Result};
use crate::ppp::codec::{PppFrame, PppProtocol};
use crate::ppp::lcp::{LcpCode, LcpState};
use crate::reconnect::DisconnectReason;
use crate::tunnel::TlsTunnel;
use crate::tun;

use std::time::Duration;
use tracing::{debug, error, info};

/// Set up TUN device, routes, and DNS. Returns the device and interface name.
pub fn setup_tun(config: &TunnelConfig) -> Result<(tun_rs::AsyncDevice, String)> {
    let (tun_dev, iface_name) = tun::create_tun(config.ip_address)?;
    tun::routes::install_routes(&config.routes, &iface_name)?;
    tun::dns::configure_dns(&config.dns_servers)?;

    info!(
        "VPN active on {} — IP={}, {} routes, {} DNS servers",
        iface_name,
        config.ip_address,
        config.routes.len(),
        config.dns_servers.len(),
    );

    Ok((tun_dev, iface_name))
}

/// Remove routes and DNS configuration.
pub fn cleanup_tun(config: &TunnelConfig, iface_name: &str) {
    info!("Cleaning up routes and DNS...");
    tun::routes::remove_routes(&config.routes, iface_name);
    tun::dns::remove_dns();
}

/// Run the VPN data plane event loop.
///
/// Forwards packets between the TUN device and the TLS tunnel, handles LCP
/// keepalive, and listens for Ctrl+C.
///
/// Returns a `DisconnectReason` indicating why the loop exited.
pub async fn event_loop(
    tunnel: &mut TlsTunnel,
    lcp: &mut LcpState,
    tun_dev: &tun_rs::AsyncDevice,
) -> DisconnectReason {
    let mut keepalive = tokio::time::interval(Duration::from_secs(10));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut missed_echoes: u32 = 0;
    let mut tun_buf = vec![0u8; 4096];
    let mut pkt_count: u64 = 0;

    loop {
        tokio::select! {
            // TUN → Tunnel (outbound: app sends packet through VPN)
            result = tun_dev.recv(&mut tun_buf) => {
                let n = match result {
                    Ok(n) => n,
                    Err(e) => return DisconnectReason::IoError(format!("TUN read error: {}", e)),
                };
                if n == 0 {
                    continue;
                }

                let version = tun_buf[0] >> 4;
                let protocol = match version {
                    4 => PppProtocol::Ipv4,
                    6 => {
                        debug!("TUN: ignoring outbound IPv6 packet");
                        continue;
                    }
                    _ => {
                        debug!("TUN: unknown IP version {}, skipping", version);
                        continue;
                    }
                };

                pkt_count += 1;
                if pkt_count <= 5 {
                    debug!("TUN → tunnel: {} bytes IPv4", n);
                }
                if let Err(e) = send_ppp(tunnel, protocol, tun_buf[..n].to_vec()).await {
                    return DisconnectReason::IoError(format!("tunnel send error: {}", e));
                }
            }

            // Tunnel → TUN (inbound: FortiGate sends packet to us)
            result = tunnel.recv_frame() => {
                let frame = match result {
                    Ok(f) => f,
                    Err(FortiError::TunnelError(msg)) if msg.contains("tunnel closed") => {
                        return DisconnectReason::TunnelClosed;
                    }
                    Err(e) => return DisconnectReason::IoError(format!("tunnel recv error: {}", e)),
                };
                let ppp = match PppFrame::decode(frame.payload()) {
                    Ok(p) => p,
                    Err(e) => {
                        debug!("PPP decode error: {}, skipping frame", e);
                        continue;
                    }
                };

                match ppp.protocol() {
                    PppProtocol::Ipv4 => {
                        pkt_count += 1;
                        if pkt_count <= 10 {
                            debug!("Tunnel → TUN: {} bytes IPv4", ppp.data().len());
                        }
                        if let Err(e) = tun_dev.send(ppp.data()).await {
                            return DisconnectReason::IoError(format!("TUN write error: {}", e));
                        }
                    }
                    PppProtocol::Lcp => {
                        let code = LcpCode::from_u8(ppp.data().first().copied().unwrap_or(0));
                        let responses = lcp.handle_packet(ppp.data());
                        for resp in responses {
                            if let Err(e) = send_ppp(tunnel, PppProtocol::Lcp, resp).await {
                                return DisconnectReason::IoError(format!("LCP send error: {}", e));
                            }
                        }
                        if code == LcpCode::EchoReply {
                            missed_echoes = 0;
                        }
                        if code == LcpCode::TerminateRequest {
                            info!("Server sent LCP Terminate-Request");
                            return DisconnectReason::ServerTerminated;
                        }
                    }
                    PppProtocol::Ipv6 => {
                        debug!("Ignoring inbound IPv6 packet");
                    }
                    other => {
                        debug!("Ignoring PPP protocol {:?}", other);
                    }
                }
            }

            // Keepalive timer
            _ = keepalive.tick() => {
                if let Err(e) = send_ppp(tunnel, PppProtocol::Lcp, lcp.build_echo_request()).await {
                    return DisconnectReason::IoError(format!("keepalive send error: {}", e));
                }
                missed_echoes += 1;
                if missed_echoes > 3 {
                    error!("Dead peer detected ({} missed echoes)", missed_echoes);
                    return DisconnectReason::DeadPeer;
                }
            }

            // Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received");
                return DisconnectReason::UserQuit;
            }
        }
    }
}

/// Legacy entry point — runs setup, event loop, and cleanup.
/// Kept for backward compatibility during transition; will be removed
/// once ReconnectController is wired in.
pub async fn run(
    mut tunnel: TlsTunnel,
    mut lcp: LcpState,
    config: &TunnelConfig,
) -> Result<()> {
    let (tun_dev, iface_name) = setup_tun(config)?;

    info!("Press Ctrl+C to disconnect.");

    let reason = event_loop(&mut tunnel, &mut lcp, &tun_dev).await;

    // Cleanup
    cleanup_tun(config, &iface_name);
    let _ = send_ppp(&mut tunnel, PppProtocol::Lcp, lcp.build_terminate_request()).await;
    info!("VPN disconnected.");

    match reason {
        DisconnectReason::UserQuit | DisconnectReason::ServerTerminated => Ok(()),
        DisconnectReason::DeadPeer => Err(FortiError::TunnelError("dead peer detected".into())),
        DisconnectReason::TunnelClosed => Err(FortiError::TunnelError("tunnel closed by peer".into())),
        DisconnectReason::IoError(msg) => Err(FortiError::TunnelError(msg)),
    }
}

async fn send_ppp(tunnel: &mut TlsTunnel, protocol: PppProtocol, data: Vec<u8>) -> Result<()> {
    let frame = PppFrame::new(protocol, data);
    tunnel.send_frame(frame.encode()).await
}
```

- [ ] **Step 2: Run existing tests to confirm no regressions**

Run: `cargo test 2>&1`
Expected: All 29 existing tests still pass. The `run()` function is preserved as a backward-compatible wrapper.

- [ ] **Step 3: Run `cargo clippy` to check for warnings**

Run: `cargo clippy 2>&1`
Expected: No new warnings

- [ ] **Step 4: Commit**

```bash
git add src/vpn.rs
git commit -m "refactor(vpn): extract event_loop to return DisconnectReason, split TUN setup/cleanup"
```

---

### Task 4: Build the `ReconnectController`

**Files:**
- Modify: `src/reconnect.rs`
- Modify: `tests/reconnect_test.rs`

- [ ] **Step 1: Write failing test for state transitions**

Append to `tests/reconnect_test.rs`:

```rust
use forti_client::reconnect::ConnectionState;

#[test]
fn test_initial_state_is_connecting() {
    let state = ConnectionState::Connecting;
    assert!(matches!(state, ConnectionState::Connecting));
}

#[test]
fn test_state_transitions() {
    // Verify all states are constructable (compile-time check of the enum)
    let states = vec![
        ConnectionState::Connecting,
        ConnectionState::Connected,
        ConnectionState::Reconnecting { attempt: 1 },
        ConnectionState::ReAuthenticating,
        ConnectionState::Cleanup,
    ];
    assert_eq!(states.len(), 5);
}

#[test]
fn test_reconnecting_tracks_attempt_number() {
    let state = ConnectionState::Reconnecting { attempt: 3 };
    if let ConnectionState::Reconnecting { attempt } = state {
        assert_eq!(attempt, 3);
    } else {
        panic!("expected Reconnecting");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test reconnect_test test_initial_state 2>&1`
Expected: Compile error — `ConnectionState` not found

- [ ] **Step 3: Add `ConnectionState` and `ReconnectController` struct to `src/reconnect.rs`**

Append to `src/reconnect.rs` (after the `Backoff` impl):

```rust
use crate::auth::AuthClient;
use crate::auth::xml::TunnelConfig;
use crate::error::{FortiError, Result};
use crate::ppp::codec::{PppFrame, PppProtocol};
use crate::ppp::PppEngine;
use crate::tunnel::TlsTunnel;
use crate::vpn;

use std::sync::Arc;
use tracing::{info, warn, error};

/// Current state of the reconnect controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial connection in progress.
    Connecting,
    /// Tunnel is up and forwarding traffic.
    Connected,
    /// Attempting to reconnect (with attempt counter for logging).
    Reconnecting { attempt: u32 },
    /// Cookie expired — running full re-authentication.
    ReAuthenticating,
    /// Final cleanup before exit.
    Cleanup,
}

/// Parameters needed to authenticate (for re-auth on cookie expiry).
pub struct AuthParams {
    pub server: String,
    pub port: u16,
    pub saml: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub realm: Option<String>,
    pub tls_config: Arc<rustls::ClientConfig>,
}

/// Reconnect controller: owns TUN/routes/DNS, drives the reconnect state machine.
pub struct ReconnectController {
    auth_params: AuthParams,
    svpn_cookie: String,
    tunnel_config: TunnelConfig,
    backoff: Backoff,
    state: ConnectionState,
}

impl ReconnectController {
    pub fn new(
        auth_params: AuthParams,
        svpn_cookie: String,
        tunnel_config: TunnelConfig,
    ) -> Self {
        Self {
            auth_params,
            svpn_cookie,
            tunnel_config,
            backoff: Backoff::new(),
            state: ConnectionState::Connecting,
        }
    }

    /// Run the reconnect loop. Returns only on user quit or unrecoverable error.
    pub async fn run(&mut self) -> Result<()> {
        // Setup TUN, routes, DNS (persist across reconnects)
        let (tun_dev, iface_name) = vpn::setup_tun(&self.tunnel_config)?;
        info!("Press Ctrl+C to disconnect.");

        self.state = ConnectionState::Connected;

        loop {
            // Connect tunnel + PPP
            let connect_result = self.connect_tunnel().await;
            let (mut tunnel, mut lcp) = match connect_result {
                Ok(pair) => {
                    self.backoff.reset();
                    info!("Tunnel established, entering data plane");
                    pair
                }
                Err(e) => {
                    // Check if it's a cookie rejection (HTTP 403)
                    let err_msg = format!("{}", e);
                    if err_msg.contains("403") || err_msg.contains("Forbidden") {
                        warn!("Cookie rejected, attempting re-authentication");
                        self.state = ConnectionState::ReAuthenticating;
                        match self.re_authenticate().await {
                            Ok(()) => {
                                info!("Re-authentication successful, retrying tunnel");
                                continue;
                            }
                            Err(auth_err) => {
                                error!("Re-authentication failed: {}", auth_err);
                                // Fall through to backoff
                            }
                        }
                    }

                    let delay = self.backoff.current();
                    warn!("Tunnel connect failed: {}. Retrying in {:?}", e, delay);
                    self.backoff.next();

                    // Sleep with Ctrl+C escape
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = tokio::signal::ctrl_c() => {
                            info!("Ctrl+C during backoff");
                            break;
                        }
                    }
                    continue;
                }
            };

            // Run event loop
            let reason = vpn::event_loop(&mut tunnel, &mut lcp, &tun_dev).await;
            info!("Event loop exited: {:?}", reason);

            // Send LCP terminate if tunnel is still usable
            let _ = Self::send_terminate(&mut tunnel, &mut lcp).await;
            drop(tunnel); // Close TLS connection

            let action = classify_disconnect(&reason);
            match action {
                ReconnectAction::Exit => {
                    self.state = ConnectionState::Cleanup;
                    break;
                }
                ReconnectAction::RetryWithCookie => {
                    let delay = self.backoff.current();
                    self.state = ConnectionState::Reconnecting { attempt: 1 };
                    info!("Reconnecting in {:?}...", delay);
                    self.backoff.next();

                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = tokio::signal::ctrl_c() => {
                            info!("Ctrl+C during backoff");
                            self.state = ConnectionState::Cleanup;
                            break;
                        }
                    }
                }
                ReconnectAction::ReAuthenticate => {
                    self.state = ConnectionState::ReAuthenticating;
                    match self.re_authenticate().await {
                        Ok(()) => {
                            info!("Re-authentication successful");
                        }
                        Err(e) => {
                            error!("Re-authentication failed: {}", e);
                            let delay = self.backoff.current();
                            self.backoff.next();
                            tokio::select! {
                                _ = tokio::time::sleep(delay) => {}
                                _ = tokio::signal::ctrl_c() => {
                                    info!("Ctrl+C during backoff");
                                    self.state = ConnectionState::Cleanup;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Final cleanup
        vpn::cleanup_tun(&self.tunnel_config, &iface_name);
        info!("VPN disconnected.");
        Ok(())
    }

    /// Connect the TLS tunnel and run PPP negotiation.
    /// Uses the cookie fast path: skip resource reservation and XML fetch.
    async fn connect_tunnel(&self) -> Result<(TlsTunnel, crate::ppp::lcp::LcpState)> {
        let mut tunnel = TlsTunnel::connect(
            &self.auth_params.server,
            self.auth_params.port,
            &self.svpn_cookie,
            self.auth_params.tls_config.clone(),
        ).await?;

        let mut ppp = PppEngine::new(1500);
        let _ipcp_config = ppp.negotiate(&mut tunnel).await?;
        let lcp = ppp.into_lcp();

        Ok((tunnel, lcp))
    }

    /// Re-authenticate (SAML or credential) and update stored cookie/config.
    async fn re_authenticate(&mut self) -> Result<()> {
        let auth_client = AuthClient::new(
            &self.auth_params.server,
            self.auth_params.port,
        )?;

        let auth_result = if self.auth_params.saml {
            info!("Re-authenticating via SAML...");
            auth_client.login_saml().await?
        } else {
            let username = self.auth_params.username.as_deref()
                .ok_or_else(|| FortiError::AuthFailed("no username for re-auth".into()))?;
            let password = self.auth_params.password.as_deref()
                .ok_or_else(|| FortiError::AuthFailed("no password for re-auth".into()))?;
            info!("Re-authenticating with credentials...");
            auth_client.login(username, password, self.auth_params.realm.as_deref()).await?
        };

        self.svpn_cookie = auth_result.svpn_cookie;

        // If IP changed, we'd need to reconfigure TUN — for now log a warning
        if auth_result.tunnel_config.ip_address != self.tunnel_config.ip_address {
            warn!(
                "Server assigned new IP {} (was {}). TUN reconfiguration not yet implemented — routes may be stale.",
                auth_result.tunnel_config.ip_address,
                self.tunnel_config.ip_address,
            );
        }
        self.tunnel_config = auth_result.tunnel_config;

        Ok(())
    }

    /// Try to send LCP Terminate-Request before closing tunnel.
    async fn send_terminate(tunnel: &mut TlsTunnel, lcp: &mut crate::ppp::lcp::LcpState) -> Result<()> {
        let frame = PppFrame::new(PppProtocol::Lcp, lcp.build_terminate_request());
        tunnel.send_frame(frame.encode()).await
    }
}
```

- [ ] **Step 4: Run tests to verify compilation and no regressions**

Run: `cargo test 2>&1`
Expected: All tests pass (29 existing + 12 new in reconnect_test)

- [ ] **Step 5: Run `cargo clippy`**

Run: `cargo clippy 2>&1`
Expected: No new warnings

- [ ] **Step 6: Commit**

```bash
git add src/reconnect.rs tests/reconnect_test.rs
git commit -m "feat(reconnect): add ReconnectController with state machine, backoff, and re-auth"
```

---

### Task 5: Wire `ReconnectController` into `main.rs`

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Replace `main.rs` orchestration with ReconnectController**

Replace `src/main.rs` with:

```rust
use clap::Parser;
use tracing_subscriber::EnvFilter;
use forti_client::auth::AuthClient;
use forti_client::reconnect::{AuthParams, ReconnectController};
use std::io::Write;

#[derive(Parser, Debug)]
#[command(name = "forti-client", about = "FortiGate SSL VPN client")]
struct Cli {
    /// VPN gateway hostname or IP
    #[arg(short, long)]
    server: String,

    /// VPN gateway port
    #[arg(short, long, default_value = "443")]
    port: u16,

    /// Username (not needed for --saml)
    #[arg(short, long)]
    username: Option<String>,

    /// Password (if omitted, will prompt)
    #[arg(short = 'P', long)]
    password: Option<String>,

    /// Realm (optional)
    #[arg(long)]
    realm: Option<String>,

    /// Use SAML/SSO authentication (opens browser)
    #[arg(long)]
    saml: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let auth_client = AuthClient::new(&cli.server, cli.port)?;

    // Prompt for password early (before we need sudo/root)
    let password = if !cli.saml {
        match cli.password.clone() {
            Some(p) => Some(p),
            None if cli.username.is_some() => {
                eprint!("Password: ");
                std::io::stderr().flush()?;
                let mut p = String::new();
                std::io::stdin().read_line(&mut p)?;
                Some(p.trim().to_string())
            }
            None => None,
        }
    } else {
        None
    };

    let auth_result = if cli.saml {
        tracing::info!("Starting SAML authentication to {}:{}", cli.server, cli.port);
        auth_client.login_saml().await?
    } else {
        let username = cli.username.as_deref()
            .ok_or_else(|| anyhow::anyhow!("--username is required for credential auth (use --saml for SSO)"))?;
        let pw = password.as_deref()
            .ok_or_else(|| anyhow::anyhow!("password required"))?;
        tracing::info!("Authenticating to {}:{}", cli.server, cli.port);
        auth_client.login(username, pw, cli.realm.as_deref()).await?
    };

    tracing::info!(
        "Authenticated. IP={}, DNS={:?}, {} routes",
        auth_result.tunnel_config.ip_address,
        auth_result.tunnel_config.dns_servers,
        auth_result.tunnel_config.routes.len(),
    );

    let auth_params = AuthParams {
        server: cli.server,
        port: cli.port,
        saml: cli.saml,
        username: cli.username,
        password,
        realm: cli.realm,
        tls_config: auth_client.tls_config(),
    };

    let mut controller = ReconnectController::new(
        auth_params,
        auth_result.svpn_cookie,
        auth_result.tunnel_config,
    );

    controller.run().await?;

    Ok(())
}
```

- [ ] **Step 2: Verify compilation**

Run: `cargo build 2>&1`
Expected: Compiles successfully

- [ ] **Step 3: Run full test suite**

Run: `cargo test 2>&1`
Expected: All tests pass

- [ ] **Step 4: Run `cargo clippy`**

Run: `cargo clippy 2>&1`
Expected: No new warnings

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat(reconnect): wire ReconnectController into main, replacing direct vpn::run"
```

---

### Task 6: Add SAML browser auto-close

**Files:**
- Modify: `src/auth/mod.rs`

- [ ] **Step 1: Update the SAML callback HTML response**

In `src/auth/mod.rs`, in the `wait_for_saml_callback` function (around line 460), replace the response HTML:

```rust
    // old
    let response = "HTTP/1.1 200 OK\r\n\
        Content-Type: text/html\r\n\
        Connection: close\r\n\
        \r\n\
        <html><body><h2>Authentication successful</h2>\
        <p>You may close this browser tab and return to the terminal.</p>\
        </body></html>";
```

with:

```rust
    // new — auto-close the browser tab
    let response = "HTTP/1.1 200 OK\r\n\
        Content-Type: text/html\r\n\
        Connection: close\r\n\
        \r\n\
        <html><body>\
        <h2>Authentication successful</h2>\
        <p>This tab will close automatically.</p>\
        <script>window.close();</script>\
        <noscript><p>You may close this browser tab and return to the terminal.</p></noscript>\
        </body></html>";
```

- [ ] **Step 2: Verify compilation**

Run: `cargo build 2>&1`
Expected: Compiles successfully

- [ ] **Step 3: Run full test suite**

Run: `cargo test 2>&1`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/auth/mod.rs
git commit -m "feat(auth): auto-close browser tab after SAML authentication"
```

---

### Task 7: Layer 1 integration test — manual testing guide

**Files:**
- No code changes — this is a manual testing checklist

- [ ] **Step 1: Build the binary**

```bash
cargo build
```

- [ ] **Step 2: Test basic connect + Ctrl+C (baseline)**

```bash
sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml
# Wait for VPN active message
# Press Ctrl+C
# Expected: clean shutdown, routes/DNS removed
```

- [ ] **Step 3: Test dead peer reconnect**

```bash
# Terminal 1: start VPN
sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml

# Terminal 2: block VPN server with PF firewall
echo "block drop out quick on en0 proto tcp to <server-ip> port 10443" | sudo pfctl -ef -

# Wait ~30s — expect "Dead peer detected" then "Reconnecting in 1s..."
# Unblock:
sudo pfctl -d

# Expected: reconnect succeeds, "Tunnel established" message
```

- [ ] **Step 4: Test cookie expiry + SAML re-auth**

```bash
# Terminal 1: start VPN
sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml

# Terminal 2: block server
echo "block drop out quick on en0 proto tcp to <server-ip> port 10443" | sudo pfctl -ef -

# Wait > 30s (cookie timeout) then unblock
sudo pfctl -d

# Expected: "Cookie rejected" → "Re-authenticating via SAML" → browser opens → tab auto-closes → reconnected
```

- [ ] **Step 5: Test Ctrl+C during backoff**

```bash
# Start VPN, block server, wait for backoff message, then Ctrl+C
# Expected: immediate clean exit, no hang
```

- [ ] **Step 6: Commit a tag marking Layer 1 complete**

```bash
git tag -a v0.2.0-layer1 -m "Phase 3 Layer 1: reconnect state machine complete"
```

---

## Layer 2: Network Change Detection

### Task 8: Add `system-configuration` dependency

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add the dependency**

Add to `[dependencies]` section of `Cargo.toml`:

```toml
# macOS network reachability (SCNetworkReachability)
system-configuration = "0.6"
```

- [ ] **Step 2: Verify it builds**

Run: `cargo build 2>&1`
Expected: Downloads and compiles `system-configuration` and deps

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: add system-configuration crate for network reachability"
```

---

### Task 9: Implement `NetworkMonitor`

**Files:**
- Create: `src/network_monitor.rs`
- Create: `tests/network_monitor_test.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing test for `NetworkEvent` enum**

Create `tests/network_monitor_test.rs`:

```rust
use forti_client::network_monitor::NetworkEvent;

#[test]
fn test_network_event_variants() {
    let events = vec![
        NetworkEvent::Reachable,
        NetworkEvent::Unreachable,
    ];
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], NetworkEvent::Reachable));
    assert!(matches!(events[1], NetworkEvent::Unreachable));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test network_monitor_test 2>&1`
Expected: Compile error — `network_monitor` module not found

- [ ] **Step 3: Implement `NetworkMonitor`**

Create `src/network_monitor.rs`:

```rust
use std::net::SocketAddr;
use system_configuration::core_foundation::runloop::{CFRunLoop, kCFRunLoopDefaultMode};
use system_configuration::network_reachability::{
    SCNetworkReachability, ReachabilityFlags, SchedulingError,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Network reachability events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEvent {
    /// Network path to VPN server is available.
    Reachable,
    /// Network path to VPN server is unavailable.
    Unreachable,
}

/// Watches network reachability to the VPN server and sends events via channel.
pub struct NetworkMonitor {
    /// Handle to the background thread (for cleanup).
    _thread: std::thread::JoinHandle<()>,
}

impl NetworkMonitor {
    /// Start monitoring reachability to the given address.
    /// Returns the monitor handle and a receiver for network events.
    pub fn start(server_addr: SocketAddr) -> Result<(Self, mpsc::Receiver<NetworkEvent>), String> {
        let (tx, rx) = mpsc::channel(16);

        let thread = std::thread::Builder::new()
            .name("network-monitor".into())
            .spawn(move || {
                Self::run_reachability(server_addr, tx);
            })
            .map_err(|e| format!("failed to spawn network monitor thread: {}", e))?;

        Ok((Self { _thread: thread }, rx))
    }

    fn run_reachability(addr: SocketAddr, tx: mpsc::Sender<NetworkEvent>) {
        let mut reachability = match SCNetworkReachability::from_address(addr) {
            Some(r) => r,
            None => {
                warn!("Failed to create SCNetworkReachability for {}", addr);
                return;
            }
        };

        let mut last_reachable: Option<bool> = None;
        let tx_clone = tx.clone();

        let callback = move |flags: ReachabilityFlags| {
            let reachable = flags.contains(ReachabilityFlags::REACHABLE)
                && !flags.contains(ReachabilityFlags::CONNECTION_REQUIRED);

            debug!("Network reachability changed: flags={:?}, reachable={}", flags, reachable);

            // Only send events on actual transitions
            if last_reachable != Some(reachable) {
                last_reachable = Some(reachable);
                let event = if reachable {
                    NetworkEvent::Reachable
                } else {
                    NetworkEvent::Unreachable
                };
                if tx_clone.blocking_send(event).is_err() {
                    debug!("Network monitor channel closed, stopping");
                    CFRunLoop::get_current().stop();
                }
            }
        };

        // Note: adapt to the actual `system-configuration` crate API —
        // callback registration and run loop scheduling may use `set_callback`
        // + `schedule_with_runloop`, or a combined `set_dispatch_queue` API
        // depending on the crate version. Check docs.rs/system-configuration.
        if !reachability.set_callback(callback).is_ok() {
            warn!("Failed to set reachability callback");
            return;
        }

        if !reachability.schedule_with_runloop(&CFRunLoop::get_current(), unsafe { kCFRunLoopDefaultMode }).is_ok() {
            warn!("Failed to schedule reachability with run loop");
            return;
        }

        info!("Network monitor started for {}", addr);
        CFRunLoop::run_current();
        debug!("Network monitor thread exiting");
    }
}
```

Add to `src/lib.rs`:

```rust
pub mod network_monitor;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test network_monitor_test 2>&1`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `cargo test 2>&1`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/network_monitor.rs src/lib.rs tests/network_monitor_test.rs
git commit -m "feat(network): add NetworkMonitor using SCNetworkReachability"
```

---

### Task 10: Integrate `NetworkMonitor` into `ReconnectController`

**Files:**
- Modify: `src/reconnect.rs`

- [ ] **Step 1: Add network monitor integration**

In `src/reconnect.rs`, add the import at the top:

```rust
use crate::network_monitor::{NetworkMonitor, NetworkEvent};
```

Modify `ReconnectController::run()` to start the network monitor and handle its events. Replace the backoff sleep sections with a `tokio::select!` that also listens for network events.

Update the `run()` method — add network monitor startup after TUN setup:

```rust
    pub async fn run(&mut self) -> Result<()> {
        let (tun_dev, iface_name) = vpn::setup_tun(&self.tunnel_config)?;
        info!("Press Ctrl+C to disconnect.");

        // Start network monitor
        let server_addr = format!("{}:{}", self.auth_params.server, self.auth_params.port)
            .parse()
            .map_err(|e| FortiError::TunnelError(format!("invalid server address: {}", e)))?;
        let (_network_monitor, mut network_rx) = NetworkMonitor::start(server_addr)
            .map_err(|e| FortiError::TunnelError(format!("network monitor failed: {}", e)))?;

        self.state = ConnectionState::Connected;

        loop {
            // Connect tunnel + PPP
            let connect_result = self.connect_tunnel().await;
            let (mut tunnel, mut lcp) = match connect_result {
                Ok(pair) => {
                    self.backoff.reset();
                    info!("Tunnel established, entering data plane");
                    pair
                }
                Err(e) => {
                    let err_msg = format!("{}", e);
                    if err_msg.contains("403") || err_msg.contains("Forbidden") {
                        warn!("Cookie rejected, attempting re-authentication");
                        self.state = ConnectionState::ReAuthenticating;
                        match self.re_authenticate().await {
                            Ok(()) => {
                                info!("Re-authentication successful, retrying tunnel");
                                continue;
                            }
                            Err(auth_err) => {
                                error!("Re-authentication failed: {}", auth_err);
                            }
                        }
                    }

                    let delay = self.backoff.current();
                    warn!("Tunnel connect failed: {}. Retrying in {:?}", e, delay);
                    self.backoff.next();

                    if self.wait_for_retry(delay, &mut network_rx).await {
                        break; // Ctrl+C
                    }
                    continue;
                }
            };

            // Run event loop
            let reason = vpn::event_loop(&mut tunnel, &mut lcp, &tun_dev).await;
            info!("Event loop exited: {:?}", reason);

            let _ = Self::send_terminate(&mut tunnel, &mut lcp).await;
            drop(tunnel);

            let action = classify_disconnect(&reason);
            match action {
                ReconnectAction::Exit => {
                    self.state = ConnectionState::Cleanup;
                    break;
                }
                ReconnectAction::RetryWithCookie => {
                    let delay = self.backoff.current();
                    self.state = ConnectionState::Reconnecting { attempt: 1 };
                    info!("Reconnecting in {:?}...", delay);
                    self.backoff.next();

                    if self.wait_for_retry(delay, &mut network_rx).await {
                        break; // Ctrl+C
                    }
                }
                ReconnectAction::ReAuthenticate => {
                    self.state = ConnectionState::ReAuthenticating;
                    match self.re_authenticate().await {
                        Ok(()) => {
                            info!("Re-authentication successful");
                        }
                        Err(e) => {
                            error!("Re-authentication failed: {}", e);
                            let delay = self.backoff.current();
                            self.backoff.next();
                            if self.wait_for_retry(delay, &mut network_rx).await {
                                break;
                            }
                        }
                    }
                }
            }
        }

        vpn::cleanup_tun(&self.tunnel_config, &iface_name);
        info!("VPN disconnected.");
        Ok(())
    }

    /// Wait for backoff timer, but cancel early if network becomes reachable.
    /// Returns true if user pressed Ctrl+C (should exit).
    async fn wait_for_retry(
        &mut self,
        delay: Duration,
        network_rx: &mut mpsc::Receiver<NetworkEvent>,
    ) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(delay) => false,
            event = network_rx.recv() => {
                match event {
                    Some(NetworkEvent::Reachable) => {
                        info!("Network reachable — reconnecting immediately");
                        self.backoff.reset();
                        false
                    }
                    Some(NetworkEvent::Unreachable) => {
                        info!("Network unreachable — resetting backoff");
                        self.backoff.reset();
                        false
                    }
                    None => {
                        debug!("Network monitor channel closed");
                        false
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C during backoff");
                self.state = ConnectionState::Cleanup;
                true
            }
        }
    }
```

Add `use tokio::sync::mpsc;` and `use tracing::debug;` to the imports in `reconnect.rs` if not already present.

- [ ] **Step 2: Verify compilation**

Run: `cargo build 2>&1`
Expected: Compiles successfully

- [ ] **Step 3: Run full test suite**

Run: `cargo test 2>&1`
Expected: All tests pass

- [ ] **Step 4: Run `cargo clippy`**

Run: `cargo clippy 2>&1`
Expected: No new warnings

- [ ] **Step 5: Commit**

```bash
git add src/reconnect.rs
git commit -m "feat(reconnect): integrate NetworkMonitor — cancel backoff on network return"
```

---

### Task 11: Layer 2 manual testing guide

**Files:**
- No code changes

- [ ] **Step 1: Test WiFi off/on reconnect**

```bash
# Start VPN
sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml

# Turn off WiFi in System Preferences (or: networksetup -setairportpower en0 off)
# Expected: "Dead peer detected" after ~30s, "Reconnecting in 1s..."
# Turn WiFi back on
# Expected: "Network reachable — reconnecting immediately" (cancels backoff)
# Expected: reconnect within 2-3s of WiFi return
```

- [ ] **Step 2: Test network switch**

```bash
# Start VPN on WiFi
# Switch to Ethernet (or different WiFi network)
# Expected: brief disconnect, then reconnect via network monitor trigger
```

- [ ] **Step 3: Commit tag**

```bash
git tag -a v0.2.0-layer2 -m "Phase 3 Layer 2: network change detection complete"
```

---

## Layer 3: Sleep/Wake Handling

### Task 12: Implement `PowerMonitor` with IOKit FFI

**Files:**
- Create: `src/power_monitor.rs`
- Create: `tests/power_monitor_test.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing test for `PowerEvent` enum**

Create `tests/power_monitor_test.rs`:

```rust
use forti_client::power_monitor::PowerEvent;

#[test]
fn test_power_event_variants() {
    let events = vec![
        PowerEvent::WillSleep,
        PowerEvent::HasPoweredOn,
    ];
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], PowerEvent::WillSleep));
    assert!(matches!(events[1], PowerEvent::HasPoweredOn));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test power_monitor_test 2>&1`
Expected: Compile error — `power_monitor` module not found

- [ ] **Step 3: Implement `PowerMonitor`**

Create `src/power_monitor.rs`:

```rust
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Power state events from macOS IOKit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerEvent {
    /// System is about to sleep. Acknowledge promptly.
    WillSleep,
    /// System has woken up. Network may not be ready yet.
    HasPoweredOn,
}

/// Monitors macOS system power state changes via IOKit.
pub struct PowerMonitor {
    _thread: std::thread::JoinHandle<()>,
}

// IOKit FFI bindings (minimal subset for power management)
mod ffi {
    use std::os::raw::{c_int, c_uint, c_void};

    pub type IONotificationPortRef = *mut c_void;
    pub type IOReturn = c_int;
    pub type IOObject = c_uint;

    pub const kIOMessageSystemWillSleep: u32 = 0xe0000280;
    pub const kIOMessageSystemHasPoweredOn: u32 = 0xe0000300;
    pub const kIOMessageCanSystemSleep: u32 = 0xe0000270;

    pub type IOServiceInterestCallback = extern "C" fn(
        refcon: *mut c_void,
        service: IOObject,
        message_type: u32,
        message_argument: *mut c_void,
    );

    extern "C" {
        pub fn IORegisterForSystemPower(
            refcon: *mut c_void,
            notify_port_ref: *mut IONotificationPortRef,
            callback: IOServiceInterestCallback,
            notifier: *mut IOObject,
        ) -> IOObject;

        pub fn IODeregisterForSystemPower(notifier: *mut IOObject) -> IOReturn;

        pub fn IOAllowPowerChange(
            kernel_port: IOObject,
            notification_id: isize,
        ) -> IOReturn;

        pub fn IONotificationPortGetRunLoopSource(
            notify: IONotificationPortRef,
        ) -> *const c_void; // CFRunLoopSourceRef

        pub fn IONotificationPortDestroy(notify: IONotificationPortRef);
    }

    // CoreFoundation run loop bindings
    extern "C" {
        pub fn CFRunLoopGetCurrent() -> *const c_void;
        pub fn CFRunLoopAddSource(
            rl: *const c_void,
            source: *const c_void,
            mode: *const c_void,
        );
        pub fn CFRunLoopRun();
        pub fn CFRunLoopStop(rl: *const c_void);
    }

    // kCFRunLoopDefaultMode
    extern "C" {
        pub static kCFRunLoopDefaultMode: *const c_void;
    }
}

struct PowerCallbackContext {
    tx: mpsc::Sender<PowerEvent>,
    root_port: ffi::IOObject,
}

extern "C" fn power_callback(
    refcon: *mut std::os::raw::c_void,
    _service: ffi::IOObject,
    message_type: u32,
    message_argument: *mut std::os::raw::c_void,
) {
    let ctx = unsafe { &*(refcon as *const PowerCallbackContext) };

    match message_type {
        ffi::kIOMessageSystemWillSleep => {
            debug!("IOKit: WillSleep");
            let _ = ctx.tx.blocking_send(PowerEvent::WillSleep);
            // Must acknowledge sleep promptly
            unsafe {
                ffi::IOAllowPowerChange(ctx.root_port, message_argument as isize);
            }
        }
        ffi::kIOMessageCanSystemSleep => {
            // Allow system to sleep (don't veto)
            unsafe {
                ffi::IOAllowPowerChange(ctx.root_port, message_argument as isize);
            }
        }
        ffi::kIOMessageSystemHasPoweredOn => {
            debug!("IOKit: HasPoweredOn");
            let _ = ctx.tx.blocking_send(PowerEvent::HasPoweredOn);
        }
        _ => {
            debug!("IOKit: unknown power message 0x{:08x}", message_type);
        }
    }
}

impl PowerMonitor {
    /// Start monitoring power state changes.
    /// Returns the monitor handle and a receiver for power events.
    pub fn start() -> Result<(Self, mpsc::Receiver<PowerEvent>), String> {
        let (tx, rx) = mpsc::channel(8);

        let thread = std::thread::Builder::new()
            .name("power-monitor".into())
            .spawn(move || {
                Self::run_power_loop(tx);
            })
            .map_err(|e| format!("failed to spawn power monitor thread: {}", e))?;

        Ok((Self { _thread: thread }, rx))
    }

    fn run_power_loop(tx: mpsc::Sender<PowerEvent>) {
        unsafe {
            let mut notify_port: ffi::IONotificationPortRef = std::ptr::null_mut();
            let mut notifier: ffi::IOObject = 0;

            // Allocate context on the heap so it lives as long as the callback needs it
            let ctx = Box::new(PowerCallbackContext {
                tx,
                root_port: 0, // Will be set after registration
            });
            let ctx_ptr = Box::into_raw(ctx);

            let root_port = ffi::IORegisterForSystemPower(
                ctx_ptr as *mut std::os::raw::c_void,
                &mut notify_port,
                power_callback,
                &mut notifier,
            );

            if root_port == 0 {
                warn!("IORegisterForSystemPower failed");
                let _ = Box::from_raw(ctx_ptr); // Clean up
                return;
            }

            // Set root_port in context so callback can use it for IOAllowPowerChange
            (*ctx_ptr).root_port = root_port;

            let run_loop_source = ffi::IONotificationPortGetRunLoopSource(notify_port);
            if run_loop_source.is_null() {
                warn!("IONotificationPortGetRunLoopSource returned null");
                let _ = Box::from_raw(ctx_ptr);
                return;
            }

            let run_loop = ffi::CFRunLoopGetCurrent();
            ffi::CFRunLoopAddSource(run_loop, run_loop_source, ffi::kCFRunLoopDefaultMode);

            info!("Power monitor started");
            ffi::CFRunLoopRun();

            // Cleanup (reached if run loop is stopped)
            ffi::IODeregisterForSystemPower(&mut notifier);
            ffi::IONotificationPortDestroy(notify_port);
            let _ = Box::from_raw(ctx_ptr);
            debug!("Power monitor thread exiting");
        }
    }
}
```

Add to `src/lib.rs`:

```rust
pub mod power_monitor;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test power_monitor_test 2>&1`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `cargo test 2>&1`
Expected: All tests pass

- [ ] **Step 6: Add IOKit framework link**

If the build fails with unresolved IOKit symbols, add to `Cargo.toml`:

```toml
[target.'cfg(target_os = "macos")'.dependencies]
```

And create `build.rs` if needed:

```rust
fn main() {
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=framework=IOKit");
}
```

- [ ] **Step 7: Verify build and tests**

Run: `cargo build 2>&1 && cargo test 2>&1`
Expected: Compiles and all tests pass

- [ ] **Step 8: Commit**

```bash
git add src/power_monitor.rs src/lib.rs tests/power_monitor_test.rs
git add build.rs  # if created
git commit -m "feat(power): add PowerMonitor with IOKit FFI for sleep/wake detection"
```

---

### Task 13: Add timing gap heuristic to event loop

**Files:**
- Modify: `src/vpn.rs`
- Modify: `tests/reconnect_test.rs`

- [ ] **Step 1: Write test for timing gap detection helper**

Append to `tests/reconnect_test.rs`:

```rust
use std::time::{Duration, Instant};
use forti_client::reconnect::detect_sleep_gap;

#[test]
fn test_no_gap_detected_for_normal_interval() {
    let last = Instant::now() - Duration::from_secs(10);
    assert!(!detect_sleep_gap(last, Duration::from_secs(10)));
}

#[test]
fn test_gap_detected_for_long_pause() {
    let last = Instant::now() - Duration::from_secs(45);
    assert!(detect_sleep_gap(last, Duration::from_secs(10)));
}

#[test]
fn test_no_gap_for_moderate_delay() {
    // 20s elapsed with 10s interval — 2x is not enough to trigger (threshold is 3x)
    let last = Instant::now() - Duration::from_secs(20);
    assert!(!detect_sleep_gap(last, Duration::from_secs(10)));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test reconnect_test detect_sleep 2>&1`
Expected: Compile error — `detect_sleep_gap` not found

- [ ] **Step 3: Implement `detect_sleep_gap`**

Add to `src/reconnect.rs`:

```rust
use std::time::Instant;

/// Detect if the system likely slept by checking if elapsed time since the last
/// keepalive tick is much larger than expected (> 3x the interval).
pub fn detect_sleep_gap(last_tick: Instant, expected_interval: Duration) -> bool {
    last_tick.elapsed() > expected_interval * 3
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test reconnect_test detect_sleep 2>&1`
Expected: All 3 tests PASS

- [ ] **Step 5: Add timing gap check to `vpn.rs` event loop**

In `src/vpn.rs`, in the keepalive timer arm, add the gap check before the echo-request send. Add an `Instant` tracker:

After `let mut pkt_count: u64 = 0;` add:

```rust
    let mut last_tick = std::time::Instant::now();
```

In the keepalive tick arm, before the existing echo-request code:

```rust
            _ = keepalive.tick() => {
                // Timing gap heuristic: detect possible sleep/wake
                if crate::reconnect::detect_sleep_gap(last_tick, Duration::from_secs(10)) {
                    info!("Timing gap detected ({}s since last tick) — possible sleep/wake",
                        last_tick.elapsed().as_secs());
                    return DisconnectReason::DeadPeer;
                }
                last_tick = std::time::Instant::now();

                // ... existing echo-request code stays here ...
```

- [ ] **Step 6: Run full test suite**

Run: `cargo test 2>&1`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add src/reconnect.rs src/vpn.rs tests/reconnect_test.rs
git commit -m "feat(reconnect): add timing gap heuristic as sleep/wake safety net"
```

---

### Task 14: Integrate `PowerMonitor` into `ReconnectController`

**Files:**
- Modify: `src/reconnect.rs`

- [ ] **Step 1: Add sleep/wake states and power monitor integration**

Add `WaitingForNetwork` to `ConnectionState`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Reconnecting { attempt: u32 },
    ReAuthenticating,
    /// Waiting for network to return after sleep/wake (Layer 3).
    WaitingForNetwork,
    Cleanup,
}
```

Add import:

```rust
use crate::power_monitor::{PowerMonitor, PowerEvent};
```

Update `ReconnectController::run()` to start the power monitor and handle its events. Add power monitor startup alongside network monitor:

```rust
        // Start power monitor
        let (_power_monitor, mut power_rx) = PowerMonitor::start()
            .map_err(|e| FortiError::TunnelError(format!("power monitor failed: {}", e)))?;
```

Add a new method for handling the sleep event — gracefully close tunnel before sleep:

```rust
    /// Handle WillSleep: gracefully close the active tunnel.
    /// Called when we receive a power event while connected.
    async fn handle_will_sleep(tunnel: &mut TlsTunnel, lcp: &mut crate::ppp::lcp::LcpState) {
        info!("System going to sleep — closing tunnel gracefully");
        let _ = Self::send_terminate(tunnel, lcp).await;
        // Tunnel will be dropped by the caller
    }
```

Update the main loop to check power events. In the main event loop, after `vpn::event_loop` returns, also check for sleep/wake. The key change is adding a `tokio::select!` around the event loop that also listens for `WillSleep`:

Replace the event loop call:

```rust
            // Run event loop — but also listen for sleep events
            let reason = tokio::select! {
                reason = vpn::event_loop(&mut tunnel, &mut lcp, &tun_dev) => reason,
                Some(PowerEvent::WillSleep) = power_rx.recv() => {
                    Self::handle_will_sleep(&mut tunnel, &mut lcp).await;
                    // Enter WaitingForNetwork — don't reconnect until network is back
                    self.state = ConnectionState::WaitingForNetwork;
                    drop(tunnel);

                    // Wait for HasPoweredOn, then Reachable
                    loop {
                        tokio::select! {
                            Some(power_event) = power_rx.recv() => {
                                if matches!(power_event, PowerEvent::HasPoweredOn) {
                                    info!("System woke up — waiting for network");
                                }
                            }
                            Some(NetworkEvent::Reachable) = network_rx.recv() => {
                                info!("Network reachable after wake — reconnecting");
                                self.backoff.reset();
                                break;
                            }
                            _ = tokio::signal::ctrl_c() => {
                                info!("Ctrl+C during wake");
                                self.state = ConnectionState::Cleanup;
                                vpn::cleanup_tun(&self.tunnel_config, &iface_name);
                                info!("VPN disconnected.");
                                return Ok(());
                            }
                        }
                    }
                    continue; // Go back to top of loop to reconnect
                }
            };
```

Note: This requires restructuring the loop slightly. The `tunnel` variable must be created inside the loop body so it can be dropped in the sleep path. The `continue` at the end of the sleep handler goes back to `connect_tunnel()`.

- [ ] **Step 2: Verify compilation**

Run: `cargo build 2>&1`
Expected: Compiles. Fix any borrow issues — the `network_rx` and `power_rx` are both used in the loop, which is fine as long as they're `&mut` references.

- [ ] **Step 3: Run full test suite**

Run: `cargo test 2>&1`
Expected: All tests pass

- [ ] **Step 4: Run `cargo clippy`**

Run: `cargo clippy 2>&1`
Expected: No new warnings (may need to suppress some clippy lints on the unsafe IOKit code)

- [ ] **Step 5: Commit**

```bash
git add src/reconnect.rs
git commit -m "feat(reconnect): integrate PowerMonitor — graceful sleep/wake with WaitingForNetwork state"
```

---

### Task 15: Layer 3 manual testing guide

**Files:**
- No code changes

- [ ] **Step 1: Test sleep via lid close**

```bash
# Start VPN
sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml

# Close laptop lid, wait a few seconds, reopen
# Expected log sequence:
#   "IOKit: WillSleep"
#   "System going to sleep — closing tunnel gracefully"
#   "IOKit: HasPoweredOn"
#   "System woke up — waiting for network"
#   "Network reachable — reconnecting"
#   "Tunnel established, entering data plane"
```

- [ ] **Step 2: Test sleep via `pmset sleepnow`**

```bash
# Terminal 1: start VPN (sudo)
sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml

# Terminal 2: trigger immediate sleep
sudo pmset sleepnow

# Wake by pressing any key / opening lid
# Expected: same sequence as Step 1
```

- [ ] **Step 3: Test long sleep (cookie expiry)**

```bash
# Start VPN, close lid
# Wait > 30 seconds (exceeds tun-user-ses-timeout)
# Open lid
# Expected:
#   "Network reachable — reconnecting"
#   "Cookie rejected, attempting re-authentication"
#   "Re-authenticating via SAML..."
#   (browser opens, auto-closes after auth)
#   "Re-authentication successful"
#   "Tunnel established, entering data plane"
```

- [ ] **Step 4: Test WiFi off before sleep**

```bash
# Start VPN
# Turn off WiFi
# Close lid (sleep)
# Open lid
# Turn on WiFi
# Expected: WaitingForNetwork until WiFi returns, then reconnect
```

- [ ] **Step 5: Test Ctrl+C during wake/wait**

```bash
# Start VPN, close lid, open lid
# Before WiFi reconnects, press Ctrl+C
# Expected: immediate clean exit
```

- [ ] **Step 6: Test timing gap heuristic**

```bash
# This is a safety net — hard to test in isolation
# If IOKit doesn't fire (rare), the keepalive timer detects the gap:
# "Timing gap detected (45s since last tick) — possible sleep/wake"
# Then normal reconnect flow follows
```

- [ ] **Step 7: Tag Layer 3 complete**

```bash
git tag -a v0.2.0-layer3 -m "Phase 3 Layer 3: sleep/wake handling complete"
```

---

### Task 16: Update CLAUDE.md for Phase 3

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update project status and module layout**

In CLAUDE.md, update the **Status** line:

```
**Status:** Phases 1–3 complete. SAML auth, TLS tunnel, PPP negotiation, TUN device, split-tunnel routing, DNS, keepalive, packet forwarding, auto-reconnect with exponential backoff, network change detection (SCNetworkReachability), and macOS sleep/wake handling (IOKit) all work end-to-end.
```

Add new modules to the **Module Layout** section:

```
- **`reconnect.rs`** — `ReconnectController` state machine, `DisconnectReason`/`ReconnectAction` enums, `Backoff`, `detect_sleep_gap`
- **`network_monitor.rs`** — `NetworkMonitor` using `system-configuration` crate for SCNetworkReachability callbacks
- **`power_monitor.rs`** — `PowerMonitor` using IOKit FFI for sleep/wake notifications (`WillSleep`, `HasPoweredOn`)
```

Update the **Architecture** section to note that `vpn.rs` event loop is wrapped by `ReconnectController`.

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for Phase 3 completion"
```
