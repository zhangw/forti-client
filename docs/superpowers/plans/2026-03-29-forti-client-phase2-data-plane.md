# FortiClient Phase 2: Data Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Phase 1 PPP tunnel into a working VPN that routes real IP traffic through a macOS utun device with split-tunnel routes and DNS.

**Architecture:** A `tun` module creates a macOS utun interface and manages routes/DNS. A `vpn` module runs the main `tokio::select!` event loop multiplexing TUN reads, tunnel reads, LCP keepalive, and signal handling. The PPP engine is refactored to expose its LCP state for keepalive use after negotiation. Cleanup runs on every exit path via an explicit cleanup function.

**Tech Stack:** Existing deps + `tun-rs 2` (utun device, async tokio support). Route/DNS management via `std::process::Command` calling `/sbin/route` and `scutil`.

**Architecture Reference:** `docs/phase2-architecture.md`

**Phase 1 Findings:** `docs/phase1-findings.md`

---

## File Structure

```
src/
├── main.rs              # Modified: call vpn::run() after PPP negotiation
├── lib.rs               # Modified: add tun, vpn modules
├── error.rs             # Unchanged
├── auth/                # Unchanged
├── tunnel/              # Unchanged
├── ppp/
│   ├── mod.rs           # Modified: expose lcp state for keepalive after negotiation
│   ├── codec.rs         # Unchanged
│   ├── lcp.rs           # Unchanged
│   └── ipcp.rs          # Unchanged
├── tun/
│   ├── mod.rs           # New: TUN device creation, IP assignment
│   ├── routes.rs        # New: route install/remove via /sbin/route
│   └── dns.rs           # New: DNS config via scutil
└── vpn.rs               # New: main event loop (select! over TUN, tunnel, keepalive, signals)
Cargo.toml               # Modified: add tun-rs dependency
```

---

### Task 1: Add `tun-rs` Dependency and TUN Device Module

Creates the utun device, assigns the IP address, and returns an async reader/writer.

**Files:**
- Modify: `Cargo.toml`
- Create: `src/tun/mod.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Add tun-rs to Cargo.toml**

Add to `[dependencies]` section in `Cargo.toml`:

```toml
# TUN device (macOS utun)
tun-rs = { version = "2", features = ["async"] }
```

- [ ] **Step 2: Create src/tun/mod.rs**

Create `src/tun/mod.rs`:

```rust
pub mod routes;
pub mod dns;

use crate::error::{FortiError, Result};
use std::net::Ipv4Addr;
use tracing::{info, debug};

/// Create a macOS utun device with the given IP address.
/// Returns the tun device and the interface name (e.g., "utun3").
///
/// Must be run as root.
pub fn create_tun(ip: Ipv4Addr) -> Result<(tun_rs::AsyncDevice, String)> {
    let mut config = tun_rs::Configuration::default();
    config.address_with_prefix(ip, 32);
    config.up();

    // Platform-specific: disable the default route tun-rs might add
    #[cfg(target_os = "macos")]
    config.platform_config(|p| {
        p.packet_information(true); // include 4-byte AF header (macOS utun requirement)
    });

    let dev = tun_rs::create_as_async(&config)
        .map_err(|e| FortiError::TunnelError(format!("failed to create TUN device: {}", e)))?;

    let name = dev.as_ref().name()
        .map_err(|e| FortiError::TunnelError(format!("failed to get TUN name: {}", e)))?;

    info!("Created TUN device {} with IP {}/32", name, ip);
    Ok((dev, name))
}
```

- [ ] **Step 3: Add tun module to lib.rs**

Modify `src/lib.rs`:

```rust
pub mod error;
pub mod ppp;
pub mod auth;
pub mod tunnel;
pub mod tun;
pub mod vpn;
```

- [ ] **Step 4: Verify it builds**

Run: `cargo build 2>&1`

This may fail if the `tun-rs` API differs from what's shown. Read the actual `tun-rs` docs/examples if needed and adjust. The key requirements are:
1. Create a utun device
2. Set its IP address
3. Get the interface name (e.g., "utun3")
4. Return an async-capable device that supports read/write

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/tun/mod.rs src/lib.rs
git commit -m "feat: add TUN device creation via tun-rs"
```

---

### Task 2: Route Installation and Removal

Installs split-tunnel routes via `/sbin/route` and removes them on cleanup.

**Files:**
- Create: `src/tun/routes.rs`
- Create: `tests/routes_test.rs`

- [ ] **Step 1: Write tests for route command generation**

Create `tests/routes_test.rs`:

```rust
use forti_client::tun::routes::{route_add_cmd, route_delete_cmd};
use forti_client::auth::xml::Route;
use std::net::Ipv4Addr;

#[test]
fn test_route_add_subnet() {
    let route = Route {
        ip: Ipv4Addr::new(10, 60, 0, 0),
        mask: Ipv4Addr::new(255, 255, 240, 0),
    };
    let args = route_add_cmd(&route, "utun3");
    assert_eq!(args, vec!["add", "-net", "10.60.0.0/20", "-interface", "utun3"]);
}

#[test]
fn test_route_add_host() {
    let route = Route {
        ip: Ipv4Addr::new(18, 169, 33, 210),
        mask: Ipv4Addr::new(255, 255, 255, 255),
    };
    let args = route_add_cmd(&route, "utun3");
    assert_eq!(args, vec!["add", "-host", "18.169.33.210", "-interface", "utun3"]);
}

#[test]
fn test_route_delete_subnet() {
    let route = Route {
        ip: Ipv4Addr::new(10, 60, 0, 0),
        mask: Ipv4Addr::new(255, 255, 240, 0),
    };
    let args = route_delete_cmd(&route, "utun3");
    assert_eq!(args, vec!["delete", "-net", "10.60.0.0/20", "-interface", "utun3"]);
}

#[test]
fn test_mask_to_prefix_len() {
    use forti_client::tun::routes::mask_to_prefix;
    assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
    assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
    assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 240, 0)), 20);
    assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
    assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), 8);
    assert_eq!(mask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), 0);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test routes_test 2>&1`
Expected: Compilation error — `tun::routes` module doesn't exist yet.

- [ ] **Step 3: Implement routes.rs**

Create `src/tun/routes.rs`:

```rust
use crate::auth::xml::Route;
use crate::error::{FortiError, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{info, debug, warn};

/// Convert a subnet mask to a prefix length (e.g., 255.255.240.0 → 20).
pub fn mask_to_prefix(mask: Ipv4Addr) -> u32 {
    u32::from_be_bytes(mask.octets()).count_ones()
}

/// Build the arguments for `/sbin/route add` for a given route.
pub fn route_add_cmd(route: &Route, iface: &str) -> Vec<String> {
    let prefix = mask_to_prefix(route.mask);
    if prefix == 32 {
        vec![
            "add".into(),
            "-host".into(),
            route.ip.to_string(),
            "-interface".into(),
            iface.into(),
        ]
    } else {
        vec![
            "add".into(),
            "-net".into(),
            format!("{}/{}", route.ip, prefix),
            "-interface".into(),
            iface.into(),
        ]
    }
}

/// Build the arguments for `/sbin/route delete` for a given route.
pub fn route_delete_cmd(route: &Route, iface: &str) -> Vec<String> {
    let prefix = mask_to_prefix(route.mask);
    if prefix == 32 {
        vec![
            "delete".into(),
            "-host".into(),
            route.ip.to_string(),
            "-interface".into(),
            iface.into(),
        ]
    } else {
        vec![
            "delete".into(),
            "-net".into(),
            format!("{}/{}", route.ip, prefix),
            "-interface".into(),
            iface.into(),
        ]
    }
}

/// Install all split-tunnel routes. Returns the number successfully installed.
/// Requires root.
pub fn install_routes(routes: &[Route], iface: &str) -> Result<usize> {
    let mut installed = 0;
    let total = routes.len();

    for route in routes {
        let args = route_add_cmd(route, iface);
        debug!("route {}", args.join(" "));

        let output = Command::new("/sbin/route")
            .args(&args)
            .output()
            .map_err(|e| FortiError::TunnelError(format!("failed to run /sbin/route: {}", e)))?;

        if output.status.success() {
            installed += 1;
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "File exists" means the route is already there — not a real error
            if !stderr.contains("File exists") {
                debug!("route add failed for {}: {}", route.ip, stderr.trim());
            }
        }
    }

    info!("Installed {}/{} routes on {}", installed, total, iface);
    Ok(installed)
}

/// Remove all split-tunnel routes. Best-effort — logs failures but doesn't error.
pub fn remove_routes(routes: &[Route], iface: &str) {
    let mut removed = 0;
    for route in routes {
        let args = route_delete_cmd(route, iface);
        if let Ok(output) = Command::new("/sbin/route").args(&args).output() {
            if output.status.success() {
                removed += 1;
            }
        }
    }
    info!("Removed {}/{} routes from {}", removed, routes.len(), iface);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test routes_test 2>&1`
Expected: All 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/tun/routes.rs tests/routes_test.rs
git commit -m "feat: implement route installation/removal via /sbin/route"
```

---

### Task 3: DNS Configuration

Configures the VPN DNS servers via `scutil` as a supplemental resolver.

**Files:**
- Create: `src/tun/dns.rs`

- [ ] **Step 1: Implement dns.rs**

Create `src/tun/dns.rs`:

```rust
use crate::error::{FortiError, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{info, debug};

const SCUTIL_SERVICE: &str = "State:/Network/Service/forti-client/DNS";

/// Configure VPN DNS servers via scutil.
/// Adds them as a supplemental resolver so internal names resolve via VPN
/// while public names use the normal system resolver.
/// Requires root.
pub fn configure_dns(servers: &[Ipv4Addr]) -> Result<()> {
    if servers.is_empty() {
        debug!("No DNS servers to configure");
        return Ok(());
    }

    let server_strs: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    let servers_joined = server_strs.join(" ");

    // Build scutil commands to set DNS
    let scutil_input = format!(
        "d.init\n\
         d.add ServerAddresses * {}\n\
         d.add SupplementalMatchDomains * \"\"\n\
         set {}\n",
        servers_joined, SCUTIL_SERVICE,
    );

    debug!("Configuring DNS via scutil:\n{}", scutil_input.trim());

    let output = Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(scutil_input.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| FortiError::TunnelError(format!("failed to run scutil: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FortiError::TunnelError(format!("scutil failed: {}", stderr.trim())));
    }

    info!("Configured DNS servers: {}", servers_joined);
    Ok(())
}

/// Remove VPN DNS configuration.
pub fn remove_dns() {
    let scutil_input = format!("remove {}\n", SCUTIL_SERVICE);

    let result = Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(scutil_input.as_bytes())?;
            }
            child.wait_with_output()
        });

    match result {
        Ok(output) if output.status.success() => info!("Removed DNS configuration"),
        _ => debug!("DNS cleanup: nothing to remove or scutil failed"),
    }
}
```

- [ ] **Step 2: Verify it builds**

Run: `cargo build 2>&1`
Expected: Compiles successfully.

- [ ] **Step 3: Commit**

```bash
git add src/tun/dns.rs
git commit -m "feat: implement DNS configuration via scutil"
```

---

### Task 4: Expose LCP State from PPP Engine

After PPP negotiation completes, the main event loop needs access to the LCP state machine (for keepalive echo handling). Refactor `PppEngine` to give back its LCP state.

**Files:**
- Modify: `src/ppp/mod.rs`
- Modify: `src/ppp/lcp.rs`

- [ ] **Step 1: Add `into_lcp` method to PppEngine**

Add to `src/ppp/mod.rs`, inside `impl PppEngine`:

```rust
    /// Consume the engine and return the LCP state for keepalive use.
    pub fn into_lcp(self) -> lcp::LcpState {
        self.lcp
    }
```

- [ ] **Step 2: Verify existing tests still pass**

Run: `cargo test 2>&1`
Expected: All 25 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/ppp/mod.rs
git commit -m "feat: expose LCP state from PppEngine for keepalive use"
```

---

### Task 5: Main VPN Event Loop

The core of Phase 2 — multiplexes TUN device reads, tunnel reads, keepalive timer, and Ctrl+C handling.

**Files:**
- Create: `src/vpn.rs`

- [ ] **Step 1: Implement vpn.rs**

Create `src/vpn.rs`:

```rust
use crate::auth::xml::{Route, TunnelConfig};
use crate::error::{FortiError, Result};
use crate::ppp::codec::{PppFrame, PppProtocol};
use crate::ppp::lcp::LcpState;
use crate::tunnel::TlsTunnel;
use crate::tun;

use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

/// Run the VPN data plane: TUN device, routes, DNS, packet forwarding, keepalive.
///
/// This function takes ownership of the tunnel and runs until disconnection
/// (Ctrl+C, dead peer, or error). It handles all cleanup on exit.
pub async fn run(
    mut tunnel: TlsTunnel,
    mut lcp: LcpState,
    config: &TunnelConfig,
) -> Result<()> {
    // 1. Create TUN device
    let (tun_dev, iface_name) = tun::create_tun(config.ip_address)?;

    // 2. Install routes
    let routes = &config.routes;
    tun::routes::install_routes(routes, &iface_name)?;

    // 3. Configure DNS
    tun::dns::configure_dns(&config.dns_servers)?;

    info!(
        "VPN active on {} — IP={}, {} routes, {} DNS servers",
        iface_name,
        config.ip_address,
        routes.len(),
        config.dns_servers.len(),
    );
    info!("Press Ctrl+C to disconnect.");

    // 4. Run the event loop
    let result = event_loop(&mut tunnel, &mut lcp, &tun_dev).await;

    // 5. Cleanup (always runs)
    info!("Cleaning up...");
    tun::routes::remove_routes(routes, &iface_name);
    tun::dns::remove_dns();

    // Send LCP Terminate-Request (best-effort)
    let term_req = lcp.build_terminate_request();
    let ppp_frame = PppFrame::new(PppProtocol::Lcp, term_req);
    let _ = tunnel.send_frame(ppp_frame.encode()).await;

    info!("VPN disconnected.");
    result
}

async fn event_loop(
    tunnel: &mut TlsTunnel,
    lcp: &mut LcpState,
    tun_dev: &tun_rs::AsyncDevice,
) -> Result<()> {
    let mut keepalive = tokio::time::interval(Duration::from_secs(10));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut missed_echoes: u32 = 0;
    let mut tun_buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            // TUN → Tunnel (outbound: app sends packet through VPN)
            result = tun_dev.read(&mut tun_buf) => {
                let n = result.map_err(|e| FortiError::TunnelError(
                    format!("TUN read error: {}", e)
                ))?;
                if n <= 4 {
                    continue; // too short — no IP packet after AF header
                }
                // Strip the 4-byte AF header (macOS utun requirement)
                let ip_packet = &tun_buf[4..n];
                let ppp = PppFrame::new(PppProtocol::Ipv4, ip_packet.to_vec());
                tunnel.send_frame(ppp.encode()).await?;
            }

            // Tunnel → TUN (inbound: FortiGate sends packet to us)
            result = tunnel.recv_frame() => {
                let frame = result?;
                let ppp = PppFrame::decode(frame.payload())?;

                match ppp.protocol() {
                    PppProtocol::Ipv4 => {
                        // Prepend 4-byte AF_INET header for macOS utun
                        let mut buf = vec![0u8, 0, 0, 2]; // AF_INET = 2
                        buf.extend_from_slice(ppp.data());
                        tun_dev.write_all(&buf).await.map_err(|e| {
                            FortiError::TunnelError(format!("TUN write error: {}", e))
                        })?;
                    }
                    PppProtocol::Lcp => {
                        let code = ppp.data().first().copied().unwrap_or(0);
                        let responses = lcp.handle_packet(ppp.data());
                        for resp in responses {
                            let ppp_frame = PppFrame::new(PppProtocol::Lcp, resp);
                            tunnel.send_frame(ppp_frame.encode()).await?;
                        }
                        if code == 10 {
                            // Echo-Reply received — peer is alive
                            missed_echoes = 0;
                        }
                        if code == 5 {
                            // Terminate-Request from server
                            info!("Server sent LCP Terminate-Request");
                            return Ok(());
                        }
                    }
                    PppProtocol::Ipv6 => {
                        // TODO: IPv6 support in Phase 3
                        debug!("Ignoring IPv6 packet");
                    }
                    other => {
                        debug!("Ignoring PPP protocol {:?}", other);
                    }
                }
            }

            // Keepalive timer
            _ = keepalive.tick() => {
                let echo = lcp.build_echo_request();
                let ppp_frame = PppFrame::new(PppProtocol::Lcp, echo);
                tunnel.send_frame(ppp_frame.encode()).await?;
                missed_echoes += 1;
                if missed_echoes > 3 {
                    error!("Dead peer detected ({} missed echoes)", missed_echoes);
                    return Err(FortiError::TunnelError("dead peer detected".into()));
                }
            }

            // Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received");
                return Ok(());
            }
        }
    }
}
```

- [ ] **Step 2: Add `build_terminate_request` to LcpState**

Add to `src/ppp/lcp.rs`, inside `impl LcpState`:

```rust
    /// Build an LCP Terminate-Request for graceful shutdown.
    pub fn build_terminate_request(&mut self) -> Vec<u8> {
        let id = self.next_id();
        let pkt = LcpPacket::new(LcpCode::TerminateRequest, id, Vec::new());
        pkt.encode()
    }
```

- [ ] **Step 3: Verify it builds**

Run: `cargo build 2>&1`
Expected: Compiles. If the `tun-rs` async API differs (e.g., `read`/`write` signatures), adjust accordingly.

- [ ] **Step 4: Run existing tests**

Run: `cargo test 2>&1`
Expected: All existing tests still pass (25+).

- [ ] **Step 5: Commit**

```bash
git add src/vpn.rs src/ppp/lcp.rs src/lib.rs
git commit -m "feat: implement VPN event loop with TUN forwarding, keepalive, and cleanup"
```

---

### Task 6: Wire Up main.rs

Connect the Phase 1 auth+negotiate flow to the Phase 2 VPN event loop.

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Update main.rs**

Replace `src/main.rs` with:

```rust
use clap::Parser;
use tracing_subscriber::EnvFilter;
use forti_client::auth::AuthClient;
use forti_client::tunnel::TlsTunnel;
use forti_client::ppp::PppEngine;
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

    let auth_result = if cli.saml {
        tracing::info!("Starting SAML authentication to {}:{}", cli.server, cli.port);
        auth_client.login_saml().await?
    } else {
        let username = cli.username
            .ok_or_else(|| anyhow::anyhow!("--username is required for credential auth (use --saml for SSO)"))?;

        let password = match cli.password {
            Some(p) => p,
            None => {
                eprint!("Password: ");
                std::io::stderr().flush()?;
                let mut p = String::new();
                std::io::stdin().read_line(&mut p)?;
                p.trim().to_string()
            }
        };

        tracing::info!("Authenticating to {}:{}", cli.server, cli.port);
        auth_client
            .login(&username, &password, cli.realm.as_deref())
            .await?
    };

    tracing::info!(
        "Authenticated. IP={}, DNS={:?}, {} routes",
        auth_result.tunnel_config.ip_address,
        auth_result.tunnel_config.dns_servers,
        auth_result.tunnel_config.routes.len(),
    );

    // Establish TLS tunnel
    tracing::info!("Establishing TLS tunnel");
    let mut tunnel = TlsTunnel::connect(
        &cli.server,
        cli.port,
        &auth_result.svpn_cookie,
        auth_client.tls_config(),
    )
    .await?;

    // PPP negotiation
    tracing::info!("Running PPP negotiation");
    let mut ppp = PppEngine::new(1500);
    let ipcp_config = ppp.negotiate(&mut tunnel).await?;

    tracing::info!("PPP negotiation complete — IP={}", ipcp_config.ip_address);
    if let Some(dns) = ipcp_config.primary_dns {
        tracing::info!("  Primary DNS: {}", dns);
    }

    // Extract LCP state for keepalive and run the VPN data plane
    let lcp = ppp.into_lcp();
    forti_client::vpn::run(tunnel, lcp, &auth_result.tunnel_config).await?;

    Ok(())
}
```

- [ ] **Step 2: Verify it builds**

Run: `cargo build 2>&1`
Expected: Compiles successfully.

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat: wire up VPN data plane in main.rs"
```

---

### Task 7: Build, Test, and Fix

Run all tests, clippy, and fix any compilation or API issues.

**Files:**
- Potentially any file that needs API adjustments

- [ ] **Step 1: Run cargo check**

Run: `cargo check 2>&1`
Fix any compilation errors. Common issues:
- `tun-rs` API may differ from what's shown (read the actual crate docs if needed)
- `AsyncDevice::read` may take `&mut [u8]` or return `io::Result<usize>` — adjust signatures
- `tun_rs::AsyncDevice` might not implement `AsyncWriteExt` directly — may need `tun_dev.send()` instead of `write_all()`

- [ ] **Step 2: Run all tests**

Run: `cargo test 2>&1`
Expected: All tests pass (25 existing + 4 new route tests = 29 total).

- [ ] **Step 3: Run clippy**

Run: `cargo clippy 2>&1`
Fix any warnings.

- [ ] **Step 4: Verify release build**

Run: `cargo build --release 2>&1`
Expected: Compiles successfully.

- [ ] **Step 5: Commit fixes if any**

```bash
git add -A
git commit -m "chore: fix compilation issues and clippy warnings"
```

---

### Task 8: Live Test Against Real FortiGate

Test the full VPN connection with real traffic.

**Files:**
- None (testing only)

- [ ] **Step 1: Build and run with sudo**

```bash
cargo build && sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --port 10443 --saml
```

Note: `cargo run` with sudo requires passing env vars carefully. Building first then running the binary directly with sudo is more reliable.

Expected output:
```
INFO  SAML authentication ...
INFO  Authenticated. IP=10.8.2.6, DNS=[...], 674 routes
INFO  Establishing TLS tunnel
INFO  PPP negotiation complete — IP=10.8.2.6
INFO  Created TUN device utun3 with IP 10.8.2.6/32
INFO  Installed 674/674 routes on utun3
INFO  Configured DNS servers: ...
INFO  VPN active on utun3 — IP=10.8.2.6, 674 routes, 2 DNS servers
INFO  Press Ctrl+C to disconnect.
```

- [ ] **Step 2: Test connectivity**

In another terminal, while the VPN is running:

```bash
# Check the TUN device exists
ifconfig utun3

# Check routes
netstat -rn | grep utun3 | head -5

# Check DNS
scutil --dns | grep forti-client -A 5

# Ping an internal host (pick one from the route list)
ping -c 3 10.60.0.1

# Test DNS resolution of an internal hostname (if known)
nslookup internal-host.company.com
```

- [ ] **Step 3: Test disconnect**

Press Ctrl+C in the forti-client terminal. Verify:
```
INFO  Ctrl+C received
INFO  Cleaning up...
INFO  Removed 674/674 routes from utun3
INFO  Removed DNS configuration
INFO  VPN disconnected.
```

Then verify cleanup:
```bash
# TUN device should be gone
ifconfig utun3  # should fail

# Routes should be gone
netstat -rn | grep utun3  # should be empty

# DNS should be gone
scutil --dns | grep forti-client  # should be empty
```

- [ ] **Step 4: Commit any fixes**

If live testing revealed issues, fix them and commit:

```bash
git add -A
git commit -m "fix: address issues found during live VPN testing"
```

---

## Scope Notes

**What Phase 2 does NOT include** (deferred to Phase 3):
- DTLS (UDP) data channel
- Auto-reconnect on dead peer or network change
- Sleep/wake handling
- IPv6 (IP6CP + routing)
- Privilege separation (launchd daemon)
- MTU optimization
