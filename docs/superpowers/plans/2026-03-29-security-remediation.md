# Security Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all 6 findings from `docs/security-review/2026-03-29-security-findings.md`, following the priority order from the remediation roadmap.

**Architecture:** Incremental patches — each task produces a self-contained commit. No new modules; all changes are in existing files. One new dependency (`secrecy`) for credential hardening.

**Tech Stack:** Rust, tokio, rustls, clap, secrecy crate

## Status
- Completed on 2026-03-30
- All remediation tasks implemented and validated
- Residual risk accepted: localhost SAML callback race for syntactically valid `id=` requests (protocol-level limitation documented in Task 2)

---

## File Structure

| File | Changes |
|------|---------|
| `src/auth/mod.rs` | Redact logs (P0-1), SAML callback hardening (P0-2), callback timeout (P1-1), keylog opt-in (P1-3) |
| `src/tunnel/mod.rs` | Redact cookie from tunnel request log (P0-1) |
| `src/main.rs` | SecretString for password (P1-2), `--tls-keylog-file` CLI flag (P1-3) |
| `src/reconnect.rs` | SecretString for password in AuthParams (P1-2) |
| `Cargo.toml` | Add `secrecy` (P1-2), remove `rustls-pemfile` (P2-1) |
| (no new test files) | Redaction helper tested via `#[cfg(test)]` unit tests inside `src/auth/mod.rs` (P0-1) |

---

### Task 1: Redact sensitive values from debug logs (P0-1)

**Files:**
- Modify: `src/auth/mod.rs:95-97, 106, 293, 360, 436, 457`
- Modify: `src/tunnel/mod.rs:51`

There are 7 debug log statements that leak secrets. Each needs a targeted fix:

| Line | Current | Fix |
|------|---------|-----|
| `auth/mod.rs:96` | `debug!("Set-Cookie: {:?}", cookie_hdr)` | Redact: `"Set-Cookie: SVPNCOOKIE=<redacted>"` or show non-SVPN cookies as-is |
| `auth/mod.rs:106` | `debug!("Login response body: {}", body[..500])` | Remove — response may contain tokens, magic values |
| `auth/mod.rs:293` | `debug!("Set-Cookie: {:?}", cookie_hdr)` | Same redaction as line 96 |
| `auth/mod.rs:360` | `debug!("Raw XML config:\n{}", xml_text)` | Redact `auth-ses` attribute values in XML if present; or remove the log |
| `auth/mod.rs:436` | `debug!("SAML callback request:\n{}", request[..500])` | Log only the request line (method + path), not headers/body |
| `auth/mod.rs:457` | `debug!("SAML session ID: {}", session_id)` | Redact: `"SAML session ID: <redacted>"` |
| `tunnel/mod.rs:51` | `debug!("Tunnel request:\n{}", http_req)` | Redact the `Cookie: SVPNCOOKIE=...` line |

- [x] **Step 1: Write a redaction helper function**

Add to `src/auth/mod.rs` (near the other helper functions at bottom):

```rust
/// Redact SVPNCOOKIE values from a Set-Cookie header string.
/// Returns the header with the cookie value replaced by "<redacted>".
fn redact_set_cookie(header: &str) -> String {
    if header.starts_with("SVPNCOOKIE=") {
        "SVPNCOOKIE=<redacted>".to_string()
    } else {
        header.to_string()
    }
}
```

- [x] **Step 2: Write unit tests inside `src/auth/mod.rs`**

Add a `#[cfg(test)]` module at the bottom of `src/auth/mod.rs`. The helper stays private — no public API surface added.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_svpncookie() {
        let input = "SVPNCOOKIE=abc123secret; path=/; secure; HttpOnly";
        assert_eq!(redact_set_cookie(input), "SVPNCOOKIE=<redacted>");
    }

    #[test]
    fn test_no_redact_other_cookie() {
        let input = "OTHERCOOKIE=value123; path=/";
        assert_eq!(redact_set_cookie(input), "OTHERCOOKIE=value123; path=/");
    }

    #[test]
    fn test_redact_empty_svpncookie() {
        let input = "SVPNCOOKIE=; path=/";
        assert_eq!(redact_set_cookie(input), "SVPNCOOKIE=<redacted>");
    }
}
```

- [x] **Step 3: Run tests**

Run: `cargo test -- test_redact -v`
Expected: 3 tests PASS

- [x] **Step 4: Fix the 7 log statements**

In `src/auth/mod.rs`:

**Line 95-97** — redact Set-Cookie in login flow:
```rust
// Before:
for cookie_hdr in resp.headers().get_all("set-cookie").iter() {
    debug!("Set-Cookie: {:?}", cookie_hdr);
}

// After:
for cookie_hdr in resp.headers().get_all("set-cookie").iter() {
    if let Ok(s) = cookie_hdr.to_str() {
        debug!("Set-Cookie: {}", redact_set_cookie(s));
    }
}
```

**Line 106** — remove login response body log entirely:
```rust
// Before:
debug!("Login response body: {}", &resp_text[..resp_text.len().min(500)]);

// After: (remove this line)
```

**Line 292-294** — redact Set-Cookie in SAML flow:
```rust
// Before:
for cookie_hdr in resp.headers().get_all("set-cookie").iter() {
    debug!("Set-Cookie: {:?}", cookie_hdr);
}

// After:
for cookie_hdr in resp.headers().get_all("set-cookie").iter() {
    if let Ok(s) = cookie_hdr.to_str() {
        debug!("Set-Cookie: {}", redact_set_cookie(s));
    }
}
```

**Line 360** — remove raw XML config log (may contain auth-ses tokens):
```rust
// Before:
debug!("Raw XML config:\n{}", xml_text);

// After:
debug!("Received XML config ({} bytes)", xml_text.len());
```

**Line 436** — log only request line, not full request:
```rust
// Before:
debug!("SAML callback request:\n{}", &request[..request.len().min(500)]);

// After:
if let Some(request_line) = request.lines().next() {
    debug!("SAML callback: {}", request_line);
}
```

**Line 457** — redact SAML session ID:
```rust
// Before:
debug!("SAML session ID: {}", session_id);

// After:
debug!("SAML session ID received ({} chars)", session_id.len());
```

In `src/tunnel/mod.rs`:

**Line 51** — redact cookie from tunnel request log:
```rust
// Before:
debug!("Tunnel request:\n{}", http_req.trim());

// After:
let redacted_req = http_req.lines()
    .map(|line| {
        if line.trim_start().starts_with("Cookie: SVPNCOOKIE=") {
            "Cookie: SVPNCOOKIE=<redacted>"
        } else {
            line
        }
    })
    .collect::<Vec<_>>()
    .join("\n");
debug!("Tunnel request:\n{}", redacted_req.trim());
```

- [x] **Step 5: Run all tests**

Run: `cargo test`
Expected: all 47+ tests pass

- [x] **Step 6: Run with debug logging to spot-check**

Run: `cargo build && RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --saml 2>&1 | grep -i "cookie\|SVPN\|session.*id\|XML config"`
Expected: No raw cookie/token values visible — only `<redacted>`, byte counts, or char counts.

- [x] **Step 7: Commit**

```bash
git add src/auth/mod.rs src/tunnel/mod.rs
git commit -m "security: redact secrets from debug logs (P0-1)

Never log SVPNCOOKIE values, SAML session IDs, login response bodies,
or raw XML config. Introduce redact_set_cookie() helper with tests."
```

---

### Task 2: Harden SAML callback against trivial preemption (P0-2)

**Files:**
- Modify: `src/auth/mod.rs` — `login_saml()` and `wait_for_saml_callback()`

**What this fixes:** The current callback accepts the very first TCP connection and trusts any data it sends — a local attacker can connect with garbage and consume the one-shot listener, causing auth failure (DoS), or send a syntactically valid `id=attacker_value` to cause session confusion.

**What this does NOT fix:** A local attacker who knows the protocol can still race a syntactically valid `GET /?id=<fake>` against the real browser callback. True state binding (CSRF nonce in the SAML flow) is not possible because FortiGate controls the callback URL (hardcoded to `http://127.0.0.1:8020/`) and the `/remote/saml/start` endpoint does not accept a custom `state` parameter. This is a protocol-level limitation, not a client-side one.

**Hardening approach (defense-in-depth, not a full fix):**
1. Validate request structure: must be GET with a non-empty `id=` query parameter.
2. Reject malformed/non-GET requests and continue listening (don't let garbage consume the listener).
3. Combined with Task 3's timeout, the attacker's window is bounded.
4. The `id` value is ultimately validated server-side when exchanged for SVPNCOOKIE — a forged `id` will fail the exchange and produce an auth error, not a hijacked session.

- [x] **Step 1: Modify `wait_for_saml_callback` to accept multiple attempts**

```rust
/// Wait for the SAML IdP to redirect the browser to our local callback server.
/// Extracts the `id` parameter from the request URL.
/// Rejects malformed/invalid requests and continues listening until a valid
/// callback is received or the timeout budget expires.
async fn wait_for_saml_callback(listener: tokio::net::TcpListener) -> Result<String> {
    // Accept up to 5 connections, rejecting invalid ones
    for attempt in 0..5 {
        let (mut stream, addr) = listener.accept().await
            .map_err(|e| FortiError::AuthFailed(format!("failed to accept SAML callback: {}", e)))?;

        debug!("SAML callback connection from {} (attempt {})", addr, attempt + 1);

        // Read the HTTP request
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        let request = String::from_utf8_lossy(&buf[..n]);

        // Log only the request line (no headers/body — may contain tokens)
        if let Some(request_line) = request.lines().next() {
            debug!("SAML callback: {}", request_line);
        }

        // Validate: must be GET with ?id= parameter
        let session_id = request.lines()
            .next()
            .and_then(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Must be "GET <path> HTTP/1.x"
                if parts.len() < 2 || parts[0] != "GET" {
                    return None;
                }
                let path = parts[1];
                let query = path.split('?').nth(1)?;
                for param in query.split('&') {
                    if let Some(value) = param.strip_prefix("id=") {
                        if !value.is_empty() {
                            return Some(value.to_string());
                        }
                    }
                }
                None
            });

        match session_id {
            Some(id) => {
                debug!("SAML session ID received ({} chars)", id.len());

                // Send success response
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

                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
                return Ok(id);
            }
            None => {
                // Invalid request — reject and continue listening
                warn!("Rejected invalid SAML callback (no valid id parameter), continuing to listen");
                let response = "HTTP/1.1 400 Bad Request\r\n\
                    Content-Type: text/plain\r\n\
                    Connection: close\r\n\
                    \r\n\
                    Invalid callback request";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
                continue;
            }
        }
    }

    Err(FortiError::AuthFailed(
        "SAML callback: too many invalid requests, giving up".into()
    ))
}
```

- [x] **Step 2: Add `warn` to tracing imports in `auth/mod.rs`**

```rust
// Before:
use tracing::{info, debug};

// After:
use tracing::{info, debug, warn};
```

- [x] **Step 3: Run all tests**

Run: `cargo test`
Expected: all tests pass

- [x] **Step 4: Commit**

```bash
git add src/auth/mod.rs
git commit -m "security: harden SAML callback against trivial preemption (P0-2)

Validate GET method and non-empty id= parameter before accepting.
Reject malformed requests and continue listening instead of trusting
the first connection unconditionally. Note: true CSRF state binding
is not possible due to FortiGate controlling the callback URL."
```

---

### Task 3: Add timeout to SAML callback server (P1-1)

**Files:**
- Modify: `src/auth/mod.rs` — `wait_for_saml_callback()` and `login_saml()`

- [x] **Step 1: Wrap the callback listener loop in a timeout**

In `wait_for_saml_callback`, wrap the accept loop:

```rust
async fn wait_for_saml_callback(listener: tokio::net::TcpListener) -> Result<String> {
    // Overall timeout for SAML callback: 5 minutes
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        wait_for_saml_callback_inner(listener),
    ).await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(FortiError::AuthFailed(
            "SAML authentication timed out after 5 minutes. Please retry.".into()
        )),
    }
}

async fn wait_for_saml_callback_inner(listener: tokio::net::TcpListener) -> Result<String> {
    // ... (the accept loop from Task 2, but also add per-connection read timeout)
}
```

- [x] **Step 2: Add per-connection read timeout**

Inside the accept loop, wrap the stream read in a timeout:

```rust
let n = match tokio::time::timeout(
    std::time::Duration::from_secs(5),
    stream.read(&mut buf),
).await {
    Ok(Ok(n)) => n,
    Ok(Err(e)) => {
        debug!("SAML callback read error: {}", e);
        continue;
    }
    Err(_) => {
        debug!("SAML callback read timeout, rejecting connection");
        let _ = stream.shutdown().await;
        continue;
    }
};
```

- [x] **Step 3: Remove the `attempt < 5` limit — timeout controls the budget now**

Change `for attempt in 0..5` to `loop` (the 5-minute outer timeout handles runaway loops):

```rust
async fn wait_for_saml_callback_inner(listener: tokio::net::TcpListener) -> Result<String> {
    loop {
        let (mut stream, addr) = listener.accept().await
            .map_err(|e| FortiError::AuthFailed(format!("failed to accept SAML callback: {}", e)))?;

        debug!("SAML callback connection from {}", addr);

        // Per-connection read timeout (5 seconds)
        let mut buf = vec![0u8; 4096];
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut buf),
        ).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                debug!("SAML callback: read failed or timed out, rejecting");
                let _ = stream.shutdown().await;
                continue;
            }
        };

        // ... rest of validation from Task 2
    }
}
```

- [x] **Step 4: Run all tests**

Run: `cargo test`
Expected: all tests pass

- [x] **Step 5: Commit**

```bash
git add src/auth/mod.rs
git commit -m "security: add timeout to SAML callback server (P1-1)

5-minute overall timeout for the SAML callback phase.
5-second per-connection read timeout to prevent slowloris DoS.
Stalling local clients are disconnected and the server continues
listening for valid callbacks."
```

---

### Task 4: Protect credential memory with SecretString (P1-2)

**Files:**
- Modify: `Cargo.toml` — add `secrecy` dependency
- Modify: `src/reconnect.rs` — `AuthParams.password` → `SecretString`
- Modify: `src/main.rs` — use `SecretString` for password handling

- [x] **Step 1: Add `secrecy` dependency**

In `Cargo.toml`, add under `[dependencies]`:

```toml
secrecy = "0.10"
```

- [x] **Step 2: Build to verify dependency resolves**

Run: `cargo build`
Expected: builds successfully

- [x] **Step 3: Update `AuthParams` in `src/reconnect.rs`**

```rust
// Add import at top:
use secrecy::{SecretString, ExposeSecret};

// Change the struct field:
pub struct AuthParams {
    pub server: String,
    pub port: u16,
    pub saml: bool,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub realm: Option<String>,
    pub tls_config: Arc<rustls::ClientConfig>,
}
```

- [x] **Step 4: Update `re_authenticate` in `src/reconnect.rs` to expose secret transiently**

```rust
// Before:
let password = self.auth_params.password.as_deref()
    .ok_or_else(|| FortiError::AuthFailed("no password for re-auth".into()))?;
// ...
auth_client.login(username, password, self.auth_params.realm.as_deref()).await?

// After:
let password = self.auth_params.password.as_ref()
    .ok_or_else(|| FortiError::AuthFailed("no password for re-auth".into()))?;
// ...
auth_client.login(username, password.expose_secret(), self.auth_params.realm.as_deref()).await?
```

- [x] **Step 5: Update `src/main.rs` to construct `SecretString`**

```rust
// Add import:
use secrecy::SecretString;

// Change password handling:
let password: Option<SecretString> = if !cli.saml {
    match cli.password.clone() {
        Some(p) => Some(SecretString::from(p)),
        None if cli.username.is_some() => {
            eprint!("Password: ");
            std::io::stderr().flush()?;
            let mut p = String::new();
            std::io::stdin().read_line(&mut p)?;
            Some(SecretString::from(p.trim().to_string()))
        }
        None => None,
    }
} else {
    None
};

// Update login call to expose secret transiently:
let pw = password.as_ref()
    .ok_or_else(|| anyhow::anyhow!("password required"))?;
auth_client.login(username, pw.expose_secret(), cli.realm.as_deref()).await?
```

- [x] **Step 6: Import `ExposeSecret` in `main.rs`**

```rust
use secrecy::ExposeSecret;
```

- [x] **Step 7: Run all tests**

Run: `cargo test`
Expected: all 47+ tests pass

- [x] **Step 8: Commit**

```bash
git add Cargo.toml src/reconnect.rs src/main.rs
git commit -m "security: use SecretString for password storage (P1-2)

Replace Option<String> with Option<SecretString> in AuthParams.
Password is now zeroized on drop and hidden from Debug output.
Exposed transiently only during login/re-auth calls."
```

---

### Task 5: Make TLS key logging opt-in via CLI flag (P1-3)

**Files:**
- Modify: `src/main.rs` — add `--tls-keylog-file` CLI arg
- Modify: `src/auth/mod.rs` — accept optional keylog flag, conditionally enable
- Modify: `src/reconnect.rs` — pass keylog setting through `AuthParams`

- [x] **Step 1: Add CLI flag to `src/main.rs`**

```rust
#[derive(Parser, Debug)]
#[command(name = "forti-client", about = "FortiGate SSL VPN client")]
struct Cli {
    // ... existing fields ...

    /// Enable TLS key logging to file (for Wireshark debugging)
    #[arg(long)]
    tls_keylog_file: Option<String>,
}
```

- [x] **Step 2: Add `enable_keylog` flag to `AuthParams` in `src/reconnect.rs`**

```rust
pub struct AuthParams {
    pub server: String,
    pub port: u16,
    pub saml: bool,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub realm: Option<String>,
    pub tls_config: Arc<rustls::ClientConfig>,
    pub enable_keylog: bool,
}
```

- [x] **Step 3: Modify `AuthClient::new` to accept keylog flag**

In `src/auth/mod.rs`, change the constructor:

```rust
pub fn new(server: &str, port: u16, enable_keylog: bool) -> Result<Self> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if enable_keylog {
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    Ok(Self {
        server: server.to_string(),
        port,
        tls_config: Arc::new(tls_config),
    })
}
```

- [x] **Step 4: Update `main.rs` to validate keylog path and emit warning**

```rust
let enable_keylog = if let Some(ref path) = cli.tls_keylog_file {
    // Validate the keylog output path before enabling
    let keylog_path = std::path::Path::new(path);

    // Reject symlinks — prevent writing to unexpected locations
    if keylog_path.is_symlink() {
        anyhow::bail!("--tls-keylog-file: refusing symlink target '{}'", path);
    }

    // Parent directory must exist and be writable
    let parent = keylog_path.parent()
        .unwrap_or(std::path::Path::new("."));
    if !parent.is_dir() {
        anyhow::bail!("--tls-keylog-file: parent directory '{}' does not exist", parent.display());
    }

    // Reject world-writable parent directories (e.g. /tmp) —
    // other users could swap the file via symlink race after validation
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(parent)?.permissions().mode();
        if mode & 0o002 != 0 {
            anyhow::bail!(
                "--tls-keylog-file: parent directory '{}' is world-writable (mode {:o})",
                parent.display(), mode & 0o777,
            );
        }
    }

    // Set SSLKEYLOGFILE env var for rustls
    std::env::set_var("SSLKEYLOGFILE", path);
    tracing::warn!("TLS key logging enabled — writing to {}", path);
    tracing::warn!("This exposes TLS session secrets. Use only for debugging.");
    true
} else {
    false
};

let auth_client = AuthClient::new(&cli.server, cli.port, enable_keylog)?;

// ... later, when constructing AuthParams:
let auth_params = AuthParams {
    // ... existing fields ...
    enable_keylog,
};
```

- [x] **Step 5: Update `ReconnectController::re_authenticate` to pass keylog flag**

```rust
// In re_authenticate():
let auth_client = AuthClient::new(
    &self.auth_params.server,
    self.auth_params.port,
    self.auth_params.enable_keylog,
)?;
```

- [x] **Step 6: Run all tests**

Run: `cargo test`
Expected: all tests pass

- [x] **Step 7: Verify keylog is disabled by default**

Run: `SSLKEYLOGFILE=/tmp/test-keys.log cargo build && sudo SSLKEYLOGFILE=/tmp/test-keys.log RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --saml`

Expected: No key file written (SSLKEYLOGFILE env var alone is ignored without `--tls-keylog-file` flag).

- [x] **Step 8: Verify path validation rejects unsafe paths**

Symlink rejection:
Run: `ln -sf /etc/passwd /tmp/keylog-symlink && sudo ./target/debug/forti-client --server sslvpn.example.com --saml --tls-keylog-file /tmp/keylog-symlink`
Expected: Error — "refusing symlink target".

World-writable directory rejection:
Run: `sudo ./target/debug/forti-client --server sslvpn.example.com --saml --tls-keylog-file /tmp/tls-keys.log`
Expected: Error — "parent directory '/tmp' is world-writable".

Valid path:
Run: `sudo RUST_LOG=debug ./target/debug/forti-client --server sslvpn.example.com --saml --tls-keylog-file ./tls-keys.log`
Expected: Warning printed, keys written to file.

- [x] **Step 9: Commit**

```bash
git add src/auth/mod.rs src/main.rs src/reconnect.rs
git commit -m "security: make TLS key logging opt-in via --tls-keylog-file (P1-3)

KeyLogFile is no longer unconditionally enabled. Requires explicit
--tls-keylog-file <path> flag. Validates path: rejects symlinks
and world-writable parent directories. Warns prominently when active."
```

---

### Task 6: Remove unused `rustls-pemfile` dependency (P2-1)

**Files:**
- Modify: `Cargo.toml` — remove `rustls-pemfile`

- [x] **Step 1: Remove the dependency**

In `Cargo.toml`, delete:

```toml
rustls-pemfile = "2"
```

- [x] **Step 2: Build and test**

Run: `cargo build && cargo test`
Expected: builds and tests pass (no source file imports rustls-pemfile)

- [x] **Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "security: remove unused rustls-pemfile dependency (P2-1)

Resolves RUSTSEC-2025-0134 unmaintained crate advisory.
Not imported anywhere in source — was a leftover from initial setup."
```

---

## Execution Order

| Order | Task | Priority | Risk |
|-------|------|----------|------|
| 1 | Task 1: Log redaction | P0 | Low — only changes log statements |
| 2 | Task 2: SAML callback hardening (mitigates trivial preemption; full state binding blocked by protocol) | P0 | Medium — changes auth flow |
| 3 | Task 3: Callback timeout | P1 | Low — additive |
| 4 | Task 4: SecretString | P1 | Medium — changes type across 2 files |
| 5 | Task 5: Keylog opt-in | P1 | Low — additive CLI flag |
| 6 | Task 6: Remove rustls-pemfile | P2 | None — unused dep removal |

## Verification Plan

After all tasks:
- `cargo test` — all 47+ tests pass
- `cargo clippy` — no warnings
- `cargo audit` — no critical/high advisories (RUSTSEC-2025-0134 resolved, RUSTSEC-2024-0436 for `paste` is transitive and tracked)
- Manual spot-check: `RUST_LOG=debug` output with credential auth and SAML auth shows no raw secrets
