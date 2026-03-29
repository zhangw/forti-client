# forti-client Security Findings (2026-03-29)

## Summary
- Review basis: `docs/security-review-plan.md`
- Code/document coverage: auth, TLS tunnel, PPP/frame parsers, TUN/routes/DNS, reconnect, power/network monitors, main CLI
- New findings: 6
- Dependency advisories: 2 warnings (unmaintained crates), 0 known CVEs reported by `cargo audit`

## Findings

### 1) High: Sensitive session secrets are logged (cookie + auth artifacts)
- Evidence:
  - `src/auth/mod.rs:96` logs full `Set-Cookie` header
  - `src/auth/mod.rs:106` logs first 500 bytes of login response body
  - `src/auth/mod.rs:293` logs full `Set-Cookie` in SAML exchange
  - `src/auth/mod.rs:360` logs full tunnel XML config
  - `src/tunnel/mod.rs:51` logs full HTTP tunnel request including `Cookie: SVPNCOOKIE=...`
- Issue:
  - Debug logging includes authentication/session material (`SVPNCOOKIE`, 2FA fields, XML tokens such as `auth-ses`) that can be harvested from logs.
- Impact:
  - Any local user or log collector with access to logs may replay active sessions or extract sensitive auth metadata.
- Recommended fix:
  - Never log cookie values or full auth responses.
  - Introduce redaction helpers (e.g., `SVPNCOOKIE=<redacted>`).
  - Gate high-risk debug logging behind explicit secure-dev build flags and sanitize before output.

### 2) High: SAML localhost callback is vulnerable to local preemption/injection
- Evidence:
  - `src/auth/mod.rs:427` accepts the first inbound localhost connection
  - `src/auth/mod.rs:440` trusts any `id=` query value from that request
  - `src/auth/mod.rs:273` uses received `id` directly to exchange for session cookie
- Issue:
  - The callback handler does not bind authentication state to a nonce, browser session, or expected origin flow; first local connector wins.
- Impact:
  - A local attacker can race the callback port and inject a forged/attacker-controlled `id`, causing session confusion, login hijack conditions, or reliable auth disruption.
- Recommended fix:
  - Add a cryptographically random `state` value when opening `/remote/saml/start` and validate on callback.
  - Reject callbacks missing expected path/method/state.
  - Optionally use a random high port and pass it in callback URL if protocol permits.

### 3) Medium: SAML callback has no timeout and can be trivially DoS’d by local clients
- Evidence:
  - `src/auth/mod.rs:427` blocks on `listener.accept().await` indefinitely
  - `src/auth/mod.rs:434` reads request once with no read timeout
- Issue:
  - A local process can connect and stall the socket or never allow valid callback processing.
- Impact:
  - Authentication can hang indefinitely until manual interrupt; repeated abuse can prevent VPN usage.
- Recommended fix:
  - Wrap accept/read in bounded `tokio::time::timeout`.
  - Close non-conforming requests quickly and continue listening until timeout budget is exhausted.

### 4) Medium: Credentials persist in heap `String` without zeroization and are retained for reconnect
- Evidence:
  - `src/main.rs:49-57` reads password into `String`
  - `src/main.rs:84-90` moves password into reconnect parameters
  - `src/reconnect.rs:110-117` stores `password: Option<String>` long-term
- Issue:
  - Password remains in plaintext heap allocations for process lifetime/re-auth lifecycle, with no memory scrubbing.
- Impact:
  - In crash/core-dump or memory disclosure scenarios, credentials are easier to recover.
- Recommended fix:
  - Use `secrecy::SecretString` or equivalent secret wrapper.
  - Minimize lifetime and zero memory on drop.
  - Re-auth via short-lived token/session where possible instead of retaining raw password.

### 5) Medium: TLS key logging is globally enabled in runtime config for a root process
- Evidence:
  - `src/auth/mod.rs:29-30` always sets `tls_config.key_log = Arc::new(rustls::KeyLogFile::new())`
- Issue:
  - Although output occurs only when `SSLKEYLOGFILE` is set, this capability is enabled unconditionally and process often runs with elevated privileges.
- Impact:
  - Misconfigured or malicious environment can exfiltrate TLS session secrets to disk, enabling traffic decryption.
- Recommended fix:
  - Make key logging opt-in via explicit CLI flag (e.g., `--tls-keylog-file`) and refuse by default.
  - When enabled, validate path ownership/permissions and warn loudly.

### 6) Low: Dependency health warnings from `cargo audit` (unmaintained crates)
- Evidence (`cargo audit --db /tmp/advisory-db --no-fetch`):
  - `RUSTSEC-2024-0436` (`paste 1.0.15`) unmaintained
  - `RUSTSEC-2025-0134` (`rustls-pemfile 2.2.0`) unmaintained
- Issue:
  - No active CVE exploit reported by audit output, but maintenance risk exists.
- Impact:
  - Future security patches may lag or stop for affected crates.
- Recommended fix:
  - Track upstream replacement/migration plans.
  - For `rustls-pemfile`, evaluate removal if unused or migrate to maintained parsing path.
  - Pin and monitor transitive updates in CI with periodic `cargo audit`.

## Validated Non-Issues (from planned checks)
- Command injection in route/DNS execution: not observed.
  - `Route.ip` and `Route.mask` are parsed into `Ipv4Addr` in `src/auth/xml.rs` before use.
  - Route/scutil commands are executed with `Command::new(...).args(...)` (no shell interpolation).
- TLS certificate validation bypasses (`danger_accept_invalid_certs` style): not observed.
- Parser panic hotspots on untrusted input (`unwrap`/`expect`) in parsing paths: no direct unsafe unwrap/expect use found in codec state machines.

## Dependency Scan Output Snapshot
- Command: `cargo audit --db /tmp/advisory-db --no-fetch`
- Result: scan completed; 2 allowed warnings (both unmaintained), no vulnerable advisory failures reported.

