# forti-client Security Remediation Roadmap (2026-03-29)

## Scope
This roadmap is derived from:
- `docs/security-review/2026-03-29-security-findings.md`
- `docs/security-review-plan.md`

Goal: convert confirmed findings into implementation-ready patch tasks.

## Priority Model
- P0: fix immediately before wider usage/release
- P1: fix in next hardening cycle
- P2: schedule as reliability/security hygiene

## P0 (Immediate)

### P0-1: Remove secret leakage from logs
- Findings addressed:
  - High: sensitive session secrets logged
- Files to patch:
  - `src/auth/mod.rs`
  - `src/tunnel/mod.rs`
- Tasks:
  1. Remove or redact all logs that can include `SVPNCOOKIE` / `Set-Cookie` values.
  2. Remove or sanitize raw auth response body logging.
  3. Remove or sanitize raw XML/tunnel request dumps containing cookies/tokens.
  4. Add helper(s) for centralized redaction to avoid regressions.
- Acceptance criteria:
  - `RUST_LOG=debug` output never prints full cookie/token values.
  - Spot-check logs from credential and SAML flows show only redacted values.
  - Unit tests (or snapshot tests) validate redaction behavior for representative strings.

### P0-2: Harden SAML callback against local preemption/injection
- Findings addressed:
  - High: callback preemption/injection
- Files to patch:
  - `src/auth/mod.rs`
- Tasks:
  1. Generate cryptographically random `state` value for login attempt.
  2. Include `state` in SAML start URL if compatible with gateway flow.
  3. Validate callback request includes expected `state`; reject otherwise.
  4. Enforce strict request parsing: method/path/query validation.
  5. Continue listening for valid callback until timeout budget is exhausted.
- Acceptance criteria:
  - Callback with invalid/missing `state` is rejected and not exchanged for cookie.
  - Only a request matching expected flow is accepted.
  - New integration tests cover valid callback, wrong-state callback, malformed callback.

## P1 (Next Hardening Cycle)

### P1-1: Add bounded timeout and resilience to callback server
- Findings addressed:
  - Medium: callback DoS by hanging local client
- Files to patch:
  - `src/auth/mod.rs`
- Tasks:
  1. Add timeout for `accept()` and request read (`tokio::time::timeout`).
  2. Handle partial/slowloris-like requests safely.
  3. Provide explicit user-facing timeout error and retry guidance.
- Acceptance criteria:
  - Callback phase exits within configured upper bound on no/invalid callback.
  - Malicious local stalling client cannot block forever.
  - Tests confirm timeout behavior.

### P1-2: Protect credential memory lifecycle
- Findings addressed:
  - Medium: plaintext password retained in `String`
- Files to patch:
  - `src/main.rs`
  - `src/reconnect.rs`
- Tasks:
  1. Replace plaintext password storage with `secrecy::SecretString` (or equivalent).
  2. Reduce lifetime of secret in memory (avoid long-lived copies).
  3. Ensure reconnect path only accesses secret transiently.
  4. Avoid debug formatting of secret-bearing structs.
- Acceptance criteria:
  - Password no longer stored as plain `Option<String>` in reconnect state.
  - Secret type does not expose contents via `Debug`/logs.
  - Re-authentication flow still passes integration tests.

### P1-3: Gate TLS key logging behind explicit operator intent
- Findings addressed:
  - Medium: key-log capability always active
- Files to patch:
  - `src/auth/mod.rs`
  - `src/main.rs` (CLI options)
- Tasks:
  1. Disable `KeyLogFile` by default.
  2. Add explicit opt-in CLI flag (for example `--tls-keylog-file <path>`).
  3. Validate output path permissions/ownership before enabling.
  4. Emit prominent warning when enabled.
- Acceptance criteria:
  - No key logging unless explicit flag is provided.
  - Invalid/insecure keylog path is rejected.
  - Existing normal authentication behavior unchanged.

## P2 (Hygiene / Ongoing)

### P2-1: Resolve dependency maintenance advisories
- Findings addressed:
  - Low: unmaintained crates reported by `cargo audit`
- Files to patch:
  - `Cargo.toml`
  - lockfile and dependent modules as needed
- Tasks:
  1. Evaluate direct usage of `rustls-pemfile`; remove if unused.
  2. Track `paste` replacement via dependency updates (likely transitive through networking stack).
  3. Add CI job for periodic `cargo audit` with fail policy for vulnerabilities.
- Acceptance criteria:
  - Dependency plan documented for both advisories.
  - CI produces regular audit reports.
  - No unresolved critical/high RustSec advisories in release branch.

## Suggested Execution Order
1. P0-1 logging redaction
2. P0-2 SAML state binding and strict callback validation
3. P1-1 callback timeout and anti-DoS handling
4. P1-2 credential memory hardening
5. P1-3 keylog explicit opt-in
6. P2-1 dependency hygiene and CI policy

## Verification Plan
- Security regression tests:
  - callback origin/state validation
  - no secret leakage in logs
  - callback timeout behavior
- Functional regression tests:
  - credential auth
  - 2FA (tokeninfo + HTML form)
  - SAML auth end-to-end
  - reconnect with re-auth

## Ownership Recommendation
- Auth hardening (`src/auth/*`): security + protocol owner
- Secret lifecycle (`main.rs`, `reconnect.rs`): runtime/controller owner
- Logging policy and tests: cross-cutting owner
- Dependency/CI audit policy: build/release owner

