# forti-client Security Review Method (2026-03-29)

## Scope
- Project: `forti-client` (Rust FortiGate SSL VPN client for macOS)
- Target code paths: auth, TLS tunnel, codecs, PPP state machines, TUN/routes/DNS, reconnect, power/network monitors, CLI entrypoint
- Source plan followed: `docs/security-review-plan.md`

## Reviewer Responsibilities
- Review security behavior without changing existing implementation files.
- Identify vulnerabilities with evidence (`file:line`) and actionable remediation guidance.
- Separate confirmed issues from non-issues and residual risks.
- Run dependency vulnerability checks (`cargo audit`) and include exact output-backed conclusions.

## Review Rules
- No changes to existing spec/design/code documents during this pass.
- Findings must include:
  - Severity
  - Evidence location (`file:line`)
  - Issue description
  - Impact
  - Recommended fix
- Distinguish local-only attack preconditions from remote attack paths.
- Treat all server data as untrusted input.

## Check/Scan Approach
1. Read high-risk docs and code first:
   - `README.md`
   - `docs/security-review-plan.md`
   - `docs/superpowers/specs/2026-03-28-rust-fortigate-vpn-client-design.md`
   - all high-risk modules listed in the plan
2. Perform targeted static checks:
   - command execution usage
   - unsafe blocks
   - unwrap/expect in parsing and privileged flows
   - sensitive data logging patterns
   - untrusted parser bounds checks
3. Validate critical controls manually:
   - TLS verification/path validation
   - SAML callback exposure and trust boundaries
   - credential/cookie lifecycle and storage
4. Dependency scan:
   - `cargo install cargo-audit`
   - `cargo audit --db /tmp/advisory-db --no-fetch`
5. Produce evidence-backed findings report in a separate file.

## Commands Executed
- `rg -n "Command::new" src/`
- `rg -n "unsafe" src/`
- `rg -n "\\.unwrap\\(\\)|\\.expect\\(" src/`
- `rg -n "cookie|SVPNCOOKIE|password|credential" src/ | rg -i "debug|info|warn|error|tracing"`
- `rg -n "format!" src/tun/`
- `rg -n "\\[.*\\.\\." src/ppp/ src/tunnel/`
- `cargo install cargo-audit`
- `cargo audit --db /tmp/advisory-db --no-fetch`

## Coverage Notes
- Command injection in `routes.rs`/`dns.rs`: reviewed argument construction and typed parsing boundaries.
- TLS config in auth/tunnel: reviewed trust store usage, server name construction, and key logging behavior.
- Parser robustness: reviewed fortinet frame parser, PPP codecs, LCP/IPCP option parsing for bounds checks.
- Unsafe/FFI: reviewed callback context lifecycle and cleanup paths in power monitor.

