# Accepted Security Risks

Residual risks from the security review (2026-03-29) that cannot be fully mitigated due to protocol or ecosystem constraints.

## SAML Callback Local Race (Medium)

**Finding:** The localhost SAML callback server (port 8020) validates request structure (GET + non-empty `id=`) and has timeouts, but cannot bind a cryptographic nonce to the browser session.

**Root cause:** FortiGate controls the callback URL (hardcoded to `http://127.0.0.1:8020/`) and the `/remote/saml/start` endpoint does not accept a custom `state` parameter. There is no way to inject a CSRF nonce into the SAML flow.

**Residual risk:** A local attacker who knows the protocol can race a syntactically valid `GET /?id=<fake>` against the real browser callback.

**Mitigations in place:**
- Request validation: rejects non-GET, missing `id=`, empty `id=`
- Retry: rejected requests don't consume the listener — it continues listening
- Timeouts: 5-minute overall, 5-second per-connection read
- Server-side validation: the `id` is validated by FortiGate during the cookie exchange — a forged `id` produces an auth error, not a hijacked session

**Shared limitation:** openfortivpn has the same constraint — no state binding in the FortiGate SAML callback flow.

## Transitive Unmaintained Crate: `paste` (Low)

**Advisory:** RUSTSEC-2024-0436 — `paste` crate is unmaintained.

**Impact:** No CVE. The crate is a deep transitive dependency via the networking stack (not directly used by forti-client).

**Action:** Tracked for upstream migration. Monitored via periodic `cargo audit`.
