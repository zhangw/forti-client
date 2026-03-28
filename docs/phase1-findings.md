# Phase 1 Findings — Real-Server Testing

**Date:** 2026-03-28
**Server:** sslvpn.webullbroker.com:10443 (FortiOS, SAML-only)

## Protocol Deviations from Spec

The wire protocol spec (`fortigate_sslvpn_wire_protocol.md`) is based on OpenConnect and openfortivpn source code. Several real-world behaviors differed from expectations:

### 1. PPP Frames Without Address/Control Header

The spec says PPP frames always have a 4-byte header: `[FF 03][protocol:BE16]`. In practice, the server sends frames **without** the `FF 03` prefix — just the 2-byte protocol ID followed by data.

```
Spec:     [FF 03] [C0 21] [LCP payload...]   (4-byte header)
Actual:          [C0 21] [LCP payload...]     (2-byte header)
```

Our codec now handles both formats. We still **send** with `FF 03` (the server accepts it).

### 2. SAML-Only Authentication

The server does not support credential-based auth via `POST /remote/logincheck`. Attempting it returns HTTP 200 with the login page HTML and an empty `SVPNCOOKIE=;` (cookie deletion, expiry date in 1984).

Only the SAML flow works:
1. Start local listener on `127.0.0.1:8020`
2. Open browser to `https://server/remote/saml/start?redirect=1`
3. User authenticates via IdP
4. Browser redirects to `http://127.0.0.1:8020/?id=<session_id>`
5. Exchange `id` for SVPNCOOKIE via `GET /remote/saml/auth_id?id=<session_id>`

Note: The callback uses **HTTP** (not HTTPS) on the localhost listener.

### 3. Server Closes Connections Between Requests

After `POST /remote/logincheck`, the server closes the TCP connection. Each subsequent HTTP request (resource reservation, XML config, tunnel) requires a **fresh TLS connection**.

### 4. Resource Reservation Required

`GET /remote/fortisslvpn` must be called before fetching XML config or opening the tunnel. Without it, subsequent requests may fail with 403.

### 5. Server Waits for Client to Send First LCP

After the `GET /remote/sslvpn-tunnel` request, the server sends **no data** until the client sends an LCP Configure-Request. The spec says the server should send the first LCP packet. We handle this with a 2-second read timeout; if the server is silent, we proceed to send our LCP Configure-Request.

### 6. IPCP DNS Rejection

The server rejects IPCP option `0x82` (secondary DNS) via Configure-Reject. DNS servers are assigned through the XML config instead:

```xml
<dns ip='183.90.189.7' />
<dns ip='8.8.8.8' />
```

The IPCP state machine tracks rejected options and resends without them.

### 7. Single-Quoted XML Attributes

The spec examples show double-quoted XML attributes. The real server uses **single quotes**:

```xml
<!-- Spec example -->
<assigned-addr ipv4="10.8.2.6" />

<!-- Real server -->
<assigned-addr ipv4='10.8.2.6' />
```

The XML parser supports both quote styles.

### 8. Timeout and Idle Values

From the real XML config:
- `idle-timeout val='86400'` (24 hours)
- `auth-timeout val='86400'` (24 hours)
- `tun-user-ses-timeout='30'` (30 seconds for reconnect window)

### 9. Tunnel Methods Advertised

```xml
<tunnel-method value='ppp' />
<tunnel-method value='tun' />
<tunnel-method value='websocket' />
```

We use `ppp` (v1 protocol). The server also supports `tun` (v2, non-PPP) and `websocket`.

### 10. DTLS Available

```xml
<sslvpn-tunnel ver='2' dtls='1' patch='1'>
<dtls-config ver='2' heartbeat-interval='3' heartbeat-fail-count='3'
             heartbeat-idle-timeout='3' client-hello-timeout='10'
             dtls-accept-check-time='1'/>
```

DTLS data channel is available on the same port (10443/UDP).

## Negotiation Trace

Complete Phase 1 negotiation (~120ms total):

```
T+0ms     TLS handshake to sslvpn.webullbroker.com:10443
T+25ms    SAML auth complete, got SVPNCOOKIE
T+60ms    GET /remote/fortisslvpn (resource reservation) → 200 OK
T+90ms    GET /remote/fortisslvpn_xml → XML config (IP=10.8.2.6, DNS, 674 routes)
T+120ms   GET /remote/sslvpn-tunnel → tunnel established (server silent)
T+2120ms  Client sends LCP Configure-Request (after 2s timeout)
T+2155ms  Server: LCP Configure-Request + LCP Configure-Ack (both in ~35ms)
T+2155ms  Client: LCP Configure-Ack → LCP done
T+2155ms  Client sends IPCP Configure-Request (IP=0.0.0.0, DNS1=0.0.0.0, DNS2=0.0.0.0)
T+2185ms  Server: IPCP Configure-Request (ACKed) + IPCP Configure-Reject (DNS2)
T+2185ms  Client resends IPCP without DNS2
T+2215ms  Server: IPCP Configure-Nak (IP=10.8.2.6, DNS1=183.90.189.7)
T+2215ms  Client resends IPCP with assigned values
T+2245ms  Server: IPCP Configure-Ack → IPCP done

Result: IP=10.8.2.6, DNS=183.90.189.7, 674 split-tunnel routes
```
