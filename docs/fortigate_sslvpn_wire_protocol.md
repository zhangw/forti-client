# FortiGate SSL VPN Wire Protocol Specification

**Status:** Reverse-engineered from open-source implementations and public documentation.
Not an official Fortinet specification.

**Primary sources:**
- OpenConnect `fortinet.c` and `ppp.c` (David Woodhouse, Daniel Lenski, 2020-2021)
- openfortivpn `http.c`, `io.c`, `hdlc.c` (Adrien Verge, 2015+)
- Fortinet official documentation (FortiOS 6.x-7.x)
- Wireshark packet captures referenced in open-source issue trackers

**Date:** 2026-03-28

---

## Table of Contents

1. [Protocol Overview](#1-protocol-overview)
2. [Authentication Phase](#2-authentication-phase)
3. [SAML/SSO Authentication](#3-samlsso-authentication)
4. [Tunnel Configuration](#4-tunnel-configuration)
5. [TLS Tunnel Establishment](#5-tls-tunnel-establishment)
6. [PPP-over-TLS Wire Format (v1)](#6-ppp-over-tls-wire-format-v1)
7. [PPP Negotiation](#7-ppp-negotiation)
8. [DTLS (UDP) Tunnel](#8-dtls-udp-tunnel)
9. [Keepalive and Dead Peer Detection](#9-keepalive-and-dead-peer-detection)
10. [Session Teardown](#10-session-teardown)
11. [Wire Protocol v2 (non-PPP)](#11-wire-protocol-v2-non-ppp)
12. [FortiOS Version Matrix](#12-fortios-version-matrix)

---

## 1. Protocol Overview

FortiGate SSL VPN is a PPP-over-TLS tunneling protocol. The high-level flow is:

```
Client                                      FortiGate
  |                                            |
  |--- TLS Handshake (port 443) -------------->|
  |                                            |
  |--- HTTP Authentication ------------------->|
  |<-- SVPNCOOKIE ------------------------------|
  |                                            |
  |--- GET /remote/fortisslvpn_xml ----------->|
  |<-- XML tunnel configuration ----------------|
  |                                            |
  |--- GET /remote/sslvpn-tunnel ------------->|
  |    (no HTTP response; stream transitions   |
  |     to raw PPP-over-TLS framing)           |
  |                                            |
  |<== PPP LCP negotiation ===================>|
  |<== PPP IPCP negotiation ==================>|
  |<== PPP IP6CP negotiation (optional) ======>|
  |                                            |
  |<== Encapsulated IP traffic ===============>|
  |                                            |
  |--- (optionally) DTLS handshake (UDP) ----->|
  |<== PPP-over-DTLS (same framing) ==========>|
```

Transport options:
- **TLS (TCP):** Always available. PPP frames carried inside TLS records.
- **DTLS (UDP):** Optional, same port as TLS. Preferred when available because
  TCP-over-TCP causes congestion control meltdown. Same PPP framing as TLS mode.

---

## 2. Authentication Phase

All authentication occurs over HTTPS (TLS on TCP port 443).

### 2.1 Initial Request

```http
GET / HTTP/1.1
Host: vpn.example.com
User-Agent: Mozilla/5.0 SV1
```

The server redirects to `/remote/login` via HTTP 302, or (FortiOS 7.4+) via
a JavaScript redirect in the HTML body:

```html
<html><script type="text/javascript">
if (window!=top) top.location=window.location;top.location="/remote/login";
</script></html>
```

**Realm handling:** If a realm/user-group is specified, the redirect URL includes
it as a query parameter: `/remote/login?realm=MyRealmName`. The client must
capture this realm value and include it in subsequent authentication POSTs.

### 2.2 Standard Username/Password Login

```http
POST /remote/logincheck HTTP/1.1
Host: vpn.example.com:443
User-Agent: Mozilla/5.0 SV1
Accept: */*
Accept-Encoding: identity
Pragma: no-cache
Cache-Control: no-store, no-cache, must-revalidate
If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

username=<URL-encoded-username>&credential=<URL-encoded-password>&realm=<URL-encoded-realm>&ajax=1&just_logged_in=1
```

**Key observations:**
- The password field is named `credential`, NOT `password`.
- The `realm` value is already URL-escaped from the redirect URL; do not double-encode.
- `ajax=1&just_logged_in=1` are appended for the initial login form.

### 2.3 Response Codes and Error Handling

| HTTP Status | Meaning |
|-------------|---------|
| **200 OK** | Authentication succeeded. Look for `SVPNCOOKIE` in `Set-Cookie`. |
| **200 OK** (no cookie) | 2FA challenge (tokeninfo-type). Body contains `ret=...` parameters. |
| **401 Unauthorized** | HTML-form-based 2FA challenge. Body contains HTML form. |
| **405 Method Not Allowed** | Invalid credentials (non-standard; used instead of 401/403). |
| **302 Found** | Redirect (realm selection, etc.). |

**Error markers in response body (any status):**
- `<!--sslvpnerrmsgkey=sslvpn_login_permission_denied-->`
- `permission_denied denied` in headers
- `Permission denied` in body

### 2.4 The SVPNCOOKIE

On successful authentication, the server sets:

```http
Set-Cookie: SVPNCOOKIE=<hex-string>; path=/; HttpOnly; Secure
```

This is THE session cookie. It is used for:
1. All subsequent HTTP requests (configuration fetch, tunnel setup)
2. DTLS tunnel authentication
3. Potentially, reconnection without reauthentication (FortiOS 6.2.1+)

The client must store it as `SVPNCOOKIE=<value>` and send it in the `Cookie:`
header of all subsequent requests.

### 2.5 Two-Factor Authentication (Tokeninfo Type)

If the 200 OK response has no `SVPNCOOKIE` but the body starts with `ret=`
and contains `,tokeninfo=`, 2FA is required.

**Response body format:**
```
ret=<status>,tokeninfo=<type>,chal_msg=<prompt>,reqid=<id>,polid=<id>,grp=<group>,portal=<portal>,peer=<peer>,magic=<value>
```

**Tokeninfo types:**
- Generic OTP: `tokeninfo=<token-name>`
- FortiToken Mobile push: `tokeninfo=ftm_push`

**Second-stage POST to `/remote/logincheck`:**
```
username=<user>&code=<otp-code>&reqid=<reqid>&polid=<polid>&grp=<grp>&portal=<portal>&peer=<peer>&magic=<magic>
```

For FTM push (if `tokeninfo=ftm_push` and code is blank):
```
username=<user>&code=&reqid=<reqid>&polid=<polid>&grp=<grp>&portal=<portal>&peer=<peer>&ftmpush=1
```
(Note: `magic` is excluded and `ftmpush=1` is appended instead.)

### 2.6 Two-Factor Authentication (HTML Form Type)

If the server returns HTTP 401 with an HTML body, the body contains a standard
HTML form with:
- Hidden fields: `username`, `magic`, `reqid`, `grpid`, etc.
- Password field: `credential` (renamed to `code` by the client)

The client submits to the form's `ACTION` URL.

### 2.7 Client Certificate Authentication

TLS client certificates are supported at the TLS handshake level. The FortiGate
requests a client certificate during the TLS handshake if configured. This is
orthogonal to username/password authentication -- both may be required.

---

## 3. SAML/SSO Authentication

### 3.1 Overview

FortiClient supports two SAML modes:
- **Embedded browser:** FortiClient renders the IdP login page internally.
- **External browser (FortiClient 7.0.1+):** System default browser handles the IdP flow.

### 3.2 SAML Flow (External Browser)

```
FortiClient          Browser              FortiGate            IdP (e.g. Azure AD)
    |                   |                    |                       |
    |-- Start local HTTP listener on 127.0.0.1:8020 --->|           |
    |                   |                    |                       |
    |-- Open browser -->|                    |                       |
    |   https://vpn.example.com/remote/saml/start?redirect=1        |
    |                   |--- GET ----------->|                       |
    |                   |<-- 302 Redirect ---|----> SAML AuthnReq -->|
    |                   |                    |                       |
    |                   |<------------------ SAML login page --------|
    |                   |--- User enters credentials --------------->|
    |                   |<------- SAML Response (POST) --------------|
    |                   |                    |                       |
    |                   |--- POST (SAML assertion) -->|              |
    |                   |<-- 302 to https://127.0.0.1:8020/?id=<session-id>
    |                   |                    |                       |
    |<--- GET /?id=<session-id> from browser callback                |
    |--- "You may close the browser window now." -->|                |
    |                   |                    |                       |
    |--- GET /remote/saml/auth_id?id=<session-id> ->|               |
    |<-- SVPNCOOKIE (Set-Cookie) ------------|                       |
```

### 3.3 Key SAML Details

**Initiation URL:**
```
GET /remote/saml/start?redirect=1 HTTP/1.1
```

**Callback URL (localhost):**
```
https://127.0.0.1:8020/?id=<session-id>
```

Port 8020 is the default, configurable on FortiGate via:
```
config vpn ssl settings
    set saml-redirect-port 8020
end
```

**Cookie acquisition after SAML:**
```http
GET /remote/saml/auth_id?id=<session-id> HTTP/1.1
Host: vpn.example.com
```
Response includes `Set-Cookie: SVPNCOOKIE=...`

### 3.4 FortiClient ConnectTunnel SAML Parameters

When FortiClient internally calls `connectTunnel` for a SAML connection, the
JSON blob includes:
```json
{
  "connection_name": "<vpn-name>",
  "connection_type": "ssl",
  "password": "",
  "username": "<user@domain.com>",
  "save_username": false,
  "save_password": "0",
  "always_up": "0",
  "auto_connect": "0",
  "saml_error": 1,
  "saml_type": 1
}
```

`saml_error: 1` and `saml_type: 1` signal that SAML authentication should be
used. The password field is empty because authentication is handled by the
browser-based SAML flow.

### 3.5 Limitations

- FortiClient (Linux) 7.0.1 does not support external browser SAML.
- External browser SAML is not supported when SSL VPN realms are configured.
- Another service on port 8020 will block the SAML callback.

---

## 4. Tunnel Configuration

After obtaining `SVPNCOOKIE`, the client fetches the tunnel configuration.

### 4.1 XML Configuration Request

```http
GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1
Host: vpn.example.com:443
User-Agent: Mozilla/5.0 SV1
Cookie: SVPNCOOKIE=<cookie-value>
```

The `?dual_stack=1` parameter requests IPv6 configuration in addition to IPv4.
Omit it to get IPv4-only configuration.

### 4.2 Legacy Configuration (FortiOS 4.x only)

```http
GET /remote/fortisslvpn HTTP/1.1
```
Returns an HTML-format configuration. Obsolete since FortiOS 5.0.

### 4.3 XML Configuration Response Schema

```xml
<?xml version="1.0" encoding="utf-8"?>
<sslvpn-tunnel ver="2" dtls="1" patch="1">
  <dtls-config
    heartbeat-interval="10"
    heartbeat-fail-count="10"
    heartbeat-idle-timeout="10"
    client-hello-timeout="10"/>
  <tunnel-method value="ppp"/>
  <tunnel-method value="tun"/>
  <fos
    platform="FG100E"
    major="5"
    minor="06"
    patch="6"
    build="1630"
    branch="1630"
    mr_num="..."/>
  <auth-ses
    check-src-ip="1"
    tun-connect-without-reauth="1"
    tun-user-ses-timeout="240"/>
  <client-config
    save-password="off"
    keep-alive="on"
    auto-connect="off"/>
  <ipv4>
    <dns ip="1.1.1.1"/>
    <dns ip="8.8.8.8" domain="foo.com"/>
    <split-dns
      domains="mydomain1.local,mydomain2.local"
      dnsserver1="10.10.10.10"
      dnsserver2="10.10.10.11"/>
    <assigned-addr ipv4="172.16.1.1"/>
    <split-tunnel-info>
      <addr ip="10.11.10.10" mask="255.255.255.255"/>
      <addr ip="10.11.1.0" mask="255.255.255.0"/>
    </split-tunnel-info>
    <split-tunnel-info negate="1">
      <addr ip="1.2.3.4" mask="255.255.255.255"/>
    </split-tunnel-info>
  </ipv4>
  <ipv6>
    <assigned-addr ipv6="fdff:ffff::1" prefix-len="120"/>
    <split-tunnel-info>
      <addr ipv6="fdff:ffff::" prefix-len="120"/>
    </split-tunnel-info>
    <split-tunnel-info negate="1">
      <addr ipv6="2011:abcd::" prefix-len="32"/>
    </split-tunnel-info>
  </ipv6>
  <idle-timeout val="3600"/>
  <auth-timeout val="18000"/>
</sslvpn-tunnel>
```

### 4.4 XML Element Reference

| Element | Attributes | Description |
|---------|-----------|-------------|
| `<sslvpn-tunnel>` | `ver`, `dtls`, `patch` | Root element. `dtls="1"` means DTLS is available. |
| `<dtls-config>` | `heartbeat-interval`, `heartbeat-fail-count`, `heartbeat-idle-timeout`, `client-hello-timeout` | DTLS keepalive parameters (seconds). |
| `<tunnel-method>` | `value` | Supported tunnel methods: `"ppp"` (v1) and/or `"tun"` (v2). |
| `<fos>` | `platform`, `major`, `minor`, `patch`, `build`, `branch`, `mr_num` | FortiOS version identification. |
| `<auth-ses>` | `check-src-ip`, `tun-connect-without-reauth`, `tun-user-ses-timeout` | Reconnection policy. |
| `<client-config>` | `save-password`, `keep-alive`, `auto-connect` | Client behavior hints. |
| `<ipv4>` / `<ipv6>` | (container) | IP configuration blocks. |
| `<assigned-addr>` | `ipv4` or `ipv6`, `prefix-len` | Assigned tunnel IP address. |
| `<dns>` | `ip`, `domain` | DNS server and search domain. |
| `<split-dns>` | `domains`, `dnsserver1`..`dnsserver9` | Split DNS configuration. |
| `<split-tunnel-info>` | `negate` | Route container. `negate="1"` = exclude routes. |
| `<addr>` | `ip`/`ipv6`, `mask`/`prefix-len` | Individual route entry. |
| `<idle-timeout>` | `val` | Idle timeout in seconds. |
| `<auth-timeout>` | `val` | Authentication session timeout in seconds. |

### 4.5 Reconnection Policy (`<auth-ses>`)

Introduced in FortiOS 6.2.1. Controlled by server-side setting:
```
config vpn ssl settings
    set tun-connect-without-reauth enable
end
```

- `tun-connect-without-reauth="1"`: Client may reuse SVPNCOOKIE to reconnect
  without full reauthentication, within `tun-user-ses-timeout` seconds.
- `tun-connect-without-reauth="0"`: Every reconnect requires full authentication.
- `check-src-ip="1"`: Reconnection only allowed from the same source IP.

**Warning (from OpenConnect):** Even servers advertising
`tun-connect-without-reauth="1"` may reject re-fetching `/remote/fortisslvpn_xml`
after reconnect, invalidating the cookie. Successful reconnection requires
skipping the configuration fetch and going straight to tunnel setup with a
PPP reset, using the previously fetched configuration.

---

## 5. TLS Tunnel Establishment

### 5.1 Tunnel Request

```http
GET /remote/sslvpn-tunnel HTTP/1.1
Host: vpn.example.com:443
User-Agent: Mozilla/5.0 SV1
Cookie: SVPNCOOKIE=<cookie-value>

```

### 5.2 Tunnel Transition (Critical Detail)

**If the request succeeds:** The server sends NO HTTP response. The connection
silently transitions from HTTP to raw PPP framing. The very next bytes on the
wire are a PPP LCP Configure-Request inside the Fortinet 6-byte framing header.

**If the request fails:** The server sends a normal HTTP error response
(e.g., `HTTP/1.1 403 Forbidden`). The client must detect this by checking whether
the first bytes after the GET look like an HTTP response or a PPP frame.

OpenConnect handles this by setting a `check_http_response` flag after sending
the GET. On the first received data, it calls `check_http_status()` to see if
the bytes are an HTTP response. If so, it's an error. If not, it's PPP data.

### 5.3 openfortivpn Differences

openfortivpn closes and reopens the HTTPS connection before sending the tunnel
request, and also sends `Host: sslvpn` rather than the true hostname. OpenConnect
found that neither is necessary, and omitting both allows vhost-based Fortinet
servers to work.

---

## 6. PPP-over-TLS Wire Format (v1)

### 6.1 The 6-Byte Fortinet Frame Header

Every PPP frame sent or received over the TLS (or DTLS) connection is wrapped
in a 6-byte header:

```
Offset  Size  Field           Description
------  ----  -----           -----------
0       2     total_length    Big-endian uint16. Total bytes on wire INCLUDING this 6-byte header.
2       2     magic           Always 0x50 0x50 (ASCII "PP").
4       2     payload_length  Big-endian uint16. PPP frame length EXCLUDING this header.
```

**Invariant:** `total_length == payload_length + 6`

**Example:** A PPP frame of 28 bytes would have:
```
Byte 0:  0x00  \
Byte 1:  0x22  / total_length = 34 (28 + 6)
Byte 2:  0x50  \
Byte 3:  0x50  / magic = 0x5050 ("PP")
Byte 4:  0x00  \
Byte 5:  0x1C  / payload_length = 28
Byte 6+: [28 bytes of PPP frame]
```

### 6.2 PPP Frame Inside the Fortinet Header

The PPP frame inside the Fortinet header uses standard PPP framing with
**full headers** (no HDLC, no compression):

```
Offset  Size  Field      Description
------  ----  -----      -----------
0       1     Address    Always 0xFF (All-Stations, per RFC 1662)
1       1     Control    Always 0x03 (Unnumbered Information, per RFC 1662)
2       2     Protocol   Big-endian uint16. PPP protocol number.
4       ...   Payload    Protocol-specific data.
```

**Important:** FortiGate servers **reject** LCP options for Protocol Field
Compression (PFCOMP) and Address/Control Field Compression (ACCOMP). The
4-byte PPP header is always present and always full-size.

### 6.3 Complete On-Wire Packet

```
+--------+--------+--------+--------+--------+--------+--------+--------+---
| total_len (BE16) | 0x50   | 0x50   | payload_len(BE16)| 0xFF   | 0x03   |...
+--------+--------+--------+--------+--------+--------+--------+--------+---
|<------------- 6-byte Fortinet header --------------->|<-- PPP frame -->
```

### 6.4 PPP Protocol Numbers

| Value    | Protocol |
|----------|----------|
| `0xC021` | LCP (Link Control Protocol) |
| `0x8021` | IPCP (IP Control Protocol) |
| `0x8057` | IP6CP (IPv6 Control Protocol) |
| `0x80FD` | CCP (Compression Control Protocol) |
| `0x0021` | IPv4 data |
| `0x0057` | IPv6 data |

### 6.5 Multiple Frames Per TLS Record

Multiple PPP frames may be concatenated within a single TLS record. The client
must parse frame boundaries using `total_length` and process each frame
independently. The next frame begins immediately after the current frame's
`total_length` bytes.

### 6.6 openfortivpn Variant (HDLC)

openfortivpn uses a different internal architecture: it spawns a `pppd` process
connected via a pseudo-terminal. The PPP frames between openfortivpn and pppd
use HDLC encoding (RFC 1662):

```
[0x7E] [escaped-address] [escaped-control] [escaped-payload] [escaped-FCS] [0x7E]
```

- Flag: `0x7E`
- Escape: `0x7D` followed by byte XOR `0x20`
- Bytes requiring escape: `< 0x20`, `0x7D`, `0x7E`
- FCS: 16-bit CRC per RFC 1662, appended little-endian

This HDLC framing is between openfortivpn and its local pppd only. On the TLS
wire, openfortivpn strips/adds HDLC and wraps the raw PPP frame in the 6-byte
Fortinet header, same as described above.

---

## 7. PPP Negotiation

### 7.1 LCP (Link Control Protocol, 0xC021)

PPP negotiation begins immediately after the TLS tunnel is established (no HTTP
response). Both sides exchange LCP packets.

**LCP Packet Format (inside PPP frame):**
```
Offset  Size  Field     Description
------  ----  -----     -----------
0       1     Code      LCP code (see table below)
1       1     ID        Identifier (monotonically increasing per side)
2       2     Length    Big-endian uint16. Total LCP packet length.
4       ...   Data      Code-dependent options/payload.
```

**LCP Codes:**
| Code | Name | Description |
|------|------|-------------|
| 1 | Configure-Request | Propose configuration options |
| 2 | Configure-Ack | Accept all options as-is |
| 3 | Configure-Nak | Reject with preferred values |
| 4 | Configure-Reject | Reject unsupported options entirely |
| 5 | Terminate-Request | Initiate link teardown |
| 6 | Terminate-Ack | Acknowledge termination |
| 7 | Code-Reject | Received unknown code |
| 8 | Protocol-Reject | Received unknown protocol |
| 9 | Echo-Request | Keepalive/DPD probe |
| 10 | Echo-Reply | Keepalive/DPD response |
| 11 | Discard-Request | Keepalive (no response expected) |

**LCP Option TLV Format:**
```
Offset  Size  Field   Description
------  ----  -----   -----------
0       1     Type    Option type
1       1     Length  Total option length (including type+length bytes)
2       ...   Value   Option value
```

### 7.2 LCP Options Relevant to FortiGate

| Type | Name | Length | Description |
|------|------|--------|-------------|
| 1 | MRU (Maximum Receive Unit) | 4 | Requested MRU. openfortivpn uses 1354. |
| 2 | Async-Control-Character-Map | 6 | 32-bit bitmap. **Rejected by FortiGate in non-HDLC mode.** |
| 5 | Magic-Number | 6 | 32-bit random value for loop detection. |
| 7 | Protocol-Field-Compression | 2 | **Rejected by FortiGate.** |
| 8 | Address-and-Control-Field-Compression | 2 | **Rejected by FortiGate.** |

**FortiGate LCP behavior:**
- Always proposes: MRU, Magic-Number
- Always rejects: PFCOMP (7), ACCOMP (8)
- Does not use asyncmap (non-HDLC mode)

### 7.3 Typical LCP Exchange

```
Client --> FortiGate:  LCP Configure-Request [MRU=1354, Magic=0xAABBCCDD]
FortiGate --> Client:  LCP Configure-Request [MRU=1354, Magic=0x11223344]
Client --> FortiGate:  LCP Configure-Ack [MRU=1354, Magic=0x11223344]
FortiGate --> Client:  LCP Configure-Ack [MRU=1354, Magic=0xAABBCCDD]
```

### 7.4 IPCP (IP Control Protocol, 0x8021)

After LCP reaches OPENED state, IPCP negotiation begins.

**IPCP Options:**
| Type | Name | Length | Description |
|------|------|--------|-------------|
| 3 | IP-Address | 6 | 4-byte IPv4 address |
| 129 | Primary DNS | 6 | 4-byte IPv4 address of primary DNS |
| 130 | Primary NBNS | 6 | 4-byte IPv4 address of primary NBNS/WINS |
| 131 | Secondary DNS | 6 | 4-byte IPv4 address of secondary DNS |
| 132 | Secondary NBNS | 6 | 4-byte IPv4 address of secondary NBNS/WINS |

**Typical IPCP exchange:**
1. Client sends Configure-Request with IP=0.0.0.0, DNS1=0.0.0.0, DNS2=0.0.0.0
   (requesting assignment).
2. Server responds with Configure-Nak containing the assigned IP and DNS servers.
3. Client re-sends Configure-Request with the assigned values.
4. Server sends Configure-Ack.

Note: When using the XML configuration endpoint, the client already knows the
assigned IP and DNS from the XML. IPCP still runs but serves as confirmation.

### 7.5 IP6CP (IPv6 Control Protocol, 0x8057)

If IPv6 is enabled (`dual_stack=1`), IP6CP negotiation follows IPCP.

**IP6CP Options:**
| Type | Name | Length | Description |
|------|------|--------|-------------|
| 1 | Interface-Identifier | 10 | 8-byte IPv6 interface identifier |

### 7.6 CCP (Compression Control Protocol, 0x80FD)

If the server proposes CCP, the client should reject it with Protocol-Reject
(LCP code 8). FortiGate does not typically insist on compression.

---

## 8. DTLS (UDP) Tunnel

### 8.1 Overview

DTLS provides the same PPP tunnel over UDP, avoiding TCP-over-TCP meltdown.
FortiGate always uses the **same port** for DTLS as for TLS (typically 443).

The XML configuration indicates DTLS availability:
```xml
<sslvpn-tunnel ver="2" dtls="1" patch="1">
```

### 8.2 DTLS Version

FortiGate uses DTLS 1.2. The DTLS handshake is a standard DTLS handshake
with the FortiGate server certificate.

### 8.3 Bespoke Fortinet DTLS Initialization

After the standard DTLS handshake completes, the client sends a bespoke
Fortinet "client hello" message (NOT a DTLS ClientHello -- this is an
application-layer message inside the established DTLS session):

**Client Hello (clthello) packet:**
```
Offset  Size    Field
------  ----    -----
0       2       Length (big-endian uint16): total bytes following
2       7       "GFtype\0"         (null-terminated key)
9       10      "clthello\0"       (null-terminated value)
19      12      "SVPNCOOKIE"       (null-terminated key, 11 bytes including \0)
30      ...     "<cookie-value>\0" (null-terminated SVPNCOOKIE value)
```

In C notation:
```c
static const char clthello[] = "GFtype\0clthello\0SVPNCOOKIE";
// Followed by cookie value + '\0'
// Length field = 2 + sizeof(clthello) + strlen(cookie_value) + 1
```

The length field at offset 0 covers everything from offset 2 to the end
(i.e., `sizeof(clthello) + strlen(cookie_value) + 1`).

**Server Hello (svrhello) response:**
```
Offset  Size    Field
------  ----    -----
0       2       Length (big-endian uint16): total bytes following
2       7       "GFtype\0"
9       10      "svrhello\0"
19      10      "handshake\0"      (null-terminated key)
29      ...     "ok\0" or "fail\0" (null-terminated status)
```

**Validation:**
```c
if (load_be16(buf) != len)           // length mismatch
if (memcmp(buf+2, svrhello, ...))    // not svrhello
if (strncmp("ok", buf+2+sizeof(svrhello), ...))  // not "ok"
    // DTLS failed, disable and fall back to TLS
```

**Edge case:** If the "ok" response is lost (UDP), the server may start sending
PPP frames instead. A client should treat receipt of a PPP frame as implicit
success.

### 8.4 Post-Handshake

After successful svrhello, PPP frames flow over DTLS using the **exact same
6-byte Fortinet header** format as over TLS. The PPP state machine is shared.

### 8.5 DTLS and TLS Coexistence

- Both tunnels may be active simultaneously.
- Data prefers DTLS when available.
- Control traffic (LCP, IPCP) may use either.
- If DTLS fails (blocked UDP, etc.), TLS takes over seamlessly.
- When DTLS is established, the TLS socket may be closed to conserve resources.

### 8.6 DTLS Heartbeat / Dead Peer Detection

Configured in the XML via `<dtls-config>`:

```xml
<dtls-config
  heartbeat-interval="10"
  heartbeat-fail-count="10"
  heartbeat-idle-timeout="10"
  client-hello-timeout="10"/>
```

FortiGate server-side configuration (FortiOS 7.4.0+):
```
config vpn ssl settings
    set dtls-heartbeat-idle-timeout 3    # seconds before heartbeat starts
    set dtls-heartbeat-interval 3        # seconds between heartbeats
    set dtls-heartbeat-fail-count 10     # missed heartbeats before disconnect
end
```

Heartbeat mechanism: After `heartbeat-idle-timeout` seconds of no traffic, the
server begins sending heartbeat probes every `heartbeat-interval` seconds. After
`heartbeat-fail-count` consecutive misses, the tunnel is torn down.

### 8.7 DTLS Failover

If DTLS fails at any point:
1. Client disables DTLS (sets state to `DTLS_DISABLED`).
2. If TLS socket was closed, client reopens TLS and re-sends
   `GET /remote/sslvpn-tunnel`.
3. PPP state is reset; LCP/IPCP negotiation repeats over TLS.

---

## 9. Keepalive and Dead Peer Detection

### 9.1 LCP Echo (PPP-Level Keepalive)

OpenConnect uses PPP LCP Echo-Request (code 9) for dead peer detection:

**Echo-Request format:**
```
[6-byte Fortinet header]
[0xFF 0x03]           -- PPP Address/Control
[0xC0 0x21]           -- PPP Protocol: LCP
[0x09]                -- Code: Echo-Request
[ID]                  -- Identifier
[0x00 0x08]           -- Length: 8
[4-byte magic number] -- Sender's magic number
```

The peer responds with Echo-Reply (code 10) containing its own magic number.

### 9.2 LCP Discard-Request (Lightweight Keepalive)

Used as a lighter-weight keepalive when real data is not flowing:

**Discard-Request format:**
```
[6-byte Fortinet header]
[0xFF 0x03]           -- PPP Address/Control
[0xC0 0x21]           -- PPP Protocol: LCP
[0x0B]                -- Code: Discard-Request
[ID]                  -- Identifier
[0x00 0x04]           -- Length: 4
```

No response is expected.

### 9.3 Idle Timeout

The XML configuration provides `<idle-timeout val="3600"/>` (server-side idle
timeout). If no traffic flows for this many seconds, the server disconnects
the session.

### 9.4 Authentication Timeout

`<auth-timeout val="18000"/>` defines the maximum session duration regardless
of activity. After this many seconds from authentication, the session expires.

---

## 10. Session Teardown

### 10.1 Clean Teardown

1. Send PPP LCP Terminate-Request.
2. Wait for LCP Terminate-Ack.
3. Close TLS/DTLS connections.
4. Send HTTP logout request:

```http
GET /remote/logout HTTP/1.1
Host: vpn.example.com:443
User-Agent: Mozilla/5.0 SV1
Cookie: SVPNCOOKIE=<cookie-value>
```

**Important:** The HTTPS connection must be **closed and reopened** before
sending the logout request. The existing connection is in PPP tunnel mode
and cannot accept HTTP requests.

### 10.2 Unclean Teardown

If the client disconnects without logout (crash, network loss), the server
will time out the session based on `idle-timeout` or `auth-timeout`.

---

## 11. Wire Protocol v2 (non-PPP)

### 11.1 Overview

FortiGate server versions starting around FortiOS 5.6.6 support a newer wire
protocol designated "v2" in the XML configuration. This appears alongside the
`<tunnel-method value="ppp"/>` entry:

```xml
<tunnel-method value="ppp"/>
<tunnel-method value="tun"/>
```

The "tun" method is the v2 protocol.

### 11.2 What is Known

Per OpenConnect issue #297 discussions:

- The v2 protocol does **not** use PPP. Instead, raw IP packets are encapsulated
  directly.
- The same 6-byte Fortinet framing header (`total_len`, `0x5050`, `payload_len`)
  is likely reused, with the payload being a raw IPv4/IPv6 packet instead of a
  PPP frame.
- LCP/IPCP negotiation is unnecessary because all configuration (IP, DNS, routes)
  is already provided in the XML configuration response.
- The v2 protocol is "easily understood" according to OpenConnect developers who
  have examined packet captures.

### 11.3 Advantages

- Simpler: no PPP state machine required.
- No LCP/IPCP negotiation delay.
- All configuration comes from the XML response.

### 11.4 Current Implementation Status

- **OpenConnect:** Does not yet implement v2. Uses v1 (PPP) exclusively.
- **openfortivpn:** Uses v1 (PPP via pppd) exclusively.
- **FortiClient:** Supports both v1 and v2.

### 11.5 FortiOS Version Support

| Feature | Minimum FortiOS |
|---------|----------------|
| v1 (PPP) wire protocol | All versions |
| v2 (tun) wire protocol | ~5.6.6 |
| DTLS support | 5.4+ |
| `tun-connect-without-reauth` | 6.2.1 |
| XML configuration (`fortisslvpn_xml`) | 5.0 |
| SAML authentication | 6.2+ |
| External browser SAML | 7.0.1 (FortiClient) |
| Adjustable DTLS heartbeat | 7.4.0 |

---

## 12. FortiOS Version Matrix

| FortiOS Version | Key Protocol Changes |
|-----------------|---------------------|
| 4.x | Legacy HTML configuration only (`/remote/fortisslvpn`). |
| 5.0+ | XML configuration (`/remote/fortisslvpn_xml`). |
| ~5.4+ | DTLS tunnel support. |
| ~5.6.6+ | Wire protocol v2 ("tun" method) alongside v1 ("ppp"). |
| 6.2.1 | `tun-connect-without-reauth` setting for cookie-based reconnection. |
| 6.2+ | SAML/SSO authentication support. |
| 7.0.1 | External browser SAML (FortiClient feature, requires FortiGate support). |
| 7.4.0 | Adjustable DTLS heartbeat parameters (`dtls-heartbeat-*`). |
| 7.4+ | JavaScript-based redirect from `GET /` (instead of HTTP 302). |
| 7.6.3 | SSL VPN tunnel mode deprecated in favor of IPsec VPN. |

---

## Appendix A: Quick Reference -- Byte-Level Header

### Fortinet Frame Header (6 bytes)
```
 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Total Length (BE16)      | 0x50  | 0x50  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Payload Length (BE16)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### PPP Header (4 bytes, always uncompressed)
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   0xFF (Addr) |  0x03 (Ctrl)  |       Protocol (BE16)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Complete Data Packet (IPv4)
```
[total_len:2] [0x5050:2] [payload_len:2] [0xFF:1] [0x03:1] [0x00:1] [0x21:1] [IPv4 packet...]
```

### Complete Data Packet (IPv6)
```
[total_len:2] [0x5050:2] [payload_len:2] [0xFF:1] [0x03:1] [0x00:1] [0x57:1] [IPv6 packet...]
```

### DTLS Client Hello
```
[length:2] "GFtype\0clthello\0SVPNCOOKIE" [cookie_value] [\0]
```

### DTLS Server Hello
```
[length:2] "GFtype\0svrhello\0handshake" "ok\0" | "fail\0"
```

---

## Appendix B: HTTP Endpoints

| Method | Path | Auth Required | Purpose |
|--------|------|---------------|---------|
| GET | `/` | No | Redirects to `/remote/login` |
| GET | `/remote/login` | No | Login page |
| POST | `/remote/logincheck` | No | Submit credentials |
| GET | `/remote/saml/start?redirect=1` | No | Initiate SAML flow |
| GET | `/remote/saml/auth_id?id=<id>` | No | Complete SAML, get SVPNCOOKIE |
| GET | `/remote/fortisslvpn` | SVPNCOOKIE | Legacy config (FortiOS 4.x) |
| GET | `/remote/fortisslvpn_xml` | SVPNCOOKIE | XML tunnel configuration |
| GET | `/remote/fortisslvpn_xml?dual_stack=1` | SVPNCOOKIE | XML config with IPv6 |
| GET | `/remote/sslvpn-tunnel` | SVPNCOOKIE | Establish PPP tunnel |
| GET | `/remote/index` | SVPNCOOKIE | Web portal index |
| GET | `/remote/logout` | SVPNCOOKIE | Terminate session |

---

## Appendix C: References

1. OpenConnect `fortinet.c` -- https://gitlab.com/openconnect/openconnect/-/blob/master/fortinet.c
2. OpenConnect `ppp.c` -- https://gitlab.com/openconnect/openconnect/-/blob/master/ppp.c
3. OpenConnect `ppp.h` -- https://gitlab.com/openconnect/openconnect/-/blob/master/ppp.h
4. OpenConnect Fortinet docs -- https://www.infradead.org/openconnect/fortinet.html
5. openfortivpn `http.c` -- https://github.com/adrienverge/openfortivpn/blob/master/src/http.c
6. openfortivpn `io.c` -- https://github.com/adrienverge/openfortivpn/blob/master/src/io.c
7. openfortivpn `hdlc.c` -- https://github.com/adrienverge/openfortivpn/blob/master/src/hdlc.c
8. FortiGate CLI Reference (vpn ssl settings) -- https://docs.fortinet.com/document/fortigate/6.2.1/cli-reference/281620/vpn-ssl-settings
9. FortiClient SAML external browser -- https://docs.fortinet.com/document/forticlient/7.0.0/new-features/748803/
10. OpenConnect Issue #297 (reconnect/v2 protocol) -- https://gitlab.com/openconnect/openconnect/-/issues/297
11. RFC 1661 -- PPP (https://tools.ietf.org/html/rfc1661)
12. RFC 1662 -- PPP in HDLC-like Framing (https://tools.ietf.org/html/rfc1662)
13. RFC 1332 -- PPP IPCP (https://tools.ietf.org/html/rfc1332)
14. RFC 1877 -- PPP IPCP DNS/NBNS Extensions (https://tools.ietf.org/html/rfc1877)
15. RFC 5072 -- PPP IP6CP (https://tools.ietf.org/html/rfc5072)
