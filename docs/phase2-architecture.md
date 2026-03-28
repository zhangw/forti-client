# Phase 2 Architecture — Data Plane

**Goal:** Turn the negotiated PPP tunnel into a working VPN that routes traffic.

## Protocol Stack

```
┌───────────────────────────────────────────────────────┐
│  Applications (curl, browser, ssh, etc.)              │
├───────────────────────────────────────────────────────┤
│  macOS TCP/IP stack + routing table                   │
├────────────────────┬──────────────────────────────────┤
│  en0 (WiFi/LAN)    │  utun3 (VPN interface)           │
│  default gateway    │  IP: 10.8.2.6                   │
│  normal internet    │  split-tunnel routes →           │
│                     │  674 destinations via VPN        │
├────────────────────┴──────────┬───────────────────────┤
│                               │                       │
│                    ┌──────────┴──────────┐            │
│                    │   forti-client      │            │
│                    │                     │            │
│                    │  TUN ←→ PPP ←→ TLS  │            │
│                    │       ↕              │            │
│                    │   LCP keepalive     │            │
│                    └──────────┬──────────┘            │
│                               │                       │
│                    TLS to FortiGate                    │
│                    (vpn.example.com:10443)     │
└───────────────────────────────────────────────────────┘
```

## Data Flow

### Outbound (app → VPN → FortiGate)

```
1. App sends packet to 10.60.1.5
2. Routing table: 10.60.0.0/20 → utun3
3. Kernel delivers raw IP packet to utun3
4. forti-client reads from utun (with 4-byte AF_INET header on macOS)
5. Strip AF header → raw IP packet
6. Wrap in PPP frame:  [FF 03] [00 21] [IP packet...]
7. Wrap in Fortinet frame:  [total_len] [50 50] [payload_len] [PPP frame...]
8. Send over TLS to FortiGate
9. FortiGate decapsulates → routes to 10.60.1.5 on internal network
```

### Inbound (FortiGate → VPN → app)

```
1. FortiGate receives reply from 10.60.1.5
2. Wraps in Fortinet frame → sends over TLS
3. forti-client receives Fortinet frame → decodes
4. PPP frame: protocol 0x0021 (IPv4) → extract IP packet
5. Prepend 4-byte AF_INET header (0x00000002 on macOS)
6. Write to utun3
7. Kernel delivers to the app's socket
```

## Components

### 1. TUN Device (utun)

macOS uses kernel control sockets for utun devices, not `/dev/net/tun` like Linux.

```
socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
  → ioctl(CTLIOCGINFO, "com.apple.net.utun_control")
  → connect(sockaddr_ctl { sc_unit = N+1 })
  → getsockopt(UTUN_OPT_IFNAME) → "utun3"
```

Use `tun-rs` crate which handles this. Critical macOS detail: **every packet has a mandatory 4-byte AF header** (`AF_INET=2` for IPv4, `AF_INET6=30` for IPv6) that must be stripped on read and prepended on write.

```rust
// Reading from utun
let packet = tun.read().await;
let af_header = u32::from_ne_bytes(packet[0..4]);  // AF_INET=2
let ip_packet = &packet[4..];  // actual IP packet

// Writing to utun
let mut buf = vec![0u8; 4];
buf[3] = 2;  // AF_INET
buf.extend(ip_packet);
tun.write(&buf).await;
```

Requires **root** (`sudo`).

### 2. Route Installation

674 split-tunnel routes from the XML config. Each one:

```bash
/sbin/route add -net 10.60.0.0/20 -interface utun3
/sbin/route add -host 18.169.33.210 -interface utun3
```

For `/32` routes (mask `255.255.255.255`), use `-host` instead of `-net`.

On cleanup (disconnect/exit), remove all routes:

```bash
/sbin/route delete -net 10.60.0.0/20 -interface utun3
```

Requires **root**.

### 3. DNS Configuration

DNS servers from XML config: `183.90.189.7`, `8.8.8.8`.

macOS ignores `/etc/resolv.conf`. Two approaches:

**Split DNS** (for specific domains):
```bash
# /etc/resolver/internal.company.com
nameserver 183.90.189.7
```
macOS auto-reads files from `/etc/resolver/` — no daemon restart needed.

**Full tunnel DNS** (override system resolver):
```bash
scutil <<EOF
d.init
d.add ServerAddresses * 183.90.189.7 8.8.8.8
d.add SupplementalMatchDomains * ""
set State:/Network/Service/forti-client/DNS
EOF
```

For split tunnel (our case with 674 routes), we likely need the VPN DNS for internal domains only. This requires knowing which domains map to the VPN — the FortiGate doesn't always provide this info.

Practical approach: use `scutil` to add the VPN DNS as a supplemental resolver with a lower priority, so internal DNS names resolve via VPN while public names use the normal resolver.

Requires **root**.

### 4. LCP Echo Keepalive

Periodic heartbeat to detect dead tunnels:

```
Every 10 seconds:
  Client → LCP Echo-Request (our magic number)
  Client ← LCP Echo-Reply (their magic number)

If 3 consecutive echoes go unanswered:
  → Tunnel is dead
  → Close connection
  → Attempt reconnect
```

The LCP state machine already handles Echo-Reply generation. We need:
- A `tokio::time::interval(Duration::from_secs(10))` timer
- A counter for missed echoes
- Reconnect logic on dead peer detection

### 5. Main Event Loop

The core of Phase 2 — a `tokio::select!` multiplexing four event sources:

```rust
let mut keepalive = tokio::time::interval(Duration::from_secs(10));
let mut missed_echoes = 0u32;

loop {
    tokio::select! {
        // TUN → Tunnel (outbound traffic)
        packet = tun.read() => {
            let ip_packet = &packet[4..];  // strip AF header
            let ppp = PppFrame::new(PppProtocol::Ipv4, ip_packet.to_vec());
            tunnel.send_frame(ppp.encode()).await?;
        }

        // Tunnel → TUN (inbound traffic)
        frame = tunnel.recv_frame() => {
            let ppp = PppFrame::decode(frame.payload())?;
            match ppp.protocol() {
                PppProtocol::Ipv4 => {
                    let mut buf = vec![0, 0, 0, 2]; // AF_INET
                    buf.extend(ppp.data());
                    tun.write(&buf).await?;
                }
                PppProtocol::Lcp => {
                    let responses = lcp.handle_packet(ppp.data());
                    for resp in responses {
                        send_ppp(&mut tunnel, PppProtocol::Lcp, resp).await?;
                    }
                    // Reset missed echo counter on any LCP response
                    if ppp.data().first() == Some(&10) { // Echo-Reply
                        missed_echoes = 0;
                    }
                }
                _ => {} // ignore CCP, IP6CP for now
            }
        }

        // Keepalive timer
        _ = keepalive.tick() => {
            let echo = lcp.build_echo_request();
            send_ppp(&mut tunnel, PppProtocol::Lcp, echo).await?;
            missed_echoes += 1;
            if missed_echoes >= 3 {
                tracing::error!("Dead peer detected (3 missed echoes)");
                break;
            }
        }

        // Ctrl+C
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Disconnecting...");
            break;
        }
    }
}

// Cleanup: remove routes, DNS, TUN
```

### 6. Graceful Cleanup

On disconnect (Ctrl+C, dead peer, error):

1. Send LCP Terminate-Request to FortiGate
2. Remove all installed routes
3. Remove DNS configuration
4. Destroy TUN device
5. Close TLS connection

Use `tokio::signal::ctrl_c()` and a drop guard or explicit cleanup function.

## Phase 2 Task Breakdown

| # | Task | Description | Needs sudo |
|---|------|-------------|-----------|
| 1 | TUN device | Create utun via `tun-rs`, assign IP | Yes |
| 2 | Route installation | Install/remove split-tunnel routes via `/sbin/route` | Yes |
| 3 | DNS configuration | Configure via `scutil` or `/etc/resolver/` | Yes |
| 4 | Packet forwarding | Read TUN → PPP → Fortinet → TLS (and reverse) | No |
| 5 | Keepalive | LCP Echo timer, dead peer detection | No |
| 6 | Event loop | `tokio::select!` over TUN, tunnel, timer, signals | No |
| 7 | Cleanup | Remove routes, DNS, TUN on exit | Yes |
| 8 | Integration test | End-to-end: connect, ping internal host, disconnect | Yes |

## Phase 3 (Future)

- **DTLS data channel** — UDP transport for better performance (server advertises `dtls='1'`)
- **Reconnect** — auto-reconnect on dead peer or network change
- **Sleep/wake** — handle macOS sleep/wake via IOKit
- **IPv6** — IP6CP negotiation + IPv6 routing
- **Privilege separation** — launchd daemon + unprivileged CLI
