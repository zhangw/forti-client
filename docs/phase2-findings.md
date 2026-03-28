# Phase 2 Findings — Data Plane Live Testing

**Date:** 2026-03-29
**Server:** sslvpn.example.com:10443 (FortiOS, SAML-only)

## What Works

- TUN device creation (utun4, IP assigned via tun-rs)
- 664 split-tunnel routes installed via `/sbin/route`
- DNS configured via `scutil` (supplemental resolver)
- Bidirectional packet forwarding (TUN ↔ PPP ↔ TLS)
- Ping through VPN (~30ms RTT to internal hosts)
- DNS resolution via VPN DNS server
- TCP connections through VPN tunnel
- LCP Echo keepalive (10s interval)
- Graceful cleanup on Ctrl+C (routes, DNS, LCP Terminate)

## Platform Discoveries (tun-rs on macOS)

### No AF Header from tun-rs

The Phase 2 architecture doc assumed macOS utun devices always prefix packets with a 4-byte AF header (`AF_INET=2` for IPv4). This is true for raw utun sockets, but **tun-rs handles the AF header internally**.

```
Expected:  [00 00 00 02] [45 00 ...IP packet...]  (4-byte AF + IP)
Actual:                  [45 00 ...IP packet...]   (raw IP packet)
```

tun-rs strips the AF header on read and prepends it on write automatically. Our code passes raw IP packets in both directions:
- **Read from TUN:** detect IP version from first nibble (`0x4` = IPv4, `0x6` = IPv6)
- **Write to TUN:** send raw IP packet directly (no AF header needed)

### DeviceBuilder API (tun-rs 2.8.1)

The tun-rs v2 API differs from older documentation:

```rust
// Correct API (v2.8.1)
let dev = tun_rs::DeviceBuilder::new()
    .ipv4(ip, 32u8, None)
    .build_async()?;

let name = dev.name()?;           // e.g., "utun4"
let n = dev.recv(&mut buf).await?; // read packet
dev.send(&packet).await?;          // write packet
```

No `Configuration` struct, no `create_as_async()`, no `platform_config()`.

## DNS Configuration

`scutil` requires precise input formatting — no leading whitespace, stdin must be closed after writing:

```
d.init
d.add ServerAddresses * 183.90.189.7 8.8.8.8
d.add SupplementalMatchDomains * ""
set State:/Network/Service/forti-client/DNS
```

With `SupplementalMatchDomains` set to empty string `""`, the VPN DNS acts as a supplemental resolver for all domains. The system resolver is still used first, but the VPN DNS catches anything the system resolver can't resolve (internal hostnames).

Verify with: `scutil --dns | grep -A 5 forti-client`

Cleanup: `remove State:/Network/Service/forti-client/DNS`

## Route Installation

664 routes installed successfully via `/sbin/route`. Subnet routes use CIDR notation (`-net 10.60.0.0/20`), host routes use `-host` flag. The `mask_to_prefix()` function converts subnet masks to prefix lengths via `count_ones()`.

Some routes may fail with "File exists" if they overlap with system routes — this is tolerated (logged but not treated as an error).

## Live Test Results

```
Interface: utun4, IP: 10.8.2.2/32
Routes: 664/664 installed
DNS: 183.90.189.7, 8.8.8.8 via scutil

Ping test:
  192.168.40.73: 3/3 packets, 28-32ms RTT

DNS test:
  dig internal-host.example.com → resolved via 183.90.189.7 (58ms)

TCP connections through VPN:
  10.8.2.2:61553 → 75.2.23.38:443 ESTABLISHED
  10.8.2.2:59382 → 34.237.113.219:443 ESTABLISHED

TLS tunnel:
  192.168.31.115:58905 → FortiGate:10443 ESTABLISHED (single connection)
```

## Event Loop Performance

The `tokio::select!` loop handles all four event sources without issues:
- TUN reads (outbound packets from apps)
- Tunnel reads (inbound packets from FortiGate)
- Keepalive timer (LCP Echo every 10s)
- Ctrl+C signal (graceful shutdown)

Packet forwarding latency is dominated by the TLS tunnel RTT (~30ms), not the event loop.
