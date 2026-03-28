pub mod routes;
pub mod dns;

use crate::error::{FortiError, Result};
use std::net::Ipv4Addr;
use tracing::info;

/// Create a macOS utun device with the given IP address.
/// Returns the tun device and the interface name (e.g., "utun3").
/// Must be run as root.
pub fn create_tun(ip: Ipv4Addr) -> Result<(tun_rs::AsyncDevice, String)> {
    let dev = tun_rs::DeviceBuilder::new()
        .ipv4(ip, 32u8, None)
        .build_async()
        .map_err(|e| FortiError::TunnelError(format!("failed to create TUN device: {}", e)))?;

    let name = dev.name()
        .map_err(|e| FortiError::TunnelError(format!("failed to get TUN name: {}", e)))?;

    info!("Created TUN device {} with IP {}/32", name, ip);
    Ok((dev, name))
}
