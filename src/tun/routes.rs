use crate::auth::xml::Route;
use crate::error::{FortiError, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{info, debug};

/// Convert a subnet mask to a CIDR prefix length by counting set bits.
pub fn mask_to_prefix(mask: Ipv4Addr) -> u32 {
    u32::from_be_bytes(mask.octets()).count_ones()
}

fn route_cmd(verb: &str, route: &Route, iface: &str) -> Vec<String> {
    let prefix = mask_to_prefix(route.mask);
    if prefix == 32 {
        vec![verb.into(), "-host".into(), route.ip.to_string(), "-interface".into(), iface.into()]
    } else {
        vec![verb.into(), "-net".into(), format!("{}/{}", route.ip, prefix), "-interface".into(), iface.into()]
    }
}

pub fn route_add_cmd(route: &Route, iface: &str) -> Vec<String> {
    route_cmd("add", route, iface)
}

pub fn route_delete_cmd(route: &Route, iface: &str) -> Vec<String> {
    route_cmd("delete", route, iface)
}

/// Install split-tunnel routes via `/sbin/route add`.
/// Returns the number of routes successfully installed.
pub fn install_routes(routes: &[Route], iface: &str) -> Result<usize> {
    let mut installed = 0;
    let total = routes.len();
    for route in routes {
        let args = route_add_cmd(route, iface);
        debug!("route {}", args.join(" "));
        let output = Command::new("/sbin/route").args(&args).output()
            .map_err(|e| FortiError::TunnelError(format!("failed to run /sbin/route: {}", e)))?;
        if output.status.success() {
            installed += 1;
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                debug!("route add failed for {}: {}", route.ip, stderr.trim());
            }
        }
    }
    info!("Installed {}/{} routes on {}", installed, total, iface);
    Ok(installed)
}

/// Remove split-tunnel routes via `/sbin/route delete`.
/// Logs the count but does not return errors (best-effort cleanup).
pub fn remove_routes(routes: &[Route], iface: &str) {
    let mut removed = 0;
    for route in routes {
        let args = route_delete_cmd(route, iface);
        if let Ok(output) = Command::new("/sbin/route").args(&args).output() {
            if output.status.success() { removed += 1; }
        }
    }
    info!("Removed {}/{} routes from {}", removed, routes.len(), iface);
}
