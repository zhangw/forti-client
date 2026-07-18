use crate::auth::xml::Route;
use crate::error::{FortiError, Result};
use crate::shutdown::Shutdown;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::process::Command;
use tracing::{debug, info, warn};

const ROUTE_BATCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Convert a subnet mask to a CIDR prefix length by counting set bits.
pub fn mask_to_prefix(mask: Ipv4Addr) -> u32 {
    u32::from_be_bytes(mask.octets()).count_ones()
}

fn route_cmd(verb: &str, route: &Route, iface: &str) -> Vec<String> {
    let prefix = mask_to_prefix(route.mask);
    if prefix == 32 {
        vec![
            verb.into(),
            "-host".into(),
            route.ip.to_string(),
            "-interface".into(),
            iface.into(),
        ]
    } else {
        vec![
            verb.into(),
            "-net".into(),
            format!("{}/{}", route.ip, prefix),
            "-interface".into(),
            iface.into(),
        ]
    }
}

pub fn route_add_cmd(route: &Route, iface: &str) -> Vec<String> {
    route_cmd("add", route, iface)
}

pub fn route_delete_cmd(route: &Route, iface: &str) -> Vec<String> {
    route_cmd("delete", route, iface)
}

async fn route_output(args: &[String]) -> std::io::Result<std::process::Output> {
    let mut command = Command::new("/sbin/route");
    command.args(args).kill_on_drop(true);
    command.output().await
}

/// Install all split-tunnel routes. The timeout covers the entire batch, not
/// each route, so one wedged system command cannot multiply the shutdown delay.
pub async fn install_routes(routes: &[Route], iface: &str, shutdown: &Shutdown) -> Result<usize> {
    let install = async {
        let mut installed = 0;
        for route in routes {
            let args = route_add_cmd(route, iface);
            debug!("route {}", args.join(" "));
            let output = route_output(&args).await.map_err(|e| {
                FortiError::TunnelError(format!("failed to run /sbin/route: {}", e))
            })?;
            if output.status.success() {
                installed += 1;
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    debug!("route add failed for {}: {}", route.ip, stderr.trim());
                }
            }
        }
        Ok::<usize, FortiError>(installed)
    };

    let installed = tokio::select! {
        biased;
        _ = shutdown.cancelled() => {
            return Err(FortiError::TunnelError("route installation cancelled".into()));
        }
        result = tokio::time::timeout(ROUTE_BATCH_TIMEOUT, install) => {
            result.map_err(|_| FortiError::TunnelError("route installation timed out after 10s".into()))??
        }
    };
    info!(
        "Installed {}/{} routes on {}",
        installed,
        routes.len(),
        iface
    );
    Ok(installed)
}

/// Best-effort removal with a hard total timeout.
pub async fn remove_routes(routes: &[Route], iface: &str) {
    let remove = async {
        let mut removed = 0;
        for route in routes {
            let args = route_delete_cmd(route, iface);
            if let Ok(output) = route_output(&args).await {
                if output.status.success() {
                    removed += 1;
                }
            }
        }
        removed
    };

    match tokio::time::timeout(ROUTE_BATCH_TIMEOUT, remove).await {
        Ok(removed) => info!("Removed {}/{} routes from {}", removed, routes.len(), iface),
        Err(_) => warn!("Route cleanup timed out after 10s"),
    }
}
