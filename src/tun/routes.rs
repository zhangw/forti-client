use crate::auth::xml::Route;
use crate::error::{FortiError, Result};
use crate::shutdown::Shutdown;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Base budget for one whole install batch, covering small route sets.
const ROUTE_BATCH_BASE_TIMEOUT: Duration = Duration::from_secs(10);
/// Additional budget per route command. A healthy `/sbin/route` invocation
/// costs single-digit milliseconds, so this is generous headroom for large
/// split-tunnel sets: a ~664-route gateway legitimately needs on the order of
/// ten seconds, which a fixed budget cannot distinguish from a stall.
const ROUTE_PER_COMMAND_BUDGET: Duration = Duration::from_millis(50);
/// A single route command taking this long is wedged, not slow — typically
/// configd stalled by interface churn. Aborting on the first wedged command
/// also keeps a stalled batch from burning the entire batch budget.
const ROUTE_COMMAND_STALL: Duration = Duration::from_secs(2);

/// The batch budget scales with the route count so a large-but-healthy batch
/// is never mistaken for a wedged one.
fn route_batch_timeout(route_count: usize) -> Duration {
    ROUTE_BATCH_BASE_TIMEOUT
        .saturating_add(ROUTE_PER_COMMAND_BUDGET.saturating_mul(route_count as u32))
}

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

/// Install all split-tunnel routes.
///
/// Two distinct deadlines keep a wedged command from being confused with a
/// large batch: a single `/sbin/route` invocation stalling past
/// [`ROUTE_COMMAND_STALL`] aborts immediately as a transient local stall,
/// while the batch budget (see [`route_batch_timeout`]) scales with the route
/// count so a big-but-healthy split-tunnel set always fits. Exceeding the
/// scaled budget means sustained system-wide slowness, which stays a hard
/// error.
pub async fn install_routes(routes: &[Route], iface: &str, shutdown: &Shutdown) -> Result<usize> {
    let install = async {
        let mut installed = 0;
        for route in routes {
            let args = route_add_cmd(route, iface);
            debug!("route {}", args.join(" "));
            let output = match tokio::time::timeout(ROUTE_COMMAND_STALL, route_output(&args)).await
            {
                Ok(result) => result.map_err(|e| {
                    FortiError::TunnelError(format!("failed to run /sbin/route: {}", e))
                })?,
                Err(_) => {
                    return Err(FortiError::LocalSetupTimedOut(format!(
                        "route add for {} on {} stalled beyond {}s",
                        route.ip,
                        iface,
                        ROUTE_COMMAND_STALL.as_secs()
                    )))
                }
            };
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

    if shutdown.is_cancelled() {
        return Err(FortiError::TunnelError(
            "route installation cancelled".into(),
        ));
    }
    let batch_timeout = route_batch_timeout(routes.len());
    let installed = tokio::select! {
        _ = shutdown.cancelled() => {
            return Err(FortiError::TunnelError("route installation cancelled".into()));
        }
        result = tokio::time::timeout(batch_timeout, install) => {
            result.map_err(|_| FortiError::TunnelError(format!(
                "route installation exceeded its {}s budget for {} routes",
                batch_timeout.as_secs(),
                routes.len()
            )))??
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

/// Best-effort removal, bounded by the same scaled budget as installation.
///
/// The budget must scale exactly as [`install_routes`] does. A batch large
/// enough to be installed legitimately is large enough to be removed
/// legitimately, and a fixed budget here would abort teardown on route sets the
/// install path just accepted — stranding routes on an interface that is about
/// to disappear.
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

    let budget = route_batch_timeout(routes.len());
    match tokio::time::timeout(budget, remove).await {
        Ok(removed) => info!("Removed {}/{} routes from {}", removed, routes.len(), iface),
        Err(_) => warn!(
            "Route cleanup timed out after {}s for {} routes",
            budget.as_secs(),
            routes.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_budget_scales_with_route_count() {
        assert_eq!(route_batch_timeout(0), ROUTE_BATCH_BASE_TIMEOUT);
        // A ~664-route split-tunnel set (the scale seen from real gateways)
        // gets proportional headroom instead of competing with small sets
        // for one fixed budget.
        assert_eq!(
            route_batch_timeout(664),
            ROUTE_BATCH_BASE_TIMEOUT + Duration::from_millis(664 * 50)
        );
    }
}
