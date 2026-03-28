use crate::error::{FortiError, Result};
use std::net::Ipv4Addr;
use std::process::{Command, Output, Stdio};
use tracing::{info, debug};

const SCUTIL_SERVICE: &str = "State:/Network/Service/forti-client/DNS";

fn run_scutil(input: &str) -> std::io::Result<Output> {
    let mut child = Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    {
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(input.as_bytes())?;
    }

    child.wait_with_output()
}

pub fn configure_dns(servers: &[Ipv4Addr]) -> Result<()> {
    if servers.is_empty() {
        debug!("No DNS servers to configure");
        return Ok(());
    }

    let servers_joined: String = servers.iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(" ");

    let scutil_input = format!(
        "d.init\nd.add ServerAddresses * {servers_joined}\nd.add SupplementalMatchDomains * \"\"\nset {SCUTIL_SERVICE}\n",
    );

    debug!("Configuring DNS via scutil:\n{}", scutil_input.trim());

    let output = run_scutil(&scutil_input)
        .map_err(|e| FortiError::TunnelError(format!("failed to run scutil: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FortiError::TunnelError(format!("scutil failed: {}", stderr.trim())));
    }

    info!("Configured DNS servers: {}", servers_joined);
    Ok(())
}

pub fn remove_dns() {
    let input = format!("remove {SCUTIL_SERVICE}\n");
    match run_scutil(&input) {
        Ok(output) if output.status.success() => info!("Removed DNS configuration"),
        _ => debug!("DNS cleanup: nothing to remove or scutil failed"),
    }
}
