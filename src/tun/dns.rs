use crate::error::{FortiError, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{info, debug};

const SCUTIL_SERVICE: &str = "State:/Network/Service/forti-client/DNS";

pub fn configure_dns(servers: &[Ipv4Addr]) -> Result<()> {
    if servers.is_empty() {
        debug!("No DNS servers to configure");
        return Ok(());
    }

    let server_strs: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    let servers_joined = server_strs.join(" ");

    let scutil_input = format!(
        "d.init\n\
         d.add ServerAddresses * {}\n\
         d.add SupplementalMatchDomains * \"\"\n\
         set {}\n",
        servers_joined, SCUTIL_SERVICE,
    );

    debug!("Configuring DNS via scutil:\n{}", scutil_input.trim());

    let output = Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(scutil_input.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| FortiError::TunnelError(format!("failed to run scutil: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FortiError::TunnelError(format!("scutil failed: {}", stderr.trim())));
    }

    info!("Configured DNS servers: {}", servers_joined);
    Ok(())
}

pub fn remove_dns() {
    let scutil_input = format!("remove {}\n", SCUTIL_SERVICE);

    let result = Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(scutil_input.as_bytes())?;
            }
            child.wait_with_output()
        });

    match result {
        Ok(output) if output.status.success() => info!("Removed DNS configuration"),
        _ => debug!("DNS cleanup: nothing to remove or scutil failed"),
    }
}
