use crate::error::{FortiError, Result};
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use tracing::{info, debug};

const SCUTIL_SERVICE: &str = "State:/Network/Service/forti-client/DNS";

pub fn configure_dns(servers: &[Ipv4Addr]) -> Result<()> {
    if servers.is_empty() {
        debug!("No DNS servers to configure");
        return Ok(());
    }

    let server_strs: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    let servers_joined = server_strs.join(" ");

    // scutil commands — no leading whitespace, each on its own line
    let scutil_input = format!(
        "d.init\nd.add ServerAddresses * {servers}\nd.add SupplementalMatchDomains * \"\"\nset {service}\n",
        servers = servers_joined,
        service = SCUTIL_SERVICE,
    );

    debug!("Configuring DNS via scutil:\n{}", scutil_input.trim());

    let mut child = Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| FortiError::TunnelError(format!("failed to spawn scutil: {}", e)))?;

    // Write input and close stdin so scutil processes it
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut()
            .ok_or_else(|| FortiError::TunnelError("failed to open scutil stdin".into()))?;
        stdin.write_all(scutil_input.as_bytes())
            .map_err(|e| FortiError::TunnelError(format!("failed to write to scutil: {}", e)))?;
    } // stdin is dropped here, closing the pipe

    let output = child.wait_with_output()
        .map_err(|e| FortiError::TunnelError(format!("scutil failed: {}", e)))?;

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
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut child| {
            {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(scutil_input.as_bytes())?;
                }
            } // close stdin
            child.wait_with_output()
        });

    match result {
        Ok(output) if output.status.success() => info!("Removed DNS configuration"),
        _ => debug!("DNS cleanup: nothing to remove or scutil failed"),
    }
}
