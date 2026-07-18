use crate::error::{FortiError, Result};
use crate::shutdown::Shutdown;
use std::net::Ipv4Addr;
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, info, warn};

const SCUTIL_SERVICE: &str = "State:/Network/Service/forti-client/DNS";
const SCUTIL_TIMEOUT: Duration = Duration::from_secs(5);

async fn run_scutil(input: &str) -> std::io::Result<Output> {
    let operation = async {
        let mut command = Command::new("/usr/sbin/scutil");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes()).await?;
        }
        child.wait_with_output().await
    };

    tokio::time::timeout(SCUTIL_TIMEOUT, operation)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "scutil timed out"))?
}

pub async fn configure_dns(servers: &[Ipv4Addr], shutdown: &Shutdown) -> Result<()> {
    if servers.is_empty() {
        debug!("No DNS servers to configure");
        return Ok(());
    }

    let servers_joined: String = servers
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(" ");

    let scutil_input = format!(
        "d.init\nd.add ServerAddresses * {servers_joined}\nd.add SupplementalMatchDomains * \"\"\nset {SCUTIL_SERVICE}\n",
    );

    debug!("Configuring DNS via scutil:\n{}", scutil_input.trim());
    let output = tokio::select! {
        biased;
        _ = shutdown.cancelled() => {
            return Err(FortiError::TunnelError("DNS configuration cancelled".into()));
        }
        result = run_scutil(&scutil_input) => {
            result.map_err(|e| FortiError::TunnelError(format!("failed to run scutil: {}", e)))?
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FortiError::TunnelError(format!(
            "scutil failed: {}",
            stderr.trim()
        )));
    }

    info!("Configured DNS servers: {}", servers_joined);
    Ok(())
}

pub async fn remove_dns() {
    let input = format!("remove {SCUTIL_SERVICE}\n");
    match run_scutil(&input).await {
        Ok(output) if output.status.success() => info!("Removed DNS configuration"),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            warn!("DNS cleanup timed out after 5s")
        }
        _ => debug!("DNS cleanup: nothing to remove or scutil failed"),
    }
}
