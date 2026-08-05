use crate::error::{FortiError, Result};
use crate::shutdown::Shutdown;
use std::net::Ipv4Addr;
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, info};

const SCUTIL_SERVICE: &str = "State:/Network/Service/forti-client/DNS";
const SCUTIL_TIMEOUT: Duration = Duration::from_secs(5);

/// Extract a failure message from a scutil run, or `None` on success.
///
/// scutil reports errors by printing them to **stdout** and still exiting `0`,
/// so the exit status alone cannot detect a failed `set` or `remove`. Mutating
/// commands are silent on success, which makes any output the error signal.
fn scutil_failure(success: bool, stdout: &str, stderr: &str) -> Option<String> {
    let message = if !stdout.trim().is_empty() {
        stdout.trim()
    } else if !stderr.trim().is_empty() {
        stderr.trim()
    } else if success {
        return None;
    } else {
        "scutil exited with a failure status and no diagnostics"
    };
    Some(message.to_string())
}

/// scutil's report for removing a key that is not present. Removal is meant to
/// be idempotent: an absent key already is the desired end state.
fn is_missing_key(message: &str) -> bool {
    message.eq_ignore_ascii_case("No such key")
}

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
    if shutdown.is_cancelled() {
        return Err(FortiError::TunnelError(
            "DNS configuration cancelled".into(),
        ));
    }
    let output = tokio::select! {
        _ = shutdown.cancelled() => {
            return Err(FortiError::TunnelError("DNS configuration cancelled".into()));
        }
        result = run_scutil(&scutil_input) => {
            result.map_err(|e| FortiError::TunnelError(format!("failed to run scutil: {}", e)))?
        }
    };

    if let Some(error) = scutil_failure(
        output.status.success(),
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    ) {
        return Err(FortiError::TunnelError(format!(
            "scutil failed to configure VPN DNS: {error}"
        )));
    }

    info!("Configured DNS servers: {}", servers_joined);
    Ok(())
}

/// Remove the VPN DNS configuration.
///
/// Returns an error when scutil cannot complete the removal (timeout or
/// non-zero exit) so callers know the VPN DNS may still be installed. In the
/// suspend path this matters: a silent failure would leave the controller
/// believing the DNS was withdrawn while the system resolver still points at
/// VPN-internal servers, black-holing the next reconnect.
pub async fn remove_dns() -> Result<()> {
    let input = format!("remove {SCUTIL_SERVICE}\n");
    let output = run_scutil(&input)
        .await
        .map_err(|e| FortiError::TunnelError(format!("failed to remove VPN DNS: {e}")))?;
    match scutil_failure(
        output.status.success(),
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    ) {
        None => {
            info!("Removed DNS configuration");
            Ok(())
        }
        Some(error) if is_missing_key(&error) => {
            debug!("VPN DNS configuration was already absent");
            Ok(())
        }
        Some(error) => Err(FortiError::TunnelError(format!(
            "scutil failed to remove VPN DNS: {error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silent_success_is_not_a_failure() {
        assert_eq!(scutil_failure(true, "", ""), None);
        assert_eq!(scutil_failure(true, "  \n ", " \n"), None);
    }

    #[test]
    fn errors_printed_to_stdout_with_exit_zero_are_detected() {
        // scutil's real behavior: diagnostics on stdout, exit status 0.
        assert_eq!(
            scutil_failure(true, "  Permission denied\n", ""),
            Some("Permission denied".to_string())
        );
        assert_eq!(
            scutil_failure(true, "  No such key\n", ""),
            Some("No such key".to_string())
        );
    }

    #[test]
    fn stderr_and_bare_failure_status_are_still_reported() {
        assert_eq!(scutil_failure(true, "", "boom\n"), Some("boom".to_string()));
        assert!(scutil_failure(false, "", "").is_some());
    }

    #[test]
    fn removing_an_absent_key_counts_as_success() {
        assert!(is_missing_key("No such key"));
        assert!(is_missing_key("no such key"));
        assert!(!is_missing_key("Permission denied"));
    }
}
