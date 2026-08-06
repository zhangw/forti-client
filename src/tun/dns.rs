use crate::error::{FortiError, Result};
use crate::shutdown::Shutdown;
use std::net::Ipv4Addr;
use std::process::{Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

const SCUTIL_SERVICE: &str = "State:/Network/Service/forti-client/DNS";
const SCUTIL_TIMEOUT: Duration = Duration::from_secs(5);
const BLOCKING_REMOVE_TIMEOUT: Duration = Duration::from_secs(2);

/// Whether our DNS key is currently installed in the system configuration.
///
/// This tracks a genuinely process-global resource. The SCDynamicStore key
/// outlives the scutil process that created it, so a client that dies without
/// removing it leaves the system resolver pointing at VPN-internal servers —
/// unlike routes, which the kernel drops when the utun interface disappears.
static DNS_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Whether this process currently has VPN DNS installed system-wide.
pub fn dns_is_installed() -> bool {
    DNS_INSTALLED.load(Ordering::SeqCst)
}

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
    DNS_INSTALLED.store(true, Ordering::SeqCst);
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
            DNS_INSTALLED.store(false, Ordering::SeqCst);
            Ok(())
        }
        Some(error) if is_missing_key(&error) => {
            debug!("VPN DNS configuration was already absent");
            DNS_INSTALLED.store(false, Ordering::SeqCst);
            Ok(())
        }
        Some(error) => Err(FortiError::TunnelError(format!(
            "scutil failed to remove VPN DNS: {error}"
        ))),
    }
}

/// Remove the VPN DNS configuration synchronously, bounded by a deadline.
///
/// Teardown paths that cannot await need this: `Drop` while unwinding from a
/// panic, and the forced-exit signal handler. The async [`remove_dns`] is
/// preferred whenever the runtime is still usable.
///
/// Returns true when the configuration is known to be gone. stdout and stderr
/// go to /dev/null rather than pipes: nothing here can act on a diagnostic, and
/// an unread pipe is one more way to block a path whose whole purpose is to
/// finish quickly.
pub fn remove_dns_blocking() -> bool {
    if !dns_is_installed() {
        return true;
    }

    let mut child = match std::process::Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            error!(%error, "Could not spawn scutil to remove VPN DNS");
            return false;
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(format!("remove {SCUTIL_SERVICE}\n").as_bytes());
        // Dropping stdin closes the pipe so scutil sees EOF and exits.
    }

    let deadline = std::time::Instant::now() + BLOCKING_REMOVE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                DNS_INSTALLED.store(false, Ordering::SeqCst);
                return true;
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return false,
        }
    }
}

/// Removes the VPN DNS configuration on drop if it is still installed.
///
/// The normal shutdown path removes DNS asynchronously, and this guard then
/// finds nothing to do. It exists for the paths that never reach that code: a
/// panic unwinding out of the controller, or an early error return. Leaving the
/// key behind breaks name resolution machine-wide until a human removes it, so
/// a best-effort synchronous attempt is worth the blocking call.
pub struct DnsGuard;

impl Drop for DnsGuard {
    fn drop(&mut self) {
        if !dns_is_installed() {
            return;
        }
        warn!("VPN DNS still installed during teardown; removing synchronously");
        if !remove_dns_blocking() {
            error!(
                "Could not remove VPN DNS. System name resolution may stay broken. \
                 Recover with: sudo scutil <<< 'remove {SCUTIL_SERVICE}'"
            );
        }
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
