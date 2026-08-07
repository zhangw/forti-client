use clap::Parser;
use forti_client::auth::AuthClient;
use forti_client::reconnect::{AuthParams, ReconnectController};
use forti_client::shutdown::Shutdown;
use secrecy::{ExposeSecret, SecretString};
use std::io::Write;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "forti-client", about = "FortiGate SSL VPN client")]
struct Cli {
    /// VPN gateway hostname or IP
    #[arg(short, long)]
    server: String,

    /// VPN gateway port
    #[arg(short, long, default_value = "443")]
    port: u16,

    /// Username (not needed for --saml)
    #[arg(short, long)]
    username: Option<String>,

    /// Password (if omitted, will prompt)
    #[arg(short = 'P', long)]
    password: Option<String>,

    /// Realm (optional)
    #[arg(long)]
    realm: Option<String>,

    /// Use SAML/SSO authentication (opens browser)
    #[arg(long)]
    saml: bool,

    /// Enable TLS key logging to file (for Wireshark debugging)
    #[arg(long)]
    tls_keylog_file: Option<String>,

    /// Failed reconnect cycles before forcing full re-authentication
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..))]
    reauth_after_failures: u32,

    /// Tunnel lifetime below this many seconds counts as a failed reconnect cycle
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    tunnel_flap_window: u64,
}

const FORCED_SIGINT_EXIT_CODE: i32 = 130;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownSignalAction {
    Graceful,
    ForceExit,
}

fn shutdown_signal_action(signal_number: u8) -> ShutdownSignalAction {
    if signal_number <= 1 {
        ShutdownSignalAction::Graceful
    } else {
        ShutdownSignalAction::ForceExit
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mut cli = Cli::parse();

    let enable_keylog = if let Some(ref path) = cli.tls_keylog_file {
        // Validate the keylog output path before enabling
        let keylog_path = std::path::Path::new(path);

        // Reject symlinks — prevent writing to unexpected locations
        if keylog_path.is_symlink() {
            anyhow::bail!("--tls-keylog-file: refusing symlink target '{}'", path);
        }

        // Parent directory must exist and be writable
        let parent = keylog_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        if !parent.is_dir() {
            anyhow::bail!(
                "--tls-keylog-file: parent directory '{}' does not exist",
                parent.display()
            );
        }

        // Reject world-writable parent directories (e.g. /tmp) —
        // other users could swap the file via symlink race after validation
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(parent)?.permissions().mode();
            if mode & 0o002 != 0 {
                anyhow::bail!(
                    "--tls-keylog-file: parent directory '{}' is world-writable (mode {:o})",
                    parent.display(),
                    mode & 0o777,
                );
            }
        }

        std::env::set_var("SSLKEYLOGFILE", path);
        tracing::warn!("TLS key logging enabled — writing to {}", path);
        tracing::warn!("This exposes TLS session secrets. Use only for debugging.");
        true
    } else {
        false
    };

    // Resolve the gateway once, up front, while the system resolver is still
    // pointed at physical DNS servers. Every later connection and reconnect
    // uses this address, so a tunnel that installs VPN-internal DNS servers
    // cannot black-hole its own reconnect path.
    let server_addr = forti_client::auth::resolve_server_addr(&cli.server, cli.port).await?;
    tracing::info!("Resolved {} to {}", cli.server, server_addr);

    let auth_client =
        AuthClient::new(&cli.server, cli.port, enable_keylog)?.with_pinned_addr(server_addr);

    // Prompt for password early (before we need sudo/root)
    let password: Option<SecretString> = if !cli.saml {
        match cli.password.take() {
            Some(p) => Some(SecretString::from(p)),
            None if cli.username.is_some() => {
                eprint!("Password: ");
                std::io::stderr().flush()?;
                let mut p = String::new();
                std::io::stdin().read_line(&mut p)?;
                Some(SecretString::from(p.trim().to_string()))
            }
            None => None,
        }
    } else {
        None
    };

    // Tokio keeps the signal handlers installed for the process lifetime. The
    // first signal starts bounded graceful shutdown; a second is an explicit
    // user override if protocol or system cleanup is stuck.
    //
    // SIGTERM and SIGHUP funnel into the same Shutdown as SIGINT rather than a
    // separate channel, so the data-plane select! gains no extra branch. Before
    // this, `kill` or a system shutdown skipped cleanup entirely and left the
    // VPN DNS key installed system-wide.
    let shutdown = Shutdown::new();
    let signal_shutdown = shutdown.clone();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    tokio::spawn(async move {
        let mut signal_number = 0u8;
        loop {
            let signal_name = tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    if result.is_err() {
                        return;
                    }
                    "SIGINT"
                }
                received = sigterm.recv() => {
                    if received.is_none() {
                        return;
                    }
                    "SIGTERM"
                }
                received = sighup.recv() => {
                    if received.is_none() {
                        return;
                    }
                    "SIGHUP"
                }
            };
            signal_number = signal_number.saturating_add(1);
            match shutdown_signal_action(signal_number) {
                ShutdownSignalAction::Graceful => {
                    tracing::info!(
                        signal = signal_name,
                        shutdown_phase = "graceful",
                        "Signal received; disconnecting"
                    );
                    signal_shutdown.cancel();
                }
                ShutdownSignalAction::ForceExit => {
                    tracing::warn!(
                        signal = signal_name,
                        shutdown_phase = "forced",
                        "Second signal received; forcing exit and possibly leaving routes behind"
                    );
                    // process::exit runs no destructors, so the DNS guard never
                    // fires here. Removing the key synchronously first is what
                    // keeps a forced exit from breaking name resolution
                    // machine-wide. Routes need no such care: the kernel drops
                    // them when the utun interface closes with the process.
                    forti_client::tun::dns::remove_dns_blocking();
                    std::process::exit(FORCED_SIGINT_EXIT_CODE);
                }
            }
        }
    });

    let auth_future = async {
        if cli.saml {
            tracing::info!(
                "Starting SAML authentication to {}:{}",
                cli.server,
                cli.port
            );
            auth_client.login_saml().await
        } else {
            let username = cli.username.as_deref().ok_or_else(|| {
                forti_client::error::FortiError::AuthFailed(
                    "--username is required for credential auth (use --saml for SSO)".into(),
                )
            })?;
            let pw = password.as_ref().ok_or_else(|| {
                forti_client::error::FortiError::AuthFailed("password required".into())
            })?;
            tracing::info!("Authenticating to {}:{}", cli.server, cli.port);
            auth_client
                .login(username, pw.expose_secret(), cli.realm.as_deref())
                .await
        }
    };

    if shutdown.is_cancelled() {
        tracing::info!("Authentication cancelled.");
        return Ok(());
    }
    let auth_result = tokio::select! {
        _ = shutdown.cancelled() => {
            tracing::info!("Authentication cancelled.");
            #[cfg(debug_assertions)]
            if std::env::var_os("FORTI_CLIENT_TEST_STALL_ON_SHUTDOWN").is_some() {
                std::future::pending::<()>().await;
            }
            return Ok(());
        }
        result = auth_future => result?,
    };

    tracing::info!(
        "Authenticated. IP={}, DNS={:?}, {} routes",
        auth_result.tunnel_config.ip_address,
        auth_result.tunnel_config.dns_servers,
        auth_result.tunnel_config.routes.len(),
    );

    let auth_params = AuthParams {
        server: cli.server,
        port: cli.port,
        server_addr: Some(server_addr),
        saml: cli.saml,
        username: cli.username,
        password,
        realm: cli.realm,
        tls_config: auth_client.tls_config(),
        enable_keylog,
    };

    let mut controller = ReconnectController::new(
        auth_params,
        auth_result.svpn_cookie,
        auth_result.tunnel_config,
        shutdown,
        forti_client::reconnect::EscalationConfig {
            max_failed_cycles: cli.reauth_after_failures,
            flap_window: std::time::Duration::from_secs(cli.tunnel_flap_window),
        },
    );

    // Last-resort cleanup for paths that never reach the controller's own
    // teardown, such as a panic unwinding out of it. Unlike routes, the DNS key
    // survives process death and would break resolution machine-wide.
    let _dns_guard = forti_client::tun::dns::DnsGuard;

    controller.run().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sigint_is_graceful_and_second_forces_130() {
        assert_eq!(shutdown_signal_action(1), ShutdownSignalAction::Graceful);
        assert_eq!(shutdown_signal_action(2), ShutdownSignalAction::ForceExit);
        assert_eq!(shutdown_signal_action(3), ShutdownSignalAction::ForceExit);
        assert_eq!(FORCED_SIGINT_EXIT_CODE, 130);
    }
}
