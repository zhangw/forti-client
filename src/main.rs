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

    let auth_client = AuthClient::new(&cli.server, cli.port, enable_keylog)?;

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

    // Install one process-wide Ctrl+C listener after the synchronous password
    // prompt. The level-triggered token remembers cancellation across states.
    let shutdown = Shutdown::new();
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("Ctrl+C received");
            signal_shutdown.cancel();
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

    let auth_result = tokio::select! {
        biased;
        _ = shutdown.cancelled() => {
            tracing::info!("Authentication cancelled.");
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
    );

    controller.run().await?;

    Ok(())
}
