use clap::Parser;
use tracing_subscriber::EnvFilter;
use forti_client::auth::AuthClient;
use forti_client::reconnect::{AuthParams, ReconnectController};
use std::io::Write;

#[derive(Parser, Debug)]
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let auth_client = AuthClient::new(&cli.server, cli.port)?;

    // Prompt for password early (before we need sudo/root)
    let password = if !cli.saml {
        match cli.password.clone() {
            Some(p) => Some(p),
            None if cli.username.is_some() => {
                eprint!("Password: ");
                std::io::stderr().flush()?;
                let mut p = String::new();
                std::io::stdin().read_line(&mut p)?;
                Some(p.trim().to_string())
            }
            None => None,
        }
    } else {
        None
    };

    let auth_result = if cli.saml {
        tracing::info!("Starting SAML authentication to {}:{}", cli.server, cli.port);
        auth_client.login_saml().await?
    } else {
        let username = cli.username.as_deref()
            .ok_or_else(|| anyhow::anyhow!("--username is required for credential auth (use --saml for SSO)"))?;
        let pw = password.as_deref()
            .ok_or_else(|| anyhow::anyhow!("password required"))?;
        tracing::info!("Authenticating to {}:{}", cli.server, cli.port);
        auth_client.login(username, pw, cli.realm.as_deref()).await?
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
    };

    let mut controller = ReconnectController::new(
        auth_params,
        auth_result.svpn_cookie,
        auth_result.tunnel_config,
    );

    controller.run().await?;

    Ok(())
}
