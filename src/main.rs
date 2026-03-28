use clap::Parser;
use tracing_subscriber::EnvFilter;
use forti_client::auth::AuthClient;
use forti_client::tunnel::TlsTunnel;
use forti_client::ppp::PppEngine;
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

    let auth_result = if cli.saml {
        // SAML/SSO authentication
        tracing::info!("Starting SAML authentication to {}:{}", cli.server, cli.port);
        auth_client.login_saml().await?
    } else {
        // Credential authentication
        let username = cli.username
            .ok_or_else(|| anyhow::anyhow!("--username is required for credential auth (use --saml for SSO)"))?;

        let password = match cli.password {
            Some(p) => p,
            None => {
                eprint!("Password: ");
                std::io::stderr().flush()?;
                let mut p = String::new();
                std::io::stdin().read_line(&mut p)?;
                p.trim().to_string()
            }
        };

        tracing::info!("Authenticating to {}:{}", cli.server, cli.port);
        auth_client
            .login(&username, &password, cli.realm.as_deref())
            .await?
    };

    tracing::info!(
        "Authenticated. Tunnel config: IP={}, DNS={:?}, {} routes",
        auth_result.tunnel_config.ip_address,
        auth_result.tunnel_config.dns_servers,
        auth_result.tunnel_config.routes.len(),
    );

    // Step 2: Establish TLS tunnel
    tracing::info!("Establishing TLS tunnel");
    let mut tunnel = TlsTunnel::connect(
        &cli.server,
        cli.port,
        &auth_result.svpn_cookie,
        auth_client.tls_config(),
    )
    .await?;

    // Step 3: PPP negotiation
    tracing::info!("Running PPP negotiation");
    let mut ppp = PppEngine::new(1500);
    let ipcp_config = ppp.negotiate(&mut tunnel).await?;

    tracing::info!("PPP negotiation complete!");
    tracing::info!("  Assigned IP:    {}", ipcp_config.ip_address);
    if let Some(dns) = ipcp_config.primary_dns {
        tracing::info!("  Primary DNS:    {}", dns);
    }
    if let Some(dns) = ipcp_config.secondary_dns {
        tracing::info!("  Secondary DNS:  {}", dns);
    }

    tracing::info!("Phase 1 feasibility validated — tunnel is up and negotiated.");
    tracing::info!("Press Ctrl+C to disconnect.");

    // Keep the tunnel alive with LCP Echo
    tokio::signal::ctrl_c().await?;
    tracing::info!("Disconnecting...");

    Ok(())
}
