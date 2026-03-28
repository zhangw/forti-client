use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "forti-vpn", about = "FortiGate SSL VPN client")]
struct Cli {
    /// VPN gateway hostname or IP
    #[arg(short, long)]
    server: String,

    /// VPN gateway port
    #[arg(short, long, default_value = "443")]
    port: u16,

    /// Username
    #[arg(short, long)]
    username: String,

    /// Password (if omitted, will prompt)
    #[arg(short = 'P', long)]
    password: Option<String>,

    /// Realm (optional)
    #[arg(long)]
    realm: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    tracing::info!("Connecting to {}:{}", cli.server, cli.port);

    // Phase 1: auth → tunnel → PPP negotiation
    // Implementation follows in subsequent tasks

    Ok(())
}
