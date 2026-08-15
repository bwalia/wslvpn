use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use wsl_agent::{AgentState, ControlClient};

#[derive(Debug, Parser)]
#[command(name = "wsl-agent", about = "WSL Zero Trust VPN agent daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Print agent status JSON
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer())
        .init();

    let cli = Cli::parse();
    let state = AgentState::load()?;
    match cli.command.unwrap_or(Commands::Status) {
        Commands::Status => {
            println!("{}", serde_json::to_string_pretty(&state.status())?);
        }
    }
    let _ = ControlClient::new();
    Ok(())
}
