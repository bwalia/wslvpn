use clap::{Parser, Subcommand};
use wsl_agent::{AgentState, ControlClient};

#[derive(Debug, Parser)]
#[command(name = "wsl", about = "WSL Zero Trust VPN CLI")]
struct Cli {
    /// Control plane base URL
    #[arg(long, env = "WSL_CONTROL_URL")]
    control_url: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Sign in (local/dev OIDC helper)
    Login {
        #[arg(long, default_value = "alice@example.com")]
        email: String,
    },
    Logout,
    Status,
    Connect {
        #[arg(long)]
        network: Option<String>,
    },
    Disconnect,
    Networks,
    Devices,
    Policy,
    Diagnostics,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut state = AgentState::load()?;
    if let Some(url) = cli.control_url {
        state.control_url = url;
        state.save()?;
    }
    let client = ControlClient::new();

    match cli.command {
        Commands::Login { email } => {
            client.dev_login(&mut state, &email).await?;
            client.ensure_device(&mut state).await?;
            println!("Signed in as {email}");
            println!(
                "Device registered: {}",
                state.device_name.as_deref().unwrap_or("?")
            );
        }
        Commands::Logout => {
            client.logout(&mut state)?;
            println!("Signed out");
        }
        Commands::Status => {
            let status = state.status();
            println!("{}", status.product);
            println!();
            println!("User:       {}", status.user.as_deref().unwrap_or("-"));
            println!("Device:     {}", status.device.as_deref().unwrap_or("-"));
            println!("Identity:   {}", status.identity);
            println!("Posture:    {}", status.posture);
            println!();
            println!("Networks:");
            if status.networks.is_empty() {
                println!("  (none)");
            } else {
                for n in status.networks {
                    println!("  {:<16} {}", n.name, n.state);
                }
            }
            if let Some(exp) = status.session_expires {
                println!();
                println!("Session expires: {exp}");
            }
            if let Some(gw) = status.gateway {
                println!("Gateway: {gw}");
            }
        }
        Commands::Connect { network } => {
            let resp = client.connect(&mut state, network.as_deref()).await?;
            println!("Connected");
            println!("Assigned IP: {}", resp.session.assigned_ip);
            println!(
                "Policy: {} v{}",
                resp.decision.policy_name.as_deref().unwrap_or("-"),
                resp.decision.policy_version.unwrap_or(0)
            );
            println!(
                "WireGuard config: {}/wsl.conf",
                AgentState::data_dir()?.display()
            );
        }
        Commands::Disconnect => {
            client.disconnect(&mut state).await?;
            println!("Disconnected");
        }
        Commands::Networks => {
            for n in client.list_networks(&state).await? {
                println!("{}  {}", n.name, n.cidr);
            }
        }
        Commands::Devices => {
            println!(
                "{}  {}  {}",
                state.device_id.map(|i| i.to_string()).unwrap_or("-".into()),
                state.device_name.as_deref().unwrap_or("-"),
                state.wireguard_public_key.as_deref().unwrap_or("-")
            );
        }
        Commands::Policy => {
            if let Some(s) = &state.session {
                println!(
                    "policy_id={:?} version={:?} expires={}",
                    s.policy_id, s.policy_version, s.expires_at
                );
            } else {
                println!("No active session");
            }
        }
        Commands::Diagnostics => {
            println!("control_url={}", state.control_url);
            println!("logged_in={}", state.access_token.is_some());
            println!("device_id={:?}", state.device_id);
            println!("session={:?}", state.session.as_ref().map(|s| s.id));
            println!("data_dir={}", AgentState::data_dir()?.display());
        }
    }
    Ok(())
}
