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
        /// Write the WireGuard config but do not bring the interface up.
        #[arg(long)]
        no_tunnel: bool,
        /// Never escalate through sudo; fail instead if not already root.
        #[arg(long)]
        no_sudo: bool,
    },
    Disconnect {
        /// Release the session but leave the interface alone.
        #[arg(long)]
        no_tunnel: bool,
        /// Never escalate through sudo; fail instead if not already root.
        #[arg(long)]
        no_sudo: bool,
    },
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
            let status = state.status(&wsl_agent::tunnel::state());
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
            println!(
                "Interface: {}",
                status.interface.as_deref().unwrap_or("(down)")
            );
        }
        Commands::Connect {
            network,
            no_tunnel,
            no_sudo,
        } => {
            let resp = if no_tunnel {
                let resp = client.connect(&mut state, network.as_deref()).await?;
                println!("Session created; tunnel not started (--no-tunnel).");
                resp
            } else {
                let (resp, tunnel) = client
                    .connect_and_bring_up(&mut state, network.as_deref(), !no_sudo)
                    .await?;
                println!("Connected on {}", tunnel.interface());
                resp
            };
            println!("Assigned IP: {}", resp.session.assigned_ip);
            println!(
                "Policy: {} v{}",
                resp.decision.policy_name.as_deref().unwrap_or("-"),
                resp.decision.policy_version.unwrap_or(0)
            );
            println!(
                "WireGuard config: {}",
                AgentState::wg_conf_path()?.display()
            );
        }
        Commands::Disconnect { no_tunnel, no_sudo } => {
            if no_tunnel {
                client.disconnect(&mut state).await?;
                println!("Session released; interface left alone (--no-tunnel).");
            } else {
                client
                    .disconnect_and_tear_down(&mut state, !no_sudo)
                    .await?;
                println!("Disconnected");
            }
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
            println!("wg_conf={}", AgentState::wg_conf_path()?.display());
            println!(
                "wg_quick={}",
                wsl_agent::tunnel::find_wg_quick()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(not found)".into())
            );
            println!("tunnel={:?}", wsl_agent::tunnel::state());
        }
    }
    Ok(())
}
