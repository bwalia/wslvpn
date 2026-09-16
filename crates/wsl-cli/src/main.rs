use clap::{Parser, Subcommand};
use wsl_agent::{AgentState, ControlClient, Escalation};

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
    /// Sign in through your identity provider.
    Login {
        /// Skip SSO and use the local development login instead. The control
        /// plane only serves it when bound to loopback.
        #[arg(long)]
        dev: bool,
        /// Email for --dev. Ignored by SSO, which gets identity from the
        /// provider.
        #[arg(long, default_value = "alice@example.com")]
        email: String,
        /// Print the sign-in URL but do not open a browser.
        #[arg(long)]
        no_browser: bool,
    },
    Logout,
    Status {
        /// Emit the status as JSON, for another program to read.
        #[arg(long)]
        json: bool,
    },
    Connect {
        #[arg(long)]
        network: Option<String>,
        /// Write the WireGuard config but do not bring the interface up.
        #[arg(long)]
        no_tunnel: bool,
        /// Never escalate; fail instead if not already root.
        #[arg(long)]
        no_sudo: bool,
        /// Ask the desktop for privilege rather than prompting on a terminal.
        /// This is what the GUI uses: it has no terminal for sudo to prompt on.
        #[arg(long)]
        gui: bool,
    },
    Disconnect {
        /// Release the session but leave the interface alone.
        #[arg(long)]
        no_tunnel: bool,
        /// Never escalate; fail instead if not already root.
        #[arg(long)]
        no_sudo: bool,
        /// Ask the desktop for privilege rather than prompting on a terminal.
        #[arg(long)]
        gui: bool,
    },
    Networks {
        /// Emit the networks as JSON.
        #[arg(long)]
        json: bool,
    },
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
        Commands::Login {
            dev,
            email,
            no_browser,
        } => {
            if dev {
                client.dev_login(&mut state, &email).await?;
            } else {
                client.login(&mut state, !no_browser).await?;
            }
            client.ensure_device(&mut state).await?;
            println!(
                "Signed in as {}",
                state.email.as_deref().unwrap_or("(unknown)")
            );
            println!(
                "Device registered: {}",
                state.device_name.as_deref().unwrap_or("?")
            );
        }
        Commands::Logout => {
            client.logout(&mut state)?;
            println!("Signed out");
        }
        Commands::Status { json } => {
            let status = state.status(&wsl_agent::tunnel::state());
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
                return Ok(());
            }
            println!("{}", status.product);
            println!();
            println!("User:       {}", status.user.as_deref().unwrap_or("-"));
            println!("Device:     {}", status.device.as_deref().unwrap_or("-"));
            println!("Identity:   {}", status.identity);
            println!("Posture:    {}", status.posture);
            for signal in &status.posture_signals {
                let mark = match signal.result {
                    wsl_agent::PostureResult::Pass => "ok",
                    wsl_agent::PostureResult::Fail => "FAIL",
                    wsl_agent::PostureResult::Unknown => "?",
                    wsl_agent::PostureResult::Unsupported => "n/a",
                };
                println!(
                    "  {:<18} {:<5} {}",
                    signal.name,
                    mark,
                    signal.detail.as_deref().unwrap_or("")
                );
            }
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
            gui,
        } => {
            let resp = if no_tunnel {
                let resp = client.connect(&mut state, network.as_deref()).await?;
                println!("Session created; tunnel not started (--no-tunnel).");
                resp
            } else {
                let (resp, tunnel) = client
                    .connect_and_bring_up(&mut state, network.as_deref(), escalation(no_sudo, gui))
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
        Commands::Disconnect {
            no_tunnel,
            no_sudo,
            gui,
        } => {
            if no_tunnel {
                client.disconnect(&mut state).await?;
                println!("Session released; interface left alone (--no-tunnel).");
            } else {
                client
                    .disconnect_and_tear_down(&mut state, escalation(no_sudo, gui))
                    .await?;
                println!("Disconnected");
            }
        }
        Commands::Networks { json } => {
            let networks = client.list_networks(&state).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&networks)?);
            } else {
                for n in networks {
                    println!("{}  {}", n.name, n.cidr);
                }
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

/// Translate the command-line flags into how the agent may ask for root.
///
/// `--no-sudo` wins: a caller that says not to escalate must not then be
/// escalated a different way.
fn escalation(no_sudo: bool, gui: bool) -> Escalation {
    match (no_sudo, gui) {
        (true, _) => Escalation::None,
        (false, true) => Escalation::Graphical,
        (false, false) => Escalation::Terminal,
    }
}
