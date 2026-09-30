use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use wsl_agent::{dns, profile, AgentState, ControlClient, Escalation, Mode};

#[derive(Debug, Parser)]
#[command(name = "wsl", about = "WSL Zero Trust VPN CLI")]
struct Cli {
    /// Control plane base URL. Saved for later commands; changing it signs out.
    #[arg(long, env = "WSL_CONTROL_URL")]
    control_url: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

// How a command that needs root may ask for it.
#[derive(Debug, Clone, Copy, clap::Args)]
struct Privilege {
    /// Never escalate; fail instead if not already root.
    #[arg(long)]
    no_sudo: bool,
    /// Ask the desktop for privilege rather than prompting on a terminal.
    /// This is what the GUI uses: it has no terminal for sudo to prompt on.
    #[arg(long)]
    gui: bool,
}

impl Privilege {
    /// `--no-sudo` wins: a caller that says not to escalate must not then be
    /// escalated a different way.
    fn escalation(self) -> Escalation {
        match (self.no_sudo, self.gui) {
            (true, _) => Escalation::None,
            (false, true) => Escalation::Graphical,
            (false, false) => Escalation::Terminal,
        }
    }
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
    /// Sign out and forget the session.
    Logout,
    /// Show sign-in, posture, and tunnel state.
    Status {
        /// Emit the status as JSON, for another program to read.
        #[arg(long)]
        json: bool,
    },
    /// Bring the tunnel up: from the imported profile, or a new session.
    Connect {
        #[arg(long)]
        network: Option<String>,
        /// Write the WireGuard config but do not bring the interface up.
        #[arg(long)]
        no_tunnel: bool,
        #[command(flatten)]
        privilege: Privilege,
    },
    /// Bring the tunnel down and release the session.
    Disconnect {
        /// Release the session but leave the interface alone.
        #[arg(long)]
        no_tunnel: bool,
        #[command(flatten)]
        privilege: Privilege,
    },
    /// List the networks you may connect to.
    Networks {
        /// Emit the networks as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Agent settings.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Connect with a WireGuard config file instead of signing in.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Local DNS overrides, like /etc/hosts but with wildcards.
    Dns {
        #[command(subcommand)]
        command: DnsCommand,
    },
    Devices,
    Policy,
    Diagnostics,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Show or set the control plane URL.
    ControlUrl { url: Option<String> },
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// Import a wg-quick config. `-` reads it from stdin.
    Import {
        path: PathBuf,
        /// Display name; defaults to the file name.
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show the imported profile.
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Forget the imported profile and go back to signing in.
    Remove,
}

#[derive(Debug, Subcommand)]
enum DnsCommand {
    /// List the overrides.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Point NAME at ADDRESS, replacing any existing entry for NAME.
    /// `*.example.com` covers every subdomain. `0.0.0.0` blocks a name.
    Set {
        name: String,
        address: std::net::IpAddr,
        #[command(flatten)]
        privilege: Privilege,
    },
    /// Remove every entry for NAME.
    Remove {
        name: String,
        #[command(flatten)]
        privilege: Privilege,
    },
    /// Turn overrides on, or route newly added names.
    Apply {
        #[command(flatten)]
        privilege: Privilege,
    },
    /// Turn overrides off.
    Disable {
        #[command(flatten)]
        privilege: Privilege,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Ask the local resolver for NAME.
    Query {
        name: String,
        #[arg(long = "type", default_value = "A")]
        qtype: String,
    },
    /// Run the resolver in the foreground. The launchd job runs this.
    Serve {
        #[arg(long)]
        listen: Option<SocketAddr>,
        #[arg(long)]
        hosts: Option<PathBuf>,
        /// Forward here instead of the nameservers in /etc/resolv.conf.
        #[arg(long)]
        upstream: Vec<SocketAddr>,
    },
    /// Write /etc/resolver files. Run as root by `dns apply`; not for people.
    #[command(hide = true)]
    SyncResolvers {
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = wsl_dns::resolver::RESOLVER_DIR)]
        dir: PathBuf,
        domains: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // These two run without agent state: one as root, where loading it would
    // create a data directory in root's home, and one under launchd.
    if let Commands::Dns { command } = &cli.command {
        match command {
            DnsCommand::SyncResolvers { port, dir, domains } => {
                return sync_resolvers(*port, dir, domains);
            }
            DnsCommand::Serve {
                listen,
                hosts,
                upstream,
            } => return serve(*listen, hosts.clone(), upstream.clone()).await,
            _ => {}
        }
    }

    let mut state = AgentState::load()?;
    if let Some(url) = cli.control_url {
        state.set_control_url(&url)?;
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
        Commands::Status { json } => print_status(&state, json)?,
        Commands::Connect {
            network,
            no_tunnel,
            privilege,
        } => {
            if state.mode() == Mode::Direct {
                if no_tunnel {
                    anyhow::bail!("--no-tunnel has nothing to do for an imported profile");
                }
                let tunnel = profile::connect(&state, privilege.escalation()).await?;
                let name = state
                    .profile
                    .as_ref()
                    .map(|p| p.name.as_str())
                    .unwrap_or("-");
                println!("Connected to {name} on {}", tunnel.interface());
                return Ok(());
            }
            let resp = if no_tunnel {
                let resp = client.connect(&mut state, network.as_deref()).await?;
                println!("Session created; tunnel not started (--no-tunnel).");
                resp
            } else {
                let (resp, tunnel) = client
                    .connect_and_bring_up(&mut state, network.as_deref(), privilege.escalation())
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
            privilege,
        } => {
            if state.mode() == Mode::Direct {
                profile::disconnect(privilege.escalation()).await?;
                println!("Disconnected");
            } else if no_tunnel {
                client.disconnect(&mut state).await?;
                println!("Session released; interface left alone (--no-tunnel).");
            } else {
                client
                    .disconnect_and_tear_down(&mut state, privilege.escalation())
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
        Commands::Config {
            command: ConfigCommand::ControlUrl { url },
        } => {
            if let Some(url) = url {
                state.set_control_url(&url)?;
                state.save()?;
            }
            println!("{}", state.control_url);
        }
        Commands::Profile { command } => profile_command(&mut state, command)?,
        Commands::Dns { command } => dns_command(command).await?,
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
            println!("mode={:?}", state.mode());
            println!("logged_in={}", state.access_token.is_some());
            println!("device_id={:?}", state.device_id);
            println!("session={:?}", state.session.as_ref().map(|s| s.id));
            println!("data_dir={}", AgentState::data_dir()?.display());
            println!("wg_conf={}", AgentState::wg_conf_path()?.display());
            match wsl_agent::tunnel::WgQuick::locate() {
                Ok(wg) => {
                    println!("wg_quick={}", wg.script.display());
                    println!(
                        "wg_quick_bash={}",
                        wg.bash
                            .map(|b| b.display().to_string())
                            .unwrap_or_else(|| "(not needed)".into())
                    );
                }
                Err(e) => println!("wg_quick=(unusable: {})", e.to_string().replace('\n', " ")),
            }
            println!("tunnel={:?}", wsl_agent::tunnel::state());
            let d = dns::status().await;
            println!(
                "dns=enabled:{} running:{} in_sync:{} entries:{}",
                d.enabled,
                d.running,
                d.in_sync,
                d.entries.len()
            );
        }
    }
    Ok(())
}

fn print_status(state: &AgentState, json: bool) -> anyhow::Result<()> {
    let status = state.status(&wsl_agent::tunnel::state());
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }
    println!("{}", status.product);
    println!();
    match status.mode {
        Mode::Direct => println!(
            "Mode:       WireGuard profile ({})",
            status
                .profile
                .as_ref()
                .map(|p| p.name.as_str())
                .unwrap_or("-")
        ),
        Mode::Managed | Mode::SignedOut => {
            println!("Control:    {}", status.control_url);
            println!("User:       {}", status.user.as_deref().unwrap_or("-"));
            println!("Device:     {}", status.device.as_deref().unwrap_or("-"));
            println!("Identity:   {}", status.identity);
        }
    }
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
        for n in &status.networks {
            println!("  {:<16} {}", n.name, n.state);
        }
    }
    if let Some(exp) = &status.session_expires {
        println!();
        println!("Session expires: {exp}");
    }
    if let Some(gw) = &status.gateway {
        println!("Gateway: {gw}");
    }
    println!(
        "Interface: {}",
        status.interface.as_deref().unwrap_or("(down)")
    );
    Ok(())
}

fn profile_command(state: &mut AgentState, command: ProfileCommand) -> anyhow::Result<()> {
    match command {
        ProfileCommand::Import { path, name, json } => {
            let text = if path.as_os_str() == "-" {
                std::io::read_to_string(std::io::stdin()).context("reading stdin")?
            } else {
                std::fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?
            };
            let name = name.unwrap_or_else(|| profile::name_from_path(&path));
            let imported = profile::import(state, &text, &name)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&imported)?);
            } else {
                println!("Imported {} ({})", imported.name, imported.endpoint);
                println!("Connect with `wsl connect`.");
            }
        }
        ProfileCommand::Show { json } => match &state.profile {
            Some(p) if json => println!("{}", serde_json::to_string_pretty(p)?),
            Some(p) => {
                println!("Name:       {}", p.name);
                println!("Endpoint:   {}", p.endpoint);
                println!("Address:    {}", p.address.join(", "));
                println!("AllowedIPs: {}", p.allowed_ips.join(", "));
                println!(
                    "DNS:        {}",
                    if p.dns.is_empty() {
                        "-".into()
                    } else {
                        p.dns.join(", ")
                    }
                );
            }
            None if json => println!("null"),
            None => println!("No profile imported"),
        },
        ProfileCommand::Remove => {
            profile::remove(state)?;
            println!("Profile removed");
        }
    }
    Ok(())
}

async fn dns_command(command: DnsCommand) -> anyhow::Result<()> {
    match command {
        DnsCommand::List { json } => {
            let overrides = dns::load()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&dns::status().await.entries)?
                );
            } else if overrides.is_empty() {
                println!("No overrides. Add one with `wsl dns set <name> <address>`.");
            } else {
                for e in overrides.entries() {
                    println!("{:<40} {}", e.name, e.address);
                }
            }
        }
        DnsCommand::Set {
            name,
            address,
            privilege,
        } => {
            let mut overrides = dns::load()?;
            overrides.set(&name, address).map_err(anyhow::Error::msg)?;
            dns::save(&overrides)?;
            println!("{name} → {address}");
            report_reconcile(dns::reconcile(privilege.escalation()).await?).await;
        }
        DnsCommand::Remove { name, privilege } => {
            let mut overrides = dns::load()?;
            if !overrides.remove(&name) {
                anyhow::bail!("no override for {name}");
            }
            dns::save(&overrides)?;
            println!("Removed {name}");
            report_reconcile(dns::reconcile(privilege.escalation()).await?).await;
        }
        DnsCommand::Apply { privilege } => {
            let s = dns::apply(privilege.escalation()).await?;
            println!(
                "DNS overrides on: {} entr{} on {}",
                s.entries.len(),
                if s.entries.len() == 1 { "y" } else { "ies" },
                s.listen
            );
        }
        DnsCommand::Disable { privilege } => {
            dns::disable(privilege.escalation()).await?;
            println!("DNS overrides off");
        }
        DnsCommand::Status { json } => {
            let s = dns::status().await;
            if json {
                println!("{}", serde_json::to_string_pretty(&s)?);
            } else {
                println!("Enabled:  {}", s.enabled);
                println!("Running:  {} ({})", s.running, s.listen);
                println!("Entries:  {}", s.entries.len());
                println!(
                    "Routing:  {}",
                    if s.in_sync {
                        "up to date"
                    } else {
                        "needs `wsl dns apply`"
                    }
                );
                if let Some(e) = s.error {
                    println!("Error:    {e}");
                }
            }
        }
        DnsCommand::Query { name, qtype } => {
            let t = match qtype.to_ascii_uppercase().as_str() {
                "A" => wsl_dns::wire::TYPE_A,
                "AAAA" => wsl_dns::wire::TYPE_AAAA,
                other => anyhow::bail!("unsupported type {other}; use A or AAAA"),
            };
            let r = wsl_dns::server::query(dns::listen_addr(), &name, t).await?;
            let source = if r.authoritative {
                "override"
            } else {
                "upstream"
            };
            if r.addresses.is_empty() {
                println!("{name}: no {qtype} records (rcode {}, {source})", r.rcode);
            }
            for a in r.addresses {
                println!("{name}\t{a}\t({source})");
            }
        }
        DnsCommand::Serve { .. } | DnsCommand::SyncResolvers { .. } => unreachable!(),
    }
    Ok(())
}

async fn report_reconcile(routed: bool) {
    if routed {
        println!("Routed to the local resolver.");
    } else if !dns::status().await.enabled {
        println!("Overrides are off; turn them on with `wsl dns apply`.");
    }
}

async fn serve(
    listen: Option<SocketAddr>,
    hosts: Option<PathBuf>,
    upstream: Vec<SocketAddr>,
) -> anyhow::Result<()> {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        // launchd sends this to a log file, where colour codes are noise.
        .with(fmt::layer().with_ansi(false))
        .init();
    let hosts = match hosts {
        Some(h) => h,
        None => dns::hosts_path()?,
    };
    let upstreams = if upstream.is_empty() {
        wsl_dns::Upstreams::ResolvConf(PathBuf::from("/etc/resolv.conf"))
    } else {
        wsl_dns::Upstreams::Fixed(upstream)
    };
    let server = wsl_dns::Server::bind(wsl_dns::Config {
        listen: listen.unwrap_or_else(dns::listen_addr),
        hosts,
        upstreams,
        ttl: 30,
    })
    .await?;
    eprintln!("wsl dns: listening on {}", server.local_addr());
    server.run().await
}

/// Runs as root. Everything it is given is re-validated by `resolver::sync`.
fn sync_resolvers(port: u16, dir: &std::path::Path, domains: &[String]) -> anyhow::Result<()> {
    let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let report = wsl_dns::resolver::sync(dir, domains, loopback, port)?;
    for d in &report.skipped {
        eprintln!(
            "warning: {}/{d} belongs to something else; left alone",
            dir.display()
        );
    }
    // mDNSResponder caches negative answers too; without a flush a name that
    // failed a minute ago keeps failing after it is routed.
    if cfg!(target_os = "macos") && dir == std::path::Path::new(wsl_dns::resolver::RESOLVER_DIR) {
        let _ = std::process::Command::new("/usr/bin/dscacheutil")
            .arg("-flushcache")
            .status();
        let _ = std::process::Command::new("/usr/bin/killall")
            .args(["-HUP", "mDNSResponder"])
            .status();
    }
    println!(
        "routed {} domain(s); removed {}",
        report.written.len(),
        report.removed.len()
    );
    Ok(())
}
