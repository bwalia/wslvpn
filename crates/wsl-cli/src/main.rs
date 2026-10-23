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
        /// Email for --dev and --opsapi. Ignored by browser sign-in, which
        /// gets identity from the provider.
        #[arg(long)]
        email: Option<String>,
        /// Print the sign-in URL but do not open a browser.
        #[arg(long)]
        no_browser: bool,
        /// Sign in with an OpsAPI account (email and password) instead of the
        /// browser. The password goes to OpsAPI, not to the control plane.
        #[arg(long, conflicts_with = "dev")]
        opsapi: bool,
        /// Finish an OpsAPI sign-in with the code OpsAPI emailed.
        #[arg(long, requires = "opsapi")]
        code: bool,
        /// Read secrets from stdin rather than prompting: the password, or
        /// with --code the challenge and then the code, one per line. Secrets
        /// never go on the command line, where `ps` would show them.
        #[arg(long)]
        stdin: bool,
        /// Report the outcome as JSON (with --opsapi).
        #[arg(long)]
        json: bool,
    },
    /// Show which ways of signing in the control plane offers.
    SignInMethods {
        #[arg(long)]
        json: bool,
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
        /// Connect with this imported profile, making it the active one.
        #[arg(long, conflicts_with = "network")]
        profile: Option<String>,
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
    /// List imported profiles; `*` marks the one Connect uses.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Make NAME the profile Connect uses, or `--none` to use the control
    /// plane instead.
    Use {
        name: Option<String>,
        #[arg(long, conflicts_with = "name")]
        none: bool,
    },
    /// Show a profile (the active one by default).
    Show {
        name: Option<String>,
        #[arg(long)]
        json: bool,
        /// Print the config file itself, private key included, for editing.
        #[arg(long, conflicts_with = "json")]
        config: bool,
    },
    /// Delete a profile (the active one by default).
    Remove { name: Option<String> },
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
            opsapi: true,
            email,
            code,
            stdin,
            json,
            ..
        } => {
            let signed_in = if code {
                let challenge = read_secret_line(stdin, "Challenge: ")?;
                let code = read_secret_line(stdin, "Code from the email: ")?;
                client
                    .opsapi_verify_code(&mut state, &challenge, &code)
                    .await?;
                true
            } else {
                let email = match email {
                    Some(e) => e,
                    None if !stdin => prompt_line("Email: ")?,
                    None => anyhow::bail!("--email is required with --stdin"),
                };
                let password = read_password(stdin)?;
                match client.opsapi_login(&mut state, &email, &password).await? {
                    None => true,
                    Some(step) if json => {
                        // The app holds the challenge and calls back with the code.
                        println!("{}", serde_json::to_string(&step)?);
                        false
                    }
                    Some(wsl_agent::opsapi::Step::CodeRequired { challenge, email }) if !stdin => {
                        eprintln!("A sign-in code was sent to {email}.");
                        let code = prompt_line("Code: ")?;
                        client
                            .opsapi_verify_code(&mut state, &challenge, &code)
                            .await?;
                        true
                    }
                    Some(_) => anyhow::bail!(
                        "OpsAPI sent a sign-in code; run again with --json to receive the challenge"
                    ),
                }
            };
            if signed_in {
                client.ensure_device(&mut state).await?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "status": "signed_in",
                            "email": state.email,
                            "device": state.device_name,
                        })
                    );
                } else {
                    println!(
                        "Signed in as {}",
                        state.email.as_deref().unwrap_or("(unknown)")
                    );
                    println!(
                        "Device registered: {}",
                        state.device_name.as_deref().unwrap_or("?")
                    );
                }
            }
        }
        Commands::SignInMethods { json } => {
            let methods = client.sign_in_methods(&state).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&methods)?);
            } else {
                println!(
                    "Browser sign-in: {}",
                    if methods.oidc { "yes" } else { "no" }
                );
                match methods.opsapi {
                    Some(o) => println!(
                        "OpsAPI sign-in:  yes ({}, workspace {})",
                        o.url, o.namespace
                    ),
                    None => println!("OpsAPI sign-in:  no"),
                }
            }
        }
        Commands::Login {
            dev,
            email,
            no_browser,
            ..
        } => {
            if dev {
                let email = email.unwrap_or_else(|| "alice@example.com".into());
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
            profile: chosen,
            no_tunnel,
            privilege,
        } => {
            if let Some(name) = chosen.as_deref() {
                profile::select(&mut state, name)?;
            }
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

/// One line from stdin, without its newline.
fn stdin_line() -> anyhow::Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading stdin")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    Ok(stdin_line()?.trim().to_string())
}

fn read_secret_line(from_stdin: bool, prompt: &str) -> anyhow::Result<String> {
    let line = if from_stdin {
        stdin_line()?
    } else {
        prompt_line(prompt)?
    };
    if line.trim().is_empty() {
        anyhow::bail!("{} was empty", prompt.trim_end_matches([':', ' ']));
    }
    Ok(line.trim().to_string())
}

/// The password, from stdin or a terminal prompt that does not echo it.
fn read_password(from_stdin: bool) -> anyhow::Result<String> {
    use std::io::IsTerminal;
    if from_stdin || !std::io::stdin().is_terminal() {
        let line = stdin_line()?;
        if line.is_empty() {
            anyhow::bail!("no password on stdin");
        }
        return Ok(line);
    }
    let stty = |arg: &str| {
        std::process::Command::new("stty")
            .arg(arg)
            .stdin(std::process::Stdio::inherit())
            .status()
    };
    eprint!("Password: ");
    let _ = stty("-echo");
    let line = stdin_line();
    let _ = stty("echo");
    eprintln!();
    let line = line?;
    if line.is_empty() {
        anyhow::bail!("no password entered");
    }
    Ok(line)
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
    if !status.other_wireguard.is_empty() {
        println!();
        println!(
            "Warning: the WireGuard app also has {} connected; two tunnels \
             competing for the same routes can leave this one carrying no traffic.",
            status.other_wireguard.join(", ")
        );
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
        ProfileCommand::List { json } => {
            let all = profile::list(state)?;
            state.save()?;
            let active = state.profile.as_ref().map(|p| p.name.clone());
            if json {
                println!("{}", serde_json::to_string_pretty(&all)?);
            } else if all.is_empty() {
                println!("No profiles imported");
            } else {
                for p in &all {
                    let mark = if Some(&p.name) == active.as_ref() {
                        "*"
                    } else {
                        " "
                    };
                    println!("{mark} {:<24} {}", p.name, p.endpoint);
                }
            }
        }
        ProfileCommand::Use { name, none } => {
            if none {
                state.profile = None;
                state.save()?;
                println!("Using the control plane; profiles are kept");
            } else {
                let name = name.context("name a profile, or pass --none")?;
                let p = profile::select(state, &name)?;
                println!("Connect now uses {}", p.name);
            }
        }
        ProfileCommand::Show { name, json, config } => {
            let name = name.or_else(|| state.profile.as_ref().map(|p| p.name.clone()));
            let Some(name) = name else {
                if json {
                    println!("null");
                } else {
                    println!("No profile imported");
                }
                return Ok(());
            };
            if config {
                print!("{}", profile::config_text(state, &name)?);
                return Ok(());
            }
            let all = profile::list(state)?;
            let p = all
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(&name))
                .with_context(|| format!("no profile named `{name}`"))?;
            if json {
                println!("{}", serde_json::to_string_pretty(p)?);
            } else {
                println!("Name:       {}", p.name);
                println!("Public key: {}", p.public_key.as_deref().unwrap_or("-"));
                println!("Address:    {}", p.address.join(", "));
                println!(
                    "DNS:        {}",
                    if p.dns.is_empty() {
                        "-".into()
                    } else {
                        p.dns.join(", ")
                    }
                );
                for peer in &p.peers {
                    println!("Peer:       {}", peer.public_key);
                    println!("  Endpoint:   {}", peer.endpoint.as_deref().unwrap_or("-"));
                    println!("  AllowedIPs: {}", peer.allowed_ips.join(", "));
                }
            }
        }
        ProfileCommand::Remove { name } => {
            profile::remove(state, name.as_deref())?;
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
