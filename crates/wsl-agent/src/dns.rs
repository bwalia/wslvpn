//! DNS overrides: keeping the local resolver running and routed to.
//!
//! Two pieces have to be in place for an override to take effect, and they
//! need different privileges, so they are managed separately:
//!
//! * The resolver itself (`wsl dns serve`) runs as the user, as a launchd
//!   agent. launchd restarts it if it dies and starts it at login, so a
//!   reboot does not leave `/etc/resolver` pointing at nothing.
//! * The `/etc/resolver` files that route each overridden domain to it need
//!   root, and are written through the same privileged path as `wg-quick` —
//!   one password prompt — only when the set of routed domains changes.
//!   Changing the address an existing name points to needs neither: the
//!   resolver re-reads its table on the next query.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use wsl_dns::resolver::{self, RESOLVER_DIR};
use wsl_dns::Overrides;

use crate::state::AgentState;
use crate::tunnel::{self, Escalation, Step};

pub const LABEL: &str = "io.wsl.zerotrust.dns";

/// Environment override for the resolver's port.
pub const PORT_ENV: &str = "WSL_DNS_PORT";

pub fn listen_addr() -> SocketAddr {
    let port = std::env::var(PORT_ENV)
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(wsl_dns::DEFAULT_PORT);
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

pub fn hosts_path() -> Result<PathBuf> {
    Ok(AgentState::data_dir()?.join("hosts"))
}

pub fn log_path() -> Result<PathBuf> {
    Ok(AgentState::data_dir()?.join("dns.log"))
}

pub fn load() -> Result<Overrides> {
    let path = hosts_path()?;
    match std::fs::read_to_string(&path) {
        Ok(text) => Overrides::parse(&text).with_context(|| format!("reading {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Overrides::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write the table atomically: the resolver re-reads on change, and must
/// never see half a file.
pub fn save(overrides: &Overrides) -> Result<()> {
    let path = hosts_path()?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, overrides.render())
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// The launchd job that keeps the resolver running.
pub fn render_plist(program: &Path, hosts: &Path, listen: SocketAddr, log: &Path) -> String {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let args = [
        program.to_string_lossy().into_owned(),
        "dns".into(),
        "serve".into(),
        "--listen".into(),
        listen.to_string(),
        "--hosts".into(),
        hosts.to_string_lossy().into_owned(),
    ];
    let args: String = args
        .iter()
        .map(|a| format!("    <string>{}</string>\n", esc(a)))
        .collect();
    let log = esc(&log.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
  <key>StandardOutPath</key>
  <string>{log}</string>
</dict>
</plist>
"#
    )
}

pub fn plist_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("no home directory")?;
    Ok(home
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

fn supported() -> bool {
    cfg!(target_os = "macos")
}

fn unsupported() -> anyhow::Error {
    anyhow::anyhow!(
        "DNS overrides are routed through /etc/resolver, which only macOS has. \
         On this platform, run `wsl dns serve` under your own supervisor and \
         point your resolver at {}.",
        listen_addr()
    )
}

fn gui_domain() -> String {
    // SAFETY: getuid cannot fail.
    format!("gui/{}", unsafe { libc::getuid() })
}

async fn launchctl(args: &[&str]) -> Result<std::process::Output> {
    tokio::process::Command::new("/bin/launchctl")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .context("running launchctl")
}

/// Install (or refresh) and start the resolver's launchd job, then wait until
/// it answers. Idempotent: an unchanged, running job is left alone.
pub async fn start() -> Result<()> {
    if !supported() {
        return Err(unsupported());
    }
    let program = std::env::current_exe().context("locating the wsl binary")?;
    let plist = render_plist(&program, &hosts_path()?, listen_addr(), &log_path()?);
    let path = plist_path()?;
    let changed = std::fs::read_to_string(&path)
        .map(|t| t != plist)
        .unwrap_or(true);
    if !changed && wsl_dns::server::probe(listen_addr()).await {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, &plist).with_context(|| format!("writing {}", path.display()))?;

    let target = format!("{}/{LABEL}", gui_domain());
    // bootout of a job that is not loaded fails; that is fine.
    let _ = launchctl(&["bootout", &target]).await;
    let out = launchctl(&["bootstrap", &gui_domain(), &path.to_string_lossy()]).await?;
    if !out.status.success() {
        bail!(
            "launchctl could not start the DNS resolver: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    for _ in 0..30 {
        if wsl_dns::server::probe(listen_addr()).await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!(
        "the DNS resolver was started but is not answering on {}. See {}",
        listen_addr(),
        log_path()?.display()
    )
}

/// Stop the resolver and remove its job.
pub async fn stop() -> Result<()> {
    if !supported() {
        return Ok(());
    }
    let _ = launchctl(&["bootout", &format!("{}/{LABEL}", gui_domain())]).await;
    let path = plist_path()?;
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(())
}

/// The privileged step that routes `domains` to the resolver.
pub fn sync_step(program: &Path, domains: &[String], listen: SocketAddr) -> Step {
    let mut args = vec![
        "dns".to_string(),
        "sync-resolvers".to_string(),
        "--port".to_string(),
        listen.port().to_string(),
    ];
    args.push("--".to_string());
    args.extend(domains.iter().cloned());
    Step::new(program, args)
}

#[derive(Debug, Clone, Serialize)]
pub struct EntryStatus {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsStatus {
    /// Whether this platform can route overrides at all.
    pub supported: bool,
    /// The user turned overrides on (the launchd job is installed).
    pub enabled: bool,
    /// The resolver answered a probe just now.
    pub running: bool,
    pub listen: String,
    pub entries: Vec<EntryStatus>,
    /// Domains that should be routed to the resolver.
    pub wanted: Vec<String>,
    /// Domains `/etc/resolver` currently routes to it.
    pub routed: Vec<String>,
    /// Routing matches the table. When false, `wsl dns apply` is needed —
    /// which is the one step that asks for a password.
    pub in_sync: bool,
    /// Set when the table could not be read.
    pub error: Option<String>,
}

pub async fn status() -> DnsStatus {
    let (entries, wanted, error) = match load() {
        Ok(o) => (
            o.entries()
                .into_iter()
                .map(|e| EntryStatus {
                    name: e.name,
                    address: e.address.to_string(),
                })
                .collect(),
            o.routed_domains(),
            None,
        ),
        Err(e) => (Vec::new(), Vec::new(), Some(format!("{e:#}"))),
    };
    let routed = resolver::routed(Path::new(RESOLVER_DIR));
    let enabled = plist_path().map(|p| p.exists()).unwrap_or(false);
    DnsStatus {
        supported: supported(),
        enabled,
        running: wsl_dns::server::probe(listen_addr()).await,
        listen: listen_addr().to_string(),
        in_sync: if enabled {
            routed == wanted
        } else {
            routed.is_empty()
        },
        entries,
        wanted,
        routed,
        error,
    }
}

/// Turn overrides on, or bring them up to date: start the resolver, and route
/// the current table's domains to it if they are not already.
pub async fn apply(escalation: Escalation) -> Result<DnsStatus> {
    if !supported() {
        return Err(unsupported());
    }
    let overrides = load()?;
    start().await?;
    let wanted = overrides.routed_domains();
    if resolver::routed(Path::new(RESOLVER_DIR)) != wanted {
        route(&wanted, escalation).await?;
    }
    Ok(status().await)
}

/// Turn overrides off: unroute everything, then stop the resolver. In that
/// order, so no domain is ever routed to a resolver that is not there.
pub async fn disable(escalation: Escalation) -> Result<DnsStatus> {
    if supported() && !resolver::routed(Path::new(RESOLVER_DIR)).is_empty() {
        route(&[], escalation).await?;
    }
    stop().await?;
    Ok(status().await)
}

async fn route(domains: &[String], escalation: Escalation) -> Result<()> {
    let program = std::env::current_exe().context("locating the wsl binary")?;
    let step = sync_step(&program, domains, listen_addr());
    tunnel::run_privileged(
        &[step],
        "/usr/bin:/bin:/usr/sbin:/sbin",
        escalation,
        "Re-run as `sudo wsl dns apply`.",
    )
    .await
}

/// After an edit: if overrides are on and the edit changed which domains need
/// routing, route them now. Returns whether a privileged step ran.
pub async fn reconcile(escalation: Escalation) -> Result<bool> {
    if !supported() || !plist_path()?.exists() {
        return Ok(false);
    }
    let wanted = load()?.routed_domains();
    if resolver::routed(Path::new(RESOLVER_DIR)) == wanted {
        return Ok(false);
    }
    start().await?;
    route(&wanted, escalation).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launchd_job_runs_the_resolver_on_loopback_and_keeps_it_alive() {
        let plist = render_plist(
            Path::new("/Applications/WSL Zero Trust.app/Contents/MacOS/wsl"),
            Path::new("/Users/a/Library/Application Support/wsl-zerotrust/hosts"),
            "127.0.0.1:15353".parse().unwrap(),
            Path::new("/tmp/dns.log"),
        );
        assert!(plist.contains("<string>io.wsl.zerotrust.dns</string>"));
        assert!(plist.contains(
            "    <string>/Applications/WSL Zero Trust.app/Contents/MacOS/wsl</string>\n    <string>dns</string>\n    <string>serve</string>\n    <string>--listen</string>\n    <string>127.0.0.1:15353</string>"
        ));
        assert!(plist.contains("<key>KeepAlive</key>\n  <true/>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n  <true/>"));
    }

    #[test]
    fn plist_strings_are_xml_escaped() {
        let plist = render_plist(
            Path::new("/Users/a&b/<wsl>"),
            Path::new("/h"),
            "127.0.0.1:1".parse().unwrap(),
            Path::new("/l"),
        );
        assert!(plist.contains("<string>/Users/a&amp;b/&lt;wsl&gt;</string>"));
    }

    /// `--` so a domain can never be read as a flag by the root-run command.
    #[test]
    fn the_sync_step_passes_domains_after_a_separator() {
        let step = sync_step(
            Path::new("/usr/local/bin/wsl"),
            &["a.example.com".into()],
            "127.0.0.1:15353".parse().unwrap(),
        );
        assert_eq!(step.program, PathBuf::from("/usr/local/bin/wsl"));
        assert_eq!(
            step.args,
            vec![
                "dns",
                "sync-resolvers",
                "--port",
                "15353",
                "--",
                "a.example.com"
            ]
        );
    }

    #[test]
    fn the_default_listen_address_is_loopback() {
        if std::env::var_os(PORT_ENV).is_none() {
            assert_eq!(
                listen_addr(),
                "127.0.0.1:15353".parse::<SocketAddr>().unwrap()
            );
        }
        assert!(listen_addr().ip().is_loopback());
    }
}
