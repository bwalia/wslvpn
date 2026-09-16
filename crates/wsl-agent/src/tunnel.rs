//! Bringing the WireGuard interface up and down.
//!
//! Until now `connect` wrote a config file and printed "Connected". Nothing
//! created an interface, so the agent reported a tunnel that did not exist.
//! This module owns the other half: handing the rendered config to `wg-quick`,
//! and reading back from the operating system whether an interface is actually
//! there — never from what the agent believes it did.
//!
//! `wg-quick` needs root. The agent does not run as root and the desktop GUI
//! must not, so escalation is explicit and visible: either the caller is
//! already root, or the command is re-run through `sudo`, which may prompt on
//! a terminal. When neither is possible the error says exactly what to run
//! instead of failing somewhere deep inside a shell script.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// The interface name. `wg-quick` derives it from the config file's basename,
/// so the config has to be written as `<INTERFACE>.conf` for the two to agree.
pub const INTERFACE: &str = "wsl";

/// Environment override for the `wg-quick` binary, so a test or a packaged
/// build can point at a specific one instead of searching `PATH`.
pub const WG_QUICK_ENV: &str = "WSL_WG_QUICK";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Up,
    Down,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Action::Up => "up",
            Action::Down => "down",
        }
    }
}

/// How the privilege `wg-quick` needs is going to be obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Privilege {
    /// Already root — run `wg-quick` directly.
    Direct,
    /// Not root; re-run through `sudo`, which may prompt.
    Sudo,
    /// Not root and no terminal to prompt on — ask the desktop for the
    /// privilege instead, through the operating system's own dialog. Carries
    /// the binary that will do the asking.
    Graphical { escalator: PathBuf },
    /// Not root and no way to escalate.
    Unavailable,
}

/// What the operating system says about the interface, as opposed to what the
/// agent remembers doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    /// An interface is present. On macOS the name is the `utun` device
    /// `wg-quick` picked, which is not the name in the config.
    Up {
        interface: String,
    },
    Down,
}

impl TunnelState {
    pub fn is_up(&self) -> bool {
        matches!(self, TunnelState::Up { .. })
    }

    /// The device name to show a user, or `-` when there is nothing up.
    pub fn interface(&self) -> &str {
        match self {
            TunnelState::Up { interface } => interface,
            TunnelState::Down => "-",
        }
    }
}

/// Locate `wg-quick`, preferring the environment override.
///
/// Homebrew on Apple silicon installs to `/opt/homebrew/bin`, which is not on
/// `PATH` for a GUI-launched process, so the usual locations are searched too.
pub fn find_wg_quick() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os(WG_QUICK_ENV) {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    search_path("wg-quick").or_else(|| {
        [
            "/opt/homebrew/bin/wg-quick",
            "/usr/local/bin/wg-quick",
            "/usr/bin/wg-quick",
        ]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
    })
}

fn search_path(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

fn is_root() -> bool {
    // SAFETY: geteuid is always safe to call and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// What a caller is able to do about not being root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Escalation {
    /// There is a terminal: `sudo` can prompt on it.
    #[default]
    Terminal,
    /// There is no terminal but there is a desktop session: ask the operating
    /// system to put up its own authorization dialog.
    Graphical,
    /// Neither. Fail rather than hang on a prompt nobody can answer.
    None,
}

/// Decide how to run `wg-quick`.
pub fn detect_privilege(escalation: Escalation) -> Privilege {
    if is_root() {
        return Privilege::Direct;
    }
    match escalation {
        Escalation::Terminal if search_path("sudo").is_some() => Privilege::Sudo,
        Escalation::Graphical => match graphical_escalator() {
            Some(escalator) => Privilege::Graphical { escalator },
            None => Privilege::Unavailable,
        },
        _ => Privilege::Unavailable,
    }
}

/// The binary that asks the desktop for privilege.
///
/// macOS has no `pkexec`; the equivalent is AppleScript's `with administrator
/// privileges`, which routes through Authorization Services and puts up the
/// system dialog. Both prompt the user directly, so neither needs a terminal.
fn graphical_escalator() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        search_path("osascript").or_else(|| {
            let fallback = PathBuf::from("/usr/bin/osascript");
            fallback.is_file().then_some(fallback)
        })
    } else {
        search_path("pkexec")
    }
}

/// Quote one argument for a POSIX shell.
///
/// `do shell script` hands its string to `/bin/sh`, so the config path — which
/// on macOS lives under "Application Support" and therefore contains a space —
/// has to survive a round trip through word splitting. Single quotes take
/// everything literally; the only character that cannot appear inside them is a
/// single quote, which is spliced in as `'\''`.
fn shell_quote(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', r"'\''"))
}

/// Escape a string to sit inside an AppleScript double-quoted literal.
fn applescript_quote(value: &str) -> String {
    value.replace('\\', r"\\").replace('"', "\\\"")
}

/// Build the command line without running it, so the argv is testable.
pub fn plan(
    action: Action,
    wg_quick: &Path,
    conf: &Path,
    privilege: Privilege,
) -> Result<(PathBuf, Vec<String>)> {
    let wg_quick = wg_quick.to_string_lossy().into_owned();
    let conf = conf.to_string_lossy().into_owned();
    match privilege {
        Privilege::Direct => Ok((
            PathBuf::from(wg_quick),
            vec![action.as_str().to_string(), conf],
        )),
        Privilege::Sudo => Ok((
            PathBuf::from("sudo"),
            vec![wg_quick, action.as_str().to_string(), conf],
        )),
        // pkexec takes an argv and needs no quoting. osascript takes a script,
        // and the string inside `do shell script` reaches /bin/sh — so the
        // arguments are shell-quoted first and the result escaped for the
        // AppleScript literal that carries it.
        Privilege::Graphical { escalator } => {
            if escalator.file_name().and_then(|n| n.to_str()) == Some("osascript") {
                let command = format!(
                    "{} {} {}",
                    shell_quote(&wg_quick),
                    shell_quote(action.as_str()),
                    shell_quote(&conf)
                );
                let script = format!(
                    "do shell script \"{}\" with administrator privileges",
                    applescript_quote(&command)
                );
                Ok((escalator, vec!["-e".to_string(), script]))
            } else {
                Ok((escalator, vec![wg_quick, action.as_str().to_string(), conf]))
            }
        }
        Privilege::Unavailable => bail!(
            "bringing the tunnel {} needs root, and there is no way to ask for it \
             here.\n\
             Re-run as `sudo wsl {}`, or pass `--no-tunnel` to only write the \
             WireGuard config and manage the interface yourself.",
            action.as_str(),
            match action {
                Action::Up => "connect",
                Action::Down => "disconnect",
            }
        ),
    }
}

/// Bring the interface up from a rendered config.
pub async fn up(conf: &Path, escalation: Escalation) -> Result<TunnelState> {
    run(Action::Up, conf, escalation).await?;
    let state = state();
    if !state.is_up() {
        bail!(
            "wg-quick reported success but no interface appeared. \
             Check `wg show` and the system log."
        );
    }
    Ok(state)
}

/// Tear the interface down. Already-down is success, not an error: a user who
/// runs `disconnect` twice wants the tunnel gone, and it is.
pub async fn down(conf: &Path, escalation: Escalation) -> Result<()> {
    if !state().is_up() {
        return Ok(());
    }
    run(Action::Down, conf, escalation).await
}

async fn run(action: Action, conf: &Path, escalation: Escalation) -> Result<()> {
    let wg_quick = find_wg_quick().with_context(|| {
        format!(
            "wg-quick not found. Install the WireGuard tools:\n  \
             macOS:  brew install wireguard-tools\n  \
             Debian: apt install wireguard-tools\n\
             Or set {WG_QUICK_ENV} to its path."
        )
    })?;
    if !conf.is_file() {
        bail!(
            "no WireGuard config at {}; run `wsl connect` first",
            conf.display()
        );
    }
    let (program, args) = plan(action, &wg_quick, conf, detect_privilege(escalation))?;

    // stdin/stderr are inherited so sudo can prompt for a password and so
    // wg-quick's own diagnostics reach the user unmangled.
    let status = Command::new(&program)
        .args(&args)
        .status()
        .await
        .with_context(|| format!("failed to run {}", program.display()))?;
    if !status.success() {
        bail!(
            "{} {} failed with {}",
            program.display(),
            action.as_str(),
            status
        );
    }
    Ok(())
}

/// Ask the operating system whether the interface exists.
///
/// This deliberately avoids `wg show`, which needs root: a user should be able
/// to run `wsl status` without a password prompt and still get the truth.
pub fn state() -> TunnelState {
    match resolved_interface() {
        Some(interface) if interface_exists(&interface) => TunnelState::Up { interface },
        _ => TunnelState::Down,
    }
}

/// The real device name behind the configured interface.
///
/// On macOS there is no way to name a tunnel device, so `wg-quick` takes the
/// `utun` the kernel gives it and records the mapping in `/var/run/wireguard`.
/// On Linux the interface carries the configured name directly.
fn resolved_interface() -> Option<String> {
    let name_file = PathBuf::from(format!("/var/run/wireguard/{INTERFACE}.name"));
    match std::fs::read_to_string(&name_file) {
        Ok(contents) => {
            let name = contents.trim();
            (!name.is_empty()).then(|| name.to_string())
        }
        Err(_) => Some(INTERFACE.to_string()),
    }
}

fn interface_exists(name: &str) -> bool {
    if cfg!(target_os = "linux") {
        return Path::new(&format!("/sys/class/net/{name}")).exists();
    }
    // macOS and the BSDs have no /sys; ifconfig is unprivileged and exits
    // non-zero for an interface that is not there.
    std::process::Command::new("ifconfig")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_privilege_runs_wg_quick_itself() {
        let (program, args) = plan(
            Action::Up,
            Path::new("/opt/homebrew/bin/wg-quick"),
            Path::new("/tmp/wsl.conf"),
            Privilege::Direct,
        )
        .expect("direct plan");
        assert_eq!(program, PathBuf::from("/opt/homebrew/bin/wg-quick"));
        assert_eq!(args, vec!["up".to_string(), "/tmp/wsl.conf".to_string()]);
    }

    #[test]
    fn sudo_privilege_puts_wg_quick_in_the_arguments() {
        let (program, args) = plan(
            Action::Down,
            Path::new("/usr/bin/wg-quick"),
            Path::new("/tmp/wsl.conf"),
            Privilege::Sudo,
        )
        .expect("sudo plan");
        assert_eq!(program, PathBuf::from("sudo"));
        assert_eq!(
            args,
            vec![
                "/usr/bin/wg-quick".to_string(),
                "down".to_string(),
                "/tmp/wsl.conf".to_string(),
            ]
        );
    }

    /// The failure a user is most likely to hit has to name the fix.
    #[test]
    fn unavailable_privilege_explains_both_ways_out() {
        let err = plan(
            Action::Up,
            Path::new("/usr/bin/wg-quick"),
            Path::new("/tmp/wsl.conf"),
            Privilege::Unavailable,
        )
        .expect_err("no privilege");
        let message = err.to_string();
        assert!(message.contains("sudo wsl connect"), "{message}");
        assert!(message.contains("--no-tunnel"), "{message}");
    }

    #[test]
    fn disconnect_error_names_the_disconnect_command() {
        let err = plan(
            Action::Down,
            Path::new("/usr/bin/wg-quick"),
            Path::new("/tmp/wsl.conf"),
            Privilege::Unavailable,
        )
        .expect_err("no privilege");
        assert!(err.to_string().contains("sudo wsl disconnect"));
    }

    #[test]
    fn refusing_escalation_leaves_no_way_to_get_root() {
        if is_root() {
            // Running the suite as root is unusual but not an error; the
            // decision this asserts is only reachable as a normal user.
            return;
        }
        assert_eq!(detect_privilege(Escalation::None), Privilege::Unavailable);
    }

    /// A GUI has no terminal, so `sudo` would block on a prompt nobody can
    /// answer. It must reach for the desktop's own dialog instead.
    #[test]
    fn a_graphical_caller_does_not_get_sudo() {
        if is_root() {
            return;
        }
        assert!(!matches!(
            detect_privilege(Escalation::Graphical),
            Privilege::Sudo
        ));
    }

    #[test]
    fn pkexec_takes_an_argv_with_no_quoting() {
        let (program, args) = plan(
            Action::Up,
            Path::new("/usr/bin/wg-quick"),
            Path::new("/tmp/wsl.conf"),
            Privilege::Graphical {
                escalator: PathBuf::from("/usr/bin/pkexec"),
            },
        )
        .expect("pkexec plan");
        assert_eq!(program, PathBuf::from("/usr/bin/pkexec"));
        assert_eq!(
            args,
            vec![
                "/usr/bin/wg-quick".to_string(),
                "up".to_string(),
                "/tmp/wsl.conf".to_string(),
            ]
        );
    }

    /// The macOS config path contains a space, so the arguments have to survive
    /// both the AppleScript literal and the /bin/sh that `do shell script` runs.
    #[test]
    fn osascript_quotes_a_path_with_a_space_through_both_layers() {
        let conf = "/Users/x/Library/Application Support/wsl-zerotrust/wsl.conf";
        let (program, args) = plan(
            Action::Up,
            Path::new("/opt/homebrew/bin/wg-quick"),
            Path::new(conf),
            Privilege::Graphical {
                escalator: PathBuf::from("/usr/bin/osascript"),
            },
        )
        .expect("osascript plan");
        assert_eq!(program, PathBuf::from("/usr/bin/osascript"));
        assert_eq!(args[0], "-e");
        assert_eq!(
            args[1],
            "do shell script \"'/opt/homebrew/bin/wg-quick' 'up' \
             '/Users/x/Library/Application Support/wsl-zerotrust/wsl.conf'\" \
             with administrator privileges"
                .replace("\n", "")
        );
    }

    #[test]
    fn shell_quoting_survives_a_quote_in_the_path() {
        // A home directory can contain an apostrophe. Closing the quote,
        // escaping one, and reopening is the only way through single quotes.
        assert_eq!(
            shell_quote("/Users/o'brien/wsl.conf"),
            r"'/Users/o'\''brien/wsl.conf'"
        );
    }

    #[test]
    fn applescript_quoting_escapes_backslashes_before_quotes() {
        assert_eq!(applescript_quote(r#"a\b"c"#), r#"a\\b\"c"#);
    }

    #[test]
    fn a_down_tunnel_shows_a_placeholder_interface() {
        assert_eq!(TunnelState::Down.interface(), "-");
        assert!(!TunnelState::Down.is_up());
        let up = TunnelState::Up {
            interface: "utun4".into(),
        };
        assert_eq!(up.interface(), "utun4");
        assert!(up.is_up());
    }

    #[test]
    fn the_env_override_is_ignored_when_it_points_at_nothing() {
        // A stale override must not shadow a working wg-quick silently; it
        // resolves to None and the caller reports the install instructions.
        std::env::set_var(WG_QUICK_ENV, "/nonexistent/wg-quick");
        assert_eq!(find_wg_quick(), None);
        std::env::remove_var(WG_QUICK_ENV);
    }
}
