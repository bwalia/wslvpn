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

/// Environment override declaring that this process already holds the
/// privilege `wg-quick` needs — it runs under a supervisor that granted it (a
/// root launchd daemon, a container with `CAP_NET_ADMIN`) or in a test with a
/// stand-in `wg-quick`. Only `direct` is recognised. It never grants anything:
/// without the real privilege the commands simply fail.
pub const PRIVILEGE_ENV: &str = "WSL_PRIVILEGE";

/// Where `wg-quick` records the `utun` it picked on macOS. Overridable so a
/// stand-in `wg-quick` in a test can say which interface it "brought up".
pub const RUN_DIR_ENV: &str = "WSL_WG_RUN_DIR";

/// Decide how to run `wg-quick`.
pub fn detect_privilege(escalation: Escalation) -> Privilege {
    if is_root() || std::env::var(PRIVILEGE_ENV).as_deref() == Ok("direct") {
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

/// One command to run with privilege, as an argv. Nothing here is ever
/// interpreted by a shell except through [`Step::shell`], which quotes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl Step {
    pub fn new(
        program: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    /// The step as one line of POSIX shell, every word quoted.
    fn shell(&self) -> String {
        std::iter::once(self.program.to_string_lossy().into_owned())
            .chain(self.args.iter().cloned())
            .map(|word| shell_quote(&word))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// How to invoke `wg-quick`.
///
/// `wg-quick` is a bash script that needs bash 4, and says so with
/// `#!/usr/bin/env bash`. macOS ships bash 3.2 in `/bin`, and a privileged
/// shell — `do shell script`, `sudo` with `secure_path` — runs with a `PATH` of
/// `/usr/bin:/bin:/usr/sbin:/sbin`, so `env` finds the old one and the script
/// exits with "Version mismatch: bash 3 detected". That was every Connect from
/// the desktop app. The fix is to not leave it to `env`: find a bash 4 and run
/// the script with it explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgQuick {
    pub script: PathBuf,
    /// The interpreter to run it with, when it is a bash script.
    pub bash: Option<PathBuf>,
}

impl WgQuick {
    /// Locate `wg-quick`, and a bash new enough to run it if it needs one.
    pub fn locate() -> Result<Self> {
        let script = find_wg_quick().with_context(|| {
            format!(
                "wg-quick not found. Install the WireGuard tools:\n  \
                 macOS:  brew install wireguard-tools\n  \
                 Debian: apt install wireguard-tools\n\
                 Or set {WG_QUICK_ENV} to its path."
            )
        })?;
        if !is_bash_script(&script) {
            return Ok(Self { script, bash: None });
        }
        let bash = find_bash().context(
            "wg-quick needs bash 4 or newer, and only an older bash was found.\n  \
             macOS:  brew install bash",
        )?;
        Ok(Self {
            script,
            bash: Some(bash),
        })
    }

    pub fn step(&self, action: Action, conf: &Path) -> Step {
        let conf = conf.to_string_lossy().into_owned();
        let script = self.script.to_string_lossy().into_owned();
        match &self.bash {
            Some(bash) => Step::new(bash, [script, action.as_str().to_string(), conf]),
            None => Step::new(&self.script, [action.as_str().to_string(), conf]),
        }
    }

    /// The `PATH` a privileged shell runs `wg-quick` with.
    ///
    /// `wg-quick` starts `wireguard-go` and `wg` by name. On macOS both are in
    /// the Homebrew prefix, which a privileged shell's `PATH` does not include.
    pub fn path(&self) -> String {
        let mut dirs: Vec<String> = Vec::new();
        for dir in [
            self.script.parent(),
            self.bash.as_deref().and_then(Path::parent),
        ]
        .into_iter()
        .flatten()
        {
            dirs.push(dir.to_string_lossy().into_owned());
        }
        dirs.extend(
            [
                "/opt/homebrew/bin",
                "/usr/local/bin",
                "/usr/bin",
                "/bin",
                "/usr/sbin",
                "/sbin",
            ]
            .map(String::from),
        );
        let mut seen = std::collections::HashSet::new();
        dirs.retain(|d| seen.insert(d.clone()));
        dirs.join(":")
    }
}

fn is_bash_script(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 64];
    let n = std::io::Read::read(&mut file, &mut head).unwrap_or(0);
    let first = String::from_utf8_lossy(&head[..n]);
    let first = first.lines().next().unwrap_or("");
    first.starts_with("#!") && first.contains("bash")
}

/// The first bash on this machine that is version 4 or newer.
pub fn find_bash() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = [
        "/opt/homebrew/bin/bash",
        "/usr/local/bin/bash",
        "/run/current-system/sw/bin/bash",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    candidates.extend(search_path("bash"));
    candidates.push(PathBuf::from("/bin/bash"));
    candidates
        .into_iter()
        .filter(|p| p.is_file())
        .find(|p| bash_major(p).is_some_and(|major| major >= 4))
}

fn bash_major(bash: &Path) -> Option<u32> {
    let output = std::process::Command::new(bash)
        .args(["-c", "echo ${BASH_VERSINFO[0]}"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

/// Build the command line that runs `steps` with privilege, without running
/// it, so the argv is testable.
///
/// The steps are joined into one shell script with `&&`, so a single password
/// prompt covers all of them and a failure stops the rest. `hint` is the
/// command a user can run instead when there is no way to escalate here.
pub fn plan(
    steps: &[Step],
    path: &str,
    privilege: Privilege,
    hint: &str,
) -> Result<(PathBuf, Vec<String>)> {
    let script = std::iter::once(format!("export PATH={}", shell_quote(path)))
        .chain(steps.iter().map(Step::shell))
        .collect::<Vec<_>>()
        .join(" && ");
    let sh = || vec!["/bin/sh".to_string(), "-c".to_string(), script.clone()];
    match privilege {
        Privilege::Direct => Ok((PathBuf::from("/bin/sh"), sh()[1..].to_vec())),
        Privilege::Sudo => Ok((PathBuf::from("sudo"), sh())),
        // pkexec takes an argv. osascript takes a script, and the string inside
        // `do shell script` reaches /bin/sh — so it is the already-quoted shell
        // line, escaped once more for the AppleScript literal that carries it.
        Privilege::Graphical { escalator } => {
            if escalator.file_name().and_then(|n| n.to_str()) == Some("osascript") {
                let apple = format!(
                    "do shell script \"{}\" with administrator privileges",
                    applescript_quote(&script)
                );
                Ok((escalator, vec!["-e".to_string(), apple]))
            } else {
                Ok((escalator, sh()))
            }
        }
        Privilege::Unavailable => bail!(
            "this needs administrator rights, and there is no way to ask for them \
             here.\n{hint}"
        ),
    }
}

fn unavailable_hint(action: Action) -> String {
    let command = match action {
        Action::Up => "connect",
        Action::Down => "disconnect",
    };
    format!(
        "Re-run as `sudo wsl {command}`, or pass `--no-tunnel` to only write the \
         WireGuard config and manage the interface yourself."
    )
}

/// Bring the interface up from a rendered config.
///
/// An interface left up by an earlier session — a crash, a sleep, a config
/// that has since changed — is taken down first, in the same privileged run,
/// so reconnecting never fails with "`wsl' already exists".
pub async fn up(conf: &Path, escalation: Escalation) -> Result<TunnelState> {
    up_with_hint(conf, escalation, &unavailable_hint(Action::Up)).await
}

/// [`up`], naming a different way out when there is no privilege to be had.
pub async fn up_with_hint(conf: &Path, escalation: Escalation, hint: &str) -> Result<TunnelState> {
    ensure_conf(conf)?;
    let wg = WgQuick::locate()?;
    let mut steps = Vec::new();
    if state().is_up() {
        steps.push(wg.step(Action::Down, conf));
    }
    steps.push(wg.step(Action::Up, conf));
    run_privileged(&steps, &wg.path(), escalation, hint).await?;
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
    ensure_conf(conf)?;
    let wg = WgQuick::locate()?;
    let steps = [wg.step(Action::Down, conf)];
    run_privileged(
        &steps,
        &wg.path(),
        escalation,
        &unavailable_hint(Action::Down),
    )
    .await
}

fn ensure_conf(conf: &Path) -> Result<()> {
    if !conf.is_file() {
        bail!(
            "no WireGuard config at {}; run `wsl connect` first",
            conf.display()
        );
    }
    Ok(())
}

/// Run `steps` with whatever privilege `escalation` allows.
pub async fn run_privileged(
    steps: &[Step],
    path: &str,
    escalation: Escalation,
    hint: &str,
) -> Result<()> {
    let privilege = detect_privilege(escalation);
    let graphical = matches!(privilege, Privilege::Graphical { .. });
    let (program, args) = plan(steps, path, privilege, hint)?;
    let mut command = Command::new(&program);
    command.args(&args);

    if !graphical {
        // stdin/stderr are inherited so sudo can prompt for a password and so
        // wg-quick's own diagnostics reach the user unmangled.
        let status = command
            .status()
            .await
            .with_context(|| format!("failed to run {}", program.display()))?;
        if !status.success() {
            bail!("{} failed with {}", steps_summary(steps), status);
        }
        return Ok(());
    }

    // The authorization dialog has no terminal to write to, so capture what
    // comes back and turn it into something a person can act on.
    let output = command
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .with_context(|| format!("failed to run {}", program.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "{}",
        explain_graphical_failure(&steps_summary(steps), &stderr)
    )
}

fn steps_summary(steps: &[Step]) -> String {
    steps
        .iter()
        .map(|s| {
            let words: Vec<&str> = std::iter::once(s.program.to_str().unwrap_or("?"))
                .chain(s.args.iter().map(String::as_str))
                .collect();
            // Name the tool, not the interpreter running it.
            let tool = words
                .iter()
                .find(|w| !w.ends_with("/bash") && !w.ends_with("/sh"))
                .copied()
                .unwrap_or("?");
            Path::new(tool)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| tool.to_string())
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Turn osascript's error text into a sentence.
///
/// It reports as `0:123: execution error: <message> (<code>)`. -128 is the
/// user pressing Cancel on the authorization dialog, which is a choice rather
/// than a failure and should read like one.
pub fn explain_graphical_failure(what: &str, stderr: &str) -> String {
    let stderr = stderr.trim();
    if stderr.contains("(-128)") {
        return "Cancelled: administrator permission was not granted.".into();
    }
    let message = stderr
        .split_once("execution error:")
        .map(|(_, rest)| rest.trim())
        .unwrap_or(stderr);
    let message = message
        .rsplit_once(" (")
        .filter(|(_, code)| code.trim_end_matches(')').parse::<i64>().is_ok())
        .map(|(m, _)| m.trim())
        .unwrap_or(message);
    if message.is_empty() {
        format!("{what} failed")
    } else {
        format!("{what} failed: {message}")
    }
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
    let run_dir = std::env::var_os(RUN_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/run/wireguard"));
    let name_file = run_dir.join(format!("{INTERFACE}.name"));
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

    fn wg(bash: Option<&str>) -> WgQuick {
        WgQuick {
            script: PathBuf::from("/opt/homebrew/bin/wg-quick"),
            bash: bash.map(PathBuf::from),
        }
    }

    const CONF: &str = "/tmp/wsl.conf";

    /// The bug that broke every Connect from the desktop app: left to
    /// `#!/usr/bin/env bash`, a privileged shell's PATH finds macOS's bash 3.2.
    #[test]
    fn wg_quick_runs_under_the_bash_that_was_found_not_whatever_env_finds() {
        let step = wg(Some("/opt/homebrew/bin/bash")).step(Action::Up, Path::new(CONF));
        assert_eq!(step.program, PathBuf::from("/opt/homebrew/bin/bash"));
        assert_eq!(step.args, vec!["/opt/homebrew/bin/wg-quick", "up", CONF]);
    }

    #[test]
    fn a_wg_quick_that_is_not_a_bash_script_runs_directly() {
        let step = wg(None).step(Action::Down, Path::new(CONF));
        assert_eq!(step.program, PathBuf::from("/opt/homebrew/bin/wg-quick"));
        assert_eq!(step.args, vec!["down", CONF]);
    }

    /// wireguard-go and wg are found by name; a privileged PATH lacks Homebrew.
    #[test]
    fn the_privileged_path_starts_with_wg_quicks_own_directory() {
        let path = wg(Some("/usr/local/bin/bash")).path();
        assert!(
            path.starts_with("/opt/homebrew/bin:/usr/local/bin:"),
            "{path}"
        );
        assert!(path.ends_with("/usr/bin:/bin:/usr/sbin:/sbin"), "{path}");
        // No directory twice.
        let dirs: Vec<&str> = path.split(':').collect();
        let unique: std::collections::HashSet<&&str> = dirs.iter().collect();
        assert_eq!(dirs.len(), unique.len(), "{path}");
    }

    fn up_step() -> Step {
        wg(Some("/opt/homebrew/bin/bash")).step(Action::Up, Path::new(CONF))
    }

    #[test]
    fn direct_privilege_runs_the_script_in_a_plain_shell() {
        let (program, args) = plan(&[up_step()], "/usr/bin:/bin", Privilege::Direct, "").unwrap();
        assert_eq!(program, PathBuf::from("/bin/sh"));
        assert_eq!(
            args,
            vec![
                "-c".to_string(),
                "export PATH='/usr/bin:/bin' && '/opt/homebrew/bin/bash' \
                 '/opt/homebrew/bin/wg-quick' 'up' '/tmp/wsl.conf'"
                    .to_string()
            ]
        );
    }

    #[test]
    fn sudo_runs_the_same_script_under_sh() {
        let (program, args) = plan(&[up_step()], "/bin", Privilege::Sudo, "").unwrap();
        assert_eq!(program, PathBuf::from("sudo"));
        assert_eq!(&args[..2], &["/bin/sh".to_string(), "-c".to_string()]);
        assert!(args[2].ends_with("'up' '/tmp/wsl.conf'"), "{}", args[2]);
    }

    /// Several steps are one script, so one password prompt covers them all
    /// and the first failure stops the rest.
    #[test]
    fn several_steps_are_chained_so_a_failure_stops_the_rest() {
        let down = wg(None).step(Action::Down, Path::new(CONF));
        let up = wg(None).step(Action::Up, Path::new(CONF));
        let (_, args) = plan(&[down, up], "/bin", Privilege::Direct, "").unwrap();
        assert_eq!(
            args[1],
            "export PATH='/bin' && '/opt/homebrew/bin/wg-quick' 'down' '/tmp/wsl.conf' \
             && '/opt/homebrew/bin/wg-quick' 'up' '/tmp/wsl.conf'"
        );
    }

    /// The failure a user is most likely to hit has to name the fix.
    #[test]
    fn unavailable_privilege_explains_both_ways_out() {
        let err = plan(
            &[up_step()],
            "/bin",
            Privilege::Unavailable,
            &unavailable_hint(Action::Up),
        )
        .expect_err("no privilege");
        let message = err.to_string();
        assert!(message.contains("sudo wsl connect"), "{message}");
        assert!(message.contains("--no-tunnel"), "{message}");
    }

    #[test]
    fn disconnect_error_names_the_disconnect_command() {
        let err = plan(
            &[up_step()],
            "/bin",
            Privilege::Unavailable,
            &unavailable_hint(Action::Down),
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
    fn pkexec_runs_the_script_under_sh() {
        let (program, args) = plan(
            &[up_step()],
            "/bin",
            Privilege::Graphical {
                escalator: PathBuf::from("/usr/bin/pkexec"),
            },
            "",
        )
        .expect("pkexec plan");
        assert_eq!(program, PathBuf::from("/usr/bin/pkexec"));
        assert_eq!(&args[..2], &["/bin/sh".to_string(), "-c".to_string()]);
    }

    /// The macOS config path contains a space, so the arguments have to survive
    /// both the AppleScript literal and the /bin/sh that `do shell script` runs.
    #[test]
    fn osascript_quotes_a_path_with_a_space_through_both_layers() {
        let conf = "/Users/x/Library/Application Support/wsl-zerotrust/wsl.conf";
        let step = wg(Some("/opt/homebrew/bin/bash")).step(Action::Up, Path::new(conf));
        let (program, args) = plan(
            &[step],
            "/opt/homebrew/bin:/usr/bin",
            Privilege::Graphical {
                escalator: PathBuf::from("/usr/bin/osascript"),
            },
            "",
        )
        .expect("osascript plan");
        assert_eq!(program, PathBuf::from("/usr/bin/osascript"));
        assert_eq!(args[0], "-e");
        assert_eq!(
            args[1],
            "do shell script \"export PATH='/opt/homebrew/bin:/usr/bin' && \
             '/opt/homebrew/bin/bash' '/opt/homebrew/bin/wg-quick' 'up' \
             '/Users/x/Library/Application Support/wsl-zerotrust/wsl.conf'\" \
             with administrator privileges"
        );
    }

    #[test]
    fn a_cancelled_authorization_dialog_reads_as_a_choice() {
        let msg = explain_graphical_failure(
            "wg-quick",
            "0:180: execution error: User canceled. (-128)\n",
        );
        assert_eq!(msg, "Cancelled: administrator permission was not granted.");
    }

    #[test]
    fn a_wg_quick_error_inside_the_dialog_is_passed_through() {
        let msg = explain_graphical_failure(
            "wg-quick",
            "0:210: execution error: wg-quick: `wsl' already exists (1)\n",
        );
        assert_eq!(msg, "wg-quick failed: wg-quick: `wsl' already exists");
    }

    #[test]
    fn the_summary_names_the_tool_not_the_interpreter() {
        assert_eq!(steps_summary(&[up_step()]), "wg-quick");
    }

    #[test]
    fn a_bash_script_is_recognised_by_its_shebang() {
        let dir = std::env::temp_dir().join(format!("wsl-shebang-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a"), "#!/usr/bin/env bash\necho\n").unwrap();
        std::fs::write(dir.join("b"), "#!/bin/sh\necho\n").unwrap();
        assert!(is_bash_script(&dir.join("a")));
        assert!(!is_bash_script(&dir.join("b")));
        assert!(!is_bash_script(&dir.join("missing")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bash_that_is_found_is_at_least_version_4() {
        if let Some(bash) = find_bash() {
            assert!(bash_major(&bash).unwrap() >= 4);
        }
    }

    /// macOS ships /bin/bash 3.2; it must never be chosen.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_system_bash_is_too_old_to_be_chosen() {
        assert_eq!(bash_major(Path::new("/bin/bash")), Some(3));
        assert_ne!(find_bash(), Some(PathBuf::from("/bin/bash")));
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
