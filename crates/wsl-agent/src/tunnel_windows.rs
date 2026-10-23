//! The tunnel on Windows, through WireGuard for Windows.
//!
//! Windows has no `wg-quick`. The official client, `wireguard.exe`, runs each
//! tunnel as a Windows service — `WireGuardTunnel$<name>` — with its own
//! signed kernel driver, and exposes that as two documented commands:
//!
//! ```text
//! wireguard.exe /installtunnelservice C:\path\to\wsl.conf   # up; the name comes from the file
//! wireguard.exe /uninstalltunnelservice wsl                 # down
//! ```
//!
//! Driving those instead of shipping our own driver keeps us on the client
//! Windows users already trust, and means a tunnel we bring up shows in the
//! WireGuard app like any other.
//!
//! Both need an administrator. A process that is not elevated asks through UAC:
//! PowerShell `Start-Process -Verb RunAs` puts up the consent dialog and runs a
//! second PowerShell elevated. Its script travels as `-EncodedCommand` (base64
//! of UTF-16LE) so no path — `C:\Users\Jane O'Neil\AppData\…` — is ever parsed
//! as PowerShell, and every step runs under one prompt, stopping at the first
//! failure.
//!
//! Everything that decides what to run is a plain function, compiled and tested
//! on every platform. Only the functions that run it are Windows-only.

use std::path::{Path, PathBuf};

use base64::Engine;

use super::{Action, Step, INTERFACE};

/// Override for `wireguard.exe`, for a test or an unusual install.
pub const WIREGUARD_EXE_ENV: &str = "WSL_WIREGUARD_EXE";

/// The service WireGuard for Windows creates for our tunnel.
pub fn service_name() -> String {
    format!("WireGuardTunnel${INTERFACE}")
}

/// Where WireGuard for Windows installs itself, given `%ProgramFiles%`.
pub fn default_locations(program_files: Option<&str>) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = program_files
        .map(|pf| Path::new(pf).join("WireGuard").join("wireguard.exe"))
        .into_iter()
        .collect();
    found.push(PathBuf::from(r"C:\Program Files\WireGuard\wireguard.exe"));
    found
}

pub fn find_wireguard_exe() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os(WIREGUARD_EXE_ENV) {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    default_locations(std::env::var("ProgramFiles").ok().as_deref())
        .into_iter()
        .find(|p| p.is_file())
}

pub fn not_installed() -> anyhow::Error {
    anyhow::anyhow!(
        "WireGuard for Windows is not installed. Install it from \
         https://www.wireguard.com/install/ (or `winget install WireGuard.WireGuard`), \
         then connect again. Or set {WIREGUARD_EXE_ENV} to wireguard.exe."
    )
}

/// The `wireguard.exe` invocation for one action.
pub fn step(exe: &Path, action: Action, conf: &Path) -> Step {
    match action {
        Action::Up => Step::new(
            exe,
            [
                "/installtunnelservice".to_string(),
                conf.to_string_lossy().into_owned(),
            ],
        ),
        Action::Down => Step::new(exe, ["/uninstalltunnelservice", INTERFACE]),
    }
}

/// Quote for a PowerShell single-quoted string: `'` is written `''`.
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// The script the elevated PowerShell runs: each step, stopping at the first
/// one that fails and exiting with its code.
pub fn script(steps: &[Step]) -> String {
    let mut lines = vec!["$ErrorActionPreference = 'Stop'".to_string()];
    for step in steps {
        let args = step
            .args
            .iter()
            .map(|a| ps_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        lines.push(format!(
            "& {} {args}; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}",
            ps_quote(&step.program.to_string_lossy())
        ));
    }
    lines.push("exit 0".into());
    lines.join("\n")
}

/// `-EncodedCommand` takes base64 of the script's UTF-16LE bytes.
pub fn encode(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The PowerShell argv that runs `steps`. Elevated already: run the script.
/// Not elevated: start an elevated PowerShell through UAC, wait, and pass its
/// exit code back.
pub fn plan(steps: &[Step], elevated: bool) -> (PathBuf, Vec<String>) {
    let encoded = encode(&script(steps));
    let base = [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
    ];
    let mut args: Vec<String> = base.iter().map(|s| s.to_string()).collect();
    if elevated {
        args.extend(["-EncodedCommand".to_string(), encoded]);
    } else {
        // base64 is [A-Za-z0-9+/=], so it is safe inside single quotes as is.
        let inner = base
            .iter()
            .map(|a| format!("'{a}'"))
            .chain(["'-EncodedCommand'".to_string(), format!("'{encoded}'")])
            .collect::<Vec<_>>()
            .join(",");
        args.extend([
            "-Command".to_string(),
            format!(
                "$p = Start-Process -FilePath 'powershell.exe' -ArgumentList {inner} \
                 -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode"
            ),
        ]);
    }
    (PathBuf::from("powershell.exe"), args)
}

/// What a failed elevated run printed, as something a person can act on.
pub fn explain_failure(what: &str, stderr: &str) -> String {
    let stderr = stderr.trim();
    if stderr.contains("canceled by the user") || stderr.contains("cancelled by the user") {
        return "Cancelled: administrator permission was not granted.".into();
    }
    let first = stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    if first.is_empty() {
        format!("{what} failed")
    } else {
        format!("{what} failed: {first}")
    }
}

/// Whether `sc query <service>` says it is running.
pub fn parse_sc_running(output: &str) -> bool {
    output
        .lines()
        .any(|l| l.trim_start().starts_with("STATE") && l.contains("RUNNING"))
}

/// Other WireGuard tunnels running on this machine, from
/// `sc query type= service state= active`: the official app's tunnels are
/// services named `WireGuardTunnel$<name>`.
pub fn parse_other_tunnels(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|l| l.trim().strip_prefix("SERVICE_NAME:"))
        .filter_map(|name| name.trim().strip_prefix("WireGuardTunnel$"))
        .filter(|name| !name.eq_ignore_ascii_case(INTERFACE) && !name.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(windows)]
pub mod run {
    //! Running the plans above. Windows only.

    use std::process::Stdio;

    use anyhow::{bail, Context, Result};

    use super::*;
    use crate::tunnel::{Escalation, TunnelState};

    fn sc(args: &[&str]) -> String {
        std::process::Command::new("sc.exe")
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    }

    pub fn state() -> TunnelState {
        if parse_sc_running(&sc(&["query", &service_name()])) {
            TunnelState::Up {
                interface: INTERFACE.to_string(),
            }
        } else {
            TunnelState::Down
        }
    }

    pub fn other_tunnels() -> Vec<String> {
        parse_other_tunnels(&sc(&["query", "type=", "service", "state=", "active"]))
    }

    /// `net session` succeeds only for an administrator.
    pub fn is_elevated() -> bool {
        std::process::Command::new("net")
            .arg("session")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    pub async fn run(steps: &[Step], escalation: Escalation, hint: &str) -> Result<()> {
        let elevated = is_elevated();
        if !elevated && escalation == Escalation::None {
            bail!(
                "this needs administrator rights, and there is no way to ask for them \
                 here.\n{hint}"
            );
        }
        let (program, args) = plan(steps, elevated);
        let output = tokio::process::Command::new(&program)
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .await
            .with_context(|| format!("failed to run {}", program.display()))?;
        if output.status.success() {
            return Ok(());
        }
        let mut text = String::from_utf8_lossy(&output.stderr).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stdout));
        bail!("{}", explain_failure("wireguard.exe", &text))
    }

    /// The service can still be starting when `/installtunnelservice` returns.
    pub async fn wait_until_up() -> TunnelState {
        for _ in 0..20 {
            let s = state();
            if s.is_up() {
                return s;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = r"C:\Program Files\WireGuard\wireguard.exe";

    fn conf() -> PathBuf {
        PathBuf::from(r"C:\Users\Jane O'Neil\AppData\Roaming\wsl-zerotrust\data\wsl.conf")
    }

    #[test]
    fn up_installs_the_tunnel_service_from_the_config_and_down_removes_it_by_name() {
        let up = step(Path::new(EXE), Action::Up, &conf());
        assert_eq!(up.program, PathBuf::from(EXE));
        assert_eq!(
            up.args,
            vec![
                "/installtunnelservice".to_string(),
                conf().to_string_lossy().into_owned()
            ]
        );
        let down = step(Path::new(EXE), Action::Down, &conf());
        assert_eq!(down.args, vec!["/uninstalltunnelservice", "wsl"]);
        assert_eq!(service_name(), "WireGuardTunnel$wsl");
    }

    #[test]
    fn the_script_quotes_every_word_and_stops_at_the_first_failure() {
        let steps = [
            step(Path::new(EXE), Action::Down, &conf()),
            step(Path::new(EXE), Action::Up, &conf()),
        ];
        let s = script(&steps);
        // The apostrophe in the user's name is doubled, not a string end.
        assert!(s.contains(r"'C:\Users\Jane O''Neil\AppData"), "{s}");
        assert!(
            s.contains(
                r"& 'C:\Program Files\WireGuard\wireguard.exe' '/uninstalltunnelservice' 'wsl'"
            ),
            "{s}"
        );
        assert_eq!(
            s.matches("if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }")
                .count(),
            2
        );
        let down = s.find("/uninstalltunnelservice").unwrap();
        let up = s.find("/installtunnelservice").unwrap();
        assert!(down < up, "down runs before up");
    }

    /// PowerShell's -EncodedCommand is base64 of UTF-16LE.
    #[test]
    fn the_script_is_encoded_the_way_powershell_decodes_it() {
        let encoded = encode("exit 0");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        let units: Vec<u16> = bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&units).unwrap(), "exit 0");
        // The literal PowerShell docs example: `dir` → ZABpAHIA
        assert_eq!(encode("dir"), "ZABpAHIA");
    }

    #[test]
    fn an_elevated_process_runs_the_script_and_one_that_is_not_asks_uac_once() {
        let steps = [step(Path::new(EXE), Action::Up, &conf())];
        let encoded = encode(&script(&steps));

        let (program, args) = plan(&steps, true);
        assert_eq!(program, PathBuf::from("powershell.exe"));
        assert_eq!(args.last(), Some(&encoded));
        assert!(!args.iter().any(|a| a.contains("RunAs")));

        let (program, args) = plan(&steps, false);
        assert_eq!(program, PathBuf::from("powershell.exe"));
        let command = args.last().unwrap();
        assert!(command.contains("-Verb RunAs"), "{command}");
        assert!(
            command.contains("-Wait -PassThru; exit $p.ExitCode"),
            "{command}"
        );
        assert!(command.contains(&format!("'{encoded}'")), "{command}");
        // No path reaches the outer command line, encoded or not.
        assert!(!command.contains("Jane"), "{command}");
    }

    #[test]
    fn dismissing_uac_reads_as_a_choice() {
        let stderr = "Start-Process : This command cannot be run due to the error: \
                      The operation was canceled by the user.";
        assert_eq!(
            explain_failure("wireguard.exe", stderr),
            "Cancelled: administrator permission was not granted."
        );
        assert_eq!(
            explain_failure("wireguard.exe", "\n Unable to open file\n"),
            "wireguard.exe failed: Unable to open file"
        );
    }

    #[test]
    fn sc_query_output_is_read() {
        let running = "\r\nSERVICE_NAME: WireGuardTunnel$wsl \r\n        TYPE               : 10  WIN32_OWN_PROCESS\r\n        STATE              : 4  RUNNING\r\n";
        assert!(parse_sc_running(running));
        let stopped = running.replace("4  RUNNING", "1  STOPPED");
        assert!(!parse_sc_running(&stopped));
        assert!(!parse_sc_running(
            "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:"
        ));
    }

    #[test]
    fn the_wireguard_apps_own_tunnels_are_found_and_ours_is_not_counted() {
        let out = "SERVICE_NAME: Dhcp\r\nSERVICE_NAME: WireGuardTunnel$office\r\n\
                   SERVICE_NAME: WireGuardTunnel$wsl\r\nSERVICE_NAME: WireGuardManager\r\n";
        assert_eq!(parse_other_tunnels(out), vec!["office"]);
    }

    #[test]
    fn wireguard_is_looked_for_under_program_files() {
        let found = default_locations(Some(r"D:\Apps"));
        assert_eq!(
            found[0],
            Path::new(r"D:\Apps")
                .join("WireGuard")
                .join("wireguard.exe")
        );
        assert!(found.contains(&PathBuf::from(EXE)));
    }
}
