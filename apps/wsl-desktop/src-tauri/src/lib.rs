//! The desktop app's bridge to the `wsl` CLI.
//!
//! The GUI owns no state and performs no privileged operation. Everything it
//! shows is read back from the CLI, and everything it does is a CLI invocation,
//! so there is exactly one implementation of what "connected" means and the
//! window cannot drift away from it.
//!
//! Two things make that harder than it sounds, and both are handled here.
//!
//! A process launched from Finder inherits a minimal `PATH` — no Homebrew, no
//! `/usr/local/bin` — so the CLI has to be found rather than assumed.
//!
//! And the GUI has no terminal, so `sudo` would block forever on a prompt
//! nobody can answer. Commands that need root are invoked with `--gui`, which
//! tells the agent to ask macOS for the privilege through its own dialog.

use serde::Serialize;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

/// Override for the CLI location, for a development build running against a
/// `cargo build` target directory.
const CLI_ENV: &str = "WSL_CLI";

/// What went wrong, in a shape the UI can branch on rather than pattern-match
/// against a human-readable string.
#[derive(Debug, Serialize)]
pub struct CliError {
    kind: ErrorKind,
    message: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The CLI could not be found. The UI explains how to install it rather
    /// than showing an empty dashboard.
    CliMissing,
    /// The CLI ran and failed. `message` is its stderr.
    CommandFailed,
    /// The CLI succeeded but did not produce the JSON it promised.
    BadOutput,
}

impl CliError {
    fn missing() -> Self {
        Self {
            kind: ErrorKind::CliMissing,
            message: format!(
                "The wsl command-line tool was not found. Install it, or set {CLI_ENV} \
                 to its path."
            ),
        }
    }

    fn failed(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::CommandFailed,
            message: message.into(),
        }
    }

    fn bad_output(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::BadOutput,
            message: message.into(),
        }
    }
}

/// Find the `wsl` binary.
///
/// The bundled copy inside the app comes first: a released app must not depend
/// on whatever happens to be on the user's `PATH`, and must not silently pick
/// up a different version than it shipped with.
pub fn find_cli() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os(CLI_ENV) {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for candidate in [dir.join("wsl"), dir.join("../Resources/wsl")] {
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    search_path("wsl").or_else(|| {
        ["/opt/homebrew/bin/wsl", "/usr/local/bin/wsl", "/usr/bin/wsl"]
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

/// Run the CLI and return its stdout.
async fn run(args: &[&str]) -> Result<String, CliError> {
    let cli = find_cli().ok_or_else(CliError::missing)?;
    let output = Command::new(&cli)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| CliError::failed(format!("could not run {}: {e}", cli.display())))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(CliError::failed(if stderr.is_empty() {
            stdout
        } else {
            stderr
        }));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn run_json(args: &[&str]) -> Result<serde_json::Value, CliError> {
    let stdout = run(args).await?;
    serde_json::from_str(&stdout)
        .map_err(|e| CliError::bad_output(format!("could not read the CLI's output: {e}")))
}

/// The whole dashboard, read from the agent rather than remembered here.
#[tauri::command]
async fn status() -> Result<serde_json::Value, CliError> {
    run_json(&["status", "--json"]).await
}

/// The networks this user may reach. Requires being signed in.
#[tauri::command]
async fn networks() -> Result<serde_json::Value, CliError> {
    run_json(&["networks", "--json"]).await
}

/// Sign in. The CLI opens a browser and waits, so this can take as long as the
/// person takes; the UI shows it as pending rather than assuming it is quick.
#[tauri::command]
async fn sign_in() -> Result<serde_json::Value, CliError> {
    run(&["login"]).await?;
    status().await
}

#[tauri::command]
async fn sign_out() -> Result<serde_json::Value, CliError> {
    run(&["logout"]).await?;
    status().await
}

/// Bring a network up. `--gui` is what routes the privilege request to the
/// macOS authorization dialog instead of a terminal prompt.
#[tauri::command]
async fn connect(network: Option<String>) -> Result<serde_json::Value, CliError> {
    let mut args = vec!["connect", "--gui"];
    if let Some(name) = network.as_deref() {
        args.push("--network");
        args.push(name);
    }
    run(&args).await?;
    status().await
}

#[tauri::command]
async fn disconnect() -> Result<serde_json::Value, CliError> {
    run(&["disconnect", "--gui"]).await?;
    status().await
}

/// Where the CLI was found, for the UI to show when something is wrong.
#[tauri::command]
fn cli_location() -> Option<String> {
    find_cli().map(|p| p.display().to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run_app() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            status,
            networks,
            sign_in,
            sign_out,
            connect,
            disconnect,
            cli_location
        ])
        .run(tauri::generate_context!())
        .expect("error while running WSL desktop");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_override_does_not_shadow_a_real_cli() {
        std::env::set_var(CLI_ENV, "/nonexistent/wsl");
        assert_eq!(find_cli(), None);
        std::env::remove_var(CLI_ENV);
    }

    #[test]
    fn the_override_is_used_when_it_points_at_a_file() {
        // The test binary itself is a convenient file that certainly exists.
        let exe = std::env::current_exe().expect("current exe");
        std::env::set_var(CLI_ENV, &exe);
        assert_eq!(find_cli(), Some(exe));
        std::env::remove_var(CLI_ENV);
    }

    #[test]
    fn errors_carry_a_kind_the_ui_can_branch_on() {
        let json = serde_json::to_value(CliError::missing()).expect("serialize");
        assert_eq!(json["kind"], "cli_missing");
        assert!(json["message"].as_str().unwrap().contains("WSL_CLI"));

        let json = serde_json::to_value(CliError::failed("no networks")).expect("serialize");
        assert_eq!(json["kind"], "command_failed");
        assert_eq!(json["message"], "no networks");
    }
}
