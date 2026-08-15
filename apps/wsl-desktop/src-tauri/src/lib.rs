use serde::Serialize;
use std::process::Command;
use tauri::Manager;

#[derive(Serialize)]
struct CliResult {
    output: String,
}

#[tauri::command]
fn run_wsl(args: Vec<String>) -> Result<CliResult, String> {
    let output = Command::new("wsl")
        .args(&args)
        .output()
        .map_err(|e| format!("failed to run wsl CLI (is it on PATH?): {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(if stderr.is_empty() { stdout } else { stderr });
    }
    Ok(CliResult { output: stdout })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![run_wsl])
        .setup(|app| {
            let _ = app.get_webview_window("main");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running WSL desktop");
}
