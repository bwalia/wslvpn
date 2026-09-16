#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    wsl_desktop_lib::run_app();
}
