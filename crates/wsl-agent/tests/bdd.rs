//! Cucumber specs for the agent: tests/features/*.feature.
//!
//! The stand-in `wg-quick` the steps install is a shell script, and the
//! permission checks are POSIX modes, so the specs run on macOS and Linux. On
//! Windows the tunnel goes through `wireguard.exe`, whose command planning is
//! unit-tested in `src/tunnel_windows.rs` on every platform.

#[cfg(unix)]
include!("bdd/steps.rs");

#[cfg(not(unix))]
fn main() {}
