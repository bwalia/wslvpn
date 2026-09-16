//! What the endpoint can say about itself.
//!
//! Posture used to be four hardcoded values: the platform triple, the agent
//! version, `disk_encryption: Unknown` and `device_management: Unsupported`.
//! Nothing was measured, so no device could ever fail a compliance check, and a
//! policy asking for `compliant: true` was satisfied by every machine that
//! asked.
//!
//! These signals are read from the operating system. None of the checks needs
//! root — a posture check that prompts for a password is a posture check that
//! gets skipped.
//!
//! What a signal cannot do is prove anything. Everything here is the endpoint's
//! own account of itself, and an endpoint that has been taken over will say
//! whatever its owner wants. Posture raises the cost of using a compromised or
//! careless device; it is not an authentication control, and the control plane
//! treats it as one input among several.
//!
//! The parsers are compiled on every platform so that the macOS ones are still
//! covered when the suite runs on Linux.

#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
use wsl_types::{PostureResult, PostureSignal};

/// Names are a contract: a policy that requires a signal names it, so renaming
/// one silently stops that requirement from matching anything.
pub const DISK_ENCRYPTION: &str = "disk_encryption";
pub const DEVICE_MANAGEMENT: &str = "device_management";
pub const FIREWALL: &str = "firewall";
pub const OS_VERSION: &str = "os_version";
pub const AGENT_VERSION: &str = "agent_version";

pub fn collect() -> Vec<PostureSignal> {
    let mut signals =
        vec![
            signal(
                OS_VERSION,
                PostureResult::Pass,
                Some(os_version().unwrap_or_else(|| {
                    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
                })),
            ),
            signal(
                AGENT_VERSION,
                PostureResult::Pass,
                Some(env!("CARGO_PKG_VERSION").into()),
            ),
        ];
    signals.extend(platform_signals());
    signals
}

fn signal(name: &str, result: PostureResult, detail: Option<String>) -> PostureSignal {
    PostureSignal {
        name: name.to_string(),
        result,
        detail,
    }
}

/// Run a read-only check and return its stdout.
///
/// A check that cannot run produces `None`, which becomes `Unknown` rather than
/// a pass — the control plane decides what an unanswered question is worth.
///
/// macOS-only: every Linux signal is read from a file, which is one less binary
/// to depend on and cannot be shadowed by something earlier on `PATH`.
#[cfg(target_os = "macos")]
fn capture(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "macos")]
fn os_version() -> Option<String> {
    let version = capture("sw_vers", &["-productVersion"])?;
    let build = capture("sw_vers", &["-buildVersion"]);
    let version = version.trim();
    Some(match build {
        Some(build) if !build.trim().is_empty() => format!("macOS {version} ({})", build.trim()),
        _ => format!("macOS {version}"),
    })
}

#[cfg(target_os = "linux")]
fn os_version() -> Option<String> {
    let release = std::fs::read_to_string("/etc/os-release").ok()?;
    parse_os_release(&release)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn os_version() -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn platform_signals() -> Vec<PostureSignal> {
    let (disk, disk_detail) = match capture("fdesetup", &["status"]) {
        Some(output) => parse_filevault(&output),
        None => (PostureResult::Unknown, Some("fdesetup did not run".into())),
    };
    let (mdm, mdm_detail) = match capture("profiles", &["status", "-type", "enrollment"]) {
        Some(output) => parse_mdm_enrollment(&output),
        None => (PostureResult::Unknown, Some("profiles did not run".into())),
    };
    let (firewall, firewall_detail) = match capture(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    ) {
        Some(output) => parse_firewall(&output),
        None => (
            PostureResult::Unknown,
            Some("socketfilterfw did not run".into()),
        ),
    };
    vec![
        signal(DISK_ENCRYPTION, disk, disk_detail),
        signal(DEVICE_MANAGEMENT, mdm, mdm_detail),
        signal(FIREWALL, firewall, firewall_detail),
    ]
}

#[cfg(target_os = "linux")]
fn platform_signals() -> Vec<PostureSignal> {
    let (disk, disk_detail) = dm_crypt_status();
    vec![
        signal(DISK_ENCRYPTION, disk, disk_detail),
        // Linux has no single enrolment mechanism to interrogate, and guessing
        // from the presence of some agent would be worse than saying so.
        signal(
            DEVICE_MANAGEMENT,
            PostureResult::Unsupported,
            Some("no enrolment mechanism to query on this platform".into()),
        ),
        signal(
            FIREWALL,
            PostureResult::Unsupported,
            Some("no single firewall to query on this platform".into()),
        ),
    ]
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_signals() -> Vec<PostureSignal> {
    vec![
        signal(DISK_ENCRYPTION, PostureResult::Unsupported, None),
        signal(DEVICE_MANAGEMENT, PostureResult::Unsupported, None),
        signal(FIREWALL, PostureResult::Unsupported, None),
    ]
}

/// Look for a dm-crypt mapping.
///
/// Reading sysfs rather than shelling out to `lsblk`: it is one less binary to
/// depend on, and the answer is a filename. Every dm device records a UUID, and
/// a LUKS or plain dm-crypt one is prefixed `CRYPT-`.
#[cfg(target_os = "linux")]
fn dm_crypt_status() -> (PostureResult, Option<String>) {
    let Ok(entries) = std::fs::read_dir("/sys/class/block") else {
        return (
            PostureResult::Unknown,
            Some("/sys/class/block is not readable".into()),
        );
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let uuid_path = entry.path().join("dm/uuid");
        if let Ok(uuid) = std::fs::read_to_string(&uuid_path) {
            if uuid.trim_start().starts_with("CRYPT-") {
                found.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    if found.is_empty() {
        (PostureResult::Fail, Some("no dm-crypt volume found".into()))
    } else {
        found.sort();
        (
            PostureResult::Pass,
            Some(format!("dm-crypt: {}", found.join(", "))),
        )
    }
}

/// `fdesetup status` prints one of a small set of sentences.
pub fn parse_filevault(output: &str) -> (PostureResult, Option<String>) {
    let text = output.trim();
    let first = text.lines().next().unwrap_or("").trim().to_string();

    // Conversion is checked ahead of the headline, because `fdesetup` starts
    // saying "FileVault is On." the moment encryption begins. A disk part-way
    // through its first pass is not yet protected, and one part-way through
    // decryption is having its protection removed; neither is a pass. The whole
    // output becomes the detail so the percentage reaches the user.
    if text.contains("Encryption in progress") || text.contains("Decryption in progress") {
        let detail = text.lines().map(str::trim).collect::<Vec<_>>().join("; ");
        return (PostureResult::Fail, Some(detail));
    }

    if text.starts_with("FileVault is On") {
        (PostureResult::Pass, Some(first))
    } else if text.starts_with("FileVault is Off") {
        (PostureResult::Fail, Some(first))
    } else if first.is_empty() {
        (PostureResult::Unknown, None)
    } else {
        (PostureResult::Unknown, Some(first))
    }
}

/// `profiles status -type enrollment` prints two lines:
///
/// ```text
/// Enrolled via DEP: No
/// MDM enrollment: Yes (User Approved)
/// ```
///
/// Only the MDM line decides the result; DEP is carried in the detail because
/// it is the difference between a device enrolled at first boot and one somebody
/// enrolled later, which an operator reading an audit log will want.
pub fn parse_mdm_enrollment(output: &str) -> (PostureResult, Option<String>) {
    let mut dep = None;
    let mut mdm = None;
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        match key.trim() {
            "Enrolled via DEP" => dep = Some(value),
            "MDM enrollment" => mdm = Some(value),
            _ => {}
        }
    }
    let Some(mdm) = mdm else {
        return (
            PostureResult::Unknown,
            Some("no MDM enrollment line in output".into()),
        );
    };
    let detail = match &dep {
        Some(dep) => format!("MDM: {mdm}; DEP: {dep}"),
        None => format!("MDM: {mdm}"),
    };
    // "Yes (User Approved)" and a bare "Yes" are both enrolled.
    let result = if mdm.starts_with("Yes") {
        PostureResult::Pass
    } else if mdm.starts_with("No") {
        PostureResult::Fail
    } else {
        PostureResult::Unknown
    };
    (result, Some(detail))
}

/// `socketfilterfw --getglobalstate` prints
/// `Firewall is enabled. (State = 1)` or `Firewall is disabled. (State = 0)`.
pub fn parse_firewall(output: &str) -> (PostureResult, Option<String>) {
    let first = output
        .trim()
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if first.contains("State = 0") || first.contains("disabled") {
        (PostureResult::Fail, Some(first))
    } else if first.contains("State = 1")
        || first.contains("State = 2")
        || first.contains("enabled")
    {
        (PostureResult::Pass, Some(first))
    } else if first.is_empty() {
        (PostureResult::Unknown, None)
    } else {
        (PostureResult::Unknown, Some(first))
    }
}

/// Pull `PRETTY_NAME` out of an os-release file, falling back to `NAME`.
pub fn parse_os_release(contents: &str) -> Option<String> {
    let mut name = None;
    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim() {
            "PRETTY_NAME" => return Some(value),
            "NAME" => name = Some(value),
            _ => {}
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filevault_on_is_a_pass() {
        let (result, detail) = parse_filevault("FileVault is On.\n");
        assert_eq!(result, PostureResult::Pass);
        assert_eq!(detail.as_deref(), Some("FileVault is On."));
    }

    #[test]
    fn filevault_off_is_a_failure_not_an_unknown() {
        let (result, _) = parse_filevault("FileVault is Off.\n");
        assert_eq!(result, PostureResult::Fail);
    }

    /// `fdesetup` says "On" as soon as encryption starts, so the headline alone
    /// would pass a disk that is only 41% protected.
    #[test]
    fn encryption_in_progress_does_not_pass_yet() {
        let (result, detail) =
            parse_filevault("FileVault is On.\nEncryption in progress; Percent completed = 41\n");
        assert_eq!(result, PostureResult::Fail);
        assert_eq!(
            detail.as_deref(),
            Some("FileVault is On.; Encryption in progress; Percent completed = 41")
        );
    }

    /// Protection being removed is not protection.
    #[test]
    fn decryption_in_progress_does_not_pass_either() {
        let (result, _) =
            parse_filevault("FileVault is On.\nDecryption in progress; Percent completed = 8\n");
        assert_eq!(result, PostureResult::Fail);
    }

    #[test]
    fn filevault_pending_a_restart_is_not_on_yet() {
        let (result, _) =
            parse_filevault("FileVault is Off, but will be enabled after the next restart.\n");
        assert_eq!(result, PostureResult::Fail);
    }

    #[test]
    fn unrecognised_filevault_output_is_unknown() {
        assert_eq!(parse_filevault("").0, PostureResult::Unknown);
        assert_eq!(
            parse_filevault("Error: not authorized\n").0,
            PostureResult::Unknown
        );
    }

    #[test]
    fn an_enrolled_mac_passes_and_keeps_the_dep_detail() {
        let (result, detail) =
            parse_mdm_enrollment("Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\n");
        assert_eq!(result, PostureResult::Pass);
        assert_eq!(
            detail.as_deref(),
            Some("MDM: Yes (User Approved); DEP: Yes")
        );
    }

    #[test]
    fn an_unenrolled_mac_fails() {
        let (result, detail) = parse_mdm_enrollment("Enrolled via DEP: No\nMDM enrollment: No\n");
        assert_eq!(result, PostureResult::Fail);
        assert_eq!(detail.as_deref(), Some("MDM: No; DEP: No"));
    }

    #[test]
    fn missing_the_mdm_line_is_unknown_not_a_pass() {
        let (result, _) = parse_mdm_enrollment("Enrolled via DEP: No\n");
        assert_eq!(result, PostureResult::Unknown);
    }

    #[test]
    fn the_firewall_state_line_is_read_both_ways() {
        assert_eq!(
            parse_firewall("Firewall is enabled. (State = 1)\n").0,
            PostureResult::Pass
        );
        assert_eq!(
            parse_firewall("Firewall is disabled. (State = 0)\n").0,
            PostureResult::Fail
        );
        // State 2 is "block all incoming", which is stricter, not weaker.
        assert_eq!(
            parse_firewall("Firewall is enabled. (State = 2)\n").0,
            PostureResult::Pass
        );
        assert_eq!(parse_firewall("").0, PostureResult::Unknown);
    }

    #[test]
    fn os_release_prefers_the_pretty_name() {
        let release = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n\
                       PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n";
        assert_eq!(
            parse_os_release(release).as_deref(),
            Some("Ubuntu 24.04.1 LTS")
        );
    }

    #[test]
    fn os_release_falls_back_to_the_bare_name() {
        assert_eq!(
            parse_os_release("NAME=\"Alpine Linux\"\nID=alpine\n").as_deref(),
            Some("Alpine Linux")
        );
        assert_eq!(parse_os_release("ID=weird\n"), None);
    }

    /// Whatever the platform, the set of names a policy can require is fixed.
    #[test]
    fn every_signal_is_reported_on_every_platform() {
        let signals = collect();
        let names: Vec<&str> = signals.iter().map(|s| s.name.as_str()).collect();
        for expected in [
            OS_VERSION,
            AGENT_VERSION,
            DISK_ENCRYPTION,
            DEVICE_MANAGEMENT,
            FIREWALL,
        ] {
            assert!(
                names.contains(&expected),
                "{expected} missing from {names:?}"
            );
        }
    }

    #[test]
    fn the_os_version_signal_is_never_empty() {
        let signals = collect();
        let os = signals
            .iter()
            .find(|s| s.name == OS_VERSION)
            .expect("os_version");
        assert!(os.detail.as_deref().is_some_and(|d| !d.is_empty()));
    }
}
