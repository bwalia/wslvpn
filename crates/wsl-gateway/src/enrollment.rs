//! Persistence of the gateway's own credential.
//!
//! The control plane discloses a gateway's credential exactly once, at
//! enrollment. Keeping it on disk means a restart resumes with the same
//! identity instead of re-enrolling, which matters because re-enrollment is
//! rate-limited by design and, on a control plane where the shared enrollment
//! secret has been retired, may not be possible at all.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrollment {
    pub gateway_id: Uuid,
    pub auth_token: String,
}

pub fn path(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("enrollment.json")
}

/// Read a stored enrollment, if there is one.
///
/// A malformed or unreadable file is treated as "not enrolled" rather than a
/// fatal error: the gateway can always recover by enrolling again, and refusing
/// to start over a corrupt cache file would turn a recoverable state into an
/// outage.
pub fn load(state_dir: &str) -> Option<Enrollment> {
    let p = path(state_dir);
    let raw = std::fs::read_to_string(&p).ok()?;
    match serde_json::from_str(&raw) {
        Ok(e) => Some(e),
        Err(err) => {
            tracing::warn!(path = %p.display(), error = %err, "ignoring unreadable enrollment");
            None
        }
    }
}

/// Persist an enrollment, readable only by the gateway's own user.
pub fn store(state_dir: &str, enrollment: &Enrollment) -> Result<()> {
    std::fs::create_dir_all(state_dir).with_context(|| format!("create state dir {state_dir}"))?;
    let p = path(state_dir);
    let body = serde_json::to_string_pretty(enrollment)?;

    // Create with restrictive permissions before any bytes are written, rather
    // than writing first and tightening after: the widened window in between is
    // exactly when another local process could read the credential.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&p)
            .with_context(|| format!("open {}", p.display()))?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    std::fs::write(&p, body.as_bytes()).with_context(|| format!("write {}", p.display()))?;

    Ok(())
}

/// Forget a stored enrollment after the control plane has rejected it.
pub fn clear(state_dir: &str) {
    let p = path(state_dir);
    if let Err(e) = std::fs::remove_file(&p) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(path = %p.display(), error = %e, "could not remove stale enrollment");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> String {
        let dir =
            std::env::temp_dir().join(format!("wsl-enroll-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn round_trips_an_enrollment() {
        let dir = temp_dir("roundtrip");
        let e = Enrollment {
            gateway_id: Uuid::new_v4(),
            auth_token: "token-value".into(),
        };
        store(&dir, &e).unwrap();
        let back = load(&dir).expect("stored enrollment should load");
        assert_eq!(back.gateway_id, e.gateway_id);
        assert_eq!(back.auth_token, e.auth_token);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_state_dir_reads_as_not_enrolled() {
        assert!(load(&temp_dir("absent")).is_none());
    }

    #[test]
    fn corrupt_file_reads_as_not_enrolled_rather_than_failing() {
        let dir = temp_dir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(path(&dir), b"{not json").unwrap();
        assert!(load(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn credential_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        store(
            &dir,
            &Enrollment {
                gateway_id: Uuid::new_v4(),
                auth_token: "secret".into(),
            },
        )
        .unwrap();
        let mode = std::fs::metadata(path(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "group and other must have no access");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_removes_the_credential_and_is_idempotent() {
        let dir = temp_dir("clear");
        store(
            &dir,
            &Enrollment {
                gateway_id: Uuid::new_v4(),
                auth_token: "secret".into(),
            },
        )
        .unwrap();
        clear(&dir);
        assert!(load(&dir).is_none());
        clear(&dir); // second call must not panic
        let _ = std::fs::remove_dir_all(&dir);
    }
}
