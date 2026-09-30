//! Routing overridden names to the local resolver, the macOS way.
//!
//! macOS reads a file per domain from `/etc/resolver` (resolver(5)): a file
//! named `example.com` holding `nameserver 127.0.0.1` and `port 15353` sends
//! every lookup for example.com and its subdomains to that address. That is
//! what lets the resolver run as the user on an unprivileged port — only the
//! overridden domains are routed to it, and the system's own DNS, whether the
//! ISP's or the VPN's, keeps answering everything else.
//!
//! The directory is shared with anything else on the machine that does the
//! same (Docker, dnsmasq, puma-dev), so every file written here carries a
//! marker line, and only marked files are ever replaced or removed.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::hosts::normalise;

pub const RESOLVER_DIR: &str = "/etc/resolver";
pub const MARKER: &str =
    "# Managed by WSL Zero Trust (`wsl dns`). Do not edit; `wsl dns apply` rewrites it.";

/// The file for one domain.
pub fn render(address: IpAddr, port: u16) -> String {
    format!("{MARKER}\nnameserver {address}\nport {port}\n")
}

/// What a sync did, for the caller to report.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub written: Vec<String>,
    pub removed: Vec<String>,
    /// Domains with a file here that someone else owns. Left alone.
    pub skipped: Vec<String>,
}

/// Make `dir` route exactly `domains` to `address:port`.
///
/// Files for domains no longer wanted are removed if and only if they carry
/// the marker. Runs as root, so every domain is re-validated here rather than
/// trusted from the caller.
pub fn sync(dir: &Path, domains: &[String], address: IpAddr, port: u16) -> Result<SyncReport> {
    let wanted: BTreeSet<String> = domains
        .iter()
        .map(|d| normalise(d).map_err(anyhow::Error::msg))
        .collect::<Result<_>>()?;
    if let Some(wild) = wanted.iter().find(|d| d.starts_with('*')) {
        bail!("`{wild}` is a wildcard; route its suffix instead");
    }

    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut report = SyncReport::default();
    let body = render(address, port);

    for domain in &wanted {
        let path = dir.join(domain);
        match std::fs::read_to_string(&path) {
            Ok(existing) if !is_ours(&existing) => {
                report.skipped.push(domain.clone());
                continue;
            }
            Ok(existing) if existing == body => continue,
            _ => {}
        }
        std::fs::write(&path, &body).with_context(|| format!("writing {}", path.display()))?;
        report.written.push(domain.clone());
    }

    for entry in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if wanted.contains(&name) || !entry.file_type()?.is_file() {
            continue;
        }
        let ours = std::fs::read_to_string(entry.path())
            .map(|t| is_ours(&t))
            .unwrap_or(false);
        if ours {
            std::fs::remove_file(entry.path())
                .with_context(|| format!("removing {}", entry.path().display()))?;
            report.removed.push(name);
        }
    }
    report.removed.sort();
    Ok(report)
}

fn is_ours(text: &str) -> bool {
    text.lines().next() == Some(MARKER)
}

/// The domains currently routed by files this module wrote.
pub fn routed(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            std::fs::read_to_string(e.path())
                .map(|t| is_ours(&t))
                .unwrap_or(false)
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wsl-resolver-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn localhost() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[test]
    fn the_file_is_what_resolver5_expects() {
        assert_eq!(
            render(localhost(), 15353),
            format!("{MARKER}\nnameserver 127.0.0.1\nport 15353\n")
        );
    }

    #[test]
    fn sync_writes_one_file_per_domain() {
        let dir = scratch("write");
        let r = sync(
            &dir,
            &["a.example.com".into(), "dev.example.com".into()],
            localhost(),
            15353,
        )
        .unwrap();
        assert_eq!(r.written, vec!["a.example.com", "dev.example.com"]);
        assert_eq!(routed(&dir), vec!["a.example.com", "dev.example.com"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_identical_sync_writes_nothing() {
        let dir = scratch("idem");
        sync(&dir, &["a.example.com".into()], localhost(), 15353).unwrap();
        let r = sync(&dir, &["a.example.com".into()], localhost(), 15353).unwrap();
        assert_eq!(r, SyncReport::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn domains_no_longer_wanted_are_removed() {
        let dir = scratch("remove");
        sync(
            &dir,
            &["a.example.com".into(), "b.example.com".into()],
            localhost(),
            15353,
        )
        .unwrap();
        let r = sync(&dir, &["a.example.com".into()], localhost(), 15353).unwrap();
        assert_eq!(r.removed, vec!["b.example.com"]);
        assert_eq!(routed(&dir), vec!["a.example.com"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Docker and dnsmasq put their own files in /etc/resolver. Touching them
    /// would break the user's other tools.
    #[test]
    fn files_someone_else_wrote_are_never_touched() {
        let dir = scratch("foreign");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("docker.internal"), "nameserver 127.0.0.1\n").unwrap();
        std::fs::write(dir.join("a.example.com"), "nameserver 10.0.0.1\n").unwrap();
        let r = sync(&dir, &["a.example.com".into()], localhost(), 15353).unwrap();
        assert_eq!(r.skipped, vec!["a.example.com"]);
        assert!(r.removed.is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.join("docker.internal")).unwrap(),
            "nameserver 127.0.0.1\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("a.example.com")).unwrap(),
            "nameserver 10.0.0.1\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_sync_clears_only_our_files() {
        let dir = scratch("clear");
        sync(&dir, &["a.example.com".into()], localhost(), 15353).unwrap();
        std::fs::write(dir.join("other.test"), "nameserver 127.0.0.1\n").unwrap();
        sync(&dir, &[], localhost(), 15353).unwrap();
        assert!(routed(&dir).is_empty());
        assert!(dir.join("other.test").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_traversal_domain_is_refused_before_anything_is_written() {
        let dir = scratch("traversal");
        let err = sync(
            &dir,
            &["ok.example.com".into(), "../../evil".into()],
            localhost(),
            15353,
        );
        assert!(err.is_err());
        assert!(!dir.join("ok.example.com").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
