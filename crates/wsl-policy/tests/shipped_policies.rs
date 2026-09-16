//! The policies shipped in `gitops/examples` are the first thing an operator
//! copies. Nothing was checking that they parse, so a field renamed in the
//! struct could leave a broken example in the repository indefinitely — and
//! the failure would land on somebody setting the product up for the first
//! time.

use std::path::{Path, PathBuf};
use wsl_policy::parse_policy_yaml;

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../gitops/examples/policies")
}

fn shipped_policies() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(examples_dir())
        .expect("gitops/examples/policies should exist")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yaml" || e == "yml")
        })
        .collect();
    paths.sort();
    paths
}

#[test]
fn every_shipped_policy_parses() {
    let paths = shipped_policies();
    assert!(!paths.is_empty(), "no example policies found to check");
    for path in paths {
        let yaml = std::fs::read_to_string(&path).expect("read policy");
        let parsed = parse_policy_yaml(&yaml);
        assert!(
            parsed.is_ok(),
            "{} does not parse: {:?}",
            path.display(),
            parsed.err()
        );
    }
}

/// A policy that names no subjects matches nobody — `matches_subjects` returns
/// false for an empty subject list — so it is silently dead. An example that
/// does nothing is worse than no example.
#[test]
fn every_shipped_policy_can_match_somebody() {
    for path in shipped_policies() {
        let yaml = std::fs::read_to_string(&path).expect("read policy");
        let doc = parse_policy_yaml(&yaml).expect("parse");
        let subjects = &doc.spec.subjects;
        assert!(
            !subjects.groups.is_empty() || !subjects.users.is_empty(),
            "{} names no subjects, so it can never match",
            path.display()
        );
        assert!(
            !doc.spec.resources.is_empty(),
            "{} names no resources",
            path.display()
        );
    }
}

/// A signal name is a contract between the policy and the agent. A policy
/// requiring a name the agent never emits denies forever, and looks like a
/// configuration problem rather than a typo.
#[test]
fn required_signals_name_something_the_agent_actually_reports() {
    // The agent's own constants, duplicated deliberately: wsl-policy does not
    // depend on wsl-agent, and this test is the thing that would catch them
    // drifting apart.
    const KNOWN: [&str; 5] = [
        "os_version",
        "agent_version",
        "disk_encryption",
        "device_management",
        "firewall",
    ];
    for path in shipped_policies() {
        let yaml = std::fs::read_to_string(&path).expect("read policy");
        let doc = parse_policy_yaml(&yaml).expect("parse");
        for signal in &doc.spec.device.required_signals {
            assert!(
                KNOWN.contains(&signal.as_str()),
                "{} requires '{signal}', which no agent reports; known: {KNOWN:?}",
                path.display()
            );
        }
    }
}
