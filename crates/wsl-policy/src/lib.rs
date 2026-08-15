//! Policy-as-code compilation and fail-closed evaluation.

use chrono::Duration;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wsl_types::{PolicyDecision, PostureResult, PostureSignal};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid policy document: {0}")]
    Invalid(String),
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicyDocument {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: PolicyMetadata,
    pub spec: AccessPolicySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicySpec {
    pub subjects: PolicySubjects,
    pub resources: Vec<String>,
    #[serde(default)]
    pub device: DeviceRequirements,
    #[serde(default)]
    pub session: SessionRequirements,
    #[serde(default)]
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicySubjects {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRequirements {
    #[serde(default)]
    pub managed: Option<bool>,
    #[serde(default)]
    pub compliant: Option<bool>,
}

impl Default for DeviceRequirements {
    fn default() -> Self {
        Self {
            managed: None,
            compliant: Some(true),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequirements {
    #[serde(default = "default_duration", with = "humantime_serde_compat")]
    pub duration: Duration,
}

mod humantime_serde_compat {
    use chrono::Duration;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let secs = value.num_seconds();
        let s = if secs % 3600 == 0 {
            format!("{}h", secs / 3600)
        } else if secs % 60 == 0 {
            format!("{}m", secs / 60)
        } else {
            format!("{secs}s")
        };
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_duration(&s).map_err(serde::de::Error::custom)
    }

    fn parse_duration(s: &str) -> Result<Duration, String> {
        let s = s.trim();
        if let Some(h) = s.strip_suffix('h') {
            let n: i64 = h.parse().map_err(|e| format!("{e}"))?;
            return Ok(Duration::hours(n));
        }
        if let Some(m) = s.strip_suffix('m') {
            let n: i64 = m.parse().map_err(|e| format!("{e}"))?;
            return Ok(Duration::minutes(n));
        }
        if let Some(sec) = s.strip_suffix('s') {
            let n: i64 = sec.parse().map_err(|e| format!("{e}"))?;
            return Ok(Duration::seconds(n));
        }
        Err(format!("invalid duration: {s}"))
    }
}

fn default_duration() -> Duration {
    Duration::hours(8)
}

impl Default for SessionRequirements {
    fn default() -> Self {
        Self {
            duration: default_duration(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAction {
    #[serde(default = "default_true")]
    pub connect: bool,
}

fn default_true() -> bool {
    true
}

impl Default for PolicyAction {
    fn default() -> Self {
        Self { connect: true }
    }
}

pub fn parse_policy_yaml(yaml: &str) -> Result<AccessPolicyDocument, PolicyError> {
    let doc: AccessPolicyDocument = serde_yaml::from_str(yaml)?;
    if doc.api_version != "wsl.io/v1" {
        return Err(PolicyError::Invalid(format!(
            "unsupported apiVersion: {}",
            doc.api_version
        )));
    }
    if doc.kind != "AccessPolicy" {
        return Err(PolicyError::Invalid(format!(
            "unsupported kind: {}",
            doc.kind
        )));
    }
    if doc.metadata.name.is_empty() {
        return Err(PolicyError::Invalid("metadata.name required".into()));
    }
    Ok(doc)
}

pub struct EvaluationInput<'a> {
    pub user_email: &'a str,
    pub groups: &'a [String],
    pub resource: &'a str,
    pub posture: &'a [PostureSignal],
    pub device_managed: bool,
}

/// Fail-closed: deny unless an explicit matching allow policy is found.
pub fn evaluate(policies: &[AccessPolicyDocument], input: &EvaluationInput<'_>) -> PolicyDecision {
    for policy in policies {
        if !matches_subjects(policy, input) {
            continue;
        }
        if !policy
            .spec
            .resources
            .iter()
            .any(|r| r == input.resource || r == "*")
        {
            continue;
        }
        if !device_ok(policy, input) {
            return PolicyDecision {
                allow: false,
                policy_id: None,
                policy_name: Some(policy.metadata.name.clone()),
                policy_version: None,
                git_commit: None,
                reason: "device posture or managed requirements not met".into(),
                resources: vec![],
                session_duration_secs: None,
            };
        }
        if !policy.spec.action.connect {
            return PolicyDecision {
                allow: false,
                policy_id: None,
                policy_name: Some(policy.metadata.name.clone()),
                policy_version: None,
                git_commit: None,
                reason: "policy action.connect is false".into(),
                resources: vec![],
                session_duration_secs: None,
            };
        }
        return PolicyDecision {
            allow: true,
            policy_id: None,
            policy_name: Some(policy.metadata.name.clone()),
            policy_version: None,
            git_commit: None,
            reason: "matched access policy".into(),
            resources: policy.spec.resources.clone(),
            session_duration_secs: Some(policy.spec.session.duration.num_seconds()),
        };
    }

    PolicyDecision {
        allow: false,
        policy_id: None,
        policy_name: None,
        policy_version: None,
        git_commit: None,
        reason: "no matching policy (fail-closed)".into(),
        resources: vec![],
        session_duration_secs: None,
    }
}

fn matches_subjects(policy: &AccessPolicyDocument, input: &EvaluationInput<'_>) -> bool {
    let subjects = &policy.spec.subjects;
    if subjects.groups.is_empty() && subjects.users.is_empty() {
        return false;
    }
    let group_match = subjects
        .groups
        .iter()
        .any(|g| input.groups.iter().any(|ug| ug == g));
    let user_match = subjects.users.iter().any(|u| u == input.user_email);
    group_match || user_match
}

fn device_ok(policy: &AccessPolicyDocument, input: &EvaluationInput<'_>) -> bool {
    if let Some(true) = policy.spec.device.managed {
        if !input.device_managed {
            return false;
        }
    }
    if let Some(true) = policy.spec.device.compliant {
        let failed = input
            .posture
            .iter()
            .any(|p| p.result == PostureResult::Fail);
        if failed {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
apiVersion: wsl.io/v1
kind: AccessPolicy
metadata:
  name: developers-registry
spec:
  subjects:
    groups:
      - developers
  resources:
    - registry
  device:
    managed: true
    compliant: true
  session:
    duration: 8h
"#;

    #[test]
    fn parses_and_allows() {
        let doc = parse_policy_yaml(SAMPLE).unwrap();
        let decision = evaluate(
            &[doc],
            &EvaluationInput {
                user_email: "alice@example.com",
                groups: &["developers".into()],
                resource: "registry",
                posture: &[],
                device_managed: true,
            },
        );
        assert!(decision.allow);
        assert_eq!(decision.session_duration_secs, Some(8 * 3600));
    }

    #[test]
    fn deny_without_match() {
        let doc = parse_policy_yaml(SAMPLE).unwrap();
        let decision = evaluate(
            &[doc],
            &EvaluationInput {
                user_email: "bob@example.com",
                groups: &["contractors".into()],
                resource: "registry",
                posture: &[],
                device_managed: true,
            },
        );
        assert!(!decision.allow);
    }
}
