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
    /// Signals that must individually pass, by name.
    ///
    /// Naming any replaces the blanket `compliant` check: an operator who says
    /// precisely which checks matter has said that the others do not. It is the
    /// way to require full-disk encryption without also requiring every machine
    /// to be MDM-enrolled and running the firewall.
    #[serde(default, rename = "requiredSignals")]
    pub required_signals: Vec<String>,
}

impl Default for DeviceRequirements {
    fn default() -> Self {
        Self {
            managed: None,
            compliant: Some(true),
            required_signals: Vec::new(),
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

/// The signal name that answers `device.managed`.
pub const DEVICE_MANAGEMENT_SIGNAL: &str = "device_management";

/// Whether the endpoint reports itself as enrolled in device management.
///
/// This is the device's own account of itself, which is weaker than a record
/// the administrator keeps: an endpoint that has been taken over will claim
/// whatever its owner wants. It is nonetheless what the control plane has, and
/// it is strictly better than the constant `true` that stood here before, which
/// made `device.managed` satisfied by every device that ever asked.
///
/// `Unsupported` is deliberately not enough. The blanket compliance check
/// forgives a platform that has no such concept, because denying there would
/// make a policy unsatisfiable rather than express anything. An operator who
/// writes `managed: true` has asked a specific question, and "this platform
/// cannot tell you" is not a yes.
pub fn device_reports_managed(posture: &[PostureSignal]) -> bool {
    posture
        .iter()
        .any(|s| s.name == DEVICE_MANAGEMENT_SIGNAL && s.result == PostureResult::Pass)
}

/// Whether the device satisfies what the policy asks of it.
///
/// The compliance rule is fail-closed, in line with the rest of evaluation.
/// Three of the four results are distinct things and are treated as such:
///
/// * `Pass` — the check ran and the device is in the required state.
/// * `Fail` — the check ran and it is not.
/// * `Unknown` — the check could not run. This is *not* a pass. An agent that
///   cannot read FileVault's state has told us nothing, and treating silence
///   as compliance is how a compliance requirement becomes decorative.
/// * `Unsupported` — the platform has no such concept. Denying here would make
///   the policy unsatisfiable on that platform rather than express anything, so
///   it passes.
///
/// A device that reports no signals at all satisfies nothing: `all()` over an
/// empty list is vacuously true, and an agent that sends an empty posture array
/// must not be the one case that gets in.
fn device_ok(policy: &AccessPolicyDocument, input: &EvaluationInput<'_>) -> bool {
    if let Some(true) = policy.spec.device.managed {
        if !input.device_managed {
            return false;
        }
    }

    let required = &policy.spec.device.required_signals;
    if !required.is_empty() {
        return required.iter().all(|name| {
            input
                .posture
                .iter()
                .any(|s| &s.name == name && s.result == PostureResult::Pass)
        });
    }

    if let Some(true) = policy.spec.device.compliant {
        if input.posture.is_empty() {
            return false;
        }
        return input
            .posture
            .iter()
            .all(|s| matches!(s.result, PostureResult::Pass | PostureResult::Unsupported));
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

    fn signal(name: &str, result: PostureResult) -> PostureSignal {
        PostureSignal {
            name: name.into(),
            result,
            detail: None,
        }
    }

    fn healthy() -> Vec<PostureSignal> {
        vec![
            signal("disk_encryption", PostureResult::Pass),
            signal("firewall", PostureResult::Pass),
            signal("device_management", PostureResult::Unsupported),
        ]
    }

    fn decide(yaml: &str, posture: &[PostureSignal]) -> PolicyDecision {
        let doc = parse_policy_yaml(yaml).unwrap();
        evaluate(
            &[doc],
            &EvaluationInput {
                user_email: "alice@example.com",
                groups: &["developers".into()],
                resource: "registry",
                posture,
                device_managed: true,
            },
        )
    }

    #[test]
    fn parses_and_allows() {
        let decision = decide(SAMPLE, &healthy());
        assert!(decision.allow, "{}", decision.reason);
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
                posture: &healthy(),
                device_managed: true,
            },
        );
        assert!(!decision.allow);
    }

    #[test]
    fn a_failing_signal_denies() {
        let mut posture = healthy();
        posture[0] = signal("disk_encryption", PostureResult::Fail);
        assert!(!decide(SAMPLE, &posture).allow);
    }

    /// The check that used to be missing. A device that cannot answer has not
    /// answered, and a compliance requirement that accepts silence is not one.
    #[test]
    fn an_unknown_signal_denies_rather_than_passing_quietly() {
        let mut posture = healthy();
        posture[0] = signal("disk_encryption", PostureResult::Unknown);
        let decision = decide(SAMPLE, &posture);
        assert!(!decision.allow, "{}", decision.reason);
    }

    /// Denying here would make the policy unsatisfiable on the platform rather
    /// than express anything about it.
    #[test]
    fn an_unsupported_signal_does_not_deny() {
        let posture = vec![
            signal("disk_encryption", PostureResult::Pass),
            signal("device_management", PostureResult::Unsupported),
        ];
        assert!(decide(SAMPLE, &posture).allow);
    }

    /// `all()` over nothing is true, so this is the case that has to be closed
    /// deliberately: an agent sending an empty posture array must not be the
    /// one caller that satisfies every requirement.
    #[test]
    fn reporting_no_posture_at_all_satisfies_nothing() {
        assert!(!decide(SAMPLE, &[]).allow);
    }

    const REQUIRES_ENCRYPTION: &str = r#"
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
    requiredSignals:
      - disk_encryption
  session:
    duration: 8h
"#;

    #[test]
    fn naming_a_signal_requires_that_one_and_forgives_the_rest() {
        let posture = vec![
            signal("disk_encryption", PostureResult::Pass),
            // Both of these would sink a blanket `compliant: true`.
            signal("firewall", PostureResult::Fail),
            signal("device_management", PostureResult::Unknown),
        ];
        let decision = decide(REQUIRES_ENCRYPTION, &posture);
        assert!(decision.allow, "{}", decision.reason);
    }

    #[test]
    fn a_named_signal_that_fails_still_denies() {
        let posture = vec![signal("disk_encryption", PostureResult::Fail)];
        assert!(!decide(REQUIRES_ENCRYPTION, &posture).allow);
    }

    /// A required signal the device never sent is not satisfied by its absence.
    #[test]
    fn a_named_signal_that_is_missing_denies() {
        let posture = vec![signal("firewall", PostureResult::Pass)];
        assert!(!decide(REQUIRES_ENCRYPTION, &posture).allow);
    }

    #[test]
    fn management_is_read_from_the_signal_the_device_reported() {
        assert!(device_reports_managed(&[signal(
            "device_management",
            PostureResult::Pass
        )]));
        assert!(!device_reports_managed(&[signal(
            "device_management",
            PostureResult::Fail
        )]));
    }

    /// The three ways of not being a yes.
    #[test]
    fn nothing_short_of_a_pass_counts_as_managed() {
        assert!(!device_reports_managed(&[]));
        assert!(!device_reports_managed(&[signal(
            "device_management",
            PostureResult::Unknown
        )]));
        assert!(!device_reports_managed(&[signal(
            "device_management",
            PostureResult::Unsupported
        )]));
        // A different signal passing says nothing about enrolment.
        assert!(!device_reports_managed(&[signal(
            "disk_encryption",
            PostureResult::Pass
        )]));
    }

    /// Unsupported is a pass for the blanket check but not for a signal the
    /// operator asked for by name: they asked for encryption, and "this
    /// platform has no such thing" is not encryption.
    #[test]
    fn a_named_signal_is_not_satisfied_by_unsupported() {
        let posture = vec![signal("disk_encryption", PostureResult::Unsupported)];
        assert!(!decide(REQUIRES_ENCRYPTION, &posture).allow);
    }
}
