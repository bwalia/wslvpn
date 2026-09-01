use crate::error::AppResult;
use crate::state::AppState;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use wsl_types::{ActorType, AuditEvent};

pub struct AuditService {
    state: AppState,
}

/// One thing that happened, and who caused it.
///
/// A builder rather than a long positional signature: most events set two or
/// three of these fields, and a nine-argument call where seven are `None` is
/// how the wrong `Uuid` ends up in the wrong column without the compiler
/// noticing.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub action: String,
    pub decision: Option<String>,
    pub actor_type: ActorType,
    pub actor_id: Option<String>,
    pub user_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub resource: Option<String>,
    pub policy_id: Option<Uuid>,
    pub policy_version: Option<i64>,
    pub git_commit: Option<String>,
    pub source_ip: Option<std::net::IpAddr>,
    pub request_id: Option<String>,
    pub details: serde_json::Value,
}

impl AuditEntry {
    /// A system-attributed event. Callers that know their principal should say
    /// so with `by_user`, `by_service` or `by_gateway`.
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            decision: None,
            actor_type: ActorType::System,
            actor_id: None,
            user_id: None,
            device_id: None,
            resource: None,
            policy_id: None,
            policy_version: None,
            git_commit: None,
            source_ip: None,
            request_id: None,
            details: serde_json::json!({}),
        }
    }

    pub fn decision(mut self, decision: impl Into<String>) -> Self {
        self.decision = Some(decision.into());
        self
    }

    /// Attribute to a signed-in person. Sets the subject to the same user when
    /// one has not been named, which is the common case: someone acting on
    /// their own resources.
    pub fn by_user(mut self, user_id: Uuid, email: &str) -> Self {
        self.actor_type = ActorType::User;
        self.actor_id = Some(email.to_string());
        self.user_id = self.user_id.or(Some(user_id));
        self
    }

    pub fn by_service(mut self, token_name: &str) -> Self {
        self.actor_type = ActorType::Service;
        self.actor_id = Some(token_name.to_string());
        self
    }

    pub fn by_gateway(mut self, gateway_id: Uuid) -> Self {
        self.actor_type = ActorType::Gateway;
        self.actor_id = Some(gateway_id.to_string());
        self
    }

    /// The person or thing the event is *about*, when that differs from who
    /// caused it — an admin disabling somebody else's account, say.
    pub fn subject(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn device(mut self, device_id: Uuid) -> Self {
        self.device_id = Some(device_id);
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    pub fn policy(mut self, policy_id: Uuid, version: i64) -> Self {
        self.policy_id = Some(policy_id);
        self.policy_version = Some(version);
        self
    }

    pub fn git_commit(mut self, commit: Option<&str>) -> Self {
        self.git_commit = commit.map(str::to_string);
        self
    }

    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

impl AuditService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// Append one event.
    ///
    /// The database assigns the sequence number and the chain hashes in a
    /// trigger, so an event written by anything else — a migration, a console
    /// session — is chained the same way and stays verifiable.
    pub async fn record(&self, entry: AuditEntry) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_events
              (action, decision, actor_type, actor_id, user_id, device_id, resource,
               policy_id, policy_version, git_commit, source_ip, request_id, details)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            "#,
        )
        .bind(&entry.action)
        .bind(&entry.decision)
        .bind(entry.actor_type.as_str())
        .bind(&entry.actor_id)
        .bind(entry.user_id)
        .bind(entry.device_id)
        .bind(&entry.resource)
        .bind(entry.policy_id)
        .bind(entry.policy_version)
        .bind(&entry.git_commit)
        .bind(entry.source_ip.map(ipnetwork::IpNetwork::from))
        .bind(&entry.request_id)
        .bind(&entry.details)
        .execute(&self.state.db)
        .await?;
        Ok(())
    }

    pub async fn list(&self, limit: i64) -> AppResult<Vec<AuditEvent>> {
        let rows = sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                Option<String>,
                String,
                Option<String>,
                Option<Uuid>,
                Option<Uuid>,
                Option<String>,
                Option<Uuid>,
                Option<i64>,
                Option<String>,
                serde_json::Value,
                DateTime<Utc>,
                i64,
                String,
            ),
        >(
            r#"
            SELECT id, action, decision, actor_type, actor_id, user_id, device_id,
                   resource, policy_id, policy_version, git_commit, details,
                   created_at, seq, entry_hash
            FROM audit_events ORDER BY seq DESC LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.state.db)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| AuditEvent {
                id: r.0,
                action: r.1,
                decision: r.2,
                actor_type: ActorType::from_db(&r.3),
                actor_id: r.4,
                user_id: r.5,
                device_id: r.6,
                resource: r.7,
                policy_id: r.8,
                policy_version: r.9,
                git_commit: r.10,
                details: r.11,
                created_at: r.12,
                seq: r.13,
                entry_hash: r.14,
            })
            .collect())
    }

    /// Walk the hash chain and report the first entry that does not verify.
    ///
    /// `None` means the log is intact from its first entry to its last.
    pub async fn verify(&self) -> AppResult<Option<AuditBreak>> {
        let row: Option<(i64, Uuid, DateTime<Utc>, String)> =
            sqlx::query_as("SELECT seq, id, created_at, problem FROM audit_verify() LIMIT 1")
                .fetch_optional(&self.state.db)
                .await?;
        Ok(row.map(|(seq, id, created_at, problem)| AuditBreak {
            seq,
            id,
            created_at,
            problem,
        }))
    }
}

/// Where the audit chain stops verifying.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct AuditBreak {
    pub seq: i64,
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub problem: String,
}
