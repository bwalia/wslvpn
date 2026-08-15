use crate::error::AppResult;
use crate::state::AppState;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use wsl_types::AuditEvent;

pub struct AuditService {
    state: AppState,
}

impl AuditService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record(
        &self,
        action: &str,
        decision: Option<&str>,
        user_id: Option<Uuid>,
        device_id: Option<Uuid>,
        resource: Option<&str>,
        policy_id: Option<Uuid>,
        policy_version: Option<i64>,
        git_commit: Option<&str>,
        details: serde_json::Value,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_events
              (action, decision, user_id, device_id, resource, policy_id, policy_version, git_commit, details)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            "#,
        )
        .bind(action)
        .bind(decision)
        .bind(user_id)
        .bind(device_id)
        .bind(resource)
        .bind(policy_id)
        .bind(policy_version)
        .bind(git_commit)
        .bind(details)
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
                Option<Uuid>,
                Option<Uuid>,
                Option<String>,
                Option<Uuid>,
                Option<i64>,
                Option<String>,
                serde_json::Value,
                DateTime<Utc>,
            ),
        >(
            r#"
            SELECT id, action, decision, user_id, device_id, resource, policy_id,
                   policy_version, git_commit, details, created_at
            FROM audit_events ORDER BY created_at DESC LIMIT $1
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
                user_id: r.3,
                device_id: r.4,
                resource: r.5,
                policy_id: r.6,
                policy_version: r.7,
                git_commit: r.8,
                details: r.9,
                created_at: r.10,
            })
            .collect())
    }
}
