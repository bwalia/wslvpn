use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditEvent {
    pub id: Uuid,
    pub action: String,
    pub decision: Option<String>,
    pub user_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub resource: Option<String>,
    pub policy_id: Option<Uuid>,
    pub policy_version: Option<i64>,
    pub git_commit: Option<String>,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
}
