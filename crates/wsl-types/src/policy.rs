use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub current_version: i64,
    pub git_commit: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyVersion {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub version: i64,
    pub document: serde_json::Value,
    pub git_commit: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyDecision {
    pub allow: bool,
    pub policy_id: Option<Uuid>,
    pub policy_name: Option<String>,
    pub policy_version: Option<i64>,
    pub git_commit: Option<String>,
    pub reason: String,
    pub resources: Vec<String>,
    pub session_duration_secs: Option<i64>,
}
