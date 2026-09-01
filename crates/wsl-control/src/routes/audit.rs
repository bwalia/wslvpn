use crate::auth::AdminUser;
use crate::error::AppResult;
use crate::services::audit::AuditService;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use wsl_types::AuditEvent;

const MAX_LIMIT: i64 = 1000;

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    100
}

/// The audit log records who reached what, so it is admin-only. `limit` is
/// clamped rather than rejected: an unbounded value would let one request pull
/// the entire history into memory.
pub async fn list(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<AuditQuery>,
) -> AppResult<Json<Vec<AuditEvent>>> {
    let limit = q.limit.clamp(1, MAX_LIMIT);
    Ok(Json(AuditService::new(state).list(limit).await?))
}
