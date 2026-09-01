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

/// Report whether the audit chain still verifies.
///
/// Answers 200 with `{"intact": true}` when every entry hashes to what it
/// claims, and 200 with the first break when it does not — a compliance check
/// wants the finding in the body, not an error status it has to interpret.
pub async fn verify(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Json<serde_json::Value>> {
    match AuditService::new(state).verify().await? {
        None => Ok(Json(serde_json::json!({ "intact": true }))),
        Some(broken) => {
            tracing::error!(
                seq = broken.seq,
                id = %broken.id,
                problem = %broken.problem,
                "audit chain verification failed"
            );
            metrics::counter!("wsl_audit_verification_failures").increment(1);
            Ok(Json(serde_json::json!({
                "intact": false,
                "first_break": broken,
            })))
        }
    }
}
