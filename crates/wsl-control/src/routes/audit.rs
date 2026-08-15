use crate::error::AppResult;
use crate::services::audit::AuditService;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use wsl_types::AuditEvent;

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    100
}

pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<AuditQuery>,
) -> AppResult<Json<Vec<AuditEvent>>> {
    Ok(Json(AuditService::new(state).list(q.limit).await?))
}
