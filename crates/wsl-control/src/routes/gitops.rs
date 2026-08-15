use crate::error::AppResult;
use crate::services::gitops::GitOpsService;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ApplyGitOpsRequest {
    pub path: Option<String>,
    pub git_commit: Option<String>,
}

pub async fn apply(
    State(state): State<AppState>,
    Json(body): Json<ApplyGitOpsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let path = body
        .path
        .unwrap_or_else(|| state.config.gitops.path.clone());
    let n = GitOpsService::new(state)
        .apply_directory(&path, body.git_commit.as_deref())
        .await?;
    Ok(Json(serde_json::json!({ "applied_policies": n })))
}
