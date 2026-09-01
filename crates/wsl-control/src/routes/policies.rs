use crate::auth::AdminUser;
use crate::error::AppResult;
use crate::services::gitops::GitOpsService;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Deserialize;
use wsl_types::{Policy, PolicyVersion};

/// Policies decide who reaches what, so reading them reveals the shape of the
/// whole access model. Both listing and applying are admin-only.
pub async fn list(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Json<Vec<Policy>>> {
    Ok(Json(GitOpsService::new(state).list_policies().await?))
}

#[derive(Debug, Deserialize)]
pub struct ApplyPolicyRequest {
    pub yaml: String,
    pub git_commit: Option<String>,
}

pub async fn apply(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(body): Json<ApplyPolicyRequest>,
) -> AppResult<Json<PolicyVersion>> {
    Ok(Json(
        GitOpsService::new(state)
            .apply_policy_yaml(&body.yaml, body.git_commit.as_deref())
            .await?,
    ))
}
