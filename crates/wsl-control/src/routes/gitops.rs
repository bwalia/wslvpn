use crate::auth::AdminUser;
use crate::error::AppResult;
use crate::services::audit::{AuditEntry, AuditService};
use crate::services::gitops::GitOpsService;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ApplyGitOpsRequest {
    pub git_commit: Option<String>,
}

/// Re-apply the configured GitOps directory.
///
/// The directory is taken from `gitops.path` in the control-plane config and is
/// deliberately *not* a request parameter. When callers could name the path,
/// this endpoint would read and apply YAML from anywhere on the control-plane
/// host's filesystem.
pub async fn apply(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(body): Json<ApplyGitOpsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let path = state.config.gitops.path.clone();
    let n = GitOpsService::new(state.clone())
        .apply_directory(&path, body.git_commit.as_deref())
        .await?;
    AuditService::new(state)
        .record(
            AuditEntry::new("gitops.apply")
                .decision("allow")
                .by_user(admin.user_id, &admin.email)
                .resource(&path)
                .git_commit(body.git_commit.as_deref())
                .details(serde_json::json!({ "applied_policies": n })),
        )
        .await?;
    Ok(Json(
        serde_json::json!({ "applied_policies": n, "path": path }),
    ))
}
