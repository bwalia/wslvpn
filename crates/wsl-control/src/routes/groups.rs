use crate::auth::{AdminUser, AuthUser};
use crate::error::{AppError, AppResult};
use crate::services::audit::{AuditEntry, AuditService};
use crate::services::groups::GroupService;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;
use wsl_types::{CreateGroupRequest, Group};

/// Group names are readable by any signed-in user: policies are written in
/// terms of them, so a member needs to be able to see what they belong to.
/// Membership changes are admin-only.
pub async fn list(State(state): State<AppState>, _user: AuthUser) -> AppResult<Json<Vec<Group>>> {
    Ok(Json(GroupService::new(state).list().await?))
}

pub async fn get(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Group>> {
    GroupService::new(state)
        .get(id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

pub async fn create(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(body): Json<CreateGroupRequest>,
) -> AppResult<Json<Group>> {
    let group = GroupService::new(state.clone()).create(body).await?;
    AuditService::new(state)
        .record(
            AuditEntry::new("group.create")
                .decision("allow")
                .by_user(admin.user_id, &admin.email)
                .resource(&group.name),
        )
        .await?;
    Ok(Json(group))
}

pub async fn delete(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    if !GroupService::new(state.clone()).delete(id).await? {
        return Err(AppError::NotFound);
    }
    // Deleting a group changes who a policy matches, so it belongs in the log
    // even though no user record changed.
    AuditService::new(state)
        .record(
            AuditEntry::new("group.delete")
                .decision("allow")
                .by_user(admin.user_id, &admin.email)
                .resource(id.to_string()),
        )
        .await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

pub async fn add_member(
    State(state): State<AppState>,
    admin: AdminUser,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    GroupService::new(state.clone())
        .add_member(id, user_id)
        .await?;
    // Group membership is what policies are written against, so this is a
    // grant of access even though nothing about the user record changed.
    AuditService::new(state)
        .record(
            AuditEntry::new("group.member_added")
                .decision("allow")
                .by_user(admin.user_id, &admin.email)
                .subject(user_id)
                .resource(id.to_string()),
        )
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn remove_member(
    State(state): State<AppState>,
    admin: AdminUser,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    GroupService::new(state.clone())
        .remove_member(id, user_id)
        .await?;
    AuditService::new(state)
        .record(
            AuditEntry::new("group.member_removed")
                .decision("allow")
                .by_user(admin.user_id, &admin.email)
                .subject(user_id)
                .resource(id.to_string()),
        )
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
