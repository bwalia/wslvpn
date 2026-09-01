use crate::auth::OpsAuth;
use crate::error::{AppError, AppResult};
use crate::services::audit::{AuditEntry, AuditService};
use crate::services::devices::DeviceService;
use crate::services::groups::GroupService;
use crate::services::sessions::SessionService;
use crate::services::users::UserService;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;
use wsl_types::{CreateGroupRequest, CreateUserRequest, Group, Session, UpdateUserRequest, User};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users", post(create_user).get(list_users))
        .route("/users/{id}/disable", post(disable_user))
        .route("/users/{id}/enable", post(enable_user))
        .route("/users/{id}", axum::routing::delete(delete_user))
        .route("/groups", post(create_group).get(list_groups))
        .route(
            "/groups/{id}/members/{user_id}",
            post(assign_group).delete(remove_group),
        )
        .route("/devices/{id}/revoke", post(revoke_device))
        .route("/sessions", get(list_sessions))
        .route("/audit", get(list_audit))
}

async fn list_users(State(state): State<AppState>, _ops: OpsAuth) -> AppResult<Json<Vec<User>>> {
    Ok(Json(UserService::new(state).list().await?))
}

async fn create_user(
    State(state): State<AppState>,
    ops: OpsAuth,
    Json(body): Json<CreateUserRequest>,
) -> AppResult<Json<User>> {
    let user = UserService::new(state.clone()).create(body).await?;
    AuditService::new(state)
        .record(
            AuditEntry::new("user.create")
                .decision("allow")
                .by_service(&ops.token_name)
                .subject(user.id)
                .resource(&user.email),
        )
        .await?;
    Ok(Json(user))
}

async fn disable_user(
    State(state): State<AppState>,
    ops: OpsAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<User>> {
    let user = UserService::new(state.clone())
        .update(
            id,
            UpdateUserRequest {
                display_name: None,
                active: Some(false),
                // Enabling and disabling is an account-lifecycle action.
                // Granting the admin role is not, and a provisioning token
                // must not be a path to one.
                role: None,
            },
        )
        .await?
        .ok_or(AppError::NotFound)?;
    AuditService::new(state)
        .record(
            AuditEntry::new("user.disable")
                .decision("allow")
                .by_service(&ops.token_name)
                .subject(user.id)
                .resource(&user.email),
        )
        .await?;
    Ok(Json(user))
}

async fn enable_user(
    State(state): State<AppState>,
    ops: OpsAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<User>> {
    let user = UserService::new(state.clone())
        .update(
            id,
            UpdateUserRequest {
                display_name: None,
                active: Some(true),
                role: None,
            },
        )
        .await?
        .ok_or(AppError::NotFound)?;
    AuditService::new(state)
        .record(
            AuditEntry::new("user.enable")
                .decision("allow")
                .by_service(&ops.token_name)
                .subject(user.id)
                .resource(&user.email),
        )
        .await?;
    Ok(Json(user))
}

async fn delete_user(
    State(state): State<AppState>,
    ops: OpsAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    if !UserService::new(state.clone()).delete(id).await? {
        return Err(AppError::NotFound);
    }
    AuditService::new(state)
        .record(
            AuditEntry::new("user.delete")
                .decision("allow")
                .by_service(&ops.token_name)
                .subject(id),
        )
        .await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

async fn list_groups(State(state): State<AppState>, _ops: OpsAuth) -> AppResult<Json<Vec<Group>>> {
    Ok(Json(GroupService::new(state).list().await?))
}

async fn create_group(
    State(state): State<AppState>,
    _ops: OpsAuth,
    Json(body): Json<CreateGroupRequest>,
) -> AppResult<Json<Group>> {
    Ok(Json(GroupService::new(state).create(body).await?))
}

async fn assign_group(
    State(state): State<AppState>,
    _ops: OpsAuth,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    GroupService::new(state).add_member(id, user_id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn remove_group(
    State(state): State<AppState>,
    _ops: OpsAuth,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    GroupService::new(state).remove_member(id, user_id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn revoke_device(
    State(state): State<AppState>,
    _ops: OpsAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let ok = DeviceService::new(state).revoke(id).await?;
    if !ok {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "revoked": true })))
}

async fn list_sessions(
    State(state): State<AppState>,
    _ops: OpsAuth,
) -> AppResult<Json<Vec<Session>>> {
    Ok(Json(SessionService::new(state).list().await?))
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    100
}

async fn list_audit(
    State(state): State<AppState>,
    _ops: OpsAuth,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> AppResult<Json<Vec<wsl_types::AuditEvent>>> {
    Ok(Json(AuditService::new(state).list(q.limit).await?))
}
