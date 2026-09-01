use crate::auth::{AdminUser, AuthUser};
use crate::error::{AppError, AppResult};
use crate::services::audit::{AuditEntry, AuditService};
use crate::services::users::UserService;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;
use wsl_types::{CreateUserRequest, UpdateUserRequest, User};

pub async fn list(State(state): State<AppState>, _admin: AdminUser) -> AppResult<Json<Vec<User>>> {
    Ok(Json(UserService::new(state).list().await?))
}

/// A member may read their own record; reading anyone else's is an admin action.
pub async fn get(
    State(state): State<AppState>,
    caller: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<User>> {
    caller.authorize_owner(id)?;
    UserService::new(state)
        .get(id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

pub async fn create(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(body): Json<CreateUserRequest>,
) -> AppResult<Json<User>> {
    let user = UserService::new(state.clone()).create(body).await?;
    AuditService::new(state)
        .record(
            AuditEntry::new("user.create")
                .decision("allow")
                .by_user(admin.user_id, &admin.email)
                .subject(user.id)
                .resource(&user.email),
        )
        .await?;
    Ok(Json(user))
}

pub async fn update(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateUserRequest>,
) -> AppResult<Json<User>> {
    // Refuse the two self-inflicted lockouts. Demoting or disabling the last
    // administrator would leave the tenant with no way back in, and the
    // recovery path is a manual UPDATE against the database.
    if id == admin.user_id
        && (body.role == Some(wsl_types::UserRole::Member) || body.active == Some(false))
    {
        return Err(AppError::bad_request(
            "an administrator cannot demote or disable their own account",
        ));
    }
    let changes = serde_json::json!({
        "display_name": body.display_name,
        "active": body.active,
        "role": body.role,
    });
    let updated = UserService::new(state.clone())
        .update(id, body)
        .await?
        .ok_or(AppError::NotFound)?;
    AuditService::new(state)
        .record(
            AuditEntry::new("user.update")
                .decision("allow")
                .by_user(admin.user_id, &admin.email)
                .subject(updated.id)
                .resource(&updated.email)
                .details(changes),
        )
        .await?;
    Ok(Json(updated))
}

pub async fn delete(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    if id == admin.user_id {
        return Err(AppError::bad_request(
            "an administrator cannot delete their own account",
        ));
    }
    let svc = UserService::new(state.clone());
    let target = svc.get(id).await?.ok_or(AppError::NotFound)?;
    if !svc.delete(id).await? {
        return Err(AppError::NotFound);
    }
    AuditService::new(state)
        .record(
            AuditEntry::new("user.delete")
                .decision("allow")
                .by_user(admin.user_id, &admin.email)
                .subject(id)
                .resource(&target.email),
        )
        .await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}
