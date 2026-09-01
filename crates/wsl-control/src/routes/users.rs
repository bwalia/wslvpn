use crate::auth::{AdminUser, AuthUser};
use crate::error::{AppError, AppResult};
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
    _admin: AdminUser,
    Json(body): Json<CreateUserRequest>,
) -> AppResult<Json<User>> {
    Ok(Json(UserService::new(state).create(body).await?))
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
    UserService::new(state)
        .update(id, body)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
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
    let ok = UserService::new(state).delete(id).await?;
    if !ok {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "deleted": true })))
}
