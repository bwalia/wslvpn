use crate::error::{AppError, AppResult};
use crate::services::users::UserService;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;
use wsl_types::{CreateUserRequest, UpdateUserRequest, User};

pub async fn list(State(state): State<AppState>) -> AppResult<Json<Vec<User>>> {
    Ok(Json(UserService::new(state).list().await?))
}

pub async fn get(State(state): State<AppState>, Path(id): Path<Uuid>) -> AppResult<Json<User>> {
    UserService::new(state)
        .get(id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

pub async fn create(
    State(state): State<AppState>,
    Json(body): Json<CreateUserRequest>,
) -> AppResult<Json<User>> {
    Ok(Json(UserService::new(state).create(body).await?))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateUserRequest>,
) -> AppResult<Json<User>> {
    UserService::new(state)
        .update(id, body)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let ok = UserService::new(state).delete(id).await?;
    if !ok {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "deleted": true })))
}
