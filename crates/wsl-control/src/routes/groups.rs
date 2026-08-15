use crate::error::{AppError, AppResult};
use crate::services::groups::GroupService;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;
use wsl_types::{CreateGroupRequest, Group};

pub async fn list(State(state): State<AppState>) -> AppResult<Json<Vec<Group>>> {
    Ok(Json(GroupService::new(state).list().await?))
}

pub async fn get(State(state): State<AppState>, Path(id): Path<Uuid>) -> AppResult<Json<Group>> {
    GroupService::new(state)
        .get(id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

pub async fn create(
    State(state): State<AppState>,
    Json(body): Json<CreateGroupRequest>,
) -> AppResult<Json<Group>> {
    Ok(Json(GroupService::new(state).create(body).await?))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let ok = GroupService::new(state).delete(id).await?;
    if !ok {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "deleted": true })))
}

pub async fn add_member(
    State(state): State<AppState>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    GroupService::new(state).add_member(id, user_id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn remove_member(
    State(state): State<AppState>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    GroupService::new(state).remove_member(id, user_id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
