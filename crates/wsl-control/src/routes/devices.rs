use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::services::devices::DeviceService;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;
use wsl_types::{Device, RegisterDeviceRequest, RegisterDeviceResponse};

pub async fn list(State(state): State<AppState>) -> AppResult<Json<Vec<Device>>> {
    Ok(Json(DeviceService::new(state).list().await?))
}

pub async fn get(State(state): State<AppState>, Path(id): Path<Uuid>) -> AppResult<Json<Device>> {
    DeviceService::new(state)
        .get(id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

pub async fn register(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<RegisterDeviceRequest>,
) -> AppResult<Json<RegisterDeviceResponse>> {
    Ok(Json(
        DeviceService::new(state)
            .register(user.user_id, body)
            .await?,
    ))
}

pub async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let ok = DeviceService::new(state).revoke(id).await?;
    if !ok {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "revoked": true })))
}
