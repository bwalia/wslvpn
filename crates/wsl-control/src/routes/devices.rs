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

/// An admin sees every device; a member sees only their own. Scoping the query
/// rather than rejecting the request keeps the endpoint usable from the client
/// without handing a member the fleet inventory.
pub async fn list(State(state): State<AppState>, caller: AuthUser) -> AppResult<Json<Vec<Device>>> {
    let svc = DeviceService::new(state);
    let devices = if caller.is_admin() {
        svc.list().await?
    } else {
        svc.list_for_user(caller.user_id).await?
    };
    Ok(Json(devices))
}

pub async fn get(
    State(state): State<AppState>,
    caller: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Device>> {
    let device = DeviceService::new(state)
        .get(id)
        .await?
        .ok_or(AppError::NotFound)?;
    caller.authorize_owner(device.user_id)?;
    Ok(Json(device))
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

/// A user may revoke their own device — losing a laptop should not require an
/// administrator — and an admin may revoke anyone's.
pub async fn revoke(
    State(state): State<AppState>,
    caller: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let svc = DeviceService::new(state);
    let device = svc.get(id).await?.ok_or(AppError::NotFound)?;
    caller.authorize_owner(device.user_id)?;
    if !svc.revoke(id).await? {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "revoked": true })))
}
