use crate::auth::{AdminUser, AuthUser};
use crate::error::{AppError, AppResult};
use crate::services::networks::NetworkService;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;
use wsl_types::{CreateNetworkRequest, Network};

/// Readable by any signed-in user: the client needs the network list to choose
/// what to connect to. Creating one changes the addressing plan, so it is an
/// admin action.
pub async fn list(State(state): State<AppState>, _user: AuthUser) -> AppResult<Json<Vec<Network>>> {
    Ok(Json(NetworkService::new(state).list().await?))
}

pub async fn get(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Network>> {
    NetworkService::new(state)
        .get(id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

pub async fn create(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(body): Json<CreateNetworkRequest>,
) -> AppResult<Json<Network>> {
    Ok(Json(NetworkService::new(state).create(body).await?))
}
