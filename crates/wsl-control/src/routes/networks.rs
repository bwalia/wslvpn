use crate::error::{AppError, AppResult};
use crate::services::networks::NetworkService;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;
use wsl_types::{CreateNetworkRequest, Network};

pub async fn list(State(state): State<AppState>) -> AppResult<Json<Vec<Network>>> {
    Ok(Json(NetworkService::new(state).list().await?))
}

pub async fn get(State(state): State<AppState>, Path(id): Path<Uuid>) -> AppResult<Json<Network>> {
    NetworkService::new(state)
        .get(id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

pub async fn create(
    State(state): State<AppState>,
    Json(body): Json<CreateNetworkRequest>,
) -> AppResult<Json<Network>> {
    Ok(Json(NetworkService::new(state).create(body).await?))
}
