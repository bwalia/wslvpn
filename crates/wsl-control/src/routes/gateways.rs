use crate::error::{AppError, AppResult};
use crate::services::gateways::GatewayService;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;
use wsl_types::{Gateway, GatewayConfig, GatewayHeartbeatRequest, RegisterGatewayRequest};

pub async fn list(State(state): State<AppState>) -> AppResult<Json<Vec<Gateway>>> {
    Ok(Json(GatewayService::new(state).list().await?))
}

pub async fn get(State(state): State<AppState>, Path(id): Path<Uuid>) -> AppResult<Json<Gateway>> {
    GatewayService::new(state)
        .get(id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterGatewayRequest>,
) -> AppResult<Json<Gateway>> {
    Ok(Json(GatewayService::new(state).register(body).await?))
}

pub async fn config(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<GatewayConfig>> {
    Ok(Json(GatewayService::new(state).config(id).await?))
}

pub async fn heartbeat(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<GatewayHeartbeatRequest>,
) -> AppResult<Json<GatewayConfig>> {
    Ok(Json(GatewayService::new(state).heartbeat(id, body).await?))
}
