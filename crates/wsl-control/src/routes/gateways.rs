use crate::auth::{AdminUser, GatewayAuth};
use crate::error::{AppError, AppResult};
use crate::services::gateways::GatewayService;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;
use wsl_types::{
    Gateway, GatewayConfig, GatewayHeartbeatRequest, RegisterGatewayRequest,
    RegisterGatewayResponse, RotateGatewayTokenResponse,
};

/// The gateway inventory maps names to endpoints and public keys, which is the
/// topology of the overlay. Admin-only.
pub async fn list(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Json<Vec<Gateway>>> {
    Ok(Json(GatewayService::new(state).list().await?))
}

pub async fn get(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Gateway>> {
    GatewayService::new(state)
        .get(id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

/// Enroll a gateway and mint its credential.
///
/// Authenticated by the enrollment secret in the request body. Re-enrolling an
/// existing name additionally requires the gateway's current credential in the
/// `Authorization` header — without that rule, anyone holding the shared
/// enrollment secret could repoint an existing gateway's endpoint and draw
/// traffic to a host of their choosing.
pub async fn register(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RegisterGatewayRequest>,
) -> AppResult<Json<RegisterGatewayResponse>> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty());
    Ok(Json(
        GatewayService::new(state).register(body, presented).await?,
    ))
}

/// Fetch the desired configuration for *this* gateway.
///
/// The id comes from the verified credential, not from the path, so a valid
/// credential cannot be used to read another gateway's peers.
pub async fn config(
    State(state): State<AppState>,
    gw: GatewayAuth,
) -> AppResult<Json<GatewayConfig>> {
    tracing::debug!(gateway = %gw.name, gateway_id = %gw.gateway_id, "serving gateway config");
    Ok(Json(
        GatewayService::new(state).config(gw.gateway_id).await?,
    ))
}

pub async fn heartbeat(
    State(state): State<AppState>,
    gw: GatewayAuth,
    Json(body): Json<GatewayHeartbeatRequest>,
) -> AppResult<Json<GatewayConfig>> {
    tracing::debug!(
        gateway = %gw.name,
        gateway_id = %gw.gateway_id,
        peers = body.peer_count,
        healthy = body.healthy,
        "gateway heartbeat"
    );
    Ok(Json(
        GatewayService::new(state)
            .heartbeat(gw.gateway_id, body)
            .await?,
    ))
}

/// Issue a fresh credential for a gateway, invalidating the previous one.
///
/// The recovery path when a gateway's credential is lost or suspected leaked:
/// an admin rotates, and the old value stops working immediately.
pub async fn rotate_token(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<RotateGatewayTokenResponse>> {
    GatewayService::new(state)
        .rotate_token(id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}
