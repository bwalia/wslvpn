use crate::auth::service_token::OpsAuth;
use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::services::audit::{AuditEntry, AuditService};
use crate::services::sessions::SessionService;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use std::net::IpAddr;
use uuid::Uuid;
use wsl_types::{CreateSessionRequest, CreateSessionResponse, Session, SessionIdentity};

/// An admin sees every session; a member sees only their own.
pub async fn list(
    State(state): State<AppState>,
    caller: AuthUser,
) -> AppResult<Json<Vec<Session>>> {
    let svc = SessionService::new(state);
    let sessions = if caller.is_admin() {
        svc.list().await?
    } else {
        svc.list_for_user(caller.user_id).await?
    };
    Ok(Json(sessions))
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CreateSessionRequest>,
) -> AppResult<Json<CreateSessionResponse>> {
    Ok(Json(
        SessionService::new(state)
            .create(user.user_id, &user.email, body)
            .await?,
    ))
}

/// Resolve an overlay address to the identity behind it.
///
/// Service-token authenticated: this answers "who is at this address", so it is
/// for infrastructure callers (edge proxies) rather than end users.
///
/// Returns 404 for an address with no active session — revoked, expired and
/// never-seen are deliberately indistinguishable, so a caller cannot use this
/// to probe which addresses exist.
pub async fn identity_by_ip(
    State(state): State<AppState>,
    _ops: OpsAuth,
    Path(ip): Path<String>,
) -> AppResult<Json<SessionIdentity>> {
    let addr: IpAddr = ip
        .parse()
        .map_err(|_| AppError::bad_request("invalid IP address"))?;
    SessionService::new(state)
        .identity_by_ip(addr)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

/// A user may end their own session; an admin may end anyone's.
pub async fn revoke(
    State(state): State<AppState>,
    caller: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let svc = SessionService::new(state.clone());
    let owner = svc.owner_of(id).await?.ok_or(AppError::NotFound)?;
    caller.authorize_owner(owner)?;
    if !svc.revoke(id).await? {
        return Err(AppError::NotFound);
    }
    AuditService::new(state)
        .record(
            AuditEntry::new("session.revoke")
                .decision("allow")
                .by_user(caller.user_id, &caller.email)
                .subject(owner)
                .resource(id.to_string()),
        )
        .await?;
    Ok(Json(serde_json::json!({ "revoked": true })))
}
