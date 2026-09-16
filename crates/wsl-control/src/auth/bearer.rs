use crate::error::{AppError, AppResult};
use crate::state::{hash_token, AppState};
use axum::{extract::FromRequestParts, http::request::Parts};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use wsl_types::UserRole;

/// Any authenticated, active user.
///
/// Carries the role so a handler can make its own ownership decision ("this
/// user, or an admin") without a second database round trip.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub email: String,
    pub role: UserRole,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == UserRole::Admin
    }

    /// Allow when the caller owns the resource, or is an administrator.
    ///
    /// Returns `NotFound` rather than `Forbidden` for a non-owner: telling an
    /// unrelated caller that some other user's device id exists is itself a
    /// disclosure, so an unauthorized read is indistinguishable from a miss.
    pub fn authorize_owner(&self, owner_id: Uuid) -> AppResult<()> {
        if self.is_admin() || self.user_id == owner_id {
            return Ok(());
        }
        Err(AppError::NotFound)
    }
}

/// Extracts the bearer token from an `Authorization` header.
pub fn bearer_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

pub async fn require_user(state: &AppState, authorization: Option<&str>) -> AppResult<AuthUser> {
    let header = authorization.ok_or(AppError::Unauthorized)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized)?;
    let token_hash = hash_token(token);
    let row: Option<(Uuid, String, String, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT u.id, u.email, u.role, t.expires_at
        FROM access_tokens t
        JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = $1 AND u.active = TRUE
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?;

    let Some((user_id, email, role, expires_at)) = row else {
        return Err(AppError::Unauthorized);
    };
    if expires_at < Utc::now() {
        return Err(AppError::Unauthorized);
    }
    Ok(AuthUser {
        user_id,
        email,
        role: UserRole::from_db(&role),
    })
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        require_user(state, auth).await
    }
}

/// An authenticated user whose role is `admin`.
///
/// Every tenant-wide mutation and every cross-user read is behind this. Using a
/// distinct extractor rather than an `if` inside the handler means a new route
/// cannot silently inherit anonymous access: it has to name its own guard.
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthUser);

impl std::ops::Deref for AdminUser {
    type Target = AuthUser;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if !user.is_admin() {
            tracing::warn!(
                user_id = %user.user_id,
                email = %user.email,
                path = %parts.uri.path(),
                "denied: admin role required"
            );
            return Err(AppError::Forbidden);
        }
        Ok(AdminUser(user))
    }
}
