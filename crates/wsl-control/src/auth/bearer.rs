use crate::error::{AppError, AppResult};
use crate::state::{hash_token, AppState};
use axum::{extract::FromRequestParts, http::request::Parts};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub email: String,
}

pub async fn require_user(state: &AppState, authorization: Option<&str>) -> AppResult<AuthUser> {
    let header = authorization.ok_or(AppError::Unauthorized)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized)?;
    let token_hash = hash_token(token);
    let row: Option<(Uuid, String, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT u.id, u.email, t.expires_at
        FROM access_tokens t
        JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = $1 AND u.active = TRUE
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?;

    let Some((user_id, email, expires_at)) = row else {
        return Err(AppError::Unauthorized);
    };
    if expires_at < Utc::now() {
        return Err(AppError::Unauthorized);
    }
    Ok(AuthUser { user_id, email })
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
