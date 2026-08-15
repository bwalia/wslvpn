use crate::error::{AppError, AppResult};
use crate::state::{hash_token, AppState};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

#[derive(Debug, Clone)]
pub struct OpsAuth {
    #[allow(dead_code)]
    pub token_name: String,
}

pub async fn require_ops(state: &AppState, authorization: Option<&str>) -> AppResult<OpsAuth> {
    let header = authorization.ok_or(AppError::Unauthorized)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized)?;
    let token_hash = hash_token(token);
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        UPDATE service_tokens
        SET last_used_at = NOW()
        WHERE token_hash = $1 AND active = TRUE AND 'ops:provision' = ANY(scopes)
        RETURNING name
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?;
    let Some((name,)) = row else {
        return Err(AppError::Unauthorized);
    };
    Ok(OpsAuth { token_name: name })
}

impl FromRequestParts<AppState> for OpsAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        require_ops(state, auth).await
    }
}
