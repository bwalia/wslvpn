use crate::auth::bearer::bearer_token;
use crate::error::{AppError, AppResult};
use crate::state::{hash_token, AppState};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{DateTime, Utc};

/// Scope granting the machine-to-machine provisioning API under `/api/v1/ops`.
pub const SCOPE_OPS: &str = "ops:provision";
/// Scope granting SCIM user and group provisioning under `/SCIM/v2`.
pub const SCOPE_SCIM: &str = "scim:manage";

/// A service token that carries a specific scope.
///
/// Scopes are checked in SQL alongside the lookup so a token can never be
/// resolved without also proving it holds the capability. Splitting SCIM from
/// ops matters in practice: an IdP holds a SCIM credential purely to sync
/// directory state, and that credential must not also read the audit log or
/// revoke sessions.
#[derive(Debug, Clone)]
pub struct ServiceToken {
    pub token_name: String,
}

pub async fn require_scope(
    state: &AppState,
    token: Option<&str>,
    scope: &'static str,
) -> AppResult<ServiceToken> {
    let token = token.ok_or(AppError::Unauthorized)?;
    let token_hash = hash_token(token);
    let row: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
        r#"
        UPDATE service_tokens
        SET last_used_at = NOW()
        WHERE token_hash = $1
          AND active = TRUE
          AND $2 = ANY(scopes)
          AND (expires_at IS NULL OR expires_at > NOW())
        RETURNING name, expires_at
        "#,
    )
    .bind(&token_hash)
    .bind(scope)
    .fetch_optional(&state.db)
    .await?;

    let Some((name, _)) = row else {
        return Err(AppError::Unauthorized);
    };
    Ok(ServiceToken { token_name: name })
}

/// Service token holding `ops:provision`.
#[derive(Debug, Clone)]
pub struct OpsAuth {
    #[allow(dead_code)]
    pub token_name: String,
}

impl FromRequestParts<AppState> for OpsAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let svc = require_scope(state, bearer_token(parts), SCOPE_OPS).await?;
        Ok(OpsAuth {
            token_name: svc.token_name,
        })
    }
}
