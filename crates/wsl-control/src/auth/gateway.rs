use crate::auth::bearer::bearer_token;
use crate::error::{AppError, AppResult};
use crate::state::{hash_token, AppState};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use uuid::Uuid;

/// A gateway that has proven possession of its own credential.
///
/// The verified id is carried on the extractor and handlers use *this* id
/// rather than re-reading `{id}` from the path. Authenticating one id and then
/// acting on another read separately from the URL is how confused-deputy bugs
/// get in; here the two cannot diverge.
#[derive(Debug, Clone)]
pub struct GatewayAuth {
    pub gateway_id: Uuid,
    pub name: String,
}

pub async fn require_gateway(
    state: &AppState,
    token: Option<&str>,
    path_id: Uuid,
) -> AppResult<GatewayAuth> {
    let token = token.ok_or(AppError::Unauthorized)?;
    let token_hash = hash_token(token);

    // Match on the token *and* the id from the path: a valid credential for
    // gateway A must not authorize a pull of gateway B's configuration.
    //
    // A gateway enrolled before per-gateway credentials existed has a NULL
    // auth_token_hash and therefore matches nothing, so it fails closed and
    // re-enrolls on its next start.
    let row: Option<(Uuid, String)> = sqlx::query_as(
        r#"
        SELECT id, name
        FROM gateways
        WHERE id = $1 AND auth_token_hash = $2
        "#,
    )
    .bind(path_id)
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?;

    let Some((gateway_id, name)) = row else {
        tracing::warn!(%path_id, "denied: gateway credential rejected");
        return Err(AppError::Unauthorized);
    };
    Ok(GatewayAuth { gateway_id, name })
}

impl FromRequestParts<AppState> for GatewayAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let axum::extract::Path(path_id) =
            axum::extract::Path::<Uuid>::from_request_parts(parts, state)
                .await
                .map_err(|_| AppError::bad_request("gateway id required"))?;
        let token = bearer_token(parts);
        require_gateway(state, token, path_id).await
    }
}
