use crate::error::{AppError, AppResult};
use crate::state::{hash_token, AppState};
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub user_id: Uuid,
    pub email: String,
}

pub async fn authorize(
    State(state): State<AppState>,
    Query(q): Query<AuthorizeQuery>,
) -> AppResult<impl IntoResponse> {
    let redirect_uri = q
        .redirect_uri
        .unwrap_or_else(|| state.config.identity.oidc.redirect_uri.clone());
    let mut verifier_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut verifier_bytes);
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let challenge = {
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    };
    let mut state_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut state_bytes);
    let oauth_state = URL_SAFE_NO_PAD.encode(state_bytes);

    sqlx::query(
        r#"
        INSERT INTO oidc_auth_states (state, code_verifier, redirect_uri, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(&oauth_state)
    .bind(&code_verifier)
    .bind(&redirect_uri)
    .bind(Utc::now() + Duration::minutes(10))
    .execute(&state.db)
    .await?;

    let oidc = &state.config.identity.oidc;
    let mut url = url::Url::parse(&format!("{}/auth", oidc.issuer.trim_end_matches('/')))
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    // Dex uses /auth on issuer; discovery would be better — keep simple for MVP
    if oidc.issuer.contains("/dex") {
        url = url::Url::parse(&format!("{}/auth", oidc.issuer.trim_end_matches('/')))
            .map_err(|e| AppError::bad_request(e.to_string()))?;
    }

    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("client_id", &oidc.client_id);
        qp.append_pair("response_type", "code");
        qp.append_pair("scope", &oidc.scopes.join(" "));
        qp.append_pair("redirect_uri", &oidc.redirect_uri);
        qp.append_pair("state", &oauth_state);
        qp.append_pair("code_challenge", &challenge);
        qp.append_pair("code_challenge_method", "S256");
    }

    Ok(Redirect::temporary(url.as_str()))
}

pub async fn callback(
    State(state): State<AppState>,
    Query(q): Query<CallbackQuery>,
) -> AppResult<Json<TokenResponse>> {
    let row: Option<(String, String)> = sqlx::query_as(
        r#"
        DELETE FROM oidc_auth_states
        WHERE state = $1 AND expires_at > NOW()
        RETURNING code_verifier, redirect_uri
        "#,
    )
    .bind(&q.state)
    .fetch_optional(&state.db)
    .await?;
    let Some((code_verifier, _redirect_uri)) = row else {
        return Err(AppError::bad_request("invalid or expired oauth state"));
    };

    let oidc = &state.config.identity.oidc;
    let token_url = format!("{}/token", oidc.issuer.trim_end_matches('/'));
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", q.code.clone()),
        ("redirect_uri", oidc.redirect_uri.clone()),
        ("client_id", oidc.client_id.clone()),
        ("code_verifier", code_verifier),
    ];
    if let Some(secret) = &oidc.client_secret {
        form.push(("client_secret", secret.clone()));
    }

    let token_resp: serde_json::Value = state
        .http
        .post(&token_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .error_for_status()
        .map_err(|e| AppError::bad_request(format!("oidc token exchange failed: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let id_token = token_resp
        .get("id_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("missing id_token"))?;

    let email = extract_email_unverified(id_token)?;
    let user_id = upsert_user(&state, &email).await?;

    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let access_token = URL_SAFE_NO_PAD.encode(token_bytes);
    let expires_in = 8 * 3600i64;
    sqlx::query(
        r#"
        INSERT INTO access_tokens (user_id, token_hash, expires_at)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(user_id)
    .bind(hash_token(&access_token))
    .bind(Utc::now() + Duration::seconds(expires_in))
    .execute(&state.db)
    .await?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        user_id,
        email,
    }))
}

/// MVP: decode JWT payload without full JWKS verification (Dex local).
/// Production must verify signature against issuer JWKS.
fn extract_email_unverified(id_token: &str) -> AppResult<String> {
    let parts: Vec<_> = id_token.split('.').collect();
    if parts.len() < 2 {
        return Err(AppError::bad_request("malformed id_token"));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|e| AppError::bad_request(e.to_string()))?;
    v.get("email")
        .and_then(|e| e.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            v.get("preferred_username")
                .and_then(|e| e.as_str())
                .map(|s| s.to_string())
        })
        .ok_or_else(|| AppError::bad_request("email claim missing"))
}

async fn upsert_user(state: &AppState, email: &str) -> AppResult<Uuid> {
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO users (email, display_name, active)
        VALUES ($1, $1, TRUE)
        ON CONFLICT (email) DO UPDATE SET updated_at = NOW(), active = TRUE
        RETURNING id
        "#,
    )
    .bind(email)
    .fetch_one(&state.db)
    .await?;
    Ok(id)
}

/// Device/CLI login helper: exchange a pre-shared local login for token (Compose demo).
#[derive(Debug, Deserialize)]
pub struct DevLoginRequest {
    pub email: String,
}

pub async fn dev_login(
    State(state): State<AppState>,
    Json(body): Json<DevLoginRequest>,
) -> AppResult<Json<TokenResponse>> {
    // Two independent gates. The explicit flag is the real control — a
    // deployment must opt in — and the loopback check is a backstop so that
    // turning the flag on by accident still cannot expose a public host. The
    // config validator also refuses to start a non-loopback deployment with
    // the flag set, so this is the third of three.
    if !state.config.identity.dev_login_enabled || !state.config.is_local() {
        tracing::warn!("denied: dev login is disabled");
        return Err(AppError::Forbidden);
    }
    let user_id = upsert_user(&state, &body.email).await?;
    // Ensure developers group membership for local demo
    let group_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM groups WHERE name = 'developers'")
            .fetch_optional(&state.db)
            .await?;
    if let Some(gid) = group_id {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(gid)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    }

    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let access_token = URL_SAFE_NO_PAD.encode(token_bytes);
    let expires_in = 8 * 3600i64;
    sqlx::query("INSERT INTO access_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(hash_token(&access_token))
        .bind(Utc::now() + Duration::seconds(expires_in))
        .execute(&state.db)
        .await?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        user_id,
        email: body.email,
    }))
}
