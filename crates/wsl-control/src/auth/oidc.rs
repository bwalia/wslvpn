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
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub redirect_uri: Option<String>,
    /// Base64url SHA-256 of a verifier held by a native client. Its presence
    /// is what makes this a CLI login rather than a browser one.
    pub client_challenge: Option<String>,
}

/// Where the control plane is willing to send a browser once login finishes.
///
/// This is the control that stops the handshake being turned into a token
/// delivery service for somewhere else: an attacker who can talk a user into
/// opening an authorize URL must not be able to choose where the result lands.
/// Only two destinations are ever allowed — the deployment's own configured
/// redirect, and a loopback address on this machine.
///
/// Loopback is restricted to the literal addresses. `localhost` is a name, and
/// a name can be made to resolve somewhere else; RFC 8252 section 8.3 says to
/// use the literal IPs for exactly that reason.
fn validate_client_redirect(uri: &str, configured: &str) -> AppResult<()> {
    if uri == configured {
        return Ok(());
    }
    let parsed =
        url::Url::parse(uri).map_err(|e| AppError::bad_request(format!("redirect_uri: {e}")))?;
    if parsed.scheme() != "http" {
        return Err(AppError::bad_request(
            "redirect_uri must be http on a loopback address",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::bad_request("redirect_uri has no host"))?;
    if !matches!(host, "127.0.0.1" | "[::1]" | "::1") {
        return Err(AppError::bad_request(
            "redirect_uri must be 127.0.0.1 or [::1]; names are not accepted",
        ));
    }
    if parsed.port().is_none() {
        return Err(AppError::bad_request("redirect_uri must name a port"));
    }
    Ok(())
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
    let configured = state.config.identity.oidc.redirect_uri.clone();
    let redirect_uri = q.redirect_uri.unwrap_or_else(|| configured.clone());
    validate_client_redirect(&redirect_uri, &configured)?;
    // A native client is one that proves possession of a verifier later. No
    // challenge means the browser flow, which ends in a JSON token response.
    let client_redirect = (redirect_uri != configured).then(|| redirect_uri.clone());
    if client_redirect.is_some() && q.client_challenge.is_none() {
        return Err(AppError::bad_request(
            "a loopback redirect_uri requires client_challenge",
        ));
    }
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
        INSERT INTO oidc_auth_states
            (state, code_verifier, redirect_uri, client_redirect_uri, client_challenge, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(&oauth_state)
    .bind(&code_verifier)
    .bind(&redirect_uri)
    .bind(&client_redirect)
    .bind(&q.client_challenge)
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
) -> AppResult<axum::response::Response> {
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        DELETE FROM oidc_auth_states
        WHERE state = $1 AND expires_at > NOW()
        RETURNING code_verifier, client_redirect_uri, client_challenge
        "#,
    )
    .bind(&q.state)
    .fetch_optional(&state.db)
    .await?;
    let Some((code_verifier, client_redirect_uri, client_challenge)) = row else {
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

    // A native client gets a one-time code, not a token: the browser is not
    // the thing that asked to log in, and a token in a redirect URL would
    // survive in browser history long after the session it belongs to.
    if let (Some(redirect), Some(challenge)) = (client_redirect_uri, client_challenge) {
        let exchange_code = random_secret();
        sqlx::query(
            r#"
            INSERT INTO oidc_cli_exchanges (code_hash, challenge, user_id, email, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(hash_token(&exchange_code))
        .bind(&challenge)
        .bind(user_id)
        .bind(&email)
        .bind(Utc::now() + Duration::seconds(CLI_EXCHANGE_TTL_SECONDS))
        .execute(&state.db)
        .await?;

        let mut target = url::Url::parse(&redirect)
            .map_err(|e| AppError::bad_request(format!("stored redirect_uri: {e}")))?;
        target.query_pairs_mut().append_pair("code", &exchange_code);
        return Ok(Redirect::temporary(target.as_str()).into_response());
    }

    let (access_token, expires_in) = mint_access_token(&state, user_id).await?;
    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        user_id,
        email,
    })
    .into_response())
}

/// How long a native client has to redeem its code. It is a local round trip
/// on the machine that just completed the browser flow, so the window can be
/// short; anything longer is only useful to someone who stole the code.
const CLI_EXCHANGE_TTL_SECONDS: i64 = 120;

fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn mint_access_token(state: &AppState, user_id: Uuid) -> AppResult<(String, i64)> {
    let access_token = random_secret();
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
    Ok((access_token, expires_in))
}

#[derive(Debug, Deserialize)]
pub struct ExchangeRequest {
    pub code: String,
    pub verifier: String,
}

/// Redeem a one-time code for an access token.
///
/// The code is deleted whether or not the verifier matches, so a wrong guess
/// costs the attempt rather than allowing another. The comparison is on the
/// SHA-256 of the verifier against the challenge recorded when the handshake
/// started, in constant time.
pub async fn exchange(
    State(state): State<AppState>,
    Json(body): Json<ExchangeRequest>,
) -> AppResult<Json<TokenResponse>> {
    let row: Option<(String, Uuid, String)> = sqlx::query_as(
        r#"
        DELETE FROM oidc_cli_exchanges
        WHERE code_hash = $1 AND expires_at > NOW()
        RETURNING challenge, user_id, email
        "#,
    )
    .bind(hash_token(&body.code))
    .fetch_optional(&state.db)
    .await?;
    let Some((challenge, user_id, email)) = row else {
        tracing::warn!("denied: unknown or expired cli exchange code");
        return Err(AppError::Forbidden);
    };

    let presented = {
        let mut hasher = Sha256::new();
        hasher.update(body.verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    };
    if presented.as_bytes().ct_eq(challenge.as_bytes()).unwrap_u8() != 1 {
        tracing::warn!(%user_id, "denied: cli exchange verifier did not match");
        return Err(AppError::Forbidden);
    }

    let (access_token, expires_in) = mint_access_token(&state, user_id).await?;
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
