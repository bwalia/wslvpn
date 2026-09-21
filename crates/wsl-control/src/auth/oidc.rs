use crate::auth::oidc_provider::{
    peek_key_id, verify_id_token, OidcError, ProviderMetadata, VerifiedIdentity,
};
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

/// Turn a verification failure into a response.
///
/// A rejected token is an authentication failure, not a malformed request, and
/// the reason is logged rather than returned: which of signature, audience,
/// issuer, expiry or nonce failed is a probing oracle if handed back. Problems
/// reaching the provider are this deployment's fault, not the caller's, and are
/// reported as such.
fn reject(err: OidcError) -> AppError {
    match err {
        OidcError::Discovery(_) | OidcError::IssuerMismatch { .. } => {
            tracing::error!(error = %err, "identity provider is unusable");
            AppError::Internal(anyhow::anyhow!("identity provider is unavailable"))
        }
        other => {
            tracing::warn!(error = %other, "denied: id_token failed validation");
            AppError::Unauthorized
        }
    }
}

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
///
/// A mobile client cannot listen on loopback at all, so it registers a
/// private-use scheme with the operating system and is sent back through that.
/// Those are accepted only when the deployment has named them in
/// `identity.oidc.native_schemes` — an unlisted scheme is refused, so an
/// authorize URL cannot be made to deliver a login to an app the operator never
/// approved.
fn validate_client_redirect(
    uri: &str,
    configured: &str,
    native_schemes: &[String],
) -> AppResult<()> {
    if uri == configured {
        return Ok(());
    }
    let parsed =
        url::Url::parse(uri).map_err(|e| AppError::bad_request(format!("redirect_uri: {e}")))?;

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        // `Url` lowercases the scheme while parsing, and the configured list is
        // required to be lowercase, so this compares like with like.
        return if native_schemes.iter().any(|s| s == parsed.scheme()) {
            Ok(())
        } else {
            Err(AppError::bad_request(
                "redirect_uri scheme is not in identity.oidc.native_schemes",
            ))
        };
    }

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
    validate_client_redirect(
        &redirect_uri,
        &configured,
        &state.config.identity.oidc.native_schemes,
    )?;
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

    // Binds the id_token the provider will mint to this handshake. `state`
    // protects the redirect; the nonce protects the token, and they are separate
    // values so that neither one leaking through a referrer or a log weakens the
    // other.
    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);

    // Resolved before the handshake is recorded. A provider that cannot be
    // reached should not leave a state row behind: this endpoint takes no
    // credential, so a write that happens before the first thing that can fail
    // turns a provider outage into unauthenticated rows in the table.
    let metadata = discover(&state).await?;

    sqlx::query(
        r#"
        INSERT INTO oidc_auth_states
            (state, code_verifier, redirect_uri, client_redirect_uri, client_challenge, nonce,
             expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(&oauth_state)
    .bind(&code_verifier)
    .bind(&redirect_uri)
    .bind(&client_redirect)
    .bind(&q.client_challenge)
    .bind(&nonce)
    .bind(Utc::now() + Duration::minutes(10))
    .execute(&state.db)
    .await?;

    // The authorize endpoint comes from discovery rather than being assumed to
    // sit at `{issuer}/auth`. That assumption held for Dex and for nothing else.
    let oidc = &state.config.identity.oidc;
    let mut url = url::Url::parse(&metadata.authorization_endpoint)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("provider authorize endpoint: {e}")))?;

    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("client_id", &oidc.client_id);
        qp.append_pair("response_type", "code");
        qp.append_pair("scope", &oidc.scopes.join(" "));
        qp.append_pair("redirect_uri", &oidc.redirect_uri);
        qp.append_pair("state", &oauth_state);
        qp.append_pair("nonce", &nonce);
        qp.append_pair("code_challenge", &challenge);
        qp.append_pair("code_challenge_method", "S256");
    }

    Ok(Redirect::temporary(url.as_str()))
}

pub async fn callback(
    State(state): State<AppState>,
    Query(q): Query<CallbackQuery>,
) -> AppResult<axum::response::Response> {
    let row: Option<(String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        DELETE FROM oidc_auth_states
        WHERE state = $1 AND expires_at > NOW()
        RETURNING code_verifier, client_redirect_uri, client_challenge, nonce
        "#,
    )
    .bind(&q.state)
    .fetch_optional(&state.db)
    .await?;
    let Some((code_verifier, client_redirect_uri, client_challenge, nonce)) = row else {
        return Err(AppError::bad_request("invalid or expired oauth state"));
    };

    let oidc = &state.config.identity.oidc;
    let metadata = discover(&state).await?;
    let token_url = metadata.token_endpoint.clone();
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

    // A handshake row with no nonce was written by a build that did not send
    // one, which during a rolling upgrade means a login started against the old
    // binary and finished against this one. Rather than skip the check for those,
    // refuse them: the row expires in ten minutes and the person clicks again,
    // whereas a nonce check that can be switched off by the *absence* of a value
    // is one an attacker would aim to reproduce.
    let Some(nonce) = nonce else {
        tracing::warn!("denied: login handshake predates nonce enforcement; retry required");
        return Err(AppError::bad_request("stale login attempt; start again"));
    };

    let identity = verify(&state, &metadata, id_token, Some(&nonce)).await?;
    let email = identity.email.clone();
    let user_id = resolve_user(&state, &identity).await?;

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

/// Look up the provider's discovery document.
async fn discover(state: &AppState) -> AppResult<ProviderMetadata> {
    let oidc = &state.config.identity.oidc;
    state
        .oidc_keys
        .metadata(&state.http, &oidc.issuer, oidc.internal_url.as_deref())
        .await
        .map_err(reject)
}

/// Verify an id_token against the provider's published keys.
async fn verify(
    state: &AppState,
    metadata: &ProviderMetadata,
    id_token: &str,
    expected_nonce: Option<&str>,
) -> AppResult<VerifiedIdentity> {
    let oidc = &state.config.identity.oidc;
    let jwks = state
        .oidc_keys
        .keys_for(
            &state.http,
            &oidc.issuer,
            &metadata.jwks_uri,
            peek_key_id(id_token).as_deref(),
        )
        .await
        .map_err(reject)?;

    verify_id_token(
        id_token,
        &jwks,
        &oidc.issuer,
        &oidc.client_id,
        expected_nonce,
        oidc.clock_skew_secs,
    )
    .map_err(reject)
}

/// Resolve a verified login to a user, creating or linking as policy allows.
///
/// The binding on `(issuer, subject)` is authoritative once it exists. Email is
/// consulted only to attach a *first* login to a user the directory already
/// created — otherwise a person provisioned through SCIM could never sign in —
/// and even then only an address the provider says it verified, which
/// [`verify_id_token`] has already required.
///
/// Three rules keep that first-login step from becoming an account-takeover
/// path:
///
///   * A user who already has a binding for this issuer is never re-linked to a
///     second subject. That is what an attacker registering a second account
///     bearing a victim's address looks like, so it is refused rather than
///     merged.
///   * A deactivated user is never reactivated by signing in. Login is not a
///     provisioning decision, and treating it as one silently undoes a
///     deprovisioning.
///   * A changed email address moves with the existing binding instead of
///     creating or matching another user.
pub async fn resolve_user(state: &AppState, identity: &VerifiedIdentity) -> AppResult<Uuid> {
    let mut tx = state.db.begin().await?;

    let bound: Option<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM oidc_identities WHERE issuer = $1 AND subject = $2")
            .bind(&identity.issuer)
            .bind(&identity.subject)
            .fetch_optional(&mut *tx)
            .await?;

    let user_id = match bound {
        Some((user_id,)) => {
            // Known subject. The email may have changed at the provider; carry
            // it across as an attribute, and leave `active` alone.
            sqlx::query(
                r#"
                UPDATE oidc_identities SET email = $3, updated_at = NOW()
                WHERE issuer = $1 AND subject = $2
                "#,
            )
            .bind(&identity.issuer)
            .bind(&identity.subject)
            .bind(&identity.email)
            .execute(&mut *tx)
            .await?;

            sqlx::query("UPDATE users SET email = $2, updated_at = NOW() WHERE id = $1")
                .bind(user_id)
                .bind(&identity.email)
                .execute(&mut *tx)
                .await?;
            user_id
        }
        None => {
            let existing: Option<(Uuid, bool)> =
                sqlx::query_as("SELECT id, active FROM users WHERE email = $1")
                    .bind(&identity.email)
                    .fetch_optional(&mut *tx)
                    .await?;

            match existing {
                Some((user_id, _)) => {
                    // Refuse to attach a second subject from the same issuer to
                    // one user.
                    let already: Option<(String,)> = sqlx::query_as(
                        "SELECT subject FROM oidc_identities WHERE issuer = $1 AND user_id = $2",
                    )
                    .bind(&identity.issuer)
                    .bind(user_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if let Some((other,)) = already {
                        tracing::warn!(
                            issuer = %identity.issuer,
                            email = %identity.email,
                            existing_subject = %other,
                            "denied: refusing to link a second provider subject to one user"
                        );
                        return Err(AppError::Unauthorized);
                    }
                    link(&mut tx, identity, user_id).await?;
                    user_id
                }
                None => {
                    let user_id: Uuid = sqlx::query_scalar(
                        r#"
                        INSERT INTO users (email, display_name, active)
                        VALUES ($1, $2, TRUE)
                        RETURNING id
                        "#,
                    )
                    .bind(&identity.email)
                    .bind(identity.display_name.as_deref().unwrap_or(&identity.email))
                    .fetch_one(&mut *tx)
                    .await?;
                    link(&mut tx, identity, user_id).await?;
                    user_id
                }
            }
        }
    };

    // Checked last, and on the row rather than on anything the token said, so
    // that a login by someone who has been deprovisioned fails no matter which
    // branch above found them.
    let active: bool = sqlx::query_scalar("SELECT active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    if !active {
        tracing::warn!(user_id = %user_id, "denied: login by a deactivated user");
        return Err(AppError::Unauthorized);
    }

    tx.commit().await?;
    Ok(user_id)
}

async fn link(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    identity: &VerifiedIdentity,
    user_id: Uuid,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO oidc_identities (issuer, subject, user_id, email)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .bind(user_id)
    .bind(&identity.email)
    .execute(&mut **tx)
    .await?;
    tracing::info!(
        user_id = %user_id,
        issuer = %identity.issuer,
        "linked identity provider subject to user"
    );
    Ok(())
}

/// Create-or-find a user for the dev login.
///
/// Separate from [`resolve_user`] because there is no provider and so no stable
/// subject to bind to — email is all this path has. It still refuses to
/// reactivate a deactivated account, so that a local deployment behaves the same
/// way a real one does when someone has been deprovisioned.
async fn dev_upsert_user(state: &AppState, email: &str) -> AppResult<Uuid> {
    let email = email.trim().to_ascii_lowercase();
    let existing: Option<(Uuid, bool)> =
        sqlx::query_as("SELECT id, active FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;

    if let Some((id, active)) = existing {
        if !active {
            tracing::warn!(user_id = %id, "denied: dev login by a deactivated user");
            return Err(AppError::Unauthorized);
        }
        return Ok(id);
    }

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, display_name, active) VALUES ($1, $1, TRUE) RETURNING id",
    )
    .bind(&email)
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
    let user_id = dev_upsert_user(&state, &body.email).await?;
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
