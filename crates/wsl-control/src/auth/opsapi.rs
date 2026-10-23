//! Signing in with an OpsAPI account (ADR-0004).
//!
//! OpsAPI tokens are HS256 under a secret this process must never hold
//! (ADR-0003), so they are never verified here. Each one is handed back to the
//! service that issued it, and the answer is checked twice, from two
//! directions:
//!
//! 1. `GET /auth/me` with the person's token. OpsAPI says whose live session it
//!    is and which workspaces they are an active member of. A token it does not
//!    recognise, or a person outside the configured workspace, stops here —
//!    OpsAPI has open sign-up, so an account on its own is not membership.
//! 2. `GET /scim/v2/Users/{uuid}` with this deployment's own `opsk_` key. The
//!    directory, asked independently of anything the client presented, must
//!    agree the person exists and is active.
//!
//! The person is then bound by OpsAPI's uuid, never by email. OpsAPI does not
//! require a verified address to register, so "an OpsAPI account carrying
//! alice's email" is not alice: a first sign-in only ever finds a user OpsAPI
//! itself provisioned under that uuid (`users.external_id`), or — under `jit`
//! admission, and only when no user has that email — creates one.
//!
//! The person's OpsAPI token is used for one request and dropped. It is not
//! stored, logged, or sent anywhere but back to OpsAPI.

use crate::auth::oidc::{mint_access_token, TokenResponse};
use crate::config::{OpsApiConfig, Provisioning};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

/// How long to wait on OpsAPI. Sign-in and connect are interactive; a hung
/// directory should fail the request, not the person's patience.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The issuer recorded in `oidc_identities` for OpsAPI bindings. Includes the
/// URL, so pointing a deployment at a different OpsAPI cannot reuse bindings
/// made against the old one.
pub fn issuer(config: &OpsApiConfig) -> String {
    format!("opsapi:{}", config.url.trim_end_matches('/'))
}

fn endpoint(config: &OpsApiConfig, path: &str) -> String {
    format!("{}{path}", config.url.trim_end_matches('/'))
}

/// Who OpsAPI says a session belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpsApiPerson {
    pub uuid: String,
    pub email: String,
    pub display_name: Option<String>,
}

#[derive(Deserialize)]
struct MeResponse {
    user: MeUser,
    #[serde(default)]
    namespaces: Vec<MeNamespace>,
}

#[derive(Deserialize)]
struct MeUser {
    uuid: String,
    email: String,
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
}

#[derive(Deserialize)]
struct MeNamespace {
    slug: String,
    #[serde(default)]
    member_status: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize)]
struct ScimUser {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    active: Option<bool>,
}

fn unreachable(err: reqwest::Error) -> AppError {
    AppError::Unavailable(format!("OpsAPI could not be reached: {err}"))
}

/// Step 1: ask OpsAPI whose session `token` is, and check membership.
async fn whose_session(
    state: &AppState,
    config: &OpsApiConfig,
    token: &str,
) -> AppResult<OpsApiPerson> {
    let response = state
        .http
        .get(endpoint(config, "/auth/me"))
        .bearer_auth(token)
        .timeout(TIMEOUT)
        .send()
        .await
        .map_err(unreachable)?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        tracing::warn!("denied: OpsAPI did not recognise the session");
        return Err(AppError::Unauthorized);
    }
    if !status.is_success() {
        return Err(AppError::Unavailable(format!(
            "OpsAPI /auth/me answered {status}"
        )));
    }
    let me: MeResponse = response.json().await.map_err(unreachable)?;

    if me.user.active == Some(false) {
        tracing::warn!(opsapi_user = %me.user.uuid, "denied: OpsAPI account is deactivated");
        return Err(AppError::Unauthorized);
    }
    // OpsAPI only lists active memberships of active workspaces today; the
    // status fields are checked as well so that a change there cannot quietly
    // widen who gets in.
    let member = me.namespaces.iter().any(|ns| {
        ns.slug.eq_ignore_ascii_case(&config.namespace)
            && ns.member_status.as_deref().is_none_or(|s| s == "active")
            && ns.status.as_deref().is_none_or(|s| s == "active")
    });
    if !member {
        tracing::warn!(
            opsapi_user = %me.user.uuid,
            namespace = %config.namespace,
            "denied: not an active member of the OpsAPI workspace"
        );
        return Err(AppError::Unauthorized);
    }
    let name = [me.user.first_name, me.user.last_name]
        .into_iter()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Ok(OpsApiPerson {
        uuid: me.user.uuid,
        email: me.user.email.trim().to_ascii_lowercase(),
        display_name: (!name.is_empty()).then_some(name),
    })
}

/// What the directory says about one person, asked with our own key.
#[derive(Debug, PartialEq, Eq)]
pub enum DirectoryAnswer {
    Active { email: Option<String> },
    Inactive,
    Unknown,
}

/// Step 2, and the check on every connect: ask SCIM about `uuid`.
pub async fn directory_lookup(
    state: &AppState,
    config: &OpsApiConfig,
    uuid: &str,
) -> AppResult<DirectoryAnswer> {
    // A uuid is all that is interpolated, and it is checked as one, so a value
    // from the database or from OpsAPI cannot reshape the path.
    let uuid = Uuid::parse_str(uuid)
        .map_err(|_| AppError::Unavailable("OpsAPI user id is not a uuid".into()))?;
    let response = state
        .http
        .get(endpoint(config, &format!("/scim/v2/Users/{uuid}")))
        .bearer_auth(&config.api_key)
        .timeout(TIMEOUT)
        .send()
        .await
        .map_err(unreachable)?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(DirectoryAnswer::Unknown);
    }
    if !status.is_success() {
        // 401/403 here mean *our* key is wrong or lacks the role — a
        // deployment fault, not the person's — so it is reported as
        // unavailable, and never as an allow.
        return Err(AppError::Unavailable(format!(
            "OpsAPI SCIM answered {status}; check identity.opsapi.api_key"
        )));
    }
    let user: ScimUser = response.json().await.map_err(unreachable)?;
    Ok(match user.active {
        Some(true) => DirectoryAnswer::Active { email: user.email },
        _ => DirectoryAnswer::Inactive,
    })
}

/// Find or create the WSL user for a verified OpsAPI person.
async fn resolve_user(
    state: &AppState,
    config: &OpsApiConfig,
    person: &OpsApiPerson,
) -> AppResult<Uuid> {
    let issuer = issuer(config);
    let mut tx = state.db.begin().await?;

    let bound: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM oidc_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(&issuer)
    .bind(&person.uuid)
    .fetch_optional(&mut *tx)
    .await?;

    let user_id = match bound {
        Some(user_id) => {
            sqlx::query(
                "UPDATE oidc_identities SET email = $3, updated_at = NOW() \
                 WHERE issuer = $1 AND subject = $2",
            )
            .bind(&issuer)
            .bind(&person.uuid)
            .bind(&person.email)
            .execute(&mut *tx)
            .await?;
            user_id
        }
        None => {
            // A user OpsAPI provisioned under this uuid.
            let provisioned: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM users WHERE external_id = $1")
                    .bind(&person.uuid)
                    .fetch_optional(&mut *tx)
                    .await?;
            let user_id = match provisioned {
                Some(id) => id,
                None => {
                    let taken: Option<Uuid> =
                        sqlx::query_scalar("SELECT id FROM users WHERE lower(email) = $1")
                            .bind(&person.email)
                            .fetch_optional(&mut *tx)
                            .await?;
                    if taken.is_some() {
                        tracing::warn!(
                            opsapi_user = %person.uuid,
                            "denied: an existing user has this email but was not provisioned \
                             by OpsAPI under this id; refusing to link on email alone"
                        );
                        return Err(AppError::Unauthorized);
                    }
                    if state.config.identity.admission.provisioning == Provisioning::Directory {
                        tracing::warn!(
                            opsapi_user = %person.uuid,
                            "denied: OpsAPI sign-in by someone not provisioned into WSL"
                        );
                        return Err(AppError::Unauthorized);
                    }
                    sqlx::query_scalar(
                        "INSERT INTO users (email, display_name, external_id, active) \
                         VALUES ($1, $2, $3, TRUE) RETURNING id",
                    )
                    .bind(&person.email)
                    .bind(person.display_name.as_deref().unwrap_or(&person.email))
                    .bind(&person.uuid)
                    .fetch_one(&mut *tx)
                    .await?
                }
            };
            sqlx::query(
                "INSERT INTO oidc_identities (issuer, subject, user_id, email) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(&issuer)
            .bind(&person.uuid)
            .bind(user_id)
            .bind(&person.email)
            .execute(&mut *tx)
            .await?;
            user_id
        }
    };

    let active: bool = sqlx::query_scalar("SELECT active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    if !active {
        tracing::warn!(%user_id, "denied: OpsAPI sign-in by a user WSL has disabled");
        return Err(AppError::Unauthorized);
    }
    tx.commit().await?;
    Ok(user_id)
}

/// The sign-in methods a client may offer. Public: the app reads it before
/// anyone has signed in.
#[derive(Debug, Serialize)]
pub struct SignInMethods {
    /// Browser sign-in through the configured OIDC provider.
    pub oidc: bool,
    pub opsapi: Option<OpsApiMethod>,
}

#[derive(Debug, Serialize)]
pub struct OpsApiMethod {
    /// Where the app sends the email and password. Not the control plane.
    pub url: String,
    pub namespace: String,
}

pub async fn methods(State(state): State<AppState>) -> Json<SignInMethods> {
    Json(SignInMethods {
        oidc: true,
        opsapi: state.config.identity.opsapi.as_ref().map(|o| OpsApiMethod {
            url: o.url.trim_end_matches('/').to_string(),
            namespace: o.namespace.clone(),
        }),
    })
}

#[derive(Deserialize)]
pub struct ExchangeRequest {
    /// The OpsAPI session token the app got from OpsAPI's `/auth/login`.
    pub token: String,
}

/// Trade an OpsAPI session for a WSL access token.
pub async fn exchange(
    State(state): State<AppState>,
    Json(body): Json<ExchangeRequest>,
) -> AppResult<Json<TokenResponse>> {
    let Some(config) = state.config.identity.opsapi.clone() else {
        return Err(AppError::NotFound);
    };
    let person = whose_session(&state, &config, body.token.trim()).await?;
    drop(body);

    match directory_lookup(&state, &config, &person.uuid).await? {
        DirectoryAnswer::Active { email } => {
            // The two answers must be about the same person.
            if email.is_some_and(|e| !e.trim().eq_ignore_ascii_case(&person.email)) {
                tracing::warn!(opsapi_user = %person.uuid, "denied: SCIM and /auth/me disagree on email");
                return Err(AppError::Unauthorized);
            }
        }
        answer => {
            tracing::warn!(opsapi_user = %person.uuid, ?answer, "denied: directory does not confirm an active user");
            return Err(AppError::Unauthorized);
        }
    }

    let user_id = resolve_user(&state, &config, &person).await?;
    let (access_token, expires_in) = mint_access_token(&state, user_id).await?;
    tracing::info!(%user_id, opsapi_user = %person.uuid, "signed in with OpsAPI");
    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        user_id,
        email: person.email,
    }))
}

/// The check on connect: if OpsAPI provisioned this user, it must still say
/// they are active. Users OpsAPI did not provision (no `external_id`) are not
/// its to judge, and pass through to the usual policy evaluation.
pub async fn verify_on_connect(state: &AppState, user_id: Uuid) -> AppResult<()> {
    let Some(config) = state.config.identity.opsapi.as_ref() else {
        return Ok(());
    };
    if !config.verify_on_connect {
        return Ok(());
    }
    let external: Option<String> =
        sqlx::query_scalar("SELECT external_id FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?
            .flatten();
    let Some(uuid) = external.filter(|e| Uuid::parse_str(e).is_ok()) else {
        return Ok(());
    };
    match directory_lookup(state, config, &uuid).await? {
        DirectoryAnswer::Active { .. } => Ok(()),
        answer => {
            tracing::warn!(%user_id, ?answer, "denied: OpsAPI no longer lists this user as active");
            Err(AppError::Forbidden)
        }
    }
}
