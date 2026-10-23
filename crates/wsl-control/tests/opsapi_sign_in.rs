//! Signing in with an OpsAPI account, and OpsAPI being asked again on connect.
//!
//! OpsAPI is not an OIDC provider (ADR-0003): its tokens are HS256 under a
//! secret the control plane must never hold. So the control plane does not
//! verify an OpsAPI token itself. It asks OpsAPI, twice, from two directions:
//!
//!   * `GET /auth/me` with the person's token — is this a live session, for
//!     whom, and are they an active member of our namespace?
//!   * `GET /scim/v2/Users/{uuid}` with the control plane's own `opsk_` key —
//!     does the directory, asked independently of anything the client sent,
//!     agree that this person exists and is active?
//!
//! The stand-in OpsAPI below answers both the way the real one does (the shapes
//! are taken from `routes/auth.lua` and `routes/users.lua`), so what is pinned
//! down here is the control plane's decision, against a real database.
//!
//! Requires a PostgreSQL instance; `#[sqlx::test]` provisions an isolated
//! database per test from `DATABASE_URL` and runs the migrations into it.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get as route;
use axum::{Json, Router};
use common::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
use wsl_control::config::{AdmissionConfig, OpsApiConfig, Provisioning};
use wsl_control::state::AppState;

const NAMESPACE: &str = "workstation";
const API_KEY: &str = "opsk_0123456789abcdef0123456789abcdef0123456789abcdef";

/// A person as OpsAPI knows them.
#[derive(Clone)]
struct Person {
    uuid: String,
    email: String,
    active: bool,
    namespaces: Vec<&'static str>,
}

#[derive(Default)]
struct Directory {
    /// Session token → uuid, as OpsAPI's JWTs map to a user.
    sessions: HashMap<String, String>,
    people: HashMap<String, Person>,
}

type Shared = Arc<Mutex<Directory>>;

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_string)
}

/// `GET /auth/me`: the session's user and their active namespaces.
async fn me(
    State(dir): State<Shared>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    let dir = dir.lock().unwrap();
    let person = bearer(&headers)
        .and_then(|t| dir.sessions.get(&t).cloned())
        .and_then(|uuid| dir.people.get(&uuid).cloned());
    match person {
        Some(p) => (
            StatusCode::OK,
            Json(json!({
                "user": { "id": 7, "uuid": p.uuid, "email": p.email, "active": p.active,
                          "first_name": "Alice", "last_name": "Example" },
                "namespaces": p.namespaces.iter().map(|slug| json!({
                    "id": 1, "uuid": "ns-uuid", "name": slug, "slug": slug,
                    "status": "active", "member_status": "active", "is_owner": false
                })).collect::<Vec<_>>(),
            })),
        ),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid or expired token" })),
        ),
    }
}

/// `GET /scim/v2/Users/{uuid}`: platform-admin only, which the API key is.
async fn scim_user(
    State(dir): State<Shared>,
    headers: HeaderMap,
    Path(uuid): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if bearer(&headers).as_deref() != Some(API_KEY) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid API key" })),
        );
    }
    match dir.lock().unwrap().people.get(&uuid) {
        Some(p) => (
            StatusCode::OK,
            Json(json!({ "id": p.uuid, "uuid": p.uuid, "internal_id": 7,
                         "email": p.email, "username": p.email, "active": p.active,
                         "roles": [] })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "User not found! Please check the UUID and try again." })),
        ),
    }
}

struct OpsApi {
    url: String,
    dir: Shared,
}

impl OpsApi {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let dir: Shared = Arc::default();
        let app = Router::new()
            .route("/auth/me", route(me))
            .route("/scim/v2/Users/{id}", route(scim_user))
            .with_state(dir.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, dir }
    }

    /// Add someone with a live session; returns (uuid, their OpsAPI token).
    fn person(&self, email: &str, namespaces: Vec<&'static str>) -> (String, String) {
        let uuid = Uuid::new_v4().to_string();
        let token = format!("opsapi-jwt-{}", Uuid::new_v4());
        let mut dir = self.dir.lock().unwrap();
        dir.people.insert(
            uuid.clone(),
            Person {
                uuid: uuid.clone(),
                email: email.into(),
                active: true,
                namespaces,
            },
        );
        dir.sessions.insert(token.clone(), uuid.clone());
        (uuid, token)
    }

    fn deactivate(&self, uuid: &str) {
        self.dir
            .lock()
            .unwrap()
            .people
            .get_mut(uuid)
            .unwrap()
            .active = false;
    }

    fn forget(&self, uuid: &str) {
        self.dir.lock().unwrap().people.remove(uuid);
    }
}

fn opsapi_config(url: &str) -> OpsApiConfig {
    OpsApiConfig {
        url: url.into(),
        namespace: NAMESPACE.into(),
        api_key: API_KEY.into(),
        verify_on_connect: true,
    }
}

async fn control_plane(
    pool: &PgPool,
    opsapi: Option<OpsApiConfig>,
    provisioning: Provisioning,
) -> Router {
    let mut config = test_config();
    config.identity.opsapi = opsapi;
    config.identity.admission = AdmissionConfig {
        provisioning,
        ..Default::default()
    };
    let state = AppState::with_pool(config, pool.clone());
    state.bootstrap().await.expect("bootstrap");
    wsl_control::routes::router(state)
}

/// OpsAPI provisions the person into WSL, naming them by its own uuid.
async fn provision(app: &Router, email: &str, uuid: &str) {
    let (status, body) = post(
        "/api/v1/ops/users",
        json!({ "email": email, "external_id": uuid }),
    )
    .with_token(OPS_TOKEN)
    .send(app)
    .await;
    assert!(status.is_success(), "{status} {body}");
}

async fn exchange(app: &Router, token: &str) -> (StatusCode, serde_json::Value) {
    post("/auth/opsapi/exchange", json!({ "token": token }))
        .send(app)
        .await
}

async fn user_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_app_is_told_which_sign_in_methods_this_control_plane_offers(pool: PgPool) {
    let ops = OpsApi::start().await;
    let app = control_plane(
        &pool,
        Some(opsapi_config(&ops.url)),
        Provisioning::Directory,
    )
    .await;
    let (status, body) = get("/auth/methods").send(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["oidc"], true);
    assert_eq!(body["opsapi"]["url"], ops.url.as_str());
    // The key is the control plane's credential; it is never handed out.
    assert!(!body.to_string().contains("opsk_"), "{body}");

    let app = control_plane(&pool, None, Provisioning::Directory).await;
    let (_, body) = get("/auth/methods").send(&app).await;
    assert!(body["opsapi"].is_null(), "{body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_provisioned_member_signs_in_and_gets_a_token_that_works(pool: PgPool) {
    let ops = OpsApi::start().await;
    let app = control_plane(
        &pool,
        Some(opsapi_config(&ops.url)),
        Provisioning::Directory,
    )
    .await;
    let (uuid, token) = ops.person("alice@example.com", vec![NAMESPACE]);
    provision(&app, "alice@example.com", &uuid).await;

    let (status, body) = exchange(&app, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["email"], "alice@example.com");
    let access = body["access_token"].as_str().expect("an access token");

    let (status, _) = get("/api/v1/sessions").with_token(access).send(&app).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the token is a working WSL credential"
    );

    // The binding is on OpsAPI's uuid, so a second sign-in finds the same user
    // without consulting the email at all.
    let (status, again) = exchange(&app, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["user_id"], body["user_id"]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_token_opsapi_does_not_recognise_is_refused(pool: PgPool) {
    let ops = OpsApi::start().await;
    let app = control_plane(&pool, Some(opsapi_config(&ops.url)), Provisioning::Jit).await;
    let (status, _) = exchange(&app, "forged-or-expired").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(user_count(&pool).await, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn someone_outside_the_namespace_is_refused(pool: PgPool) {
    let ops = OpsApi::start().await;
    let app = control_plane(&pool, Some(opsapi_config(&ops.url)), Provisioning::Jit).await;
    // A real OpsAPI account, in some other workspace — exactly what open
    // sign-up at OpsAPI produces.
    let (_, token) = ops.person("stranger@example.com", vec!["someone-elses-shop"]);
    let (status, _) = exchange(&app, &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(user_count(&pool).await, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_directory_saying_inactive_wins_over_a_live_session(pool: PgPool) {
    let ops = OpsApi::start().await;
    let app = control_plane(
        &pool,
        Some(opsapi_config(&ops.url)),
        Provisioning::Directory,
    )
    .await;
    let (uuid, token) = ops.person("alice@example.com", vec![NAMESPACE]);
    provision(&app, "alice@example.com", &uuid).await;
    ops.deactivate(&uuid);
    let (status, _) = exchange(&app, &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn someone_scim_cannot_find_is_refused(pool: PgPool) {
    let ops = OpsApi::start().await;
    let app = control_plane(&pool, Some(opsapi_config(&ops.url)), Provisioning::Jit).await;
    let (uuid, token) = ops.person("alice@example.com", vec![NAMESPACE]);
    // The session still answers /auth/me, but the directory no longer has them.
    {
        let mut dir = ops.dir.lock().unwrap();
        let person = dir.people.remove(&uuid).unwrap();
        dir.people.insert("someone-else".into(), person);
    }
    let (status, _) = exchange(&app, &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The account-takeover case. OpsAPI does not require a verified email to
/// register, so "an OpsAPI account with alice's address" is not alice. Only a
/// user OpsAPI itself provisioned under this uuid may be signed into.
#[sqlx::test(migrations = "../../migrations")]
async fn an_email_match_alone_never_signs_into_an_existing_user(pool: PgPool) {
    let ops = OpsApi::start().await;
    for provisioning in [Provisioning::Jit, Provisioning::Directory] {
        let app = control_plane(&pool, Some(opsapi_config(&ops.url)), provisioning).await;
        let email = format!("victim-{provisioning:?}@example.com");
        // Alice exists in WSL already — from Google, say — with no OpsAPI link.
        let (status, _) = post("/api/v1/ops/users", json!({ "email": email }))
            .with_token(OPS_TOKEN)
            .send(&app)
            .await;
        assert!(status.is_success());
        let (_, token) = ops.person(&email, vec![NAMESPACE]);
        let (status, _) = exchange(&app, &token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{provisioning:?}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn directory_admission_refuses_someone_wsl_was_never_given(pool: PgPool) {
    let ops = OpsApi::start().await;
    let app = control_plane(
        &pool,
        Some(opsapi_config(&ops.url)),
        Provisioning::Directory,
    )
    .await;
    let (_, token) = ops.person("alice@example.com", vec![NAMESPACE]);
    let (status, _) = exchange(&app, &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(user_count(&pool).await, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn jit_admission_creates_the_user_bound_to_the_opsapi_uuid(pool: PgPool) {
    let ops = OpsApi::start().await;
    let app = control_plane(&pool, Some(opsapi_config(&ops.url)), Provisioning::Jit).await;
    let (uuid, token) = ops.person("alice@example.com", vec![NAMESPACE]);
    let (status, body) = exchange(&app, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let external: Option<String> =
        sqlx::query_scalar("SELECT external_id FROM users WHERE email = 'alice@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(external.as_deref(), Some(uuid.as_str()));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_user_wsl_has_disabled_stays_out(pool: PgPool) {
    let ops = OpsApi::start().await;
    let app = control_plane(
        &pool,
        Some(opsapi_config(&ops.url)),
        Provisioning::Directory,
    )
    .await;
    let (uuid, token) = ops.person("alice@example.com", vec![NAMESPACE]);
    provision(&app, "alice@example.com", &uuid).await;
    sqlx::query("UPDATE users SET active = FALSE WHERE external_id = $1")
        .bind(&uuid)
        .execute(&pool)
        .await
        .unwrap();
    let (status, _) = exchange(&app, &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn without_opsapi_configured_there_is_no_such_sign_in(pool: PgPool) {
    let app = control_plane(&pool, None, Provisioning::Jit).await;
    let (status, _) = exchange(&app, "anything").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Connect asks again. A session is the point at which access is granted, so
/// someone deprovisioned in OpsAPI after signing in is stopped here rather than
/// when their WSL token happens to expire.
#[sqlx::test(migrations = "../../migrations")]
async fn connect_rechecks_the_directory_before_granting_a_session(pool: PgPool) {
    let ops = OpsApi::start().await;
    let app = control_plane(
        &pool,
        Some(opsapi_config(&ops.url)),
        Provisioning::Directory,
    )
    .await;
    let (uuid, token) = ops.person("alice@example.com", vec![NAMESPACE]);
    provision(&app, "alice@example.com", &uuid).await;
    let (_, body) = exchange(&app, &token).await;
    let access = body["access_token"].as_str().unwrap().to_string();

    let request = json!({
        "device_id": Uuid::new_v4(),
        "network_id": Uuid::new_v4(),
        "posture": [],
    });
    let session = || post("/api/v1/sessions", request.clone()).with_token(&access);

    // Active in OpsAPI: the check passes and the request goes on to the device
    // lookup, which knows no such device.
    let (status, body) = session().send(&app).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    ops.deactivate(&uuid);
    let (status, _) = session().send(&app).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    ops.forget(&uuid);
    let (status, _) = session().send(&app).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// If OpsAPI cannot be asked, the answer is not "yes".
#[sqlx::test(migrations = "../../migrations")]
async fn connect_fails_closed_when_opsapi_cannot_be_reached(pool: PgPool) {
    let ops = OpsApi::start().await;
    let (uuid, token) = ops.person("alice@example.com", vec![NAMESPACE]);
    let live = control_plane(
        &pool,
        Some(opsapi_config(&ops.url)),
        Provisioning::Directory,
    )
    .await;
    provision(&live, "alice@example.com", &uuid).await;
    let (_, body) = exchange(&live, &token).await;
    let access = body["access_token"].as_str().unwrap().to_string();

    let dead = control_plane(
        &pool,
        Some(opsapi_config("http://127.0.0.1:1")),
        Provisioning::Directory,
    )
    .await;
    let (status, _) = post(
        "/api/v1/sessions",
        json!({ "device_id": Uuid::new_v4(), "network_id": Uuid::new_v4(), "posture": [] }),
    )
    .with_token(&access)
    .send(&dead)
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// People OpsAPI did not provision (no external id) are not OpsAPI's to judge.
#[sqlx::test(migrations = "../../migrations")]
async fn connect_does_not_consult_opsapi_about_users_it_does_not_own(pool: PgPool) {
    let app = control_plane(
        &pool,
        Some(opsapi_config("http://127.0.0.1:1")),
        Provisioning::Jit,
    )
    .await;
    let (_, access) = user_with_token(&pool, "google-only@example.com", "member").await;
    let (status, body) = post(
        "/api/v1/sessions",
        json!({ "device_id": Uuid::new_v4(), "network_id": Uuid::new_v4(), "posture": [] }),
    )
    .with_token(&access)
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

/// Someone who had a VPN account before OpsAPI was connected — a bootstrap
/// administrator, say — is linked by OpsAPI's own provisioning call, which is
/// the directory asserting who they are. An email match at sign-in never is.
#[sqlx::test(migrations = "../../migrations")]
async fn provisioning_links_an_existing_account_to_its_opsapi_id(pool: PgPool) {
    let ops = OpsApi::start().await;
    let app = control_plane(
        &pool,
        Some(opsapi_config(&ops.url)),
        Provisioning::Directory,
    )
    .await;
    let (status, _) = post("/api/v1/ops/users", json!({ "email": "admin@example.com" }))
        .with_token(OPS_TOKEN)
        .send(&app)
        .await;
    assert!(status.is_success());
    let (uuid, token) = ops.person("admin@example.com", vec![NAMESPACE]);
    assert_eq!(exchange(&app, &token).await.0, StatusCode::UNAUTHORIZED);

    provision(&app, "admin@example.com", &uuid).await;
    let (status, body) = exchange(&app, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(user_count(&pool).await, 1, "linked, not duplicated");

    // Re-provisioning with the same id is a no-op; a different id is a
    // conflict, never a silent re-link.
    provision(&app, "admin@example.com", &uuid).await;
    let (status, _) = post(
        "/api/v1/ops/users",
        json!({ "email": "admin@example.com", "external_id": Uuid::new_v4().to_string() }),
    )
    .with_token(OPS_TOKEN)
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}
