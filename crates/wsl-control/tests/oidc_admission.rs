//! Who may sign in: Google proves who someone is, OpsAPI decides who is in.
//!
//! Written as behaviour, against a real database and the real ops router.
//! OpsAPI provisions a user exactly the way it does in production — a
//! service-token call to `/api/v1/ops/users` — and a login is then resolved
//! the way the OIDC callback resolves one, from an identity the provider has
//! already verified.
//!
//! Requires a PostgreSQL instance; `#[sqlx::test]` provisions an isolated
//! database per test from `DATABASE_URL` and runs the migrations into it.

mod common;

use axum::Router;
use common::*;
use sqlx::PgPool;
use wsl_control::auth::oidc::resolve_user;
use wsl_control::auth::oidc_provider::VerifiedIdentity;
use wsl_control::config::{AdmissionConfig, Config, Provisioning};
use wsl_control::error::AppError;
use wsl_control::state::AppState;

const GOOGLE: &str = "https://accounts.google.com";

fn google_login(subject: &str, email: &str, hd: Option<&str>) -> VerifiedIdentity {
    VerifiedIdentity {
        issuer: GOOGLE.into(),
        subject: subject.into(),
        email: email.into(),
        display_name: None,
        hosted_domain: hd.map(str::to_string),
    }
}

fn config(admission: AdmissionConfig) -> Config {
    let mut config = test_config();
    config.identity.oidc.issuer = GOOGLE.into();
    config.identity.admission = admission;
    config
}

fn directory_only() -> AdmissionConfig {
    AdmissionConfig {
        provisioning: Provisioning::Directory,
        ..Default::default()
    }
}

fn workspace(domain: &str) -> AdmissionConfig {
    AdmissionConfig {
        hosted_domains: vec![domain.into()],
        ..Default::default()
    }
}

async fn given(pool: &PgPool, admission: AdmissionConfig) -> (AppState, Router) {
    let state = AppState::with_pool(config(admission), pool.clone());
    state.bootstrap().await.expect("bootstrap");
    let router = wsl_control::routes::router(state.clone());
    (state, router)
}

/// OpsAPI provisions a person, through the endpoint it actually calls.
async fn opsapi_provisions(router: &Router, email: &str) -> serde_json::Value {
    let (status, body) = post(
        "/api/v1/ops/users",
        serde_json::json!({ "email": email, "display_name": "Provisioned" }),
    )
    .with_token(OPS_TOKEN)
    .send(router)
    .await;
    assert!(status.is_success(), "ops create user: {status} {body}");
    body
}

async fn users_named(pool: &PgPool, email: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(pool)
        .await
        .unwrap()
}

// --- directory provisioning -------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_person_opsapi_provisioned_signs_in_with_google(pool: PgPool) {
    let (state, router) = given(&pool, directory_only()).await;
    let provisioned = opsapi_provisions(&router, "alice@example.com").await;

    let user_id = resolve_user(&state, &google_login("g-1", "alice@example.com", None))
        .await
        .expect("a provisioned person is admitted");

    assert_eq!(
        provisioned["id"].as_str(),
        Some(user_id.to_string().as_str())
    );
    // And the Google subject is now bound, so a later email change follows it.
    let again = resolve_user(&state, &google_login("g-1", "alice@example.com", None))
        .await
        .expect("second login");
    assert_eq!(again, user_id);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_google_account_opsapi_never_provisioned_is_refused(pool: PgPool) {
    let (state, _router) = given(&pool, directory_only()).await;

    let result = resolve_user(&state, &google_login("g-2", "mallory@gmail.com", None)).await;

    assert!(matches!(result, Err(AppError::Unauthorized)), "{result:?}");
    assert_eq!(
        users_named(&pool, "mallory@gmail.com").await,
        0,
        "a refused login must not leave a user behind"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_person_opsapi_disabled_cannot_sign_in(pool: PgPool) {
    let (state, router) = given(&pool, directory_only()).await;
    let user = opsapi_provisions(&router, "bob@example.com").await;
    resolve_user(&state, &google_login("g-3", "bob@example.com", None))
        .await
        .expect("admitted while enabled");

    let (status, _) = post(
        &format!("/api/v1/ops/users/{}/disable", user["id"].as_str().unwrap()),
        serde_json::json!({}),
    )
    .with_token(OPS_TOKEN)
    .send(&router)
    .await;
    assert!(status.is_success(), "ops disable: {status}");

    let result = resolve_user(&state, &google_login("g-3", "bob@example.com", None)).await;
    assert!(matches!(result, Err(AppError::Unauthorized)), "{result:?}");
}

// --- Google Workspace domain ------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_workspace_account_in_the_allowed_domain_is_admitted(pool: PgPool) {
    let (state, _router) = given(&pool, workspace("example.com")).await;

    resolve_user(
        &state,
        &google_login("g-4", "carol@example.com", Some("example.com")),
    )
    .await
    .expect("same Workspace domain");
}

/// A consumer Google account can carry any verified address, including one at
/// your domain. Only `hd` says the account belongs to your Workspace.
#[sqlx::test(migrations = "../../migrations")]
async fn a_consumer_account_using_your_domain_address_is_refused(pool: PgPool) {
    let (state, _router) = given(&pool, workspace("example.com")).await;

    let result = resolve_user(&state, &google_login("g-5", "carol@example.com", None)).await;

    assert!(matches!(result, Err(AppError::Unauthorized)), "{result:?}");
    assert_eq!(users_named(&pool, "carol@example.com").await, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn another_organisations_workspace_is_refused(pool: PgPool) {
    let (state, _router) = given(&pool, workspace("example.com")).await;

    let result = resolve_user(
        &state,
        &google_login("g-6", "dave@other.example", Some("other.example")),
    )
    .await;

    assert!(matches!(result, Err(AppError::Unauthorized)), "{result:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_domain_comparison_ignores_case(pool: PgPool) {
    let (state, _router) = given(&pool, workspace("Example.COM")).await;

    resolve_user(
        &state,
        &google_login("g-7", "erin@example.com", Some("example.com")),
    )
    .await
    .expect("case-insensitive");
}

// --- both together ------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn with_both_rules_a_provisioned_person_outside_the_workspace_is_refused(pool: PgPool) {
    let admission = AdmissionConfig {
        provisioning: Provisioning::Directory,
        hosted_domains: vec!["example.com".into()],
    };
    let (state, router) = given(&pool, admission).await;
    opsapi_provisions(&router, "frank@example.com").await;

    let consumer = resolve_user(&state, &google_login("g-8", "frank@example.com", None)).await;
    assert!(
        matches!(consumer, Err(AppError::Unauthorized)),
        "{consumer:?}"
    );

    resolve_user(
        &state,
        &google_login("g-9", "frank@example.com", Some("example.com")),
    )
    .await
    .expect("provisioned and in the Workspace");
}

// --- unchanged behaviour ----------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_default_still_provisions_on_first_login(pool: PgPool) {
    let state = AppState::with_pool(test_config(), pool.clone());
    resolve_user(
        &state,
        &VerifiedIdentity {
            issuer: TEST_ISSUER.into(),
            subject: "s".into(),
            email: "gina@example.com".into(),
            display_name: None,
            hosted_domain: None,
        },
    )
    .await
    .expect("just-in-time provisioning is still the default");
    assert_eq!(users_named(&pool, "gina@example.com").await, 1);
}

/// The administrators named in config exist before anyone provisions them, so
/// directory-only admission cannot lock them out of their own deployment.
#[sqlx::test(migrations = "../../migrations")]
async fn a_configured_administrator_can_sign_in_without_being_provisioned(pool: PgPool) {
    let mut cfg = config(directory_only());
    cfg.bootstrap.admin_emails = vec!["root@example.com".into()];
    let state = AppState::with_pool(cfg, pool.clone());
    state.bootstrap().await.expect("bootstrap");

    resolve_user(&state, &google_login("g-10", "root@example.com", None))
        .await
        .expect("the bootstrap admin is admitted");
}
