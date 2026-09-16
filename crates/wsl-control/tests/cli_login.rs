//! Native-app login: what the CLI and the desktop client use to sign in.
//!
//! Two things are worth holding here. The handshake must not become a way to
//! deliver somebody else's token somewhere else — so the set of places the
//! browser can be sent at the end is small and checked. And the code that comes
//! back over loopback must be worth nothing on its own — so redeeming it takes
//! a secret the client never published, once.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
use wsl_control::state::hash_token;

/// The verifier and its challenge, from the RFC 7636 worked example.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn authorize_uri(redirect: &str, challenge: Option<&str>) -> String {
    let mut uri = format!(
        "/auth/oidc/authorize?redirect_uri={}",
        urlencoding(redirect)
    );
    if let Some(challenge) = challenge {
        uri.push_str(&format!("&client_challenge={challenge}"));
    }
    uri
}

fn urlencoding(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            other => format!("%{:02X}", other as u32),
        })
        .collect()
}

/// Seed a redeemable code, as the OIDC callback would have.
async fn pending_exchange(pool: &PgPool, code: &str, challenge: &str, ttl: &str) -> Uuid {
    let user_id: Uuid = sqlx::query_scalar("INSERT INTO users (email) VALUES ($1) RETURNING id")
        .bind(format!("{}@example.com", Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .expect("create user");
    sqlx::query(&format!(
        "INSERT INTO oidc_cli_exchanges (code_hash, challenge, user_id, email, expires_at)
         VALUES ($1, $2, $3, $4, NOW() + INTERVAL '{ttl}')"
    ))
    .bind(hash_token(code))
    .bind(challenge)
    .bind(user_id)
    .bind("pending@example.com")
    .execute(pool)
    .await
    .expect("seed exchange");
    user_id
}

// --- where the browser may be sent ----------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_loopback_redirect_starts_a_native_login(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (status, _) = get(&authorize_uri(
        "http://127.0.0.1:49152/callback",
        Some(CHALLENGE),
    ))
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);

    let (client_redirect, challenge): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT client_redirect_uri, client_challenge FROM oidc_auth_states LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("an auth state");
    assert_eq!(
        client_redirect.as_deref(),
        Some("http://127.0.0.1:49152/callback")
    );
    assert_eq!(challenge.as_deref(), Some(CHALLENGE));
}

/// The browser flow is unchanged: no client redirect, no challenge recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn the_configured_redirect_is_still_a_browser_login(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (status, _) = get("/auth/oidc/authorize").send(&app).await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);

    let (client_redirect, challenge): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT client_redirect_uri, client_challenge FROM oidc_auth_states LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("an auth state");
    assert!(client_redirect.is_none());
    assert!(challenge.is_none());
}

/// The one that matters: an authorize URL must not be turnable into a token
/// delivery to a host the operator never configured.
#[sqlx::test(migrations = "../../migrations")]
async fn a_redirect_to_somewhere_else_is_refused(pool: PgPool) {
    let app = app(pool.clone()).await;
    for hostile in [
        "https://evil.example.com/callback",
        "http://evil.example.com/callback",
        "http://127.0.0.1.evil.example.com/callback",
        "http://10.0.0.5:8080/callback",
    ] {
        let (status, body) = get(&authorize_uri(hostile, Some(CHALLENGE)))
            .send(&app)
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{hostile} was allowed: {body}"
        );
    }

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oidc_auth_states")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(count, 0, "a refused handshake must not leave state behind");
}

/// `localhost` is a name, and a name can be made to resolve elsewhere.
#[sqlx::test(migrations = "../../migrations")]
async fn a_loopback_name_is_refused_where_the_literal_address_is_not(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (named, _) = get(&authorize_uri(
        "http://localhost:49152/callback",
        Some(CHALLENGE),
    ))
    .send(&app)
    .await;
    assert_eq!(named, StatusCode::BAD_REQUEST);

    let (literal, _) = get(&authorize_uri(
        "http://127.0.0.1:49152/callback",
        Some(CHALLENGE),
    ))
    .send(&app)
    .await;
    assert_eq!(literal, StatusCode::TEMPORARY_REDIRECT);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_loopback_redirect_without_a_challenge_is_refused(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (status, _) = get(&authorize_uri("http://127.0.0.1:49152/callback", None))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_loopback_redirect_without_a_port_is_refused(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (status, _) = get(&authorize_uri("http://127.0.0.1/callback", Some(CHALLENGE)))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// --- redeeming the code ----------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_verifier_redeems_the_code_for_a_usable_token(pool: PgPool) {
    let app = app(pool.clone()).await;
    pending_exchange(&pool, "code-happy", CHALLENGE, "2 minutes").await;

    let (status, body) = post(
        "/auth/oidc/exchange",
        json!({"code": "code-happy", "verifier": VERIFIER}),
    )
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let token = body["access_token"].as_str().expect("a token");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["email"], "pending@example.com");

    // The point of the token is that it works on the API.
    let (api_status, _) = get("/api/v1/networks").with_token(token).send(&app).await;
    assert_eq!(api_status, StatusCode::OK);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_wrong_verifier_does_not_redeem_the_code(pool: PgPool) {
    let app = app(pool.clone()).await;
    pending_exchange(&pool, "code-wrong", CHALLENGE, "2 minutes").await;

    let (status, _) = post(
        "/auth/oidc/exchange",
        json!({"code": "code-wrong", "verifier": "not-the-verifier"}),
    )
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let issued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM access_tokens")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(issued, 0, "a failed exchange must not mint a token");
}

/// A wrong guess costs the code, not just the attempt: the row is deleted
/// whatever the verifier turns out to be, so there is nothing to guess at twice.
#[sqlx::test(migrations = "../../migrations")]
async fn a_wrong_verifier_burns_the_code(pool: PgPool) {
    let app = app(pool.clone()).await;
    pending_exchange(&pool, "code-burn", CHALLENGE, "2 minutes").await;

    let (first, _) = post(
        "/auth/oidc/exchange",
        json!({"code": "code-burn", "verifier": "wrong"}),
    )
    .send(&app)
    .await;
    assert_eq!(first, StatusCode::FORBIDDEN);

    let (second, _) = post(
        "/auth/oidc/exchange",
        json!({"code": "code-burn", "verifier": VERIFIER}),
    )
    .send(&app)
    .await;
    assert_eq!(
        second,
        StatusCode::FORBIDDEN,
        "the correct verifier must not rescue a burnt code"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_code_cannot_be_redeemed_twice(pool: PgPool) {
    let app = app(pool.clone()).await;
    pending_exchange(&pool, "code-replay", CHALLENGE, "2 minutes").await;

    let (first, _) = post(
        "/auth/oidc/exchange",
        json!({"code": "code-replay", "verifier": VERIFIER}),
    )
    .send(&app)
    .await;
    assert_eq!(first, StatusCode::OK);

    let (second, _) = post(
        "/auth/oidc/exchange",
        json!({"code": "code-replay", "verifier": VERIFIER}),
    )
    .send(&app)
    .await;
    assert_eq!(second, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_expired_code_is_refused(pool: PgPool) {
    let app = app(pool.clone()).await;
    pending_exchange(&pool, "code-stale", CHALLENGE, "-1 minute").await;

    let (status, _) = post(
        "/auth/oidc/exchange",
        json!({"code": "code-stale", "verifier": VERIFIER}),
    )
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_code_is_refused(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (status, _) = post(
        "/auth/oidc/exchange",
        json!({"code": "never-issued", "verifier": VERIFIER}),
    )
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The code is stored the way an access token is: hashed, so a database dump
/// does not hand over pending logins.
#[sqlx::test(migrations = "../../migrations")]
async fn the_code_itself_is_never_stored(pool: PgPool) {
    let _app = app(pool.clone()).await;
    pending_exchange(&pool, "code-secret", CHALLENGE, "2 minutes").await;

    let stored: String = sqlx::query_scalar("SELECT code_hash FROM oidc_cli_exchanges LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("a row");
    assert_ne!(stored, "code-secret");
    assert_eq!(stored, hash_token("code-secret"));
}
