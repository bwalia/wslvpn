//! Enrollment and credential rules for gateways.
//!
//! A gateway's configuration lists every peer's WireGuard public key and
//! allowed-IPs — the topology of the overlay. These tests hold the line that
//! reading it takes a credential bound to that specific gateway, and that
//! holding the shared enrollment secret is not enough to take over a gateway
//! that already exists.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_network(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO networks (name, cidr) VALUES ('testnet', '10.90.0.0/24') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed network")
}

fn enroll_body(name: &str, endpoint: &str, network_id: Uuid) -> serde_json::Value {
    json!({
        "name": name,
        "public_key": "test-public-key",
        "endpoint": endpoint,
        "network_id": network_id,
        "token": GATEWAY_ENROLL_TOKEN,
    })
}

#[sqlx::test(migrations = "../../migrations")]
async fn enrollment_requires_the_shared_secret(pool: PgPool) {
    let app = app(pool.clone()).await;
    let net = seed_network(&pool).await;

    let mut body = enroll_body("gw-1", "1.2.3.4:51820", net);
    body["token"] = json!("wrong-secret");

    let (status, _) = post("/api/v1/gateways/register", body).send(&app).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn enrollment_returns_a_credential_that_opens_only_its_own_config(pool: PgPool) {
    let app = app(pool.clone()).await;
    let net = seed_network(&pool).await;

    let (status, first) = post(
        "/api/v1/gateways/register",
        enroll_body("gw-1", "1.2.3.4:51820", net),
    )
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let gw1_id = first["id"].as_str().expect("gateway id").to_string();
    let gw1_token = first["auth_token"].as_str().expect("token").to_string();

    let (status, second) = post(
        "/api/v1/gateways/register",
        enroll_body("gw-2", "5.6.7.8:51820", net),
    )
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let gw2_id = second["id"].as_str().expect("gateway id").to_string();

    // Its own configuration: allowed.
    let (status, _) = get(&format!("/api/v1/gateways/{gw1_id}/config"))
        .with_token(&gw1_token)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Another gateway's: refused, even though the credential is valid.
    let (status, _) = get(&format!("/api/v1/gateways/{gw2_id}/config"))
        .with_token(&gw1_token)
        .send(&app)
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a gateway credential must not read another gateway's peers"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn config_and_heartbeat_refuse_an_anonymous_caller(pool: PgPool) {
    let app = app(pool.clone()).await;
    let net = seed_network(&pool).await;

    let (_, body) = post(
        "/api/v1/gateways/register",
        enroll_body("gw-1", "1.2.3.4:51820", net),
    )
    .send(&app)
    .await;
    let id = body["id"].as_str().unwrap().to_string();

    let (status, _) = get(&format!("/api/v1/gateways/{id}/config"))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = post(
        &format!("/api/v1/gateways/{id}/heartbeat"),
        json!({"config_version": 0, "peer_count": 0, "healthy": true}),
    )
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_shared_secret_alone_cannot_repoint_an_existing_gateway(pool: PgPool) {
    let app = app(pool.clone()).await;
    let net = seed_network(&pool).await;

    let (status, first) = post(
        "/api/v1/gateways/register",
        enroll_body("gw-1", "1.2.3.4:51820", net),
    )
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");

    // An attacker holding only the enrollment secret tries to move the
    // gateway's endpoint to a host they control.
    let (status, _) = post(
        "/api/v1/gateways/register",
        enroll_body("gw-1", "66.66.66.66:51820", net),
    )
    .send(&app)
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "re-enrollment must require the gateway's current credential"
    );

    let endpoint: String = sqlx::query_scalar("SELECT endpoint FROM gateways WHERE name = 'gw-1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(endpoint, "1.2.3.4:51820", "the endpoint must be unchanged");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_gateway_holding_its_credential_may_re_enroll(pool: PgPool) {
    let app = app(pool.clone()).await;
    let net = seed_network(&pool).await;

    let (_, first) = post(
        "/api/v1/gateways/register",
        enroll_body("gw-1", "1.2.3.4:51820", net),
    )
    .send(&app)
    .await;
    let token = first["auth_token"].as_str().unwrap().to_string();

    let (status, second) = post(
        "/api/v1/gateways/register",
        enroll_body("gw-1", "9.9.9.9:51820", net),
    )
    .with_token(&token)
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");

    let endpoint: String = sqlx::query_scalar("SELECT endpoint FROM gateways WHERE name = 'gw-1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(endpoint, "9.9.9.9:51820");

    // Re-enrollment mints a new credential, so the old one stops working.
    let new_token = second["auth_token"].as_str().unwrap();
    assert_ne!(new_token, token);
    let id = second["id"].as_str().unwrap();
    let (status, _) = get(&format!("/api/v1/gateways/{id}/config"))
        .with_token(&token)
        .send(&app)
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the superseded credential must stop working"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_can_rotate_a_gateway_credential(pool: PgPool) {
    let app = app(pool.clone()).await;
    let net = seed_network(&pool).await;
    let (_, admin) = user_with_token(&pool, "admin@example.com", "admin").await;

    let (_, registered) = post(
        "/api/v1/gateways/register",
        enroll_body("gw-1", "1.2.3.4:51820", net),
    )
    .send(&app)
    .await;
    let id = registered["id"].as_str().unwrap().to_string();
    let old_token = registered["auth_token"].as_str().unwrap().to_string();

    let (status, rotated) = post(&format!("/api/v1/gateways/{id}/rotate-token"), json!({}))
        .with_token(&admin)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    let new_token = rotated["auth_token"].as_str().unwrap().to_string();
    assert_ne!(new_token, old_token);

    let (status, _) = get(&format!("/api/v1/gateways/{id}/config"))
        .with_token(&old_token)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = get(&format!("/api/v1/gateways/{id}/config"))
        .with_token(&new_token)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_member_cannot_rotate_a_gateway_credential(pool: PgPool) {
    let app = app(pool.clone()).await;
    let net = seed_network(&pool).await;
    let (_, member) = user_with_token(&pool, "member@example.com", "member").await;

    let (_, registered) = post(
        "/api/v1/gateways/register",
        enroll_body("gw-1", "1.2.3.4:51820", net),
    )
    .send(&app)
    .await;
    let id = registered["id"].as_str().unwrap();

    let (status, _) = post(&format!("/api/v1/gateways/{id}/rotate-token"), json!({}))
        .with_token(&member)
        .send(&app)
        .await;
    assert!(is_denied(status), "got {status}");
}
