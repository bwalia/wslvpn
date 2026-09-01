//! Authorization coverage for the control-plane HTTP surface.
//!
//! The first of these tests is the important one: it walks every route under
//! `/api/v1` and `/SCIM/v2` with no credential at all and asserts none of them
//! answers successfully. Before per-route guards existed, most of this surface
//! returned 200 to an anonymous caller — including the gateway configuration,
//! which discloses every peer's WireGuard public key.
//!
//! Requires a PostgreSQL instance; `#[sqlx::test]` provisions an isolated
//! database per test from `DATABASE_URL` and runs the migrations into it.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Every route that must refuse an anonymous caller, with a body where the
/// handler needs one so the request reaches the guard rather than failing
/// deserialization first.
fn guarded_routes() -> Vec<(Method, String, Option<serde_json::Value>)> {
    let id = Uuid::nil();
    vec![
        (Method::GET, "/api/v1/users".into(), None),
        (
            Method::POST,
            "/api/v1/users".into(),
            Some(json!({"email": "x@example.com"})),
        ),
        (Method::GET, format!("/api/v1/users/{id}"), None),
        (
            Method::PUT,
            format!("/api/v1/users/{id}"),
            Some(json!({"display_name": "x"})),
        ),
        (Method::DELETE, format!("/api/v1/users/{id}"), None),
        (Method::GET, "/api/v1/groups".into(), None),
        (
            Method::POST,
            "/api/v1/groups".into(),
            Some(json!({"name": "x"})),
        ),
        (Method::GET, format!("/api/v1/groups/{id}"), None),
        (Method::DELETE, format!("/api/v1/groups/{id}"), None),
        (
            Method::POST,
            format!("/api/v1/groups/{id}/members/{id}"),
            Some(json!({})),
        ),
        (
            Method::DELETE,
            format!("/api/v1/groups/{id}/members/{id}"),
            None,
        ),
        (Method::GET, "/api/v1/devices".into(), None),
        (
            Method::POST,
            "/api/v1/devices/register".into(),
            Some(json!({"name": "d", "platform": "macos", "wireguard_public_key": "k"})),
        ),
        (Method::GET, format!("/api/v1/devices/{id}"), None),
        (
            Method::POST,
            format!("/api/v1/devices/{id}/revoke"),
            Some(json!({})),
        ),
        (Method::GET, "/api/v1/networks".into(), None),
        (
            Method::POST,
            "/api/v1/networks".into(),
            Some(json!({"name": "n", "cidr": "10.9.0.0/24"})),
        ),
        (Method::GET, format!("/api/v1/networks/{id}"), None),
        (Method::GET, "/api/v1/policies".into(), None),
        (
            Method::POST,
            "/api/v1/policies/apply".into(),
            Some(json!({"yaml": "kind: Policy"})),
        ),
        (Method::GET, "/api/v1/sessions".into(), None),
        (
            Method::POST,
            "/api/v1/sessions".into(),
            Some(json!({"network_id": id, "device_id": id})),
        ),
        (Method::GET, "/api/v1/sessions/by-ip/10.88.0.5".into(), None),
        (Method::DELETE, format!("/api/v1/sessions/{id}"), None),
        (Method::GET, "/api/v1/gateways".into(), None),
        (Method::GET, format!("/api/v1/gateways/{id}"), None),
        (Method::GET, format!("/api/v1/gateways/{id}/config"), None),
        (
            Method::POST,
            format!("/api/v1/gateways/{id}/heartbeat"),
            Some(json!({"config_version": 0, "peer_count": 0, "healthy": true})),
        ),
        (
            Method::POST,
            format!("/api/v1/gateways/{id}/rotate-token"),
            Some(json!({})),
        ),
        (Method::GET, "/api/v1/audit".into(), None),
        (Method::POST, "/api/v1/gitops/apply".into(), Some(json!({}))),
        (Method::GET, "/api/v1/ops/users".into(), None),
        (Method::GET, "/api/v1/ops/sessions".into(), None),
        (Method::GET, "/api/v1/ops/audit".into(), None),
        (Method::GET, "/SCIM/v2/Users".into(), None),
        (
            Method::POST,
            "/SCIM/v2/Users".into(),
            Some(json!({"userName": "x@example.com"})),
        ),
        (Method::GET, format!("/SCIM/v2/Users/{id}"), None),
        (Method::DELETE, format!("/SCIM/v2/Users/{id}"), None),
        (Method::GET, "/SCIM/v2/Groups".into(), None),
        (Method::GET, "/SCIM/v2/ServiceProviderConfig".into(), None),
    ]
}

#[sqlx::test(migrations = "../../migrations")]
async fn no_route_serves_an_anonymous_caller(pool: PgPool) {
    let app = app(pool).await;
    let mut served = Vec::new();

    for (method, uri, body) in guarded_routes() {
        let call = Call {
            method: method.clone(),
            uri: uri.clone(),
            token: None,
            body,
        };
        let (status, _) = call.send(&app).await;
        if status.is_success() {
            served.push(format!("{method} {uri} -> {status}"));
        }
    }

    assert!(
        served.is_empty(),
        "these routes answered an anonymous caller:\n  {}",
        served.join("\n  ")
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_bad_token_is_no_better_than_no_token(pool: PgPool) {
    let app = app(pool).await;
    let mut served = Vec::new();

    for (method, uri, body) in guarded_routes() {
        let call = Call {
            method: method.clone(),
            uri: uri.clone(),
            token: Some("not-a-real-token".into()),
            body,
        };
        let (status, _) = call.send(&app).await;
        if status.is_success() {
            served.push(format!("{method} {uri} -> {status}"));
        }
    }

    assert!(
        served.is_empty(),
        "these routes accepted an invalid token:\n  {}",
        served.join("\n  ")
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_member_cannot_reach_the_administrative_surface(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (_, member) = user_with_token(&pool, "member@example.com", "member").await;

    let admin_only = [
        (Method::GET, "/api/v1/users".to_string(), None),
        (
            Method::POST,
            "/api/v1/users".into(),
            Some(json!({"email": "new@example.com"})),
        ),
        (Method::GET, "/api/v1/gateways".into(), None),
        (Method::GET, "/api/v1/audit".into(), None),
        (Method::GET, "/api/v1/policies".into(), None),
        (Method::POST, "/api/v1/gitops/apply".into(), Some(json!({}))),
        (
            Method::POST,
            "/api/v1/networks".into(),
            Some(json!({"name": "n2", "cidr": "10.9.0.0/24"})),
        ),
    ];

    for (method, uri, body) in admin_only {
        let (status, _) = Call {
            method: method.clone(),
            uri: uri.clone(),
            token: Some(member.clone()),
            body,
        }
        .send(&app)
        .await;
        assert!(
            is_denied(status),
            "{method} {uri} should be admin-only, got {status}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_reaches_the_administrative_surface(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (_, admin) = user_with_token(&pool, "admin@example.com", "admin").await;

    let (status, body) = get("/api/v1/users").with_token(&admin).send(&app).await;
    assert_eq!(status, StatusCode::OK, "admin should list users: {body}");

    let (status, _) = get("/api/v1/audit").with_token(&admin).send(&app).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = get("/api/v1/gateways").with_token(&admin).send(&app).await;
    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_member_reads_their_own_record_but_not_another(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (alice_id, alice) = user_with_token(&pool, "alice@example.com", "member").await;
    let (bob_id, _) = user_with_token(&pool, "bob@example.com", "member").await;

    let (status, _) = get(&format!("/api/v1/users/{alice_id}"))
        .with_token(&alice)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK, "a member may read their own record");

    let (status, _) = get(&format!("/api/v1/users/{bob_id}"))
        .with_token(&alice)
        .send(&app)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another user's record must be indistinguishable from absent"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_member_sees_only_their_own_devices(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (alice_id, alice) = user_with_token(&pool, "alice@example.com", "member").await;
    let (bob_id, _) = user_with_token(&pool, "bob@example.com", "member").await;

    for (owner, key) in [(alice_id, "alice-key"), (bob_id, "bob-key")] {
        sqlx::query(
            "INSERT INTO devices (user_id, name, platform, wireguard_public_key)
             VALUES ($1, 'laptop', 'macos', $2)",
        )
        .bind(owner)
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    }

    let (status, body) = get("/api/v1/devices").with_token(&alice).send(&app).await;
    assert_eq!(status, StatusCode::OK);
    let devices = body.as_array().expect("a device list");
    assert_eq!(devices.len(), 1, "a member must not see the whole fleet");
    assert_eq!(devices[0]["user_id"], json!(alice_id));
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_expired_token_is_rejected(pool: PgPool) {
    let app = app(pool.clone()).await;
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, role) VALUES ('stale@example.com', 'admin') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let token = "expired-token-value";
    sqlx::query(
        "INSERT INTO access_tokens (user_id, token_hash, expires_at)
         VALUES ($1, $2, NOW() - INTERVAL '1 minute')",
    )
    .bind(user_id)
    .bind(wsl_control::state::hash_token(token))
    .execute(&pool)
    .await
    .unwrap();

    let (status, _) = get("/api/v1/users").with_token(token).send(&app).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_deactivated_user_loses_api_access_immediately(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (user_id, token) = user_with_token(&pool, "leaver@example.com", "admin").await;

    let (status, _) = get("/api/v1/users").with_token(&token).send(&app).await;
    assert_eq!(status, StatusCode::OK);

    sqlx::query("UPDATE users SET active = FALSE WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    let (status, _) = get("/api/v1/users").with_token(&token).send(&app).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unexpired token must stop working the moment the account is disabled"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_ops_token_does_not_open_the_user_api_or_scim(pool: PgPool) {
    let app = app(pool).await;

    // The ops token is valid for its own surface...
    let (status, _) = get("/api/v1/ops/users")
        .with_token(OPS_TOKEN)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK);

    // ...and for nothing else. Scopes are the point: a provisioning credential
    // is not an administrator's session.
    let (status, _) = get("/api/v1/users").with_token(OPS_TOKEN).send(&app).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = get("/SCIM/v2/Users").with_token(OPS_TOKEN).send(&app).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an ops credential must not carry the SCIM scope"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_scim_token_opens_scim_and_nothing_else(pool: PgPool) {
    let app = app(pool).await;

    let (status, _) = get("/SCIM/v2/Users")
        .with_token(SCIM_TOKEN)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = get("/api/v1/ops/audit")
        .with_token(SCIM_TOKEN)
        .send(&app)
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a directory-sync credential must not read the audit log"
    );

    let (status, _) = get("/api/v1/users").with_token(SCIM_TOKEN).send(&app).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn scim_cannot_grant_the_admin_role(pool: PgPool) {
    let app = app(pool.clone()).await;

    let (status, body) = post(
        "/SCIM/v2/Users",
        json!({"userName": "escalate@example.com", "active": true}),
    )
    .with_token(SCIM_TOKEN)
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let role: String =
        sqlx::query_scalar("SELECT role FROM users WHERE email = 'escalate@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        role, "member",
        "a directory-provisioned account must never arrive as an administrator"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn dev_login_is_refused_when_not_explicitly_enabled(pool: PgPool) {
    let app = app(pool).await;
    let (status, _) = post("/auth/dev/login", json!({"email": "anyone@example.com"}))
        .send(&app)
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "dev login must be off unless a deployment opts in"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn health_and_probes_stay_open(pool: PgPool) {
    let app = app(pool).await;
    for uri in ["/health", "/livez", "/readyz", "/metrics"] {
        let (status, _) = get(uri).send(&app).await;
        assert_eq!(status, StatusCode::OK, "{uri} should serve unauthenticated");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn openapi_docs_are_not_mounted_by_default(pool: PgPool) {
    let app = app(pool).await;
    let (status, _) = get("/api-docs/openapi.json").send(&app).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the API document enumerates the whole surface; it must be opt-in"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_who_is_signed_in_cannot_lock_themselves_out(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (admin_id, admin) = user_with_token(&pool, "solo@example.com", "admin").await;

    let (status, _) = put(
        &format!("/api/v1/users/{admin_id}"),
        json!({"role": "member"}),
    )
    .with_token(&admin)
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = put(
        &format!("/api/v1/users/{admin_id}"),
        json!({"active": false}),
    )
    .with_token(&admin)
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = delete(&format!("/api/v1/users/{admin_id}"))
        .with_token(&admin)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
