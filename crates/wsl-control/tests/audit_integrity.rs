//! The audit log has to be able to answer "was this changed?".
//!
//! These tests hold three properties: every administrative action lands in the
//! log attributed to the principal that performed it; the log cannot be edited
//! or deleted through the database connection the application uses; and a row
//! altered by someone who bypasses those protections is detectable.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn administrative_actions_are_attributed_to_the_administrator(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (_, admin) = user_with_token(&pool, "admin@example.com", "admin").await;

    let (status, created) = post("/api/v1/users", json!({"email": "newhire@example.com"}))
        .with_token(&admin)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");

    let (actor_type, actor_id, resource): (String, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT actor_type, actor_id, resource FROM audit_events
             WHERE action = 'user.create' ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("a user.create event");

    assert_eq!(actor_type, "user");
    assert_eq!(actor_id.as_deref(), Some("admin@example.com"));
    assert_eq!(resource.as_deref(), Some("newhire@example.com"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_service_credential_is_recorded_as_the_actor(pool: PgPool) {
    let app = app(pool.clone()).await;

    let (status, _) = post("/api/v1/ops/users", json!({"email": "viaops@example.com"}))
        .with_token(OPS_TOKEN)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (actor_type, actor_id): (String, Option<String>) = sqlx::query_as(
        "SELECT actor_type, actor_id FROM audit_events
         WHERE action = 'user.create' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(actor_type, "service");
    assert_eq!(
        actor_id.as_deref(),
        Some("opsapi"),
        "the token's name, so a leaked credential can be traced to its actions"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn group_membership_changes_are_recorded(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (_, admin) = user_with_token(&pool, "admin@example.com", "admin").await;
    let (member_id, _) = user_with_token(&pool, "member@example.com", "member").await;

    let (_, group) = post("/api/v1/groups", json!({"name": "engineering"}))
        .with_token(&admin)
        .send(&app)
        .await;
    let group_id = group["id"].as_str().unwrap();

    let (status, _) = post(
        &format!("/api/v1/groups/{group_id}/members/{member_id}"),
        json!({}),
    )
    .with_token(&admin)
    .send(&app)
    .await;
    assert_eq!(status, StatusCode::OK);

    let actions: Vec<(String,)> =
        sqlx::query_as("SELECT action FROM audit_events WHERE action LIKE 'group.%' ORDER BY seq")
            .fetch_all(&pool)
            .await
            .unwrap();
    let actions: Vec<&str> = actions.iter().map(|a| a.0.as_str()).collect();
    assert!(actions.contains(&"group.create"), "{actions:?}");
    assert!(
        actions.contains(&"group.member_added"),
        "membership decides what a policy matches, so the grant must be logged: {actions:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_log_refuses_updates_and_deletes(pool: PgPool) {
    // Bootstrap writes at least one event, so there is something to try to edit.
    let _app = app(pool.clone()).await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(count > 0, "expected a bootstrap event to exist");

    let update = sqlx::query("UPDATE audit_events SET action = 'tampered'")
        .execute(&pool)
        .await;
    assert!(
        update.is_err(),
        "an audit row must not be editable through the application's own connection"
    );

    let delete = sqlx::query("DELETE FROM audit_events").execute(&pool).await;
    assert!(delete.is_err(), "an audit row must not be deletable");

    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(after, count, "nothing should have been removed");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_intact_log_verifies(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (_, admin) = user_with_token(&pool, "admin@example.com", "admin").await;

    for i in 0..5 {
        post("/api/v1/groups", json!({ "name": format!("group-{i}") }))
            .with_token(&admin)
            .send(&app)
            .await;
    }

    let (status, body) = get("/api/v1/audit/verify")
        .with_token(&admin)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["intact"], json!(true), "{body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_altered_entry_is_detected(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (_, admin) = user_with_token(&pool, "admin@example.com", "admin").await;

    for i in 0..4 {
        post("/api/v1/groups", json!({ "name": format!("group-{i}") }))
            .with_token(&admin)
            .send(&app)
            .await;
    }

    // Someone with direct database access disables the guard triggers and
    // rewrites history — the exact scenario the chain exists to expose.
    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update")
        .execute(&pool)
        .await
        .unwrap();
    let target: i64 = sqlx::query_scalar(
        "SELECT seq FROM audit_events WHERE action = 'group.create' ORDER BY seq LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE audit_events SET resource = 'covered-up' WHERE seq = $1")
        .bind(target)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update")
        .execute(&pool)
        .await
        .unwrap();

    let (status, body) = get("/api/v1/audit/verify")
        .with_token(&admin)
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["intact"], json!(false), "{body}");
    assert_eq!(
        body["first_break"]["seq"],
        json!(target),
        "verification should point at the altered entry: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_removed_entry_is_detected(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (_, admin) = user_with_token(&pool, "admin@example.com", "admin").await;

    for i in 0..4 {
        post("/api/v1/groups", json!({ "name": format!("group-{i}") }))
            .with_token(&admin)
            .send(&app)
            .await;
    }

    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_delete")
        .execute(&pool)
        .await
        .unwrap();
    let target: i64 = sqlx::query_scalar(
        "SELECT seq FROM audit_events WHERE action = 'group.create' ORDER BY seq LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM audit_events WHERE seq = $1")
        .bind(target)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_delete")
        .execute(&pool)
        .await
        .unwrap();

    let (_, body) = get("/api/v1/audit/verify")
        .with_token(&admin)
        .send(&app)
        .await;
    assert_eq!(
        body["intact"],
        json!(false),
        "a removed entry leaves a gap the chain must expose: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_writers_produce_one_unbroken_chain(pool: PgPool) {
    // The chain links each entry to its predecessor by commit order. If `seq`
    // came from a sequence instead, two writers taking numbers 4 and 5 and
    // committing in the other order would fork the chain and this would fail on
    // a log nobody tampered with.
    let app = app(pool.clone()).await;
    let (_, admin) = user_with_token(&pool, "admin@example.com", "admin").await;

    let writes = (0..20).map(|i| {
        let app = app.clone();
        let admin = admin.clone();
        async move {
            post(
                "/api/v1/groups",
                json!({ "name": format!("concurrent-{i}") }),
            )
            .with_token(&admin)
            .send(&app)
            .await
        }
    });
    futures::future::join_all(writes).await;

    let (_, body) = get("/api/v1/audit/verify")
        .with_token(&admin)
        .send(&app)
        .await;
    assert_eq!(body["intact"], json!(true), "{body}");

    let (count, max_seq): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COALESCE(MAX(seq), 0) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count, max_seq,
        "sequence numbers must be dense: {count} entries but highest seq is {max_seq}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_an_admin_may_read_or_verify_the_log(pool: PgPool) {
    let app = app(pool.clone()).await;
    let (_, member) = user_with_token(&pool, "member@example.com", "member").await;

    for uri in ["/api/v1/audit", "/api/v1/audit/verify"] {
        let (status, _) = get(uri).send(&app).await;
        assert!(is_denied(status), "{uri} anonymous -> {status}");

        let (status, _) = get(uri).with_token(&member).send(&app).await;
        assert!(is_denied(status), "{uri} as member -> {status}");
    }
}
