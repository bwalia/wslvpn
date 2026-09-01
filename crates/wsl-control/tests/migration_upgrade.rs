//! The upgrade path, not just the fresh-install path.
//!
//! Every other test starts from an empty database, so migration 004's backfill
//! loop never sees a row. But an existing deployment upgrading into this
//! release has an audit table full of history that has to come out the other
//! side chained and verifiable — that is what docs/UPGRADING.md promises, and
//! it is the one code path a fresh install can never exercise.

use sqlx::migrate::Migrator;
use sqlx::PgPool;
use std::path::Path;

/// Migrations up to and including the one that adds RBAC, but stopping short of
/// the audit chain. `#[sqlx::test]` with no `migrations` argument leaves the
/// database empty, so this applies them by hand.
async fn migrate_to_003(pool: &PgPool) {
    let migrator = Migrator::new(Path::new("../../migrations"))
        .await
        .expect("load migrations");
    for migration in migrator.iter() {
        if migration.version > 3 {
            break;
        }
        // raw_sql, not query: a migration is several statements, and the
        // prepared-statement protocol accepts only one.
        sqlx::raw_sql(&migration.sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("apply migration {}: {e}", migration.version));
    }
}

async fn apply_004(pool: &PgPool) -> Result<(), sqlx::Error> {
    let migrator = Migrator::new(Path::new("../../migrations"))
        .await
        .expect("load migrations");
    let m = migrator
        .iter()
        .find(|m| m.version == 4)
        .expect("migration 004 should exist");
    sqlx::raw_sql(&m.sql).execute(pool).await.map(|_| ())
}

#[sqlx::test]
async fn existing_audit_history_is_chained_by_the_upgrade(pool: PgPool) {
    migrate_to_003(&pool).await;

    // History written by the previous release: no seq, no hashes, no actor.
    for i in 0..25 {
        sqlx::query(
            "INSERT INTO audit_events (action, decision, resource, details)
             VALUES ($1, 'allow', $2, $3)",
        )
        .bind(format!("legacy.event.{i}"))
        .bind(format!("resource-{i}"))
        .bind(serde_json::json!({ "index": i }))
        .execute(&pool)
        .await
        .unwrap();
    }

    apply_004(&pool).await.expect("migration 004 should apply");

    let broken: Vec<(i64, String)> = sqlx::query_as("SELECT seq, problem FROM audit_verify()")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(
        broken.is_empty(),
        "backfilled history must verify, but: {broken:?}"
    );

    let (count, max_seq): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COALESCE(MAX(seq), 0) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 25);
    assert_eq!(max_seq, 25, "sequence numbers must be dense after backfill");

    let first_prev: String = sqlx::query_scalar("SELECT prev_hash FROM audit_events WHERE seq = 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        first_prev,
        "0".repeat(64),
        "the chain starts from a zero root"
    );
}

#[sqlx::test]
async fn events_written_after_the_upgrade_continue_the_same_chain(pool: PgPool) {
    migrate_to_003(&pool).await;

    for i in 0..5 {
        sqlx::query("INSERT INTO audit_events (action, details) VALUES ($1, '{}')")
            .bind(format!("legacy.{i}"))
            .execute(&pool)
            .await
            .unwrap();
    }
    apply_004(&pool).await.expect("migration 004 should apply");

    for i in 0..5 {
        sqlx::query("INSERT INTO audit_events (action, details) VALUES ($1, '{}')")
            .bind(format!("post-upgrade.{i}"))
            .execute(&pool)
            .await
            .unwrap();
    }

    let broken: Vec<(i64, String)> = sqlx::query_as("SELECT seq, problem FROM audit_verify()")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(
        broken.is_empty(),
        "new events must link onto backfilled history: {broken:?}"
    );

    // The first post-upgrade entry links to the last backfilled one, rather
    // than restarting the chain.
    let (prev, expected): (String, String) = sqlx::query_as(
        "SELECT (SELECT prev_hash FROM audit_events WHERE seq = 6),
                (SELECT entry_hash FROM audit_events WHERE seq = 5)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(prev, expected);
}

#[sqlx::test]
async fn tampering_with_backfilled_history_is_detected(pool: PgPool) {
    migrate_to_003(&pool).await;
    for i in 0..10 {
        sqlx::query("INSERT INTO audit_events (action, resource, details) VALUES ($1, $2, '{}')")
            .bind(format!("legacy.{i}"))
            .bind(format!("resource-{i}"))
            .execute(&pool)
            .await
            .unwrap();
    }
    apply_004(&pool).await.expect("migration 004 should apply");

    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE audit_events SET resource = 'rewritten' WHERE seq = 4")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update")
        .execute(&pool)
        .await
        .unwrap();

    let broken: Vec<(i64, String)> = sqlx::query_as("SELECT seq, problem FROM audit_verify()")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(
        broken.first().map(|b| b.0),
        Some(4),
        "history that predates the upgrade must be protected too: {broken:?}"
    );
}

#[sqlx::test]
async fn the_upgrade_applies_to_an_empty_database(pool: PgPool) {
    // The fresh-install path: the backfill loop iterates nothing and the
    // NOT NULL constraints it sets up must still be satisfiable.
    migrate_to_003(&pool).await;
    apply_004(&pool)
        .await
        .expect("migration 004 on an empty log");

    sqlx::query("INSERT INTO audit_events (action, details) VALUES ('first', '{}')")
        .execute(&pool)
        .await
        .expect("the first event on a fresh install");

    let (seq, prev): (i64, String) =
        sqlx::query_as("SELECT seq, prev_hash FROM audit_events ORDER BY seq LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(seq, 1);
    assert_eq!(prev, "0".repeat(64));
}
