//! What a verified login resolves to, and what it refuses to resolve to.
//!
//! The rules under test are the ones that keep a login from becoming a
//! provisioning decision. They are asserted against a real database because
//! they are enforced partly by SQL constraints — a unique index on
//! `(issuer, user_id)` is doing as much work here as the branch that reads it,
//! and an in-memory stand-in would assert neither.
//!
//! Requires a PostgreSQL instance; `#[sqlx::test]` provisions an isolated
//! database per test from `DATABASE_URL` and runs the migrations into it.

mod common;

use common::*;
use sqlx::PgPool;
use uuid::Uuid;
use wsl_control::auth::oidc::resolve_user;
use wsl_control::auth::oidc_provider::VerifiedIdentity;
use wsl_control::state::AppState;

const ISSUER: &str = "https://idp.example.com";
const OTHER_ISSUER: &str = "https://other-idp.example.com";

fn identity(subject: &str, email: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        issuer: ISSUER.into(),
        subject: subject.into(),
        email: email.into(),
        display_name: Some("Test Person".into()),
    }
}

fn state_for(pool: PgPool) -> AppState {
    AppState::with_pool(test_config(), pool)
}

async fn email_of(pool: &PgPool, user_id: Uuid) -> String {
    sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("read user email")
}

#[sqlx::test(migrations = "../../migrations")]
async fn first_login_creates_a_user_and_binds_the_subject(pool: PgPool) {
    let state = state_for(pool.clone());

    let user_id = resolve_user(&state, &identity("subject-1", "alice@example.com"))
        .await
        .expect("first login should succeed");

    assert_eq!(email_of(&pool, user_id).await, "alice@example.com");

    let bound: (Uuid,) =
        sqlx::query_as("SELECT user_id FROM oidc_identities WHERE issuer = $1 AND subject = $2")
            .bind(ISSUER)
            .bind("subject-1")
            .fetch_one(&pool)
            .await
            .expect("binding should exist");
    assert_eq!(bound.0, user_id);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_same_subject_resolves_to_the_same_user(pool: PgPool) {
    let state = state_for(pool.clone());
    let id = identity("subject-1", "alice@example.com");

    let first = resolve_user(&state, &id).await.expect("first login");
    let second = resolve_user(&state, &id).await.expect("second login");

    assert_eq!(
        first, second,
        "a repeat login must not create a second user"
    );
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 1);
}

/// The case that email-keyed identity got wrong: a person whose address changes
/// at the provider is still the same person, and must not become a second
/// account.
#[sqlx::test(migrations = "../../migrations")]
async fn a_changed_email_follows_the_existing_binding(pool: PgPool) {
    let state = state_for(pool.clone());

    let before = resolve_user(&state, &identity("subject-1", "alice@example.com"))
        .await
        .expect("first login");
    let after = resolve_user(&state, &identity("subject-1", "alice.smith@example.com"))
        .await
        .expect("login after rename");

    assert_eq!(before, after, "a rename must not fork the account");
    assert_eq!(email_of(&pool, after).await, "alice.smith@example.com");

    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 1);
}

/// A user the directory created through SCIM has no binding yet, and must be
/// able to sign in — otherwise provisioning and login are two disconnected
/// worlds.
#[sqlx::test(migrations = "../../migrations")]
async fn a_provisioned_user_is_linked_on_first_login(pool: PgPool) {
    let provisioned: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, display_name, active) VALUES ($1, $1, TRUE) RETURNING id",
    )
    .bind("bob@example.com")
    .fetch_one(&pool)
    .await
    .expect("provision user");

    let state = state_for(pool.clone());
    let resolved = resolve_user(&state, &identity("subject-bob", "bob@example.com"))
        .await
        .expect("provisioned user should be able to sign in");

    assert_eq!(
        resolved, provisioned,
        "login must attach to the provisioned user, not create another"
    );
}

/// The account-takeover shape. Someone registers a second account at the
/// provider carrying a victim's address; the provider may even have verified it.
/// Linking it to the victim's user would hand over their access, so it is
/// refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_subject_claiming_a_linked_address_is_refused(pool: PgPool) {
    let state = state_for(pool.clone());

    let victim = resolve_user(&state, &identity("subject-victim", "carol@example.com"))
        .await
        .expect("victim's own login");

    let attempt = resolve_user(&state, &identity("subject-attacker", "carol@example.com")).await;

    assert!(
        attempt.is_err(),
        "a second subject from the same issuer must not be linked to an existing user"
    );

    // The victim's binding is untouched.
    let bound: (Uuid,) =
        sqlx::query_as("SELECT user_id FROM oidc_identities WHERE issuer = $1 AND subject = $2")
            .bind(ISSUER)
            .bind("subject-victim")
            .fetch_one(&pool)
            .await
            .expect("victim binding intact");
    assert_eq!(bound.0, victim);

    let bindings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oidc_identities")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(bindings, 1, "the attacker's subject must not be bound");
}

/// Logging in is not a provisioning decision. Before this, the callback's
/// `ON CONFLICT ... SET active = TRUE` quietly undid a deprovisioning.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deactivated_user_cannot_sign_in_and_is_not_reactivated(pool: PgPool) {
    let state = state_for(pool.clone());
    let id = identity("subject-1", "dave@example.com");

    let user_id = resolve_user(&state, &id).await.expect("first login");

    sqlx::query("UPDATE users SET active = FALSE WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("deprovision");

    assert!(
        resolve_user(&state, &id).await.is_err(),
        "a deprovisioned user must not be able to sign in"
    );

    let active: bool = sqlx::query_scalar("SELECT active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!active, "the login attempt must not have reactivated them");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_deactivated_provisioned_user_cannot_sign_in(pool: PgPool) {
    sqlx::query("INSERT INTO users (email, display_name, active) VALUES ($1, $1, FALSE)")
        .bind("eve@example.com")
        .execute(&pool)
        .await
        .expect("provision inactive user");

    let state = state_for(pool.clone());
    assert!(
        resolve_user(&state, &identity("subject-eve", "eve@example.com"))
            .await
            .is_err(),
        "a user provisioned as inactive must not be able to sign in"
    );
}

/// A subject identifier is unique only within its issuer, so the same string
/// from two providers is two different people.
#[sqlx::test(migrations = "../../migrations")]
async fn the_same_subject_at_two_issuers_is_two_people(pool: PgPool) {
    let state = state_for(pool.clone());

    let first = resolve_user(&state, &identity("shared-subject", "frank@example.com"))
        .await
        .expect("first issuer");

    let second = resolve_user(
        &state,
        &VerifiedIdentity {
            issuer: OTHER_ISSUER.into(),
            subject: "shared-subject".into(),
            email: "grace@example.com".into(),
            display_name: None,
        },
    )
    .await
    .expect("second issuer");

    assert_ne!(
        first, second,
        "the same subject string at a different issuer must not collide"
    );
}
