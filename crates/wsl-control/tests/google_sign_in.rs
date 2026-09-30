//! Signing in with Google from the desktop app, end to end.
//!
//! The whole handshake runs for real: the app's `/auth/oidc/authorize`, the
//! redirect to the provider, the provider calling back, the control plane
//! exchanging the code at the token endpoint, fetching the signing keys,
//! verifying the id_token, and deciding admission. Only Google is stood in
//! for — by a local server that publishes a JWKS, answers the token endpoint,
//! and signs genuine ES256 id_tokens with a key generated for this run.
//!
//! What this pins down is the app's experience of a refusal. A login the
//! control plane will not admit must come back to the app's loopback listener
//! as `error=access_denied` — the OAuth error response (RFC 6749 §4.1.2.1) —
//! so the app says why at once, instead of waiting out its five-minute timeout
//! while the browser shows a bare 401.
//!
//! Requires a PostgreSQL instance; `#[sqlx::test]` provisions an isolated
//! database per test from `DATABASE_URL` and runs the migrations into it.

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use common::*;
use sqlx::PgPool;
use tower::ServiceExt;
use wsl_control::auth::oidc_provider::ProviderMetadata;
use wsl_control::config::{AdmissionConfig, Provisioning};
use wsl_control::state::AppState;

const CLIENT_ID: &str = "wsl-test.apps.googleusercontent.com";
const KID: &str = "google-test-key";
const APP_REDIRECT: &str = "http://127.0.0.1:49152/callback";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Who the stand-in Google says is signing in, and the nonce to echo.
#[derive(Default)]
struct Account {
    email: String,
    hd: Option<String>,
    nonce: String,
}

struct Google {
    issuer: String,
    signing: jsonwebtoken::EncodingKey,
    jwk: serde_json::Value,
    account: Mutex<Account>,
}

type Shared = Arc<Google>;

async fn keys(State(g): State<Shared>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "keys": [g.jwk.clone()] }))
}

async fn token(State(g): State<Shared>) -> Json<serde_json::Value> {
    let account = g.account.lock().unwrap();
    let now = chrono::Utc::now().timestamp();
    let mut claims = serde_json::json!({
        "iss": g.issuer,
        "sub": format!("google-{}", account.email),
        "aud": CLIENT_ID,
        "exp": now + 300,
        "iat": now,
        "email": account.email,
        "email_verified": true,
        "nonce": account.nonce,
    });
    if let Some(hd) = &account.hd {
        claims["hd"] = serde_json::json!(hd);
    }
    let mut jwt_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    jwt_header.kid = Some(KID.into());
    let id_token = jsonwebtoken::encode(&jwt_header, &claims, &g.signing).unwrap();
    Json(serde_json::json!({
        "access_token": "google-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
    }))
}

/// Start the stand-in on a loopback port. Its issuer is its own address, so
/// the control plane's key fetch reaches it the way it would reach Google.
async fn start_google() -> Shared {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::EncodePrivateKey;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());

    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let der = secret.to_pkcs8_der().unwrap();
    let point = secret.public_key().to_encoded_point(false);
    let google = Arc::new(Google {
        issuer,
        signing: jsonwebtoken::EncodingKey::from_ec_der(der.as_bytes()),
        jwk: serde_json::json!({
            "kty": "EC", "use": "sig", "crv": "P-256", "alg": "ES256", "kid": KID,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }),
        account: Mutex::new(Account::default()),
    });
    let app = Router::new()
        .route("/keys", get(keys))
        .route("/token", axum::routing::post(token))
        .with_state(google.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    google
}

async fn control_plane(pool: &PgPool, google: &Google, admission: AdmissionConfig) -> Router {
    let mut config = test_config();
    config.identity.oidc.issuer = google.issuer.clone();
    config.identity.oidc.client_id = CLIENT_ID.into();
    config.identity.admission = admission;
    let state = AppState::with_pool(config, pool.clone());
    state.bootstrap().await.expect("bootstrap");
    state
        .oidc_keys
        .preload(
            &google.issuer,
            ProviderMetadata {
                issuer: google.issuer.clone(),
                authorization_endpoint: format!("{}/authorize", google.issuer),
                token_endpoint: format!("{}/token", google.issuer),
                jwks_uri: format!("{}/keys", google.issuer),
                end_session_endpoint: None,
            },
        )
        .await;
    wsl_control::routes::router(state)
}

async fn request(app: &Router, uri: &str) -> (StatusCode, Option<url::Url>) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| url::Url::parse(v).ok());
    (response.status(), location)
}

fn query(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

/// The desktop app signs in as `email`; returns where the browser ends up.
async fn app_signs_in(
    app: &Router,
    google: &Google,
    email: &str,
    hd: Option<&str>,
) -> (StatusCode, Option<url::Url>) {
    let (status, to_google) = request(
        app,
        &format!(
            "/auth/oidc/authorize?redirect_uri={}&client_challenge={CHALLENGE}",
            url::form_urlencoded::byte_serialize(APP_REDIRECT.as_bytes()).collect::<String>()
        ),
    )
    .await;
    assert!(status.is_redirection(), "authorize: {status}");
    let to_google = to_google.expect("a redirect to the provider");
    *google.account.lock().unwrap() = Account {
        email: email.into(),
        hd: hd.map(str::to_string),
        nonce: query(&to_google, "nonce").expect("nonce"),
    };
    let state = query(&to_google, "state").expect("state");
    request(
        app,
        &format!("/auth/oidc/callback?code=google-code&state={state}"),
    )
    .await
}

fn directory_only() -> AdmissionConfig {
    AdmissionConfig {
        provisioning: Provisioning::Directory,
        ..Default::default()
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_provisioned_person_gets_a_code_back_at_the_app(pool: PgPool) {
    let google = start_google().await;
    let app = control_plane(&pool, &google, directory_only()).await;
    let (status, _) = post(
        "/api/v1/ops/users",
        serde_json::json!({ "email": "alice@example.com" }),
    )
    .with_token(OPS_TOKEN)
    .send(&app)
    .await;
    assert!(status.is_success());

    let (status, back) = app_signs_in(&app, &google, "alice@example.com", None).await;

    assert!(status.is_redirection(), "{status}");
    let back = back.expect("sent back to the app");
    assert_eq!(back.as_str().split('?').next(), Some(APP_REDIRECT));
    assert!(query(&back, "code").is_some(), "{back}");
    assert_eq!(query(&back, "error"), None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unprovisioned_person_is_sent_back_to_the_app_with_access_denied(pool: PgPool) {
    let google = start_google().await;
    let app = control_plane(&pool, &google, directory_only()).await;

    let (status, back) = app_signs_in(&app, &google, "mallory@gmail.com", None).await;

    assert!(
        status.is_redirection(),
        "a refusal must not strand the app: {status}"
    );
    let back = back.expect("sent back to the app");
    assert_eq!(back.as_str().split('?').next(), Some(APP_REDIRECT));
    assert_eq!(query(&back, "error").as_deref(), Some("access_denied"));
    assert!(
        query(&back, "error_description").is_some_and(|d| d.contains("not allowed")),
        "{back}"
    );
    assert_eq!(query(&back, "code"), None, "a refusal carries no code");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_account_outside_the_workspace_is_sent_back_with_access_denied(pool: PgPool) {
    let google = start_google().await;
    let admission = AdmissionConfig {
        hosted_domains: vec!["example.com".into()],
        ..Default::default()
    };
    let app = control_plane(&pool, &google, admission).await;

    let (_, back) = app_signs_in(&app, &google, "carol@example.com", None).await;
    assert_eq!(
        query(&back.expect("back to the app"), "error").as_deref(),
        Some("access_denied")
    );

    let (_, back) = app_signs_in(&app, &google, "carol@example.com", Some("example.com")).await;
    assert!(query(&back.expect("back to the app"), "code").is_some());
}

/// A browser login has no app to return to; it still gets a plain refusal.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_browser_login_is_still_a_401(pool: PgPool) {
    let google = start_google().await;
    let app = control_plane(&pool, &google, directory_only()).await;

    let (status, to_google) = request(&app, "/auth/oidc/authorize").await;
    assert!(status.is_redirection());
    let to_google = to_google.unwrap();
    *google.account.lock().unwrap() = Account {
        email: "mallory@gmail.com".into(),
        hd: None,
        nonce: query(&to_google, "nonce").unwrap(),
    };
    let state = query(&to_google, "state").unwrap();
    let (status, location) =
        request(&app, &format!("/auth/oidc/callback?code=c&state={state}")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(location.is_none());
}
