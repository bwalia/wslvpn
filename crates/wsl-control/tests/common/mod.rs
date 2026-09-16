#![allow(dead_code)]

//! Shared harness for the control-plane HTTP tests.
//!
//! Every test drives the *real* router built by `routes::router`, so what it
//! asserts is what the binary serves. Anything less would let an authorization
//! rule pass in tests while the shipped router routes around it.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use wsl_control::config::{
    BootstrapConfig, Config, DatabaseConfig, GitOpsConfig, IdentityConfig, OidcConfig,
    ProductConfig, SecurityConfig, ServerConfig, WireGuardConfig,
};
use wsl_control::state::{hash_token, AppState};

pub const OPS_TOKEN: &str = "test-ops-token-0123456789abcdef";
pub const SCIM_TOKEN: &str = "test-scim-token-0123456789abcdef";
pub const GATEWAY_ENROLL_TOKEN: &str = "test-gateway-token-0123456789abcdef";

pub fn test_config() -> Config {
    Config {
        server: ServerConfig {
            listen: "127.0.0.1:0".into(),
            public_url: "http://localhost:8080".into(),
            expose_docs: false,
        },
        product: ProductConfig {
            namespace: "wsl".into(),
            display_name: "test".into(),
        },
        database: DatabaseConfig {
            url: "postgres://unused".into(),
            max_connections: 5,
            min_connections: 1,
            acquire_timeout_secs: 5,
            idle_timeout_secs: 300,
            max_lifetime_secs: 1800,
        },
        identity: IdentityConfig {
            oidc: OidcConfig {
                issuer: "http://localhost:5556/dex".into(),
                client_id: "test".into(),
                client_secret: None,
                scopes: vec!["openid".into()],
                redirect_uri: "http://localhost:8080/auth/oidc/callback".into(),
                native_schemes: vec!["io.wsl.zerotrust".into()],
            },
            dev_login_enabled: false,
        },
        wireguard: WireGuardConfig {
            default_port: 51820,
        },
        gitops: GitOpsConfig {
            enabled: false,
            path: "./gitops/examples".into(),
        },
        bootstrap: BootstrapConfig {
            ops_service_token: OPS_TOKEN.into(),
            gateway_registration_token: GATEWAY_ENROLL_TOKEN.into(),
            scim_service_token: Some(SCIM_TOKEN.into()),
            admin_emails: vec![],
        },
        // Rate limiting is off in the harness: these tests fire many requests
        // from one address, and a 429 would mask the status code under test.
        security: SecurityConfig::disabled(),
    }
}

pub async fn app(pool: PgPool) -> Router {
    let state = AppState::with_pool(test_config(), pool);
    state.bootstrap().await.expect("bootstrap");
    wsl_control::routes::router(state)
}

/// Create a user and a live access token for them.
pub async fn user_with_token(pool: &PgPool, email: &str, role: &str) -> (Uuid, String) {
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, role) VALUES ($1, $2)
         ON CONFLICT (email) DO UPDATE SET role = EXCLUDED.role
         RETURNING id",
    )
    .bind(email)
    .bind(role)
    .fetch_one(pool)
    .await
    .expect("create user");

    let token = format!("test-token-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO access_tokens (user_id, token_hash, expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
    )
    .bind(user_id)
    .bind(hash_token(&token))
    .execute(pool)
    .await
    .expect("create access token");

    (user_id, token)
}

pub struct Call {
    pub method: Method,
    pub uri: String,
    pub token: Option<String>,
    pub body: Option<serde_json::Value>,
}

pub fn get(uri: &str) -> Call {
    Call {
        method: Method::GET,
        uri: uri.into(),
        token: None,
        body: None,
    }
}

pub fn post(uri: &str, body: serde_json::Value) -> Call {
    Call {
        method: Method::POST,
        uri: uri.into(),
        token: None,
        body: Some(body),
    }
}

pub fn put(uri: &str, body: serde_json::Value) -> Call {
    Call {
        method: Method::PUT,
        uri: uri.into(),
        token: None,
        body: Some(body),
    }
}

pub fn delete(uri: &str) -> Call {
    Call {
        method: Method::DELETE,
        uri: uri.into(),
        token: None,
        body: None,
    }
}

impl Call {
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    pub async fn send(self, app: &Router) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().method(self.method).uri(&self.uri);
        if let Some(token) = &self.token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = match self.body {
            Some(body) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };

        let response = app.clone().oneshot(request).await.expect("route request");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }
}

/// Statuses that mean "this request was not allowed to do the thing".
///
/// A guarded route may answer 401 (no credential), 403 (wrong role) or 404
/// (exists, but not yours — deliberately indistinguishable from absent). What
/// matters is that it is never a success.
pub fn is_denied(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
    )
}
