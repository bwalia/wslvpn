pub mod audit;
pub mod devices;
pub mod gateways;
pub mod gitops;
pub mod groups;
pub mod health;
pub mod networks;
pub mod ops;
pub mod policies;
pub mod scim;
pub mod sessions;
pub mod users;

use crate::auth::oidc;
use crate::middleware::rate_limit::{rate_limit, RateLimiter};
use crate::middleware::shutdown;
use crate::openapi::ApiDoc;
use crate::state::AppState;
use axum::{
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub use shutdown::signal as shutdown_signal;

/// Assemble the HTTP surface.
///
/// Every route under `/api/v1` names an authorization guard in its handler
/// signature — `AuthUser`, `AdminUser`, `OpsAuth` or `GatewayAuth`. The two
/// deliberate exceptions are `/gateways/register`, which authenticates with the
/// enrollment secret carried in its body, and the unauthenticated surface
/// below: health, metrics and the OIDC handshake.
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/users", get(users::list).post(users::create))
        .route(
            "/users/{id}",
            get(users::get).put(users::update).delete(users::delete),
        )
        .route("/groups", get(groups::list).post(groups::create))
        .route("/groups/{id}", get(groups::get).delete(groups::delete))
        .route(
            "/groups/{id}/members/{user_id}",
            post(groups::add_member).delete(groups::remove_member),
        )
        .route("/devices", get(devices::list))
        .route("/devices/register", post(devices::register))
        .route("/devices/{id}", get(devices::get))
        .route("/devices/{id}/revoke", post(devices::revoke))
        .route("/networks", get(networks::list).post(networks::create))
        .route("/networks/{id}", get(networks::get))
        .route("/policies", get(policies::list))
        .route("/policies/apply", post(policies::apply))
        .route("/sessions", get(sessions::list).post(sessions::create))
        .route("/sessions/by-ip/{ip}", get(sessions::identity_by_ip))
        .route("/sessions/{id}", delete(sessions::revoke))
        .route("/gateways", get(gateways::list))
        .route("/gateways/register", post(gateways::register))
        .route("/gateways/{id}", get(gateways::get))
        .route("/gateways/{id}/config", get(gateways::config))
        .route("/gateways/{id}/heartbeat", post(gateways::heartbeat))
        .route("/gateways/{id}/rotate-token", post(gateways::rotate_token))
        .route("/audit", get(audit::list))
        .route("/gitops/apply", post(gitops::apply))
        .nest("/ops", ops::router());

    // Credential-checking endpoints get a tighter budget than the rest of the
    // API: they are the ones worth guessing at, and a legitimate client hits
    // them once per session rather than once per action.
    let auth_limiter = Arc::new(RateLimiter::new(state.config.security.rate_limit.auth));
    let api_limiter = Arc::new(RateLimiter::new(state.config.security.rate_limit.api));

    let auth = Router::new()
        .route("/auth/oidc/authorize", get(oidc::authorize))
        .route("/auth/oidc/callback", get(oidc::callback))
        .route("/auth/dev/login", post(oidc::dev_login))
        .route_layer(axum::middleware::from_fn_with_state(
            auth_limiter,
            rate_limit,
        ));

    let mut app = Router::new()
        .route("/health", get(health::health))
        .route("/livez", get(health::livez))
        .route("/readyz", get(health::readyz))
        .route("/metrics", get(health::metrics))
        .merge(auth)
        .nest(
            "/api/v1",
            api.route_layer(axum::middleware::from_fn_with_state(
                api_limiter,
                rate_limit,
            )),
        )
        .nest("/SCIM/v2", scim::router(state.clone()));

    // The OpenAPI document enumerates every route and schema. That is a
    // convenience in development and a map for an attacker in production, so it
    // is opt-in rather than always mounted.
    if state.config.server.expose_docs {
        tracing::warn!(
            "serving OpenAPI docs at /swagger-ui; disable server.expose_docs in production"
        );
        app = app
            .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()));
    }

    app.layer(TraceLayer::new_for_http()).with_state(state)
}
