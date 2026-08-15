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
use crate::openapi::ApiDoc;
use crate::state::AppState;
use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

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
        .route("/sessions/{id}", delete(sessions::revoke))
        .route("/gateways", get(gateways::list))
        .route("/gateways/register", post(gateways::register))
        .route("/gateways/{id}", get(gateways::get))
        .route("/gateways/{id}/config", get(gateways::config))
        .route("/gateways/{id}/heartbeat", post(gateways::heartbeat))
        .route("/audit", get(audit::list))
        .route("/gitops/apply", post(gitops::apply))
        .nest("/ops", ops::router());

    Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/health", get(health::health))
        .route("/metrics", get(health::metrics))
        .route("/auth/oidc/authorize", get(oidc::authorize))
        .route("/auth/oidc/callback", get(oidc::callback))
        .route("/auth/dev/login", post(oidc::dev_login))
        .nest("/api/v1", api)
        .nest("/SCIM/v2", scim::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
