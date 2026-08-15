use crate::state::AppState;
use axum::{extract::State, Json};
use wsl_types::HealthResponse;

pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    tracing::debug!(product = %state.config.product.display_name, namespace = %state.config.product.namespace, "health");
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

pub async fn metrics(State(state): State<AppState>) -> String {
    state.metrics_handle.render()
}
