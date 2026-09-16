use crate::error::AppResult;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use wsl_types::HealthResponse;

pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    tracing::debug!(product = %state.config.product.display_name, namespace = %state.config.product.namespace, "health");
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

/// Liveness: the process is running and can serve. Deliberately does not touch
/// the database — a liveness probe that fails on a database blip would have the
/// orchestrator restart every replica during an outage the restarts cannot fix.
pub async fn livez() -> &'static str {
    "ok"
}

/// Readiness: this replica can actually serve requests, which means it can
/// reach Postgres. A failing readiness probe takes the replica out of the load
/// balancer without restarting it.
pub async fn readyz(State(state): State<AppState>) -> Result<&'static str, (StatusCode, String)> {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
    {
        Ok(_) => Ok("ready"),
        Err(e) => {
            tracing::warn!(error = %e, "readiness probe failed");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "database unavailable".to_string(),
            ))
        }
    }
}

pub async fn metrics(State(state): State<AppState>) -> AppResult<String> {
    Ok(state.metrics_handle.render())
}
