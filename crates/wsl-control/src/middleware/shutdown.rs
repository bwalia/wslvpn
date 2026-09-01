/// Resolve when the process is asked to stop.
///
/// Handed to `axum::serve(..).with_graceful_shutdown(..)` so in-flight requests
/// finish instead of being cut off mid-response. Without it a rolling deploy
/// turns every request in flight at that instant into a client-visible error.
pub async fn signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT; draining"),
        _ = terminate => tracing::info!("received SIGTERM; draining"),
    }
}
