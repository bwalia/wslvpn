#![allow(clippy::type_complexity)]

mod auth;
mod config;
mod error;
mod openapi;
mod routes;
mod services;
mod state;

use anyhow::Context;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Parser)]
#[command(name = "wsl-control", about = "WSL Zero Trust VPN control plane")]
struct Cli {
    /// Path to YAML configuration file
    #[arg(
        short,
        long,
        env = "WSL_CONTROL_CONFIG",
        default_value = "config/control.example.yaml"
    )]
    config: PathBuf,

    /// Override database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().json())
        .init();

    let cli = Cli::parse();
    let mut cfg = config::Config::load(&cli.config)
        .with_context(|| format!("load config {}", cli.config.display()))?;
    if let Some(url) = cli.database_url {
        cfg.database.url = url;
    }

    let state = state::AppState::new(cfg).await?;
    state.bootstrap().await?;

    let app = routes::router(state.clone());
    let addr: SocketAddr = state.config.server.listen.parse()?;
    tracing::info!(%addr, "wsl-control listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
