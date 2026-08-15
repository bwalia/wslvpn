mod apply;
mod config;

use anyhow::Context;
use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use wsl_types::{GatewayHeartbeatRequest, RegisterGatewayRequest};

#[derive(Debug, Parser)]
#[command(name = "wsl-gateway", about = "WSL Zero Trust VPN gateway")]
struct Cli {
    #[arg(
        short,
        long,
        env = "WSL_GATEWAY_CONFIG",
        default_value = "config/gateway.example.yaml"
    )]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().json())
        .init();

    let cli = Cli::parse();
    let cfg = config::GatewayConfigFile::load(&cli.config)
        .with_context(|| format!("load {}", cli.config.display()))?;

    let http = reqwest::Client::new();
    let keypair = if let Some(pk) = &cfg.wireguard.public_key {
        // Reuse configured public key; private key must exist on host wg interface
        (None, pk.clone())
    } else {
        let kp = wsl_crypto::generate_wireguard_keypair();
        tracing::info!(public_key = %kp.public_key_b64, "generated gateway wireguard keypair");
        // Persist private key for wg-quick if interface management enabled
        if cfg.wireguard.manage_interface {
            std::fs::create_dir_all(&cfg.wireguard.state_dir)?;
            let path = std::path::Path::new(&cfg.wireguard.state_dir).join("private.key");
            std::fs::write(&path, kp.private_key_b64.as_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        (Some(kp.private_key_b64.clone()), kp.public_key_b64)
    };

    let register = RegisterGatewayRequest {
        name: cfg.gateway.name.clone(),
        public_key: keypair.1.clone(),
        endpoint: cfg.gateway.endpoint.clone(),
        network_id: cfg.gateway.network_id,
        token: cfg.control.registration_token.clone(),
    };

    let gw: wsl_types::Gateway = http
        .post(format!(
            "{}/api/v1/gateways/register",
            cfg.control.url.trim_end_matches('/')
        ))
        .json(&register)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    tracing::info!(gateway_id = %gw.id, "registered with control plane");

    let mut last_version = -1i64;
    loop {
        let hb = GatewayHeartbeatRequest {
            config_version: last_version.max(0),
            peer_count: 0,
            healthy: true,
        };
        let config: wsl_types::GatewayConfig = http
            .post(format!(
                "{}/api/v1/gateways/{}/heartbeat",
                cfg.control.url.trim_end_matches('/'),
                gw.id
            ))
            .json(&hb)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        if config.version != last_version {
            tracing::info!(
                version = config.version,
                peers = config.peers.len(),
                "applying gateway configuration"
            );
            if chrono::Utc::now() > config.expires_at {
                tracing::warn!("refusing expired configuration");
            } else {
                apply::apply_config(&cfg, &config, keypair.0.as_ref().map(|s| s.as_str())).await?;
                last_version = config.version;
            }
        }

        tokio::time::sleep(Duration::from_secs(cfg.control.heartbeat_secs)).await;
    }
}
