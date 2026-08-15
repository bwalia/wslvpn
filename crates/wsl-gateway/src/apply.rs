use crate::config::GatewayConfigFile;
use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use wsl_types::GatewayConfig;

/// Apply WireGuard peer configuration using `wg` (native WireGuard tools).
/// Does not implement cryptography. Fail closed on validation errors.
pub async fn apply_config(
    cfg: &GatewayConfigFile,
    config: &GatewayConfig,
    private_key_b64: Option<&str>,
) -> Result<()> {
    if config.listen_port == 0 {
        anyhow::bail!("invalid listen_port");
    }
    for peer in &config.peers {
        if peer.public_key.is_empty() {
            anyhow::bail!("peer missing public key");
        }
        if peer.allowed_ips.is_empty() {
            anyhow::bail!("peer missing allowed_ips");
        }
        if chrono::Utc::now() > peer.expires_at {
            anyhow::bail!("refusing expired peer {}", peer.peer_id);
        }
    }

    if !cfg.wireguard.manage_interface {
        tracing::info!(
            interface = %cfg.wireguard.interface,
            peers = config.peers.len(),
            "manage_interface=false; logging desired peers only"
        );
        for peer in &config.peers {
            tracing::info!(
                public_key = %peer.public_key,
                allowed_ips = ?peer.allowed_ips,
                expires_at = %peer.expires_at,
                "desired peer"
            );
        }
        return Ok(());
    }

    // Ensure interface exists (best-effort)
    let _ = Command::new("ip")
        .args([
            "link",
            "add",
            "dev",
            &cfg.wireguard.interface,
            "type",
            "wireguard",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    if let Some(privkey) = private_key_b64 {
        let status = Command::new("wg")
            .args([
                "set",
                &cfg.wireguard.interface,
                "listen-port",
                &config.listen_port.to_string(),
                "private-key",
                "/dev/stdin",
            ])
            .stdin(Stdio::piped())
            .spawn();
        if let Ok(mut child) = status {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(privkey.as_bytes()).await?;
                stdin.write_all(b"\n").await?;
            }
            let _ = child.wait().await;
        }
    }

    // Replace peers: set each peer allowed-ips
    for peer in &config.peers {
        let allowed = peer.allowed_ips.join(",");
        let status = Command::new("wg")
            .args([
                "set",
                &cfg.wireguard.interface,
                "peer",
                &peer.public_key,
                "allowed-ips",
                &allowed,
            ])
            .status()
            .await
            .context("wg set peer")?;
        if !status.success() {
            anyhow::bail!("wg set peer failed for {}", peer.public_key);
        }
    }

    // nftables allowlist (best-effort)
    for route in &config.routes {
        let _ = Command::new("nft")
            .args([
                "add", "rule", "inet", "filter", "forward", "ip", "daddr", route, "accept",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }

    Ok(())
}
