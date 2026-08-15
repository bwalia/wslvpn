use crate::config::GatewayConfigFile;
use crate::firewall;
use crate::wg::{self, ReconcilePlan};
use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use std::process::Stdio;
use tokio::process::Command;
use wsl_types::GatewayConfig;

/// Apply WireGuard peer configuration using `wg` (native WireGuard tools).
/// Does not implement cryptography. Fail closed on validation errors.
///
/// Returns the number of peers the control plane expects on the wire.
pub async fn apply_config(
    cfg: &GatewayConfigFile,
    config: &GatewayConfig,
    private_key_b64: Option<&str>,
) -> Result<usize> {
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

    let managed = cfg.managed_range(&config.private_network_cidr);
    if managed.is_none() {
        tracing::warn!(
            control_cidr = %config.private_network_cidr,
            "no managed range resolved; peer removal is disabled this cycle"
        );
    }

    // Read live state so the plan is a real diff. If `wg` is unavailable we
    // degrade to an empty view rather than failing: in dry-run that is merely a
    // less useful log, and under management the adds below are still correct.
    let live = match wg::live_peers(&cfg.wireguard.interface).await {
        Ok(peers) => peers,
        Err(e) => {
            tracing::warn!(
                interface = %cfg.wireguard.interface,
                error = %e,
                "could not read live peers; treating interface as empty"
            );
            Vec::new()
        }
    };

    let plan = wg::plan(&config.peers, &live, managed.as_ref());
    log_plan(cfg, &plan, config);

    if !cfg.wireguard.manage_interface {
        tracing::info!(
            interface = %cfg.wireguard.interface,
            "manage_interface=false; no changes applied"
        );
        return Ok(plan.desired_count());
    }

    if cfg.wireguard.adopt_existing {
        // Never create the interface, set its listen port, or write its private
        // key: the hub already owns all three, and rewriting the key would
        // invalidate every peer on it.
        if private_key_b64.is_some() {
            anyhow::bail!(
                "refusing to write a private key to adopted interface {}",
                cfg.wireguard.interface
            );
        }
        tracing::info!(
            interface = %cfg.wireguard.interface,
            "adopt_existing=true; managing peers only"
        );
    } else {
        ensure_interface(cfg, config, private_key_b64).await?;
    }

    if plan.is_noop() {
        tracing::debug!(
            interface = %cfg.wireguard.interface,
            "peer state already converged"
        );
    } else {
        for peer in plan.add.iter().chain(plan.update.iter()) {
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

        // Removal is what makes revocation real. `plan` has already excluded
        // every peer outside the managed range, so foreign hub peers cannot
        // land here.
        for public_key in &plan.remove {
            let status = Command::new("wg")
                .args([
                    "set",
                    &cfg.wireguard.interface,
                    "peer",
                    public_key,
                    "remove",
                ])
                .status()
                .await
                .context("wg set peer remove")?;
            if !status.success() {
                anyhow::bail!("wg set peer remove failed for {public_key}");
            }
            tracing::info!(public_key = %public_key, "removed revoked peer");
        }
    }

    apply_firewall(config, managed.as_ref()).await;

    Ok(plan.desired_count())
}

async fn ensure_interface(
    cfg: &GatewayConfigFile,
    config: &GatewayConfig,
    private_key_b64: Option<&str>,
) -> Result<()> {
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
    Ok(())
}

/// Apply the gateway's nftables policy: which services overlay clients may
/// reach, with everything else from the overlay denied.
///
/// The whole ruleset is replaced atomically in a table the gateway owns, so
/// rules cannot accumulate and the host's own firewall is never touched.
async fn apply_firewall(config: &GatewayConfig, managed: Option<&IpNetwork>) {
    let range = managed.map(|m| m.to_string());
    let Some(script) = firewall::render(&config.services, &config.routes, range.as_deref()) else {
        tracing::warn!("no managed range; skipping firewall policy");
        return;
    };

    let child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();

    let Ok(mut child) = child else {
        tracing::warn!("nft unavailable; service restrictions not applied");
        return;
    };

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        if let Err(e) = stdin.write_all(script.as_bytes()).await {
            tracing::warn!(error = %e, "failed writing nft ruleset");
            return;
        }
        drop(stdin);
    }

    match child.wait_with_output().await {
        Ok(out) if out.status.success() => {
            tracing::info!(services = config.services.len(), "applied firewall policy");
        }
        Ok(out) => {
            // Loud rather than silent: an unapplied ruleset means services the
            // operator believes are restricted are not.
            tracing::error!(
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "nft rejected the ruleset; service restrictions NOT applied"
            );
        }
        Err(e) => tracing::error!(error = %e, "nft failed; service restrictions NOT applied"),
    }
}

fn log_plan(cfg: &GatewayConfigFile, plan: &ReconcilePlan, config: &GatewayConfig) {
    let dry_run = !cfg.wireguard.manage_interface;
    tracing::info!(
        interface = %cfg.wireguard.interface,
        version = config.version,
        dry_run,
        add = plan.add.len(),
        update = plan.update.len(),
        unchanged = plan.unchanged.len(),
        remove = plan.remove.len(),
        foreign = plan.foreign.len(),
        "reconcile plan"
    );
    for peer in &plan.add {
        tracing::info!(
            public_key = %peer.public_key,
            allowed_ips = ?peer.allowed_ips,
            expires_at = %peer.expires_at,
            dry_run,
            "peer add"
        );
    }
    for peer in &plan.update {
        tracing::info!(
            public_key = %peer.public_key,
            allowed_ips = ?peer.allowed_ips,
            dry_run,
            "peer update"
        );
    }
    for public_key in &plan.remove {
        tracing::info!(public_key = %public_key, dry_run, "peer remove");
    }
    for public_key in &plan.foreign {
        tracing::debug!(
            public_key = %public_key,
            "peer outside managed range; left untouched"
        );
    }
}
