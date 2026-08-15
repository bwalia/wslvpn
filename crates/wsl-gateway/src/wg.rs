//! Live WireGuard state and reconciliation planning.
//!
//! The gateway never owns the interface exclusively: it may be adopting a hub
//! that already carries peers managed by other means. Every destructive action
//! is therefore scoped to a managed CIDR, and anything outside it is reported
//! as foreign and left alone.

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use std::collections::BTreeMap;
use tokio::process::Command;
use wsl_types::GatewayPeer;

/// A peer as reported by `wg show <interface> dump`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
}

/// What the gateway intends to do to the interface this cycle.
#[derive(Debug, Default)]
pub struct ReconcilePlan {
    /// Desired peers absent from the interface.
    pub add: Vec<GatewayPeer>,
    /// Desired peers present but with different allowed-ips.
    pub update: Vec<GatewayPeer>,
    /// Desired peers already correct on the wire.
    pub unchanged: Vec<GatewayPeer>,
    /// Managed peers no longer desired — these get removed.
    pub remove: Vec<String>,
    /// Live peers outside the managed range — never touched.
    pub foreign: Vec<String>,
}

impl ReconcilePlan {
    /// Peers the control plane expects to be on the wire after this cycle.
    pub fn desired_count(&self) -> usize {
        self.add.len() + self.update.len() + self.unchanged.len()
    }

    pub fn is_noop(&self) -> bool {
        self.add.is_empty() && self.update.is_empty() && self.remove.is_empty()
    }
}

/// Read peers currently configured on `interface`.
pub async fn live_peers(interface: &str) -> Result<Vec<LivePeer>> {
    let output = Command::new("wg")
        .args(["show", interface, "dump"])
        .output()
        .await
        .context("wg show dump")?;
    if !output.status.success() {
        anyhow::bail!(
            "wg show {} dump failed: {}",
            interface,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(parse_wg_dump(&String::from_utf8_lossy(&output.stdout)))
}

/// Parse `wg show <interface> dump`.
///
/// The first line describes the interface (private-key, public-key, listen-port,
/// fwmark). Every later line is a peer: public-key, preshared-key, endpoint,
/// allowed-ips, latest-handshake, rx, tx, keepalive — tab separated, with
/// `(none)` standing in for empty values.
pub fn parse_wg_dump(dump: &str) -> Vec<LivePeer> {
    dump.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() < 4 || fields[0].is_empty() {
                return None;
            }
            let allowed_ips = match fields[3] {
                "(none)" | "" => Vec::new(),
                raw => raw
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            };
            Some(LivePeer {
                public_key: fields[0].to_string(),
                allowed_ips,
            })
        })
        .collect()
}

/// True when every allowed-ip of `peer` sits inside `managed`.
///
/// Fail-safe: an unparseable or partially-outside peer is *not* managed, so it
/// can never be selected for removal.
fn is_managed(peer: &LivePeer, managed: &IpNetwork) -> bool {
    if peer.allowed_ips.is_empty() {
        return false;
    }
    peer.allowed_ips
        .iter()
        .all(|raw| match raw.parse::<IpNetwork>() {
            Ok(net) => contains_network(managed, &net),
            Err(_) => false,
        })
}

/// True when `inner` is a subnet of (or equal to) `outer`.
fn contains_network(outer: &IpNetwork, inner: &IpNetwork) -> bool {
    match (outer, inner) {
        (IpNetwork::V4(_), IpNetwork::V4(_)) | (IpNetwork::V6(_), IpNetwork::V6(_)) => {
            inner.prefix() >= outer.prefix() && outer.contains(inner.network())
        }
        _ => false,
    }
}

/// Diff desired peers against live interface state.
///
/// `managed` scopes removal. When it is `None` nothing is ever removed — that is
/// the deliberate posture for an adopted hub whose range could not be resolved.
pub fn plan(
    desired: &[GatewayPeer],
    live: &[LivePeer],
    managed: Option<&IpNetwork>,
) -> ReconcilePlan {
    let live_by_key: BTreeMap<&str, &LivePeer> =
        live.iter().map(|p| (p.public_key.as_str(), p)).collect();

    let mut plan = ReconcilePlan::default();

    for peer in desired {
        match live_by_key.get(peer.public_key.as_str()) {
            None => plan.add.push(peer.clone()),
            Some(existing) => {
                if same_allowed_ips(&peer.allowed_ips, &existing.allowed_ips) {
                    plan.unchanged.push(peer.clone());
                } else {
                    plan.update.push(peer.clone());
                }
            }
        }
    }

    let desired_keys: BTreeMap<&str, ()> = desired
        .iter()
        .map(|p| (p.public_key.as_str(), ()))
        .collect();

    for peer in live {
        if desired_keys.contains_key(peer.public_key.as_str()) {
            continue;
        }
        match managed {
            Some(range) if is_managed(peer, range) => plan.remove.push(peer.public_key.clone()),
            _ => plan.foreign.push(peer.public_key.clone()),
        }
    }

    plan
}

/// Compare allowed-ips as sets, normalised through `IpNetwork` so that
/// `10.8.1.5/32` and `10.8.1.5` compare equal.
fn same_allowed_ips(desired: &[String], live: &[String]) -> bool {
    let normalise = |ips: &[String]| -> Option<Vec<String>> {
        let mut out: Vec<String> = ips
            .iter()
            .map(|s| s.parse::<IpNetwork>().map(|n| n.to_string()))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        out.sort();
        out.dedup();
        Some(out)
    };
    match (normalise(desired), normalise(live)) {
        (Some(a), Some(b)) => a == b,
        // Unparseable on either side: treat as different so the desired state
        // is re-applied rather than silently assumed correct.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    fn peer(public_key: &str, allowed: &[&str]) -> GatewayPeer {
        GatewayPeer {
            peer_id: Uuid::new_v4(),
            public_key: public_key.to_string(),
            allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            session_id: Uuid::new_v4(),
            expires_at: Utc::now() + Duration::hours(1),
        }
    }

    fn live(public_key: &str, allowed: &[&str]) -> LivePeer {
        LivePeer {
            public_key: public_key.to_string(),
            allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn managed() -> IpNetwork {
        "10.8.1.0/24".parse().unwrap()
    }

    #[test]
    fn parses_dump_skipping_interface_line() {
        let dump = "privkey\tpubkey\t51820\toff\n\
                    peerA\t(none)\t192.168.1.104:51820\t10.8.0.15/32\t1755000000\t100\t200\toff\n\
                    peerB\t(none)\t192.168.1.73:51820\t10.8.0.7/32,10.8.1.5/32\t0\t0\t0\t25\n";
        let peers = parse_wg_dump(dump);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0], live("peerA", &["10.8.0.15/32"]));
        assert_eq!(peers[1], live("peerB", &["10.8.0.7/32", "10.8.1.5/32"]));
    }

    #[test]
    fn parses_dump_with_no_allowed_ips() {
        let dump = "privkey\tpubkey\t51820\toff\n\
                    peerA\t(none)\t(none)\t(none)\t0\t0\t0\toff\n";
        assert_eq!(parse_wg_dump(dump)[0].allowed_ips, Vec::<String>::new());
    }

    #[test]
    fn empty_dump_yields_no_peers() {
        assert!(parse_wg_dump("").is_empty());
        assert!(parse_wg_dump("privkey\tpubkey\t51820\toff\n").is_empty());
    }

    #[test]
    fn foreign_hub_peers_are_never_removed() {
        // The nine live home-lab peers sit in 10.8.0.0/24; managed range is
        // 10.8.1.0/24. None of them may be selected for removal.
        let hub: Vec<LivePeer> = (4..=15)
            .map(|n| {
                let key = format!("hub{n}");
                LivePeer {
                    public_key: key,
                    allowed_ips: vec![format!("10.8.0.{n}/32")],
                }
            })
            .collect();
        let p = plan(&[], &hub, Some(&managed()));
        assert!(p.remove.is_empty());
        assert_eq!(p.foreign.len(), hub.len());
    }

    #[test]
    fn managed_peer_no_longer_desired_is_removed() {
        let live_peers = vec![
            live("zt1", &["10.8.1.5/32"]),
            live("hub1", &["10.8.0.15/32"]),
        ];
        let p = plan(&[], &live_peers, Some(&managed()));
        assert_eq!(p.remove, vec!["zt1".to_string()]);
        assert_eq!(p.foreign, vec!["hub1".to_string()]);
    }

    #[test]
    fn without_managed_range_nothing_is_removed() {
        let live_peers = vec![live("zt1", &["10.8.1.5/32"])];
        let p = plan(&[], &live_peers, None);
        assert!(p.remove.is_empty());
        assert_eq!(p.foreign, vec!["zt1".to_string()]);
    }

    #[test]
    fn peer_straddling_managed_range_is_foreign() {
        // One allowed-ip inside the managed range, one outside: not ours.
        let live_peers = vec![live("mixed", &["10.8.1.5/32", "10.8.0.9/32"])];
        let p = plan(&[], &live_peers, Some(&managed()));
        assert!(p.remove.is_empty());
        assert_eq!(p.foreign, vec!["mixed".to_string()]);
    }

    #[test]
    fn unparseable_allowed_ip_is_foreign() {
        let live_peers = vec![live("junk", &["not-a-cidr"])];
        let p = plan(&[], &live_peers, Some(&managed()));
        assert!(p.remove.is_empty());
        assert_eq!(p.foreign, vec!["junk".to_string()]);
    }

    #[test]
    fn wildcard_peer_is_foreign() {
        // 0.0.0.0/0 is not inside 10.8.1.0/24 and must never be removed.
        let live_peers = vec![live("exit", &["0.0.0.0/0"])];
        let p = plan(&[], &live_peers, Some(&managed()));
        assert!(p.remove.is_empty());
        assert_eq!(p.foreign, vec!["exit".to_string()]);
    }

    #[test]
    fn v6_peer_is_not_managed_by_v4_range() {
        let live_peers = vec![live("v6", &["fd00::1/128"])];
        let p = plan(&[], &live_peers, Some(&managed()));
        assert!(p.remove.is_empty());
        assert_eq!(p.foreign, vec!["v6".to_string()]);
    }

    #[test]
    fn classifies_add_update_and_unchanged() {
        let desired = vec![
            peer("new", &["10.8.1.10/32"]),
            peer("moved", &["10.8.1.11/32"]),
            peer("same", &["10.8.1.12/32"]),
        ];
        let live_peers = vec![
            live("moved", &["10.8.1.99/32"]),
            live("same", &["10.8.1.12/32"]),
        ];
        let p = plan(&desired, &live_peers, Some(&managed()));
        assert_eq!(p.add.len(), 1);
        assert_eq!(p.add[0].public_key, "new");
        assert_eq!(p.update.len(), 1);
        assert_eq!(p.update[0].public_key, "moved");
        assert_eq!(p.unchanged.len(), 1);
        assert_eq!(p.unchanged[0].public_key, "same");
        assert_eq!(p.desired_count(), 3);
        assert!(!p.is_noop());
    }

    #[test]
    fn allowed_ips_compare_order_insensitively() {
        let desired = vec![peer("p", &["10.8.1.5/32", "10.8.1.6/32"])];
        let live_peers = vec![live("p", &["10.8.1.6/32", "10.8.1.5/32"])];
        let p = plan(&desired, &live_peers, Some(&managed()));
        assert_eq!(p.unchanged.len(), 1);
        assert!(p.is_noop());
    }

    #[test]
    fn bare_address_equals_host_prefix() {
        let desired = vec![peer("p", &["10.8.1.5/32"])];
        let live_peers = vec![live("p", &["10.8.1.5"])];
        let p = plan(&desired, &live_peers, Some(&managed()));
        assert_eq!(p.unchanged.len(), 1);
    }

    #[test]
    fn desired_peer_is_never_listed_for_removal() {
        let desired = vec![peer("zt1", &["10.8.1.5/32"])];
        let live_peers = vec![live("zt1", &["10.8.1.5/32"])];
        let p = plan(&desired, &live_peers, Some(&managed()));
        assert!(p.remove.is_empty());
        assert!(p.foreign.is_empty());
    }

    #[test]
    fn equal_range_is_contained() {
        let outer: IpNetwork = "10.8.1.0/24".parse().unwrap();
        let inner: IpNetwork = "10.8.1.0/24".parse().unwrap();
        assert!(contains_network(&outer, &inner));
    }

    #[test]
    fn wider_range_is_not_contained() {
        let outer: IpNetwork = "10.8.1.0/24".parse().unwrap();
        let inner: IpNetwork = "10.8.0.0/16".parse().unwrap();
        assert!(!contains_network(&outer, &inner));
    }
}
