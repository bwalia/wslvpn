use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use wsl_types::{ClientWireGuardConfig, PostureResult, PostureSignal, Session};

use crate::posture;
use crate::tunnel::TunnelState;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentState {
    pub control_url: String,
    pub access_token: Option<String>,
    pub email: Option<String>,
    pub user_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub device_name: Option<String>,
    pub wireguard_public_key: Option<String>,
    pub session: Option<Session>,
    pub wireguard: Option<ClientWireGuardConfig>,
    #[serde(default)]
    pub network_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentStatus {
    pub product: String,
    pub user: Option<String>,
    pub device: Option<String>,
    pub identity: String,
    pub posture: String,
    pub networks: Vec<NetworkStatus>,
    pub session_expires: Option<String>,
    pub gateway: Option<String>,
    /// The device the tunnel is on — a `utun` on macOS, the configured name on
    /// Linux. `None` when nothing is up.
    pub interface: Option<String>,
    /// Every signal behind the `posture` summary, so a user can see which check
    /// is the one holding them up.
    pub posture_signals: Vec<PostureSignal>,
}

/// Reduce the signals to one line.
///
/// A failing check is what a user needs to see first, and an unanswered one
/// second — a check that could not run is not a check that passed. Naming the
/// signals rather than counting them means the summary says what to go and fix.
fn summarise_posture(signals: &[PostureSignal]) -> String {
    let named = |result: PostureResult| -> Vec<&str> {
        signals
            .iter()
            .filter(|s| s.result == result)
            .map(|s| s.name.as_str())
            .collect()
    };
    let failed = named(PostureResult::Fail);
    if !failed.is_empty() {
        return format!("Failing: {}", failed.join(", "));
    }
    let unknown = named(PostureResult::Unknown);
    if !unknown.is_empty() {
        return format!("Unknown: {}", unknown.join(", "));
    }
    if signals.is_empty() {
        return "No signals".into();
    }
    "Compliant".into()
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkStatus {
    pub name: String,
    pub state: String,
}

impl AgentState {
    pub fn data_dir() -> Result<PathBuf> {
        let dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("wsl-zerotrust");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn path() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join("agent-state.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self {
                control_url: "http://localhost:8080".into(),
                ..Default::default()
            });
        }
        let raw = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let raw = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, raw)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Where the rendered WireGuard config lives.
    ///
    /// The basename is what `wg-quick` turns into the interface name, so this
    /// is not a free choice: it has to be `<tunnel::INTERFACE>.conf`.
    pub fn wg_conf_path() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join(format!("{}.conf", crate::tunnel::INTERFACE)))
    }

    pub fn keystore_dir() -> Result<PathBuf> {
        let dir = Self::data_dir()?.join("keys");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Build a status report.
    ///
    /// The tunnel state is passed in rather than derived from `self`: holding a
    /// session record is not the same as having an interface, and conflating
    /// the two is what let the agent claim it was connected when it was not.
    pub fn status(&self, tunnel: &TunnelState) -> AgentStatus {
        let signals = posture::collect();
        self.status_with_posture(tunnel, signals)
    }

    /// The same report from a given set of signals, so the summary can be
    /// asserted without the host the suite happens to run on deciding it.
    pub fn status_with_posture(
        &self,
        tunnel: &TunnelState,
        posture_signals: Vec<PostureSignal>,
    ) -> AgentStatus {
        let connected = tunnel.is_up();
        AgentStatus {
            product: "WSL Zero Trust".into(),
            user: self.email.clone(),
            device: self.device_name.clone(),
            identity: if self.access_token.is_some() {
                "Trusted".into()
            } else {
                "Signed out".into()
            },
            posture: summarise_posture(&posture_signals),
            networks: match (self.session.is_some(), connected) {
                (true, true) => vec![NetworkStatus {
                    name: self.network_name(),
                    state: "Connected".into(),
                }],
                // A session the gateway is holding open with no interface at
                // this end. Worth naming: it is the state a failed bring-up
                // leaves behind, and it is not "disconnected".
                (true, false) => vec![NetworkStatus {
                    name: self.network_name(),
                    state: "Session open, tunnel down".into(),
                }],
                (false, true) => vec![NetworkStatus {
                    name: "Unmanaged".into(),
                    state: "Interface up without a session".into(),
                }],
                (false, false) => vec![],
            },
            session_expires: self.session.as_ref().map(|s| s.expires_at.to_rfc3339()),
            gateway: self.wireguard.as_ref().map(|w| w.peer_endpoint.clone()),
            interface: match tunnel {
                TunnelState::Up { interface } => Some(interface.clone()),
                TunnelState::Down => None,
            },
            posture_signals,
        }
    }

    fn network_name(&self) -> String {
        self.network_name
            .clone()
            .unwrap_or_else(|| "Connected network".into())
    }

    /// Render the `wg-quick` config for the current session.
    ///
    /// Separate from writing it so the output can be asserted without a
    /// keystore or a home directory in the way.
    pub fn render_wg_config(&self, private_key: &str) -> Result<String> {
        let wg = self
            .wireguard
            .as_ref()
            .context("no wireguard config; connect first")?;
        Ok(format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}\nDNS = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = {}\n",
            private_key.trim(),
            wg.interface_address,
            wg.dns.join(", "),
            wg.peer_public_key,
            wg.peer_endpoint,
            wg.allowed_ips.join(", "),
            wg.persistent_keepalive
        ))
    }

    pub fn write_wg_config(&self, path: &Path) -> Result<()> {
        let privkey = std::fs::read_to_string(Self::keystore_dir()?.join("wg.private"))
            .context("missing private key")?;
        write_private_file(path, &self.render_wg_config(&privkey)?)
    }
}

/// Write a file only its owner can read.
///
/// Both the agent state and the rendered WireGuard config carry secrets — a
/// bearer token in one, the interface private key in the other — and the
/// default umask on a shared host leaves them world-readable.
fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting permissions on {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use wsl_types::{ClientWireGuardConfig, SessionStatus};

    fn connected_state() -> AgentState {
        AgentState {
            wireguard: Some(ClientWireGuardConfig {
                interface_address: "10.80.0.7/32".into(),
                dns: vec!["10.80.0.1".into(), "10.80.0.2".into()],
                peer_public_key: "cGVlcg==".into(),
                peer_endpoint: "gw.example.com:51820".into(),
                allowed_ips: vec!["10.80.0.0/16".into(), "10.90.0.0/16".into()],
                persistent_keepalive: 25,
            }),
            network_name: Some("Development".into()),
            ..Default::default()
        }
    }

    #[test]
    fn the_rendered_config_is_what_wg_quick_expects() {
        let conf = connected_state()
            .render_wg_config("cHJpdmF0ZQ==\n")
            .expect("render");
        // Multi-valued fields are comma-joined, and the trailing newline on the
        // key read back from the keystore must not leak into the file.
        assert_eq!(
            conf,
            "[Interface]\n\
             PrivateKey = cHJpdmF0ZQ==\n\
             Address = 10.80.0.7/32\n\
             DNS = 10.80.0.1, 10.80.0.2\n\
             \n\
             [Peer]\n\
             PublicKey = cGVlcg==\n\
             Endpoint = gw.example.com:51820\n\
             AllowedIPs = 10.80.0.0/16, 10.90.0.0/16\n\
             PersistentKeepalive = 25\n"
        );
    }

    #[test]
    fn rendering_without_a_session_says_so() {
        let err = AgentState::default()
            .render_wg_config("k")
            .expect_err("no session");
        assert!(err.to_string().contains("connect first"));
    }

    #[cfg(unix)]
    #[test]
    fn a_config_holding_a_private_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("wsl-conf-{}.conf", std::process::id()));
        write_private_file(&path, "secret").expect("write");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn rewriting_an_existing_config_does_not_widen_it() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("wsl-rewrite-{}.conf", std::process::id()));
        std::fs::write(&path, "stale").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        write_private_file(&path, "fresh").expect("write");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        let _ = std::fs::remove_file(&path);
    }

    /// wg-quick takes the interface name from the config's basename, so these
    /// two cannot drift apart without the tunnel coming up under a name the
    /// agent then fails to find.
    #[test]
    fn the_config_basename_is_the_interface_name() {
        let path = AgentState::wg_conf_path().expect("path");
        assert_eq!(
            path.file_stem().and_then(|s| s.to_str()),
            Some(crate::tunnel::INTERFACE)
        );
        assert_eq!(path.extension().and_then(|s| s.to_str()), Some("conf"));
    }

    #[test]
    fn a_session_without_an_interface_is_not_reported_as_connected() {
        let mut state = connected_state();
        state.session = Some(session_fixture());
        let status = state.status_with_posture(&TunnelState::Down, Vec::new());
        assert_eq!(status.networks.len(), 1);
        assert_eq!(status.networks[0].name, "Development");
        assert_eq!(status.networks[0].state, "Session open, tunnel down");
        assert!(status.interface.is_none());
    }

    #[test]
    fn an_interface_and_a_session_together_read_as_connected() {
        let mut state = connected_state();
        state.session = Some(session_fixture());
        let status = state.status_with_posture(
            &TunnelState::Up {
                interface: "utun6".into(),
            },
            Vec::new(),
        );
        assert_eq!(status.networks[0].state, "Connected");
        assert_eq!(status.interface.as_deref(), Some("utun6"));
    }

    #[test]
    fn nothing_signed_in_lists_no_networks() {
        let status = AgentState::default().status_with_posture(&TunnelState::Down, Vec::new());
        assert!(status.networks.is_empty());
        assert_eq!(status.identity, "Signed out");
    }

    fn posture(pairs: &[(&str, PostureResult)]) -> Vec<PostureSignal> {
        pairs
            .iter()
            .map(|(name, result)| PostureSignal {
                name: (*name).into(),
                result: *result,
                detail: None,
            })
            .collect()
    }

    #[test]
    fn a_healthy_device_reads_as_compliant() {
        let signals = posture(&[
            ("disk_encryption", PostureResult::Pass),
            ("device_management", PostureResult::Unsupported),
        ]);
        assert_eq!(summarise_posture(&signals), "Compliant");
    }

    /// The summary names the check rather than counting them: a user reading
    /// "Failing: disk_encryption" knows what to go and turn on.
    #[test]
    fn a_failing_check_is_named() {
        let signals = posture(&[
            ("disk_encryption", PostureResult::Fail),
            ("firewall", PostureResult::Pass),
        ]);
        assert_eq!(summarise_posture(&signals), "Failing: disk_encryption");
    }

    #[test]
    fn a_failure_outranks_an_unknown() {
        let signals = posture(&[
            ("disk_encryption", PostureResult::Unknown),
            ("firewall", PostureResult::Fail),
        ]);
        assert_eq!(summarise_posture(&signals), "Failing: firewall");
    }

    /// A check that could not run is not a check that passed, and the summary
    /// must not round it to "Compliant".
    #[test]
    fn an_unknown_check_is_not_compliant() {
        let signals = posture(&[
            ("disk_encryption", PostureResult::Unknown),
            ("firewall", PostureResult::Pass),
        ]);
        assert_eq!(summarise_posture(&signals), "Unknown: disk_encryption");
    }

    #[test]
    fn no_signals_is_not_compliance_either() {
        assert_eq!(summarise_posture(&[]), "No signals");
    }

    #[test]
    fn the_status_carries_the_signals_behind_the_summary() {
        let signals = posture(&[("disk_encryption", PostureResult::Fail)]);
        let status = AgentState::default().status_with_posture(&TunnelState::Down, signals);
        assert_eq!(status.posture, "Failing: disk_encryption");
        assert_eq!(status.posture_signals.len(), 1);
    }

    fn session_fixture() -> Session {
        Session {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            device_id: Uuid::nil(),
            gateway_id: Uuid::nil(),
            network_id: Uuid::nil(),
            policy_id: None,
            policy_version: None,
            assigned_ip: "10.80.0.7".into(),
            status: SessionStatus::Active,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(8),
        }
    }
}
