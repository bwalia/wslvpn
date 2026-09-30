use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use wsl_types::{ClientWireGuardConfig, PostureResult, PostureSignal, Session};

use crate::posture;
use crate::profile::DirectProfile;
use crate::tunnel::TunnelState;

/// Environment override for where the agent keeps its state, so a test, or a
/// second profile, never touches the user's real one.
pub const DATA_DIR_ENV: &str = "WSL_DATA_DIR";

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
    /// An imported WireGuard config. While there is one, Connect uses it and
    /// the control plane is not involved.
    #[serde(default)]
    pub profile: Option<DirectProfile>,
}

/// How this agent connects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// An imported WireGuard config, no control plane.
    Direct,
    /// Signed in to a control plane, which issues sessions.
    Managed,
    /// Neither yet.
    SignedOut,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentStatus {
    pub product: String,
    pub mode: Mode,
    pub control_url: String,
    pub profile: Option<DirectProfile>,
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
        let dir = data_dir_from(std::env::var_os(DATA_DIR_ENV), dirs::data_dir())?;
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
                control_url: DEFAULT_CONTROL_URL.into(),
                ..Default::default()
            });
        }
        let raw = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save(&self) -> Result<()> {
        let raw = serde_json::to_string_pretty(self)?;
        write_private_file(&Self::path()?, &raw)
    }

    pub fn mode(&self) -> Mode {
        if self.profile.is_some() {
            Mode::Direct
        } else if self.access_token.is_some() {
            Mode::Managed
        } else {
            Mode::SignedOut
        }
    }

    /// Point the agent at a control plane. Changing it signs out: a token and
    /// device registration from one control plane mean nothing to another.
    pub fn set_control_url(&mut self, url: &str) -> Result<()> {
        let url = validate_control_url(url)?;
        if url != self.control_url {
            self.access_token = None;
            self.email = None;
            self.user_id = None;
            self.device_id = None;
            self.device_name = None;
            self.wireguard_public_key = None;
            self.session = None;
            self.wireguard = None;
            self.network_name = None;
            self.control_url = url;
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
        let mode = self.mode();
        let networks = match (mode, &self.profile) {
            (Mode::Direct, Some(profile)) => vec![NetworkStatus {
                name: profile.name.clone(),
                state: if connected { "Connected" } else { "Ready" }.into(),
            }],
            _ => self.managed_networks(connected),
        };
        let gateway = match (&self.profile, &self.wireguard) {
            (Some(profile), _) => Some(profile.endpoint.clone()),
            (None, Some(wg)) => Some(wg.peer_endpoint.clone()),
            (None, None) => None,
        };
        AgentStatus {
            product: "WSL Zero Trust".into(),
            mode,
            control_url: self.control_url.clone(),
            profile: self.profile.clone(),
            user: self.email.clone(),
            device: self.device_name.clone(),
            identity: if self.access_token.is_some() {
                "Trusted".into()
            } else {
                "Signed out".into()
            },
            posture: summarise_posture(&posture_signals),
            networks,
            session_expires: self.session.as_ref().map(|s| s.expires_at.to_rfc3339()),
            gateway,
            interface: match tunnel {
                TunnelState::Up { interface } => Some(interface.clone()),
                TunnelState::Down => None,
            },
            posture_signals,
        }
    }

    fn managed_networks(&self, connected: bool) -> Vec<NetworkStatus> {
        match (self.session.is_some(), connected) {
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
        // An empty `DNS =` is not "no DNS" to every wg-quick; leave the line
        // out and the system resolver is left alone.
        let dns = if wg.dns.is_empty() {
            String::new()
        } else {
            format!("DNS = {}\n", wg.dns.join(", "))
        };
        Ok(format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}\n{}\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = {}\n",
            private_key.trim(),
            wg.interface_address,
            dns,
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
///
/// The file is created 0600 before anything is written to it, so there is no
/// moment at which the secret sits in a file anyone else can open.
pub(crate) fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("writing {}", path.display()))?;
        // `mode` only applies on creation; an existing file keeps its old one.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting permissions on {}", path.display()))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Resolve the data directory from the override and the platform default.
///
/// An empty override is unset, not "the current directory": `WSL_DATA_DIR=`
/// in a script would otherwise scatter keys into wherever it was run from. And
/// with no platform default there is no safe guess, so it is an error.
fn data_dir_from(
    explicit: Option<std::ffi::OsString>,
    platform: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(dir) = explicit.filter(|d| !d.is_empty()) {
        let dir = PathBuf::from(dir);
        anyhow::ensure!(
            dir.is_absolute(),
            "{DATA_DIR_ENV} must be an absolute path, not {}",
            dir.display()
        );
        return Ok(dir);
    }
    platform
        .map(|d| d.join("wsl-zerotrust"))
        .with_context(|| format!("no data directory for this user; set {DATA_DIR_ENV}"))
}

pub const DEFAULT_CONTROL_URL: &str = "http://localhost:8080";

/// Accept a control-plane URL only if a bearer token sent to it stays private.
///
/// Plain HTTP is allowed to loopback — the Compose demo — and nowhere else:
/// the token rides in every request, and over HTTP anyone on the café Wi-Fi
/// can read it.
pub fn validate_control_url(raw: &str) -> Result<String> {
    let url = url::Url::parse(raw.trim()).with_context(|| format!("`{raw}` is not a URL"))?;
    let host = url
        .host_str()
        .with_context(|| format!("`{raw}` has no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => anyhow::bail!(
            "the control plane must use https unless it is on this machine; \
             `{raw}` would send your sign-in token in the clear"
        ),
        other => anyhow::bail!("`{other}` is not a control-plane scheme; use https"),
    }
    if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() {
        anyhow::bail!("`{raw}` should be just the control plane's base URL");
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
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

    /// `WSL_DATA_DIR=` once put a private key in the current directory.
    #[test]
    fn an_empty_data_dir_override_means_the_default_not_the_cwd() {
        let home = Some(PathBuf::from("/Users/a/Library/Application Support"));
        assert_eq!(
            data_dir_from(Some("".into()), home.clone()).unwrap(),
            PathBuf::from("/Users/a/Library/Application Support/wsl-zerotrust")
        );
        assert_eq!(
            data_dir_from(Some("/tmp/x".into()), home.clone()).unwrap(),
            PathBuf::from("/tmp/x")
        );
        assert!(data_dir_from(Some("relative".into()), home).is_err());
        assert!(data_dir_from(None, None).is_err());
    }

    #[test]
    fn no_dns_servers_means_no_dns_line() {
        let mut state = connected_state();
        state.wireguard.as_mut().unwrap().dns.clear();
        let conf = state.render_wg_config("k").unwrap();
        assert!(!conf.contains("DNS"), "{conf}");
        assert!(conf.contains("Address = 10.80.0.7/32\n\n[Peer]"), "{conf}");
    }

    #[test]
    fn control_urls_must_be_https_unless_loopback() {
        assert_eq!(
            validate_control_url("https://vpn.example.com/").unwrap(),
            "https://vpn.example.com"
        );
        assert_eq!(
            validate_control_url("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
        assert_eq!(
            validate_control_url("http://127.0.0.1:8080/").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            validate_control_url("http://[::1]:8080").unwrap(),
            "http://[::1]:8080"
        );
        assert!(validate_control_url("http://vpn.example.com")
            .unwrap_err()
            .to_string()
            .contains("https"));
        assert!(validate_control_url("ftp://vpn.example.com").is_err());
        assert!(validate_control_url("vpn.example.com").is_err());
        assert!(validate_control_url("https://u:p@vpn.example.com").is_err());
    }

    /// A token from one control plane means nothing to another.
    #[test]
    fn changing_the_control_plane_signs_out() {
        let mut state = connected_state();
        state.control_url = "https://a.example.com".into();
        state.access_token = Some("t".into());
        state.device_id = Some(Uuid::nil());
        state.set_control_url("https://a.example.com/").unwrap();
        assert!(state.access_token.is_some(), "same URL must not sign out");
        state.set_control_url("https://b.example.com").unwrap();
        assert!(state.access_token.is_none());
        assert!(state.device_id.is_none());
        assert!(state.wireguard.is_none());
        assert_eq!(state.control_url, "https://b.example.com");
    }

    fn direct_profile() -> DirectProfile {
        DirectProfile {
            name: "office".into(),
            endpoint: "vpn.example.com:51820".into(),
            address: vec!["10.8.0.2/32".into()],
            dns: vec![],
            allowed_ips: vec!["10.8.0.0/24".into()],
        }
    }

    #[test]
    fn a_profile_makes_the_mode_direct_even_when_signed_in() {
        let mut state = AgentState::default();
        assert_eq!(state.mode(), Mode::SignedOut);
        state.access_token = Some("t".into());
        assert_eq!(state.mode(), Mode::Managed);
        state.profile = Some(direct_profile());
        assert_eq!(state.mode(), Mode::Direct);
    }

    #[test]
    fn a_direct_profile_reports_its_own_network_and_gateway() {
        let state = AgentState {
            profile: Some(direct_profile()),
            ..Default::default()
        };
        let down = state.status_with_posture(&TunnelState::Down, Vec::new());
        assert_eq!(down.networks[0].name, "office");
        assert_eq!(down.networks[0].state, "Ready");
        assert_eq!(down.gateway.as_deref(), Some("vpn.example.com:51820"));
        let up = state.status_with_posture(
            &TunnelState::Up {
                interface: "utun3".into(),
            },
            Vec::new(),
        );
        assert_eq!(up.networks[0].state, "Connected");
        let json = serde_json::to_value(&up).unwrap();
        assert_eq!(json["mode"], "direct");
        assert_eq!(json["profile"]["endpoint"], "vpn.example.com:51820");
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
