use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use wsl_types::{ClientWireGuardConfig, Session};

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

    pub fn keystore_dir() -> Result<PathBuf> {
        let dir = Self::data_dir()?.join("keys");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn status(&self) -> AgentStatus {
        let connected = self.session.is_some();
        AgentStatus {
            product: "WSL Zero Trust".into(),
            user: self.email.clone(),
            device: self.device_name.clone(),
            identity: if self.access_token.is_some() {
                "Trusted".into()
            } else {
                "Signed out".into()
            },
            posture: "Compliant".into(),
            networks: if connected {
                vec![NetworkStatus {
                    name: "Connected network".into(),
                    state: "Connected".into(),
                }]
            } else {
                vec![]
            },
            session_expires: self.session.as_ref().map(|s| s.expires_at.to_rfc3339()),
            gateway: self.wireguard.as_ref().map(|w| w.peer_endpoint.clone()),
        }
    }

    pub fn write_wg_config(&self, path: &Path) -> Result<()> {
        let wg = self
            .wireguard
            .as_ref()
            .context("no wireguard config; connect first")?;
        let privkey = std::fs::read_to_string(Self::keystore_dir()?.join("wg.private"))
            .context("missing private key")?;
        let conf = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}\nDNS = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = {}\n",
            privkey.trim(),
            wg.interface_address,
            wg.dns.join(", "),
            wg.peer_public_key,
            wg.peer_endpoint,
            wg.allowed_ips.join(", "),
            wg.persistent_keepalive
        );
        std::fs::write(path, conf)?;
        Ok(())
    }
}
