use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfigFile {
    pub control: ControlSection,
    pub gateway: GatewaySection,
    pub wireguard: WireGuardSection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlSection {
    pub url: String,
    pub registration_token: String,
    #[serde(default = "default_hb")]
    pub heartbeat_secs: u64,
}

fn default_hb() -> u64 {
    15
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewaySection {
    pub name: String,
    pub endpoint: String,
    pub network_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WireGuardSection {
    pub interface: String,
    #[serde(default)]
    pub manage_interface: bool,
    #[serde(default = "default_state")]
    pub state_dir: String,
    pub public_key: Option<String>,
}

fn default_state() -> String {
    "/var/lib/wsl-gateway".into()
}

impl GatewayConfigFile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
        Ok(serde_yaml::from_str(&raw)?)
    }
}
