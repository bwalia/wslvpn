use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
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
    /// Adopt an interface that already exists and already carries peers.
    ///
    /// The gateway will not create the interface, will not set its listen port,
    /// and will never write a private key — doing any of those to a live hub
    /// would invalidate every existing peer.
    #[serde(default)]
    pub adopt_existing: bool,
    #[serde(default = "default_state")]
    pub state_dir: String,
    pub public_key: Option<String>,
    /// CIDR the control plane owns on this interface. Only peers whose
    /// allowed-ips fall entirely inside it are eligible for removal.
    ///
    /// Defaults to the network CIDR served by the control plane.
    pub managed_range: Option<String>,
}

fn default_state() -> String {
    "/var/lib/wsl-gateway".into()
}

impl GatewayConfigFile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
        let cfg: Self = serde_yaml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Fail fast on configurations that would damage an adopted hub.
    pub fn validate(&self) -> Result<()> {
        if self.wireguard.adopt_existing && self.wireguard.public_key.is_none() {
            anyhow::bail!(
                "wireguard.adopt_existing requires wireguard.public_key (the existing \
                 interface's public key); without it the gateway would generate a new \
                 keypair and overwrite the private key of every live peer"
            );
        }
        if let Some(range) = &self.wireguard.managed_range {
            range
                .parse::<IpNetwork>()
                .with_context(|| format!("invalid wireguard.managed_range: {range}"))?;
        }
        Ok(())
    }

    /// The CIDR that scopes peer removal, preferring the explicit config value
    /// over the network the control plane reports.
    ///
    /// Returns `None` when neither parses, which disables removal entirely.
    pub fn managed_range(&self, control_cidr: &str) -> Option<IpNetwork> {
        self.wireguard
            .managed_range
            .as_deref()
            .and_then(|r| r.parse().ok())
            .or_else(|| control_cidr.parse().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(extra: &str) -> GatewayConfigFile {
        let yaml = format!(
            r#"
control:
  url: "http://localhost:8080"
  registration_token: "t"
gateway:
  name: "gw"
  endpoint: "vpn.example.com:51820"
wireguard:
  interface: "wg0"
{extra}
"#
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[test]
    fn adopt_without_public_key_is_rejected() {
        let cfg = base("  adopt_existing: true");
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("adopt_existing requires"), "{err}");
    }

    #[test]
    fn adopt_with_public_key_is_accepted() {
        let cfg = base("  adopt_existing: true\n  public_key: \"abc=\"");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn invalid_managed_range_is_rejected() {
        let cfg = base("  managed_range: \"not-a-cidr\"");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn managed_range_prefers_explicit_over_control() {
        let cfg = base("  managed_range: \"10.8.1.0/24\"");
        assert_eq!(
            cfg.managed_range("10.8.0.0/24").unwrap().to_string(),
            "10.8.1.0/24"
        );
    }

    #[test]
    fn managed_range_falls_back_to_control_cidr() {
        let cfg = base("");
        assert_eq!(
            cfg.managed_range("10.88.0.0/24").unwrap().to_string(),
            "10.88.0.0/24"
        );
    }

    #[test]
    fn managed_range_is_none_when_neither_parses() {
        let cfg = base("");
        assert!(cfg.managed_range("").is_none());
    }

    #[test]
    fn defaults_are_conservative() {
        let cfg = base("");
        assert!(!cfg.wireguard.manage_interface);
        assert!(!cfg.wireguard.adopt_existing);
    }
}
