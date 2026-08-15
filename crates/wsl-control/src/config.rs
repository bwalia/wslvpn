use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub product: ProductConfig,
    pub database: DatabaseConfig,
    pub identity: IdentityConfig,
    pub wireguard: WireGuardConfig,
    pub gitops: GitOpsConfig,
    pub bootstrap: BootstrapConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub public_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProductConfig {
    pub namespace: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    pub oidc: OidcConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WireGuardConfig {
    pub default_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitOpsConfig {
    pub enabled: bool,
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapConfig {
    pub ops_service_token: String,
    pub gateway_registration_token: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
        let cfg: Self = serde_yaml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.server.listen.is_empty() {
            anyhow::bail!("server.listen required");
        }
        if !self.database.url.starts_with("postgres") {
            anyhow::bail!("database.url must be a postgres URL");
        }
        if self.identity.oidc.issuer.is_empty() || self.identity.oidc.client_id.is_empty() {
            anyhow::bail!("identity.oidc.issuer and client_id required");
        }
        Ok(())
    }
}
