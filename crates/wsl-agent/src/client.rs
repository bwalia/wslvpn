use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use uuid::Uuid;
use wsl_crypto::{generate_wireguard_keypair, SecureKeyStore};
use wsl_types::{
    CreateSessionRequest, CreateSessionResponse, Network, RegisterDeviceRequest,
    RegisterDeviceResponse,
};

use crate::oidc;
use crate::posture;
use crate::state::AgentState;
use crate::tunnel::{self, TunnelState};

pub struct ControlClient {
    http: reqwest::Client,
}

impl ControlClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }

    /// Sign in through the identity provider.
    ///
    /// This is what a real deployment uses. `dev_login` below talks to an
    /// endpoint the control plane refuses to serve unless it is bound to
    /// loopback, so it can only ever reach a local demo.
    pub async fn login(&self, state: &mut AgentState, open_browser: bool) -> Result<()> {
        let token = oidc::browser_login(&self.http, &state.control_url, open_browser).await?;
        state.access_token = Some(token.access_token);
        state.user_id = Some(token.user_id);
        state.email = Some(token.email);
        state.save()?;
        Ok(())
    }

    pub async fn dev_login(&self, state: &mut AgentState, email: &str) -> Result<()> {
        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            user_id: Uuid,
            email: String,
        }
        let resp: TokenResponse = self
            .http
            .post(format!(
                "{}/auth/dev/login",
                state.control_url.trim_end_matches('/')
            ))
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        state.access_token = Some(resp.access_token);
        state.user_id = Some(resp.user_id);
        state.email = Some(resp.email);
        state.save()?;
        Ok(())
    }

    pub async fn ensure_device(&self, state: &mut AgentState) -> Result<Uuid> {
        if let Some(id) = state.device_id {
            return Ok(id);
        }
        let store = wsl_crypto::FileKeyStore::new(AgentState::keystore_dir()?)?;
        let kp = generate_wireguard_keypair();
        store
            .store("wg.private", kp.private_key_b64.as_bytes())
            .await?;

        let hostname = hostname();
        let req = RegisterDeviceRequest {
            name: hostname.clone(),
            platform: std::env::consts::OS.into(),
            os_version: Some(std::env::consts::ARCH.into()),
            agent_version: Some(env!("CARGO_PKG_VERSION").into()),
            wireguard_public_key: kp.public_key_b64.clone(),
            posture: posture::collect(),
        };
        let resp: RegisterDeviceResponse = self
            .http
            .post(format!(
                "{}/api/v1/devices/register",
                state.control_url.trim_end_matches('/')
            ))
            .headers(auth_headers(state)?)
            .json(&req)
            .send()
            .await?
            .error_for_status()
            .context("device register")?
            .json()
            .await?;
        state.device_id = Some(resp.device.id);
        state.device_name = Some(resp.device.name);
        state.wireguard_public_key = Some(resp.device.wireguard_public_key);
        state.save()?;
        Ok(resp.device.id)
    }

    pub async fn list_networks(&self, state: &AgentState) -> Result<Vec<Network>> {
        let networks: Vec<Network> = self
            .http
            .get(format!(
                "{}/api/v1/networks",
                state.control_url.trim_end_matches('/')
            ))
            .headers(auth_headers(state)?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(networks)
    }

    pub async fn connect(
        &self,
        state: &mut AgentState,
        network_name: Option<&str>,
    ) -> Result<CreateSessionResponse> {
        let device_id = self.ensure_device(state).await?;
        let networks = self.list_networks(state).await?;
        let network = if let Some(name) = network_name {
            networks
                .into_iter()
                .find(|n| n.name == name)
                .context("network not found")?
        } else {
            networks.into_iter().next().context("no networks")?
        };
        let req = CreateSessionRequest {
            network_id: network.id,
            device_id,
            posture: posture::collect(),
        };
        let resp: CreateSessionResponse = self
            .http
            .post(format!(
                "{}/api/v1/sessions",
                state.control_url.trim_end_matches('/')
            ))
            .headers(auth_headers(state)?)
            .json(&req)
            .send()
            .await?
            .error_for_status()
            .context("create session")?
            .json()
            .await?;
        state.session = Some(resp.session.clone());
        state.wireguard = Some(resp.wireguard.clone());
        state.network_name = Some(network.name.clone());
        state.save()?;
        let conf_path = AgentState::wg_conf_path()?;
        state.write_wg_config(&conf_path)?;
        tracing::info!(path = %conf_path.display(), "wrote wireguard config");
        Ok(resp)
    }

    /// Create a session and bring the interface up.
    ///
    /// The session is created first because the gateway has to know about the
    /// peer before traffic will pass. If the interface then fails to come up
    /// the session is left in place rather than silently revoked: that is what
    /// `wsl status` reports as "Session open, tunnel down", and it is what the
    /// user retries against once they have fixed whatever wg-quick complained
    /// about.
    pub async fn connect_and_bring_up(
        &self,
        state: &mut AgentState,
        network_name: Option<&str>,
        allow_sudo: bool,
    ) -> Result<(CreateSessionResponse, TunnelState)> {
        let resp = self.connect(state, network_name).await?;
        let conf_path = AgentState::wg_conf_path()?;
        let tunnel = tunnel::up(&conf_path, allow_sudo).await?;
        tracing::info!(interface = %tunnel.interface(), "tunnel up");
        Ok((resp, tunnel))
    }

    /// Tear the interface down, then release the session.
    ///
    /// In that order: releasing the session first would leave an interface up
    /// and pointed at a gateway that has already dropped the peer, which looks
    /// to the user like a connected tunnel that silently blackholes.
    pub async fn disconnect_and_tear_down(
        &self,
        state: &mut AgentState,
        allow_sudo: bool,
    ) -> Result<()> {
        let conf_path = AgentState::wg_conf_path()?;
        tunnel::down(&conf_path, allow_sudo).await?;
        self.disconnect(state).await
    }

    pub async fn disconnect(&self, state: &mut AgentState) -> Result<()> {
        if let Some(session) = &state.session {
            let _ = self
                .http
                .delete(format!(
                    "{}/api/v1/sessions/{}",
                    state.control_url.trim_end_matches('/'),
                    session.id
                ))
                .headers(auth_headers(state)?)
                .send()
                .await;
        }
        state.session = None;
        state.wireguard = None;
        state.network_name = None;
        state.save()?;
        Ok(())
    }

    pub fn logout(&self, state: &mut AgentState) -> Result<()> {
        state.access_token = None;
        state.email = None;
        state.user_id = None;
        state.session = None;
        state.wireguard = None;
        state.network_name = None;
        state.save()?;
        Ok(())
    }
}

impl Default for ControlClient {
    fn default() -> Self {
        Self::new()
    }
}

fn auth_headers(state: &AgentState) -> Result<HeaderMap> {
    let token = state
        .access_token
        .as_ref()
        .context("not logged in; run wsl login")?;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    Ok(headers)
}

fn hostname() -> String {
    hostname_impl().unwrap_or_else(|| "unknown-device".into())
}

fn hostname_impl() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
}
