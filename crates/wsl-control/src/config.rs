use crate::middleware::rate_limit::RateLimitConfig;
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
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub public_url: String,
    /// Serve Swagger UI and the OpenAPI document. Off by default: the document
    /// enumerates every route and schema on the control plane.
    #[serde(default)]
    pub expose_docs: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProductConfig {
    pub namespace: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,
    /// Give up waiting for a pooled connection rather than queueing forever.
    /// Without this a database stall turns into unbounded request pile-up.
    #[serde(default = "default_acquire_timeout_secs")]
    pub acquire_timeout_secs: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_max_lifetime_secs")]
    pub max_lifetime_secs: u64,
}

fn default_max_connections() -> u32 {
    20
}
fn default_min_connections() -> u32 {
    2
}
fn default_acquire_timeout_secs() -> u64 {
    5
}
fn default_idle_timeout_secs() -> u64 {
    300
}
fn default_max_lifetime_secs() -> u64 {
    1800
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    pub oidc: OidcConfig,
    /// Enable `POST /auth/dev/login`, which mints a session for any email with
    /// no credential at all.
    ///
    /// This must be an explicit opt-in rather than inferred from the public URL:
    /// deriving it from a hostname means one config typo silently turns a
    /// production control plane into an open door.
    #[serde(default)]
    pub dev_login_enabled: bool,
    /// Who may sign in at all, beyond "the provider verified them".
    #[serde(default)]
    pub admission: AdmissionConfig,
}

/// Which verified logins are admitted.
///
/// The provider proves who someone is; it says nothing about whether they
/// belong here. For a private provider — Dex, Keycloak, a tenant of Entra ID —
/// everyone it can sign in is already one of yours. For Google it is anyone
/// with a Google account, so a Google deployment has to narrow it, and
/// [`Config::validate`] refuses to start one that does not.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct AdmissionConfig {
    /// Whether a first login creates a user, or only finds one the directory
    /// (OpsAPI, over `/api/v1/ops/users` or SCIM) already created.
    #[serde(default)]
    pub provisioning: Provisioning,
    /// Google Workspace domains whose accounts may sign in, compared with the
    /// id_token's `hd` claim. Not the email domain: a consumer Google account
    /// can carry a verified address at any domain, including yours. Empty
    /// means no domain restriction.
    #[serde(default)]
    pub hosted_domains: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Provisioning {
    /// A first login by a verified identity with no user creates one.
    #[default]
    Jit,
    /// Only people the directory has provisioned may sign in. The directory
    /// decides who is in; the provider only proves who is asking.
    Directory,
}

/// Google's issuer, whose accounts are open to anyone.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    /// Private-use URI schemes a native app may be sent back to.
    ///
    /// A desktop client can listen on loopback; a mobile one cannot, and uses a
    /// scheme the operating system routes to it instead (RFC 8252 section 7.1).
    /// Nothing is accepted unless it is named here: an empty list means no
    /// mobile client can complete a login, which is the right default for a
    /// deployment that does not have one.
    #[serde(default)]
    pub native_schemes: Vec<String>,
    /// Tolerance when comparing an id_token's `exp` and `iat` against local
    /// time.
    ///
    /// A provider and a control plane that disagree by a few seconds would
    /// otherwise reject valid logins, which is the kind of failure that gets
    /// "fixed" by switching expiry checking off. A minute is enough for hosts
    /// that keep time and small enough that an expired token is not usable for
    /// meaningfully longer.
    #[serde(default = "default_clock_skew_secs")]
    pub clock_skew_secs: u64,
    /// Where the provider is reachable from the control plane, when that is not
    /// the issuer.
    ///
    /// The issuer is an identity: it appears in every token and must match what
    /// the provider signs. It is not always an address this process can open a
    /// connection to. A control plane running in a cluster alongside its provider
    /// reaches it by service DNS while the tokens name the public hostname, and
    /// the compose stack has the same split — the browser is sent to
    /// `localhost:5556` and the container resolves `dex:5556`.
    ///
    /// Setting this changes only which address is dialled. The issuer is still
    /// compared strictly against the discovery document and the token's `iss`.
    #[serde(default)]
    pub internal_url: Option<String>,
}

fn default_clock_skew_secs() -> u64 {
    60
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
    /// Service token for SCIM provisioning, held by the IdP. Separate from the
    /// ops token so a directory-sync credential cannot read the audit log.
    #[serde(default)]
    pub scim_service_token: Option<String>,
    /// Users granted the `admin` role at every startup. This is the only way an
    /// administrator comes into existence, so an empty list on a fresh database
    /// means nobody can administer it.
    #[serde(default)]
    pub admin_emails: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub rate_limit: RateLimitsConfig,
}

impl SecurityConfig {
    /// Every budget switched off. For test harnesses that drive many requests
    /// from a single address, where a 429 would hide the status under test.
    pub fn disabled() -> Self {
        let off = RateLimitConfig {
            enabled: false,
            requests: 0,
            window_secs: 60,
        };
        Self {
            rate_limit: RateLimitsConfig {
                auth: off,
                api: off,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct RateLimitsConfig {
    /// Budget for credential-checking endpoints (OIDC handshake, dev login).
    #[serde(default = "default_auth_limit")]
    pub auth: RateLimitConfig,
    /// Budget for the authenticated API surface.
    #[serde(default = "default_api_limit")]
    pub api: RateLimitConfig,
}

impl Default for RateLimitsConfig {
    fn default() -> Self {
        Self {
            auth: default_auth_limit(),
            api: default_api_limit(),
        }
    }
}

fn default_auth_limit() -> RateLimitConfig {
    RateLimitConfig {
        enabled: true,
        requests: 20,
        window_secs: 60,
    }
}

fn default_api_limit() -> RateLimitConfig {
    RateLimitConfig {
        enabled: true,
        requests: 600,
        window_secs: 60,
    }
}

/// Secrets that must never be left at their shipped example values.
const PLACEHOLDER_SECRETS: &[&str] = &[
    "dev-ops-token-change-me",
    "dev-gateway-token-change-me",
    "dev-scim-token-change-me",
    "change-me",
];

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
        let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)?;
        expand_env_in_document(&mut document)?;
        let cfg: Self = serde_yaml::from_value(document)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate_admission(&self) -> Result<()> {
        let admission = &self.identity.admission;
        for domain in &admission.hosted_domains {
            let ok = domain.contains('.')
                && domain.split('.').all(|l| {
                    !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                });
            if !ok {
                anyhow::bail!("identity.admission.hosted_domains: '{domain}' is not a domain name");
            }
        }
        let open =
            admission.provisioning == Provisioning::Jit && admission.hosted_domains.is_empty();
        if self.identity.oidc.issuer.trim_end_matches('/') == GOOGLE_ISSUER && open {
            anyhow::bail!(
                "identity.oidc.issuer is Google, which signs in anyone with a Google account, \
                 and nothing narrows that. Set identity.admission.hosted_domains to your \
                 Google Workspace domain, or identity.admission.provisioning to `directory` \
                 so only people OpsAPI has provisioned can sign in (or both)."
            );
        }
        Ok(())
    }

    /// True when the control plane is addressed as a loopback host.
    pub fn is_local(&self) -> bool {
        self.server.public_url.contains("localhost") || self.server.public_url.contains("127.0.0.1")
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
        for scheme in &self.identity.oidc.native_schemes {
            validate_native_scheme(scheme)?;
        }
        self.validate_admission()?;
        if self.database.max_connections == 0 {
            anyhow::bail!("database.max_connections must be at least 1");
        }

        // Refuse to start a non-local deployment carrying example secrets or a
        // development back door. Both are the kind of mistake that survives
        // review and is only noticed after it is exploited, so the process
        // fails loudly at boot instead.
        if !self.is_local() {
            for (name, value) in [
                (
                    "bootstrap.ops_service_token",
                    &self.bootstrap.ops_service_token,
                ),
                (
                    "bootstrap.gateway_registration_token",
                    &self.bootstrap.gateway_registration_token,
                ),
            ] {
                if PLACEHOLDER_SECRETS.contains(&value.as_str()) {
                    anyhow::bail!("{name} still holds its example value; set a real secret");
                }
                if value.len() < 16 {
                    anyhow::bail!("{name} must be at least 16 characters");
                }
            }
            if let Some(scim) = &self.bootstrap.scim_service_token {
                if PLACEHOLDER_SECRETS.contains(&scim.as_str()) || scim.len() < 16 {
                    anyhow::bail!(
                        "bootstrap.scim_service_token still holds its example value or is too short"
                    );
                }
            }
            if self.identity.dev_login_enabled {
                anyhow::bail!(
                    "identity.dev_login_enabled must be false unless server.public_url is loopback"
                );
            }
            if self.bootstrap.admin_emails.is_empty() {
                anyhow::bail!(
                    "bootstrap.admin_emails must name at least one administrator; \
                     without it no one can administer this deployment"
                );
            }
        }
        Ok(())
    }
}

/// Expand `${VAR}` in every string in a parsed document.
///
/// Substitution happens after parsing rather than over the raw text, so a
/// `${...}` written inside a YAML comment — which is exactly where a config
/// file explains that the feature exists — is not treated as a reference to a
/// variable nobody set.
pub fn expand_env_in_document(value: &mut serde_yaml::Value) -> Result<()> {
    match value {
        serde_yaml::Value::String(s) => {
            if s.contains("${") {
                *s = expand_env(s)?;
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                expand_env_in_document(item)?;
            }
        }
        serde_yaml::Value::Mapping(map) => {
            // Keys are field names, never secrets; only values are expanded.
            for (_, v) in map.iter_mut() {
                expand_env_in_document(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Replace `${VAR}` with the environment variable's value.
///
/// Lets a deployment keep secrets in the process environment — or in whatever
/// injects it, a Kubernetes Secret or a vault agent — while the config file
/// itself stays checkable into git. An unset variable is an error rather than
/// an empty string, so a missing secret fails at boot instead of silently
/// becoming a blank password.
pub fn expand_env(raw: &str) -> Result<String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            anyhow::bail!("unterminated ${{ in configuration");
        };
        let name = &after[..end];
        let value = std::env::var(name).with_context(|| {
            format!("configuration references unset environment variable {name}")
        })?;
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Check that a configured native redirect scheme is one it is safe to accept.
///
/// Private-use schemes are first come, first served on every operating system
/// that has them: nothing stops a second app registering the same one, and the
/// OS may then route the redirect to either. RFC 8252 section 7.1 answers that
/// by requiring a scheme derived from a domain name the app's author controls,
/// which is why a bare word is refused here — `wslvpn:` is squattable in a way
/// `io.wsl.zerotrust:` is not.
///
/// `http` and `https` are refused outright. Accepting either here would route
/// around the loopback rules the other branch enforces.
pub fn validate_native_scheme(scheme: &str) -> anyhow::Result<()> {
    let lower = scheme.to_ascii_lowercase();
    if lower != scheme {
        anyhow::bail!("identity.oidc.native_schemes: '{scheme}' must be lowercase");
    }
    if matches!(
        lower.as_str(),
        "http" | "https" | "file" | "data" | "javascript"
    ) {
        anyhow::bail!("identity.oidc.native_schemes: '{scheme}' is not a private-use scheme");
    }
    if !lower.contains('.') {
        anyhow::bail!(
            "identity.oidc.native_schemes: '{scheme}' must be derived from a domain \
             name you control, such as 'io.example.vpn' (RFC 8252 section 7.1)"
        );
    }
    // The scheme grammar from RFC 3986: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    let mut chars = lower.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !first_ok || !rest_ok {
        anyhow::bail!("identity.oidc.native_schemes: '{scheme}' is not a valid URI scheme");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(issuer: &str, admission: AdmissionConfig) -> Config {
        let yaml = format!(
            r#"
server: {{ listen: "0.0.0.0:8080", public_url: "http://localhost:8080" }}
product: {{ namespace: wsl, display_name: test }}
database: {{ url: "postgres://x", max_connections: 5, min_connections: 1 }}
identity:
  oidc:
    issuer: "{issuer}"
    client_id: c
    scopes: [openid]
    redirect_uri: "http://localhost:8080/auth/oidc/callback"
wireguard: {{ default_port: 51820 }}
gitops: {{ enabled: false, path: "." }}
bootstrap: {{ ops_service_token: "0123456789abcdef", gateway_registration_token: "0123456789abcdef" }}
"#
        );
        let mut config: Config = serde_yaml::from_str(&yaml).expect("parse");
        config.identity.admission = admission;
        config
    }

    /// With Google as the provider and nothing else configured, every Google
    /// account in the world could create a user here.
    #[test]
    fn google_with_open_admission_refuses_to_start() {
        let err = config_with("https://accounts.google.com", AdmissionConfig::default())
            .validate()
            .expect_err("open Google admission must be refused");
        let message = err.to_string();
        assert!(message.contains("hosted_domains"), "{message}");
        assert!(message.contains("directory"), "{message}");
    }

    #[test]
    fn google_limited_to_a_workspace_domain_starts() {
        let admission = AdmissionConfig {
            hosted_domains: vec!["example.com".into()],
            ..Default::default()
        };
        config_with("https://accounts.google.com", admission)
            .validate()
            .expect("a hosted-domain restriction is enough");
    }

    #[test]
    fn google_admitting_only_directory_users_starts() {
        let admission = AdmissionConfig {
            provisioning: Provisioning::Directory,
            ..Default::default()
        };
        config_with("https://accounts.google.com", admission)
            .validate()
            .expect("directory-only admission is enough");
    }

    #[test]
    fn a_private_provider_keeps_just_in_time_provisioning_by_default() {
        config_with("https://idp.example.com", AdmissionConfig::default())
            .validate()
            .expect("unchanged for existing deployments");
    }

    #[test]
    fn admission_reads_from_yaml() {
        let admission: AdmissionConfig =
            serde_yaml::from_str("provisioning: directory\nhosted_domains: [Example.com]\n")
                .expect("parse");
        assert_eq!(admission.provisioning, Provisioning::Directory);
        assert_eq!(admission.hosted_domains, vec!["Example.com".to_string()]);
    }

    #[test]
    fn a_hosted_domain_that_is_not_a_domain_is_refused() {
        let admission = AdmissionConfig {
            hosted_domains: vec!["*.example.com".into()],
            ..Default::default()
        };
        assert!(config_with("https://accounts.google.com", admission)
            .validate()
            .is_err());
    }

    #[test]
    fn expands_a_set_variable() {
        std::env::set_var("WSL_TEST_SECRET", "s3cret");
        let out = expand_env("token: ${WSL_TEST_SECRET}").unwrap();
        assert_eq!(out, "token: s3cret");
    }

    #[test]
    fn expands_several_variables_in_one_document() {
        std::env::set_var("WSL_TEST_A", "one");
        std::env::set_var("WSL_TEST_B", "two");
        let out = expand_env("a: ${WSL_TEST_A}\nb: ${WSL_TEST_B}\n").unwrap();
        assert_eq!(out, "a: one\nb: two\n");
    }

    #[test]
    fn unset_variable_fails_rather_than_expanding_to_empty() {
        std::env::remove_var("WSL_TEST_MISSING");
        let err = expand_env("token: ${WSL_TEST_MISSING}").unwrap_err();
        assert!(err.to_string().contains("WSL_TEST_MISSING"));
    }

    #[test]
    fn unterminated_placeholder_is_rejected() {
        assert!(expand_env("token: ${OOPS").is_err());
    }

    #[test]
    fn document_without_placeholders_is_unchanged() {
        let raw = "server:\n  listen: 0.0.0.0:8080\n";
        assert_eq!(expand_env(raw).unwrap(), raw);
    }

    #[test]
    fn a_placeholder_inside_a_comment_is_not_a_reference() {
        // A config file that documents the ${VAR} feature in a comment must not
        // fail to load because the example variable does not exist.
        std::env::set_var("WSL_TEST_REAL", "real-value");
        let raw = "# secrets may be written as ${NOT_SET_ANYWHERE}\ntoken: ${WSL_TEST_REAL}\n";
        let mut doc: serde_yaml::Value = serde_yaml::from_str(raw).unwrap();
        expand_env_in_document(&mut doc).unwrap();
        assert_eq!(doc["token"], serde_yaml::Value::String("real-value".into()));
    }

    #[test]
    fn expansion_reaches_into_sequences_and_nested_mappings() {
        std::env::set_var("WSL_TEST_NESTED", "deep");
        let raw = "outer:\n  inner:\n    - ${WSL_TEST_NESTED}\n    - plain\n";
        let mut doc: serde_yaml::Value = serde_yaml::from_str(raw).unwrap();
        expand_env_in_document(&mut doc).unwrap();
        assert_eq!(
            doc["outer"]["inner"][0],
            serde_yaml::Value::String("deep".into())
        );
        assert_eq!(
            doc["outer"]["inner"][1],
            serde_yaml::Value::String("plain".into())
        );
    }
}
