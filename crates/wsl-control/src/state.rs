use crate::config::Config;
use crate::services::audit::{AuditEntry, AuditService};
use crate::services::gitops::GitOpsService;
use anyhow::Context;
use metrics_exporter_prometheus::PrometheusHandle;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{migrate::Migrator, PgPool};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub http: reqwest::Client,
    pub metrics_handle: PrometheusHandle,
}

impl AppState {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        // Bounded and time-limited on every axis. An unbounded acquire in
        // particular turns a slow database into an unbounded queue of waiting
        // requests, which looks like a control-plane hang rather than an error.
        let db = PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .min_connections(config.database.min_connections)
            .acquire_timeout(Duration::from_secs(config.database.acquire_timeout_secs))
            .idle_timeout(Duration::from_secs(config.database.idle_timeout_secs))
            .max_lifetime(Duration::from_secs(config.database.max_lifetime_secs))
            .connect(&config.database.url)
            .await
            .context("connect postgres")?;
        MIGRATOR.run(&db).await.context("run migrations")?;

        Ok(Self::with_pool(config, db))
    }

    /// Build state around an existing pool.
    ///
    /// The seam integration tests use: they are handed a pool for a throwaway
    /// database and need the same router the binary serves, not a reduced one.
    pub fn with_pool(config: Config, db: PgPool) -> Self {
        Self {
            config: Arc::new(config),
            db,
            http: reqwest::Client::new(),
            metrics_handle: metrics_handle(),
        }
    }

    pub async fn bootstrap(&self) -> anyhow::Result<()> {
        let ops_hash = hash_token(&self.config.bootstrap.ops_service_token);
        sqlx::query(
            r#"
            INSERT INTO service_tokens (name, token_hash, scopes, description)
            VALUES ('opsapi', $1, ARRAY['ops:provision'], 'Machine provisioning API')
            ON CONFLICT (name) DO UPDATE SET token_hash = EXCLUDED.token_hash, active = TRUE
            "#,
        )
        .bind(&ops_hash)
        .execute(&self.db)
        .await?;

        // SCIM gets its own credential and its own scope. The IdP holding it
        // can sync the directory and nothing else.
        match &self.config.bootstrap.scim_service_token {
            Some(token) => {
                sqlx::query(
                    r#"
                    INSERT INTO service_tokens (name, token_hash, scopes, description)
                    VALUES ('scim', $1, ARRAY['scim:manage'], 'SCIM directory provisioning')
                    ON CONFLICT (name) DO UPDATE SET
                      token_hash = EXCLUDED.token_hash,
                      scopes = EXCLUDED.scopes,
                      active = TRUE
                    "#,
                )
                .bind(hash_token(token))
                .execute(&self.db)
                .await?;
            }
            // No token configured means SCIM is not in use. Deactivate any
            // credential a previous configuration left behind rather than
            // leaving a provisioning key live that nobody is tracking.
            None => {
                sqlx::query("UPDATE service_tokens SET active = FALSE WHERE name = 'scim'")
                    .execute(&self.db)
                    .await?;
            }
        }

        self.reconcile_admins().await?;

        // Seed default network if empty
        let networks: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM networks")
            .fetch_one(&self.db)
            .await?;
        if networks.0 == 0 {
            sqlx::query(
                r#"
                INSERT INTO networks (name, cidr, dns_servers, dns_domains)
                VALUES ('development', '10.88.0.0/24', ARRAY['10.88.0.53'], ARRAY['internal.example.com'])
                "#,
            )
            .execute(&self.db)
            .await?;
            sqlx::query(
                r#"
                INSERT INTO routes (network_id, destination, description)
                SELECT id, '10.88.0.0/24', 'development overlay' FROM networks WHERE name = 'development'
                "#,
            )
            .execute(&self.db)
            .await?;
        }

        if self.config.gitops.enabled {
            let gitops = GitOpsService::new(self.clone());
            if let Err(e) = gitops.apply_directory(&self.config.gitops.path, None).await {
                tracing::warn!(error = %e, "initial gitops apply skipped or failed");
            }
        }

        AuditService::new(self.clone())
            .record(
                AuditEntry::new("control.bootstrap").details(serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "gitops_enabled": self.config.gitops.enabled,
                    "dev_login_enabled": self.config.identity.dev_login_enabled,
                })),
            )
            .await?;

        Ok(())
    }
}

impl AppState {
    /// Make `bootstrap.admin_emails` the source of truth for who is an admin.
    ///
    /// Runs on every start so the list is declarative: adding an address grants
    /// the role, removing one takes it away. Removing the last address does not
    /// silently strip the final administrator — that is caught before the
    /// demotion, because a deployment with no admin cannot be recovered through
    /// the API.
    async fn reconcile_admins(&self) -> anyhow::Result<()> {
        let emails: Vec<String> = self
            .config
            .bootstrap
            .admin_emails
            .iter()
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty())
            .collect();

        if emails.is_empty() {
            let existing: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                    .fetch_one(&self.db)
                    .await?;
            if existing == 0 {
                tracing::warn!(
                    "no bootstrap.admin_emails configured and no admin exists; \
                     the administrative API will be unreachable"
                );
            }
            return Ok(());
        }

        // Create any listed address that has never signed in, so the first
        // administrator does not have to exist before they can be granted.
        for email in &emails {
            sqlx::query(
                "INSERT INTO users (email, role) VALUES ($1, 'admin')
                 ON CONFLICT (email) DO UPDATE SET role = 'admin', updated_at = NOW()",
            )
            .bind(email)
            .execute(&self.db)
            .await?;
        }

        let demoted = sqlx::query(
            "UPDATE users SET role = 'member', updated_at = NOW()
             WHERE role = 'admin' AND lower(email) <> ALL($1)",
        )
        .bind(&emails)
        .execute(&self.db)
        .await?;

        tracing::info!(
            admins = emails.len(),
            demoted = demoted.rows_affected(),
            "reconciled administrators from configuration"
        );
        Ok(())
    }
}

/// The Prometheus recorder is process-global and may only be installed once.
/// Installing it lazily behind a `OnceLock` lets a test binary build many
/// `AppState`s without the second one failing.
fn metrics_handle() -> PrometheusHandle {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    HANDLE
        .get_or_init(|| {
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .install_recorder()
                .expect("install prometheus recorder")
        })
        .clone()
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Mint a bearer secret: 256 bits from the OS CSPRNG, URL-safe so it survives
/// being pasted into a config file or an `Authorization` header unescaped.
pub fn generate_token() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Compare two token hashes without leaking how far the match got.
///
/// The values compared here are already digests, so a timing leak would only
/// narrow a hash rather than a secret — but comparisons against attacker-supplied
/// input are exactly where this habit is worth keeping.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
