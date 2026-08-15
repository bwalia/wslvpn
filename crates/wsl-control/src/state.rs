use crate::config::Config;
use crate::services::audit::AuditService;
use crate::services::gitops::GitOpsService;
use anyhow::Context;
use metrics_exporter_prometheus::PrometheusHandle;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{migrate::Migrator, PgPool};
use std::sync::Arc;

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
        let db = PgPoolOptions::new()
            .max_connections(10)
            .connect(&config.database.url)
            .await
            .context("connect postgres")?;
        MIGRATOR.run(&db).await.context("run migrations")?;

        let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .context("install prometheus recorder")?;

        Ok(Self {
            config: Arc::new(config),
            db,
            http: reqwest::Client::new(),
            metrics_handle,
        })
    }

    pub async fn bootstrap(&self) -> anyhow::Result<()> {
        let ops_hash = hash_token(&self.config.bootstrap.ops_service_token);
        sqlx::query(
            r#"
            INSERT INTO service_tokens (name, token_hash, scopes)
            VALUES ('opsapi', $1, ARRAY['ops:provision'])
            ON CONFLICT (name) DO UPDATE SET token_hash = EXCLUDED.token_hash, active = TRUE
            "#,
        )
        .bind(&ops_hash)
        .execute(&self.db)
        .await?;

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
                "control.bootstrap",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                serde_json::json!({}),
            )
            .await?;

        Ok(())
    }
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}
