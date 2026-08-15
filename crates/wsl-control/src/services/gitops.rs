use crate::error::{AppError, AppResult};
use crate::state::AppState;
use std::path::Path;
use uuid::Uuid;
use wsl_policy::parse_policy_yaml;
use wsl_types::{Policy, PolicyVersion};

pub struct GitOpsService {
    state: AppState,
}

impl GitOpsService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn apply_directory(&self, path: &str, git_commit: Option<&str>) -> AppResult<usize> {
        let root = Path::new(path);
        let policies_dir = root.join("policies");
        if !policies_dir.is_dir() {
            return Err(AppError::bad_request(format!(
                "policies directory not found: {}",
                policies_dir.display()
            )));
        }

        // Ensure developers group exists from groups/
        let groups_dir = root.join("groups");
        if groups_dir.is_dir() {
            for entry in std::fs::read_dir(&groups_dir).map_err(|e| AppError::Internal(e.into()))? {
                let entry = entry.map_err(|e| AppError::Internal(e.into()))?;
                if entry.path().extension().and_then(|s| s.to_str()) != Some("yaml") {
                    continue;
                }
                let raw = std::fs::read_to_string(entry.path())
                    .map_err(|e| AppError::Internal(e.into()))?;
                let v: serde_yaml::Value =
                    serde_yaml::from_str(&raw).map_err(|e| AppError::bad_request(e.to_string()))?;
                if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
                    let desc = v
                        .get("description")
                        .and_then(|d| d.as_str())
                        .map(|s| s.to_string());
                    crate::services::groups::GroupService::new(self.state.clone())
                        .create(wsl_types::CreateGroupRequest {
                            name: name.to_string(),
                            description: desc,
                        })
                        .await?;
                }
            }
        }

        // Networks
        let networks_dir = root.join("networks");
        if networks_dir.is_dir() {
            for entry in
                std::fs::read_dir(&networks_dir).map_err(|e| AppError::Internal(e.into()))?
            {
                let entry = entry.map_err(|e| AppError::Internal(e.into()))?;
                if entry.path().extension().and_then(|s| s.to_str()) != Some("yaml") {
                    continue;
                }
                let raw = std::fs::read_to_string(entry.path())
                    .map_err(|e| AppError::Internal(e.into()))?;
                let v: serde_yaml::Value =
                    serde_yaml::from_str(&raw).map_err(|e| AppError::bad_request(e.to_string()))?;
                let name = v
                    .get("name")
                    .and_then(|n| n.as_str())
                    .ok_or_else(|| AppError::bad_request("network name required"))?;
                let cidr = v
                    .get("cidr")
                    .and_then(|n| n.as_str())
                    .ok_or_else(|| AppError::bad_request("network cidr required"))?;
                let dns_servers = v
                    .get("dns")
                    .and_then(|d| d.get("servers"))
                    .and_then(|s| s.as_sequence())
                    .map(|seq| {
                        seq.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let dns_domains = v
                    .get("dns")
                    .and_then(|d| d.get("domains"))
                    .and_then(|s| s.as_sequence())
                    .map(|seq| {
                        seq.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let existing = crate::services::networks::NetworkService::new(self.state.clone())
                    .get_by_name(name)
                    .await?;
                let network_id = if let Some(n) = existing {
                    n.id
                } else {
                    crate::services::networks::NetworkService::new(self.state.clone())
                        .create(wsl_types::CreateNetworkRequest {
                            name: name.to_string(),
                            cidr: cidr.to_string(),
                            dns_servers,
                            dns_domains,
                        })
                        .await?
                        .id
                };

                if let Some(services) = v.get("services").and_then(|s| s.as_sequence()) {
                    for service in services {
                        let (Some(name), Some(dest)) = (
                            service.get("name").and_then(|n| n.as_str()),
                            service.get("destination").and_then(|d| d.as_str()),
                        ) else {
                            return Err(AppError::bad_request(
                                "service requires name and destination",
                            ));
                        };
                        let protocol = service
                            .get("protocol")
                            .and_then(|p| p.as_str())
                            .unwrap_or("tcp");
                        let ports: Vec<i32> = service
                            .get("ports")
                            .and_then(|p| p.as_sequence())
                            .map(|seq| {
                                seq.iter()
                                    .filter_map(|x| x.as_i64().map(|n| n as i32))
                                    .collect()
                            })
                            .unwrap_or_default();
                        if ports.is_empty() {
                            // Rejected rather than stored: a portless service
                            // renders an invalid firewall rule, and nft failing
                            // means nothing gets restricted.
                            return Err(AppError::bad_request(format!(
                                "service {name} requires at least one port"
                            )));
                        }
                        let description = service
                            .get("description")
                            .and_then(|d| d.as_str())
                            .map(|s| s.to_string());
                        sqlx::query(
                            r#"
                            INSERT INTO network_services
                                (network_id, name, destination, protocol, ports, description)
                            VALUES ($1, $2, $3::cidr, $4, $5, $6)
                            ON CONFLICT (network_id, name) DO UPDATE SET
                              destination = EXCLUDED.destination,
                              protocol = EXCLUDED.protocol,
                              ports = EXCLUDED.ports,
                              description = EXCLUDED.description,
                              updated_at = NOW()
                            "#,
                        )
                        .bind(network_id)
                        .bind(name)
                        .bind(dest)
                        .bind(protocol)
                        .bind(&ports)
                        .bind(description)
                        .execute(&self.state.db)
                        .await?;
                    }
                }

                if let Some(routes) = v.get("routes").and_then(|r| r.as_sequence()) {
                    for route in routes {
                        if let Some(dest) = route.get("destination").and_then(|d| d.as_str()) {
                            let desc = route
                                .get("description")
                                .and_then(|d| d.as_str())
                                .map(|s| s.to_string());
                            sqlx::query(
                                r#"
                                INSERT INTO routes (network_id, destination, description)
                                VALUES ($1, $2::cidr, $3)
                                ON CONFLICT (network_id, destination) DO NOTHING
                                "#,
                            )
                            .bind(network_id)
                            .bind(dest)
                            .bind(desc)
                            .execute(&self.state.db)
                            .await?;
                        }
                    }
                }
            }
        }

        let mut applied = 0usize;
        for entry in std::fs::read_dir(&policies_dir).map_err(|e| AppError::Internal(e.into()))? {
            let entry = entry.map_err(|e| AppError::Internal(e.into()))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
                continue;
            }
            let raw = std::fs::read_to_string(&path).map_err(|e| AppError::Internal(e.into()))?;
            self.apply_policy_yaml(&raw, git_commit).await?;
            applied += 1;
            sqlx::query(
                r#"
                INSERT INTO git_revisions (commit_sha, path, status, details)
                VALUES ($1, $2, 'applied', '{}'::jsonb)
                "#,
            )
            .bind(git_commit.unwrap_or("local"))
            .bind(path.display().to_string())
            .execute(&self.state.db)
            .await?;
        }
        Ok(applied)
    }

    pub async fn apply_policy_yaml(
        &self,
        yaml: &str,
        git_commit: Option<&str>,
    ) -> AppResult<PolicyVersion> {
        let doc = parse_policy_yaml(yaml).map_err(|e| AppError::bad_request(e.to_string()))?;
        let document = serde_json::to_value(&doc).map_err(|e| AppError::Internal(e.into()))?;

        let policy_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO policies (name, current_version, git_commit)
            VALUES ($1, 0, $2)
            ON CONFLICT (name) DO UPDATE SET updated_at = NOW()
            RETURNING id
            "#,
        )
        .bind(&doc.metadata.name)
        .bind(git_commit)
        .fetch_one(&self.state.db)
        .await?;

        let version: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions WHERE policy_id = $1",
        )
        .bind(policy_id)
        .fetch_one(&self.state.db)
        .await?;

        let row: (
            Uuid,
            Uuid,
            i64,
            serde_json::Value,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
        ) = sqlx::query_as(
            r#"
                INSERT INTO policy_versions (policy_id, version, document, git_commit)
                VALUES ($1, $2, $3, $4)
                RETURNING id, policy_id, version, document, git_commit, created_at
                "#,
        )
        .bind(policy_id)
        .bind(version)
        .bind(&document)
        .bind(git_commit)
        .fetch_one(&self.state.db)
        .await?;

        sqlx::query(
            "UPDATE policies SET current_version = $2, git_commit = $3, updated_at = NOW() WHERE id = $1",
        )
        .bind(policy_id)
        .bind(version)
        .bind(git_commit)
        .execute(&self.state.db)
        .await?;

        Ok(PolicyVersion {
            id: row.0,
            policy_id: row.1,
            version: row.2,
            document: row.3,
            git_commit: row.4,
            created_at: row.5,
        })
    }

    pub async fn list_policies(&self) -> AppResult<Vec<Policy>> {
        let rows: Vec<(
            Uuid,
            String,
            i64,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            "SELECT id, name, current_version, git_commit, created_at, updated_at FROM policies ORDER BY name",
        )
        .fetch_all(&self.state.db)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Policy {
                id: r.0,
                name: r.1,
                current_version: r.2,
                git_commit: r.3,
                created_at: r.4,
                updated_at: r.5,
            })
            .collect())
    }
}
