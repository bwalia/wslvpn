use crate::error::AppResult;
use crate::state::AppState;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use wsl_types::{CreateNetworkRequest, Network};

pub struct NetworkService {
    state: AppState,
}

impl NetworkService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn list(&self) -> AppResult<Vec<Network>> {
        let rows: Vec<(
            Uuid,
            String,
            ipnetwork::IpNetwork,
            Vec<String>,
            Vec<String>,
            DateTime<Utc>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT id, name, cidr, dns_servers, dns_domains, created_at, updated_at FROM networks ORDER BY name",
        )
        .fetch_all(&self.state.db)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Network {
                id: r.0,
                name: r.1,
                cidr: r.2.to_string(),
                dns_servers: r.3,
                dns_domains: r.4,
                created_at: r.5,
                updated_at: r.6,
            })
            .collect())
    }

    pub async fn get(&self, id: Uuid) -> AppResult<Option<Network>> {
        let row: Option<(
            Uuid,
            String,
            ipnetwork::IpNetwork,
            Vec<String>,
            Vec<String>,
            DateTime<Utc>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT id, name, cidr, dns_servers, dns_domains, created_at, updated_at FROM networks WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.state.db)
        .await?;
        Ok(row.map(|r| Network {
            id: r.0,
            name: r.1,
            cidr: r.2.to_string(),
            dns_servers: r.3,
            dns_domains: r.4,
            created_at: r.5,
            updated_at: r.6,
        }))
    }

    pub async fn get_by_name(&self, name: &str) -> AppResult<Option<Network>> {
        let row: Option<(
            Uuid,
            String,
            ipnetwork::IpNetwork,
            Vec<String>,
            Vec<String>,
            DateTime<Utc>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT id, name, cidr, dns_servers, dns_domains, created_at, updated_at FROM networks WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(&self.state.db)
        .await?;
        Ok(row.map(|r| Network {
            id: r.0,
            name: r.1,
            cidr: r.2.to_string(),
            dns_servers: r.3,
            dns_domains: r.4,
            created_at: r.5,
            updated_at: r.6,
        }))
    }

    pub async fn create(&self, req: CreateNetworkRequest) -> AppResult<Network> {
        let row: (
            Uuid,
            String,
            ipnetwork::IpNetwork,
            Vec<String>,
            Vec<String>,
            DateTime<Utc>,
            DateTime<Utc>,
        ) = sqlx::query_as(
            r#"
            INSERT INTO networks (name, cidr, dns_servers, dns_domains)
            VALUES ($1, $2::cidr, $3, $4)
            RETURNING id, name, cidr, dns_servers, dns_domains, created_at, updated_at
            "#,
        )
        .bind(&req.name)
        .bind(&req.cidr)
        .bind(&req.dns_servers)
        .bind(&req.dns_domains)
        .fetch_one(&self.state.db)
        .await?;
        Ok(Network {
            id: row.0,
            name: row.1,
            cidr: row.2.to_string(),
            dns_servers: row.3,
            dns_domains: row.4,
            created_at: row.5,
            updated_at: row.6,
        })
    }

    pub async fn routes_for(&self, network_id: Uuid) -> AppResult<Vec<String>> {
        let rows: Vec<(ipnetwork::IpNetwork,)> =
            sqlx::query_as("SELECT destination FROM routes WHERE network_id = $1")
                .bind(network_id)
                .fetch_all(&self.state.db)
                .await?;
        Ok(rows.into_iter().map(|r| r.0.to_string()).collect())
    }
}
