use crate::error::{AppError, AppResult};
use crate::state::{hash_token, AppState};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
use wsl_types::{
    Gateway, GatewayConfig, GatewayHeartbeatRequest, GatewayPeer, GatewayService as ServiceEntry,
    RegisterGatewayRequest, ServiceProtocol,
};

pub struct GatewayService {
    state: AppState,
}

impl GatewayService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn list(&self) -> AppResult<Vec<Gateway>> {
        let rows: Vec<(
            Uuid,
            String,
            String,
            String,
            Option<Uuid>,
            Option<DateTime<Utc>>,
            i64,
            DateTime<Utc>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            r#"
            SELECT id, name, public_key, endpoint, network_id, last_heartbeat_at,
                   config_version, created_at, updated_at
            FROM gateways ORDER BY name
            "#,
        )
        .fetch_all(&self.state.db)
        .await?;
        Ok(rows.into_iter().map(map_gw).collect())
    }

    pub async fn get(&self, id: Uuid) -> AppResult<Option<Gateway>> {
        let row: Option<(
            Uuid,
            String,
            String,
            String,
            Option<Uuid>,
            Option<DateTime<Utc>>,
            i64,
            DateTime<Utc>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            r#"
            SELECT id, name, public_key, endpoint, network_id, last_heartbeat_at,
                   config_version, created_at, updated_at
            FROM gateways WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.state.db)
        .await?;
        Ok(row.map(map_gw))
    }

    pub async fn register(&self, req: RegisterGatewayRequest) -> AppResult<Gateway> {
        let expected = hash_token(&self.state.config.bootstrap.gateway_registration_token);
        if hash_token(&req.token) != expected {
            return Err(AppError::Unauthorized);
        }
        let token_hash = hash_token(&req.token);
        let mut network_id = req.network_id;
        if network_id.is_none() {
            network_id = sqlx::query_scalar("SELECT id FROM networks WHERE name = 'development'")
                .fetch_optional(&self.state.db)
                .await?;
        }
        let row: (
            Uuid,
            String,
            String,
            String,
            Option<Uuid>,
            Option<DateTime<Utc>>,
            i64,
            DateTime<Utc>,
            DateTime<Utc>,
        ) = sqlx::query_as(
            r#"
            INSERT INTO gateways (name, public_key, endpoint, network_id, registration_token_hash)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (name) DO UPDATE SET
              public_key = EXCLUDED.public_key,
              endpoint = EXCLUDED.endpoint,
              network_id = COALESCE(EXCLUDED.network_id, gateways.network_id),
              updated_at = NOW()
            RETURNING id, name, public_key, endpoint, network_id, last_heartbeat_at,
                      config_version, created_at, updated_at
            "#,
        )
        .bind(&req.name)
        .bind(&req.public_key)
        .bind(&req.endpoint)
        .bind(network_id)
        .bind(&token_hash)
        .fetch_one(&self.state.db)
        .await?;
        Ok(map_gw(row))
    }

    pub async fn heartbeat(
        &self,
        id: Uuid,
        req: GatewayHeartbeatRequest,
    ) -> AppResult<GatewayConfig> {
        sqlx::query(
            "UPDATE gateways SET last_heartbeat_at = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&self.state.db)
        .await?;
        metrics::gauge!("wsl_gateway_health").set(if req.healthy { 1.0 } else { 0.0 });
        metrics::gauge!("wsl_gateway_peers").set(req.peer_count as f64);
        self.config(id).await
    }

    pub async fn config(&self, id: Uuid) -> AppResult<GatewayConfig> {
        let gw = self.get(id).await?.ok_or(AppError::NotFound)?;
        let network_id = gw
            .network_id
            .ok_or_else(|| AppError::bad_request("gateway has no network_id; assign a network"))?;
        let cidr: String = sqlx::query_scalar("SELECT cidr::text FROM networks WHERE id = $1")
            .bind(network_id)
            .fetch_one(&self.state.db)
            .await?;

        // Expire stale sessions
        sqlx::query(
            r#"
            UPDATE sessions SET status = 'expired'
            WHERE gateway_id = $1 AND status = 'active' AND expires_at < NOW()
            "#,
        )
        .bind(id)
        .execute(&self.state.db)
        .await?;
        sqlx::query("DELETE FROM wireguard_peers WHERE gateway_id = $1 AND expires_at < NOW()")
            .bind(id)
            .execute(&self.state.db)
            .await?;

        let peer_rows: Vec<(Uuid, String, Vec<ipnetwork::IpNetwork>, Uuid, DateTime<Utc>)> =
            sqlx::query_as(
                r#"
                SELECT p.id, p.public_key, p.allowed_ips, p.session_id, p.expires_at
                FROM wireguard_peers p
                JOIN sessions s ON s.id = p.session_id
                WHERE p.gateway_id = $1 AND s.status = 'active' AND p.expires_at > NOW()
                "#,
            )
            .bind(id)
            .fetch_all(&self.state.db)
            .await?;

        let peers: Vec<GatewayPeer> = peer_rows
            .into_iter()
            .map(|r| GatewayPeer {
                peer_id: r.0,
                public_key: r.1,
                allowed_ips: r.2.iter().map(|a| a.to_string()).collect(),
                session_id: r.3,
                expires_at: r.4,
            })
            .collect();

        let routes: Vec<(ipnetwork::IpNetwork,)> =
            sqlx::query_as("SELECT destination FROM routes WHERE network_id = $1")
                .bind(network_id)
                .fetch_all(&self.state.db)
                .await?;

        let service_rows: Vec<(String, ipnetwork::IpNetwork, String, Vec<i32>)> = sqlx::query_as(
            r#"
            SELECT name, destination, protocol, ports
            FROM network_services WHERE network_id = $1 ORDER BY name
            "#,
        )
        .bind(network_id)
        .fetch_all(&self.state.db)
        .await?;

        let services: Vec<ServiceEntry> = service_rows
            .into_iter()
            .filter_map(|(name, destination, protocol, ports)| {
                // A row the gateway cannot render is dropped rather than sent:
                // an invalid rule makes nft reject the whole ruleset, which
                // would leave every other service unrestricted.
                let protocol = protocol.parse::<ServiceProtocol>().ok()?;
                let ports: Vec<u16> = ports
                    .into_iter()
                    .filter_map(|p| u16::try_from(p).ok())
                    .collect();
                if ports.is_empty() {
                    tracing::warn!(service = %name, "skipping service with no valid ports");
                    return None;
                }
                Some(ServiceEntry {
                    name,
                    destination: destination.to_string(),
                    protocol,
                    ports,
                })
            })
            .collect();

        Ok(GatewayConfig {
            version: gw.config_version,
            expires_at: Utc::now() + Duration::minutes(5),
            listen_port: self.state.config.wireguard.default_port,
            private_network_cidr: cidr,
            peers,
            routes: routes.into_iter().map(|r| r.0.to_string()).collect(),
            services,
        })
    }
}

fn map_gw(
    row: (
        Uuid,
        String,
        String,
        String,
        Option<Uuid>,
        Option<DateTime<Utc>>,
        i64,
        DateTime<Utc>,
        DateTime<Utc>,
    ),
) -> Gateway {
    Gateway {
        id: row.0,
        name: row.1,
        public_key: row.2,
        endpoint: row.3,
        network_id: row.4,
        last_heartbeat_at: row.5,
        config_version: row.6,
        created_at: row.7,
        updated_at: row.8,
    }
}
