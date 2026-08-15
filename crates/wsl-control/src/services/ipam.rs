use crate::error::{AppError, AppResult};
use crate::state::AppState;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use uuid::Uuid;

pub struct IpamService {
    state: AppState,
}

impl IpamService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn allocate(&self, network_id: Uuid, session_id: Uuid) -> AppResult<String> {
        let cidr: IpNetwork = sqlx::query_scalar("SELECT cidr FROM networks WHERE id = $1")
            .bind(network_id)
            .fetch_optional(&self.state.db)
            .await?
            .ok_or_else(|| AppError::NotFound)?;

        let used: Vec<(IpNetwork,)> =
            sqlx::query_as("SELECT address FROM ipam_allocations WHERE network_id = $1")
                .bind(network_id)
                .fetch_all(&self.state.db)
                .await?;
        let used_set: std::collections::HashSet<IpAddr> =
            used.into_iter().map(|a| a.0.ip()).collect();

        for addr in cidr.iter() {
            // Skip network and broadcast for IPv4
            if matches!(addr, IpAddr::V4(v4) if v4.octets()[3] == 0 || v4.octets()[3] == 255) {
                continue;
            }
            // Reserve .1 for gateway
            if matches!(addr, IpAddr::V4(v4) if v4.octets()[3] == 1) {
                continue;
            }
            if used_set.contains(&addr) {
                continue;
            }
            let host =
                IpNetwork::new(addr, 32).map_err(|e| AppError::bad_request(e.to_string()))?;
            sqlx::query(
                r#"
                INSERT INTO ipam_allocations (network_id, address, session_id)
                VALUES ($1, $2, $3)
                "#,
            )
            .bind(network_id)
            .bind(host)
            .bind(session_id)
            .execute(&self.state.db)
            .await?;
            return Ok(format!("{addr}/32"));
        }
        Err(AppError::bad_request("no free IP addresses in network"))
    }

    pub async fn release_session(&self, session_id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM ipam_allocations WHERE session_id = $1")
            .bind(session_id)
            .execute(&self.state.db)
            .await?;
        Ok(())
    }
}
