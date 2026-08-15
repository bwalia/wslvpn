use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Gateway {
    pub id: Uuid,
    pub name: String,
    pub public_key: String,
    pub endpoint: String,
    pub network_id: Option<Uuid>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub config_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterGatewayRequest {
    pub name: String,
    pub public_key: String,
    pub endpoint: String,
    pub network_id: Option<Uuid>,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GatewayConfig {
    pub version: i64,
    pub expires_at: DateTime<Utc>,
    pub listen_port: u16,
    pub private_network_cidr: String,
    pub peers: Vec<GatewayPeer>,
    pub routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GatewayPeer {
    pub peer_id: Uuid,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub session_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GatewayHeartbeatRequest {
    pub config_version: i64,
    pub peer_count: i32,
    pub healthy: bool,
}
