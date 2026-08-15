use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub gateway_id: Uuid,
    pub network_id: Uuid,
    pub policy_id: Option<Uuid>,
    pub policy_version: Option<i64>,
    pub assigned_ip: String,
    pub status: SessionStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateSessionRequest {
    pub network_id: Uuid,
    pub device_id: Uuid,
    #[serde(default)]
    pub posture: Vec<crate::device::PostureSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateSessionResponse {
    pub session: Session,
    pub decision: crate::policy::PolicyDecision,
    pub wireguard: ClientWireGuardConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClientWireGuardConfig {
    pub interface_address: String,
    pub dns: Vec<String>,
    pub peer_public_key: String,
    pub peer_endpoint: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u16,
}
