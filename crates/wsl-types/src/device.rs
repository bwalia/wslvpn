use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PostureResult {
    Pass,
    Fail,
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PostureSignal {
    pub name: String,
    pub result: PostureResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub platform: String,
    pub os_version: Option<String>,
    pub agent_version: Option<String>,
    pub wireguard_public_key: String,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterDeviceRequest {
    pub name: String,
    pub platform: String,
    pub os_version: Option<String>,
    pub agent_version: Option<String>,
    pub wireguard_public_key: String,
    #[serde(default)]
    pub posture: Vec<PostureSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterDeviceResponse {
    pub device: Device,
    pub certificate_pem: String,
    pub expires_at: DateTime<Utc>,
}
