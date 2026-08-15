use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Network {
    pub id: Uuid,
    pub name: String,
    pub cidr: String,
    pub dns_servers: Vec<String>,
    pub dns_domains: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateNetworkRequest {
    pub name: String,
    pub cidr: String,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub dns_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Route {
    pub id: Uuid,
    pub network_id: Uuid,
    pub destination: String,
    pub description: Option<String>,
}
