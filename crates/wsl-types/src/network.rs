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

/// A non-HTTP service reachable from the overlay: a database, SSH host, cache.
///
/// The proxy never sees this traffic, so it is restricted at the gateway rather
/// than by proxy rules.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NetworkService {
    pub id: Uuid,
    pub network_id: Uuid,
    pub name: String,
    pub destination: String,
    pub protocol: ServiceProtocol,
    pub ports: Vec<i32>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ServiceProtocol {
    Tcp,
    Udp,
}

impl ServiceProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceProtocol::Tcp => "tcp",
            ServiceProtocol::Udp => "udp",
        }
    }
}

impl std::str::FromStr for ServiceProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(ServiceProtocol::Tcp),
            "udp" => Ok(ServiceProtocol::Udp),
            other => Err(format!("unknown protocol: {other}")),
        }
    }
}

/// A service as delivered to the gateway, flattened for firewall rendering.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GatewayService {
    pub name: String,
    pub destination: String,
    pub protocol: ServiceProtocol,
    pub ports: Vec<u16>,
}
