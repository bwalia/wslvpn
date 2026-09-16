use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// What kind of principal caused an event.
///
/// Distinct from the event's *subject*: an administrator disabling someone
/// else's account is an `User` actor with a different `user_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ActorType {
    /// A signed-in person, identified by email.
    User,
    /// A service credential, identified by token name.
    Service,
    /// A gateway acting on its own credential.
    Gateway,
    /// The control plane itself — startup, scheduled sweeps, migrations.
    System,
}

impl ActorType {
    pub fn as_str(self) -> &'static str {
        match self {
            ActorType::User => "user",
            ActorType::Service => "service",
            ActorType::Gateway => "gateway",
            ActorType::System => "system",
        }
    }

    /// An unrecognised value reads as `System` rather than failing the read: an
    /// audit log written by a newer build must stay legible to an older one.
    pub fn from_db(s: &str) -> Self {
        match s {
            "user" => ActorType::User,
            "service" => ActorType::Service,
            "gateway" => ActorType::Gateway,
            _ => ActorType::System,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditEvent {
    pub id: Uuid,
    pub action: String,
    pub decision: Option<String>,
    /// Who caused this.
    pub actor_type: ActorType,
    /// Which one — an email for a person, a token name for a service.
    pub actor_id: Option<String>,
    /// Who or what the event is about.
    pub user_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub resource: Option<String>,
    pub policy_id: Option<Uuid>,
    pub policy_version: Option<i64>,
    pub git_commit: Option<String>,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
    /// Position in the tamper-evident chain.
    pub seq: i64,
    /// Hash over this entry and its predecessor. Altering any earlier entry
    /// invalidates every hash after it.
    pub entry_hash: String,
}
