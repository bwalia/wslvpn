//! WSL endpoint agent library (shared with CLI).

pub mod client;
pub mod dns;
pub mod oidc;
pub mod posture;
pub mod profile;
pub mod state;
pub mod tunnel;

pub use client::ControlClient;
pub use state::{AgentState, AgentStatus, Mode};
pub use tunnel::{Escalation, TunnelState};
pub use wsl_types::{PostureResult, PostureSignal};
