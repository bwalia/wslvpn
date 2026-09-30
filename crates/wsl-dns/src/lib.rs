//! A tiny local DNS resolver.
//!
//! It answers names from a hosts-style override table and forwards everything
//! else to the real resolver, so a user can pin `intranet.example.com` to an
//! address the ISP's DNS would never return — the way `/etc/hosts` does, but
//! with wildcards, with IPv6 handled properly, and editable without root.
//!
//! * [`hosts`] parses and edits the table.
//! * [`wire`] reads queries and writes answers.
//! * [`server`] serves UDP and TCP on loopback and forwards the rest.
//! * [`resolver`] routes the overridden domains to it through `/etc/resolver`.

pub mod hosts;
pub mod resolver;
pub mod server;
pub mod wire;

pub use hosts::{Entry, Overrides};
pub use server::{Config, Server, Upstreams};

/// Where the resolver listens unless told otherwise. Loopback only, and below
/// the ephemeral range so an outgoing connection never takes it first.
pub const DEFAULT_PORT: u16 = 15353;
