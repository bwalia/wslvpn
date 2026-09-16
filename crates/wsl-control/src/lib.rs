// sqlx `query_as` rows are positional tuples; naming each one would add a
// type per query without making any of them clearer.
#![allow(clippy::type_complexity)]

//! WSL Zero Trust VPN control plane.
//!
//! Exposed as a library as well as a binary so the HTTP surface can be
//! exercised end to end from integration tests — the authorization rules on
//! these routes are only meaningful if something actually asserts them.

pub mod auth;
pub mod config;
pub mod error;
pub mod middleware;
pub mod openapi;
pub mod routes;
pub mod services;
pub mod state;
