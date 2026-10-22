//! Jig Server crate entry point.

pub mod auth;
pub mod config;
pub mod error;
pub mod handler;
pub mod runtime;
pub mod server;
pub mod v0_0_2;
pub mod v0_0_2_admin;
pub mod v0_0_2_admission;
pub mod v0_0_2_blocks;
pub mod v0_0_2_bridge_storage;
pub mod v0_0_2_bridges;
pub mod v0_0_2_federation;
pub mod v0_0_2_federation_tls;
pub mod v0_0_2_ingest_error;
pub mod v0_0_2_manifest_log;
pub mod v0_0_2_mls;
pub mod v0_0_2_nameserver_tls;
pub mod v0_0_2_peer;
pub mod v0_0_2_ws;

pub use config::ServerConfig;
pub use error::{Result, ServerError};
pub use runtime::ExecutionConfig;
pub use server::JigServer;
