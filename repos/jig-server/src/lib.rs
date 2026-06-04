//! Jig Server crate entry point.

pub mod capability;
pub mod config;
pub mod error;
pub mod handler;
pub mod runtime;
pub mod server;
pub mod storage;
pub mod v0_0_2;
pub mod v0_0_2_admin;
pub mod v0_0_2_blocks;
pub mod v0_0_2_bridge_storage;
pub mod v0_0_2_bridges;
pub mod v0_0_2_federation;
pub mod v0_0_2_federation_tls;
pub mod v0_0_2_ws;

pub use config::ServerConfig;
pub use error::{Result, ServerError};
pub use runtime::{BlockRuntime, ExecutionConfig};
pub use server::JigServer;
pub use storage::{
    SqliteBlockStore, StoredBlock, StoredBlockSummary, StoredReceipt, StoredResource,
    encode_resource_data,
};
