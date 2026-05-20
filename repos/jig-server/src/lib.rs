//! Jig Server crate entry point.

pub mod analytics;
pub mod capability;
pub mod config;
pub mod error;
pub mod handler;
pub mod runtime;
pub mod server;
pub mod storage;
pub mod v0_0_2;
pub mod v0_0_2_admin;
pub mod v0_0_2_ws;

pub use config::ServerConfig;
pub use error::{Result, ServerError};
pub use runtime::{BlockRuntime, ExecutionConfig};
pub use server::JigServer;
pub use storage::{
    SqliteBlockStore, StoredBlock, StoredBlockSummary, StoredReceipt, StoredResource,
    encode_resource_data,
};

#[cfg(feature = "telemetry_v0_2")]
pub mod telemetry;

#[cfg(feature = "telemetry_v0_2")]
pub use telemetry::{Percentiles, TimingsRecorder, TimingsSnapshot};

pub use analytics::{ReceiptStats, TimeRange, receipt_stats_for_range};
