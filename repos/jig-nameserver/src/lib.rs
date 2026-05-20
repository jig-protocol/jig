//! Jig Nameserver: provides distributed identity verification and localized anonymity.

pub mod analytics;
pub mod anomaly;
pub mod config;
pub mod crypto;
pub mod error;
pub mod federation;
pub mod hot;
pub mod identity;
pub mod pow;
pub mod runtime;
pub mod server;
pub mod storage;
pub mod transparency;
pub mod types;

pub use config::NameServerConfig;
pub use error::{NameServerError, Result};
