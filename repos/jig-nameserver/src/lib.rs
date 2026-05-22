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
pub mod v0_0_2;
pub mod v0_0_2_handles;
pub mod v0_0_2_register;
pub mod v0_0_2_resolve;
pub mod v0_0_2_rotate_renew;

pub use config::NameServerConfig;
pub use error::{NameServerError, Result};
