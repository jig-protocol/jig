//! Jig Nameserver: provides distributed identity verification and localized anonymity.

pub mod analytics;
pub mod config;
pub mod error;
pub mod federation;
pub mod identity;
pub mod runtime;
pub mod server;
pub mod storage;
pub mod types;
pub mod v0_0_2;
pub mod v0_0_2_handles;
pub mod v0_0_2_rate_limit;
pub mod v0_0_2_register;
pub mod v0_0_2_resolve;
pub mod v0_0_2_rotate_renew;

pub use config::NameServerConfig;
pub use error::{NameServerError, Result};
