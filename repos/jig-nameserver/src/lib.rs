//! Jig Nameserver: provides distributed identity verification and localized anonymity.

pub mod config;
pub mod error;
pub mod server;
pub mod v0_0_2;
pub mod v0_0_2_handles;
pub mod v0_0_2_metrics;
pub mod v0_0_2_policy;
pub mod v0_0_2_pow_policy;
#[cfg(test)]
mod v0_0_2_pow_tests;
pub mod v0_0_2_rate_limit;
pub mod v0_0_2_register;
pub mod v0_0_2_resolve;
pub mod v0_0_2_rotate_renew;
#[cfg(test)]
mod v0_0_2_suffix_tests;

pub use config::NameServerConfig;
pub use error::{NameServerError, Result};
