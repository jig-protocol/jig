//! Jig email bridge — in-process `Bridge` implementation.

pub mod config;
pub mod provider;

pub use config::EmailBridgeConfig;
pub use provider::{EmailProvider, InboundEmail, OutboundEmail, ProviderMessageId};
