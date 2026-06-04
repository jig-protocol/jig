//! Jig email bridge — in-process `Bridge` implementation.

pub mod config;
pub mod identity;
pub mod provider;

pub use config::EmailBridgeConfig;
pub use identity::{normalize_email, shadow_did, shadow_signing_key};
pub use provider::{EmailProvider, InboundEmail, OutboundEmail, ProviderMessageId};
