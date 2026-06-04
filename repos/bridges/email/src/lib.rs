//! Jig email bridge — in-process `Bridge` implementation.
//!
//! Migrated from a standalone SMTP daemon to a library loaded in-process by
//! jig-server. Subsequent tasks add the provider/identity/address_book/
//! resend/channel/outbound/inbound/bridge modules.

pub mod config;

pub use config::EmailBridgeConfig;
