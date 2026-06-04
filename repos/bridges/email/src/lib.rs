//! Jig email bridge — in-process `Bridge` implementation.

pub mod address_book;
pub mod channel;
pub mod config;
pub mod identity;
pub mod provider;
pub mod resend;

pub use address_book::{AddressBook, Resolution};
pub use channel::dm_channel_slug;
pub use config::EmailBridgeConfig;
pub use identity::{normalize_email, shadow_did, shadow_signing_key};
pub use provider::{EmailProvider, InboundEmail, OutboundEmail, ProviderMessageId};
pub use resend::ResendProvider;
