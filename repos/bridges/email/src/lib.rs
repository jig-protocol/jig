//! Jig email bridge — in-process `Bridge` implementation.

/// Max inline message size the bridge will translate in either direction
/// (25 MB). Larger payloads are dropped (outbound) or rejected with 413
/// (inbound); attachment/large-payload handling is a later iteration. Shared by
/// `inbound` and `outbound` so the two directions never drift.
pub(crate) const MAX_INLINE_BYTES: usize = 25 * 1024 * 1024;

/// BridgeStorage namespace for the `channel-slug -> external-sender-email` map.
/// Written by the inbound handler, read by `outbound()` — a shared const so the
/// two sides of this string-keyed seam can never silently drift apart.
pub(crate) const CHANNEL_EMAIL_NS: &str = "channel-email";

pub mod address_book;
pub mod bridge;
pub mod channel;
pub mod config;
pub mod identity;
pub mod inbound;
pub mod outbound;
pub mod provider;
pub mod resend;

pub use address_book::{AddressBook, Resolution};
pub use bridge::EmailBridge;
pub use channel::dm_channel_slug;
pub use config::EmailBridgeConfig;
pub use identity::{normalize_email, shadow_did, shadow_signing_key};
pub use inbound::{InboundState, handle_inbound};
pub use outbound::block_to_outbound_email;
pub use provider::{
    EmailProvider, InboundEmail, InboundNotification, OutboundEmail, ProviderMessageId,
};
pub use resend::ResendProvider;
