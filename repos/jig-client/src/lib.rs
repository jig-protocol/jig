//! Client library for jig-protocol.
//!
//! Provides connection management, identity loading, and block bundle
//! construction. Consumed by `jig-cli` (Phase C5 refactor) and — in
//! v0.0.3 — by `jig-email-bridge` and `jig-gui/riverdance`. The
//! goal is one shared client implementation so bug fixes propagate
//! to every consumer.

pub mod blocks;
pub mod connection;
pub mod identity;

pub use connection::envelope;
pub use connection::{BlockStream, Client, ClientError, DeliveredBlock};
pub use identity::{Identity, IdentityError};
