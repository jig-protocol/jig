//! Common Bridge trait + context types for jig-protocol bridges.
//!
//! Every bridge (email, slack, irc, ssh, matrix, ...) implements [`Bridge`].
//! Server constructs a [`BridgeContext`] containing handles to submit blocks
//! and subscribe to channels, then calls [`Bridge::start`] once at boot. The
//! bridge owns its external listener loop (SMTP server, websocket, ...) and
//! uses `ctx.submit` to push inbound-translated blocks to ingest.
//!
//! Server controls policy: it decides which bridges load, applies rate limits,
//! and may deny individual submissions via [`SubmitDenied`].

pub mod bridge;
pub mod context;

// Re-exports added incrementally as Tasks A2-A4 populate the modules:
// - Task A2: pub use context::SubmitDenied;
// - Task A3: pub use context::{BridgeContext, SubmitHandle, SubscribeHandle};
// - Task A4: pub use bridge::Bridge;
