//! The [`Bridge`] trait — the contract every jig-protocol bridge implements.

use anyhow::Result;
use async_trait::async_trait;

use crate::context::BridgeContext;

/// A delivered block routed to the bridge for outbound emission.
///
/// Mirrors `jig_client::connection::DeliveredBlock` but is re-declared here
/// to avoid pulling jig-client into the bridge dependency graph (bridges are
/// server-side; the client is a separate consumer).
#[derive(Debug, Clone)]
pub struct DeliveredBlock {
    /// Base64-encoded canonical bundle bytes (matches the WSS Block frame format).
    pub bundle_b64: String,
    /// Receipt references attached to this delivery.
    pub receipts: Vec<ReceiptRef>,
    /// Delivery CID assigned by the server's fanout layer.
    pub delivery_cid: String,
}

/// Lightweight receipt reference for bridge consumption. Mirrors
/// `jig_pipeline::envelope::ReceiptRef` minus pipeline-internal fields.
#[derive(Debug, Clone)]
pub struct ReceiptRef {
    pub receipt_cid: String,
    pub render_hash: Option<String>,
    pub produced_at: i64,
}

/// What every jig-protocol bridge implements.
///
/// Lifecycle:
/// 1. Server reads `[bridges]` policy from config. If the bridge is not
///    allowlisted or has `[bridge.<name>] enabled = false`, server skips
///    construction entirely.
/// 2. For permitted bridges, server constructs the bridge instance and calls
///    [`Bridge::start`] with a [`BridgeContext`] containing the submit/
///    subscribe handles + the bridge's config slice.
/// 3. Bridge spawns its own listener tasks (SMTP server, websocket, etc.)
///    and uses `ctx.submit` to push inbound-translated blocks. Server may
///    deny via [`crate::SubmitDenied`]; bridge MUST translate the denial back
///    to its transport (SMTP 5xx, IRC error, etc.).
/// 4. When a block is delivered to a bridged channel, server calls
///    [`Bridge::outbound`] with the delivered block; bridge translates
///    and emits via its transport.
/// 5. On shutdown, server calls [`Bridge::shutdown`]; bridge flushes
///    in-flight messages and closes transports cleanly.
#[async_trait]
pub trait Bridge: Send + Sync {
    /// Stable bridge identifier ("email", "slack", "irc"). Maps to
    /// `[bridge.<name>]` config and `jig bridge <name> <verb>` CLI.
    fn name(&self) -> &'static str;

    /// Called once at server startup. Bridge spawns its own external
    /// listener tasks here, using `ctx.submit` to push translated blocks.
    /// Returning `Err` aborts bridge startup; server logs and continues
    /// without this bridge.
    async fn start(&mut self, ctx: BridgeContext) -> Result<()>;

    /// Called by server when a delivered block on a bridged channel should
    /// emit externally. Returning `Err` logs but does not crash the server.
    async fn outbound(&self, block: &DeliveredBlock) -> Result<()>;

    /// Called by server during shutdown. Bridge should flush in-flight
    /// state and close transports. Returning `Err` is logged but doesn't
    /// block shutdown.
    async fn shutdown(&mut self) -> Result<()>;
}
