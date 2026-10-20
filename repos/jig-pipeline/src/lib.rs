//! Shared block ingest/effect/persist pipeline.
//!
//! Consumed by `jig-server` and `jig-nameserver`. The library exposes the
//! transport-agnostic WSS envelope codec (see [`envelope`]), the HLC clock
//! ([`hlc`]), the identity resolver ([`identity`]), and the unified
//! `ingest()` entry point that flows blocks through validation → execution
//! → effect application → persistence → fanout.
//!
//! Modules are stubbed in this initial commit; subsequent Phase B tasks
//! (B3 through B8) populate them.

pub mod authorize_write;
pub mod effect;
pub mod envelope;
#[cfg(feature = "executor")]
pub mod executor;
/// Built without the `executor` feature: the pipeline cannot run blocks, and links no Wasm
/// engine. Such a build never constructs an `IngestContext` with an executor, so every block that
/// must execute is refused with [`IngestError::NoExecutor`].
#[cfg(not(feature = "executor"))]
pub mod executor {
    /// No value of this type exists without the `executor` feature.
    #[derive(Debug)]
    pub enum BlockExecutor {}
}
pub mod fanout;
pub mod handshake;
pub mod hlc;
pub mod identity;
pub mod ingest;
pub mod ingest_record;
pub mod metrics;
pub mod mls_gate;
pub mod persist;
pub mod receipts;
pub mod roles;
pub mod server_manifest;
pub mod visibility;

pub use effect::apply_effect;
pub use envelope::{Envelope, Frame, HlcCursor, ReceiptRef, Scope};
pub use fanout::{Fanout, SubscriptionScope};
pub use ingest::{IngestContext, IngestError, IngestSource, ingest};
