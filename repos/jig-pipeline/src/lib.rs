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

pub mod effect;
pub mod envelope;
pub mod fanout;
pub mod hlc;
pub mod identity;
pub mod ingest;
pub mod persist;

pub use envelope::{Envelope, Frame, HlcCursor, ReceiptRef, Scope};
