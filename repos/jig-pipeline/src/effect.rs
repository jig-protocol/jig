//! Apply-effect dispatch by block kind.
//!
//! v0.0.2 minimal surface: B6's ingest pipeline calls this; full per-kind
//! dispatch logic (channel-create, member-add, fed-hello, ns-*) lands
//! in Task B7.

use crate::persist::SqliteStore;
use jig_core::BlockBundle;
use std::sync::Arc;

/// Apply the side-effects of a block to the derived state tables
/// (channels, memberships, peers, alias_attestations). v0.0.2 B6 stub
/// is a no-op; B7 implements the per-block-kind dispatch.
pub async fn apply_effect(
    _store: &Arc<SqliteStore>,
    _bundle: &BlockBundle<'_>,
    _receipt_bytes: &[u8],
    _block_cid: &str,
) -> anyhow::Result<()> {
    // v0.0.2 stub. B7 implements actual effect application.
    Ok(())
}
