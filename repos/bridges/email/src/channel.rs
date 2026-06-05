//! 1:1 channel-slug derivation for restricted-mode email conversations.
//!
//! The slug is a hash of the sorted DID pair, so it's identical regardless of
//! which DID is "sender" — inbound and outbound both resolve to one channel.

use sha2::{Digest, Sha256};

/// Deterministic DM channel slug for a DID pair (order-independent).
pub fn dm_channel_slug(did_a: &str, did_b: &str) -> String {
    let mut pair = [did_a, did_b];
    pair.sort_unstable();
    let mut h = Sha256::new();
    h.update(pair[0].as_bytes());
    h.update(b"|");
    h.update(pair[1].as_bytes());
    let digest = h.finalize();
    format!("#dm/{}", hex::encode(&digest[..8]))
}

use jig_bridge_core::{SubmitDenied, SubmitHandle};
use jig_client::Identity;
use jig_client::blocks::{BuiltBlock, build_channel_create, build_member_add};

const ENSURED_NS: &str = "channel-ensured";

/// Package a built block as the bridge submit payload and submit it.
pub(crate) async fn submit_built_block(
    submit: &SubmitHandle,
    block: BuiltBlock,
) -> Result<String, SubmitDenied> {
    let payload = serde_json::to_vec(&(block.manifest_bytes, block.code_bytes, block.sender_sig))
        .expect("serializing a (Vec<u8>, Vec<u8>, Vec<u8>) tuple cannot fail");
    submit.submit(payload).await
}

/// Ensure the 1:1 DM channel `slug` exists with both members, creating it on
/// first contact. Idempotent via a BridgeStorage marker so repeat inbound mail
/// on an existing conversation doesn't re-create the channel. `creator` is the
/// bridge's shadow identity (it authors the channel-create — which auto-adds it
/// as owner — and the member-add for the real recipient DID).
pub(crate) async fn ensure_dm_channel(
    submit: &SubmitHandle,
    storage: &dyn jig_bridge_core::BridgeStorage,
    creator: &Identity,
    other_member_did: &str,
    slug: &str,
) -> anyhow::Result<()> {
    if storage.get(ENSURED_NS, slug).await?.is_some() {
        return Ok(());
    }
    let hlc = jig_core::HlcTimestamp::now_wall(creator.did().clone());
    let cc = build_channel_create(creator, slug, "restricted", hlc);
    // FIXME(alpha): partial-ensure window — if channel-create succeeds but the
    // member-add below is denied, the marker is never written, so the next
    // inbound re-submits channel-create and creates a duplicate channel row
    // (same slug, new CID). Narrow (needs a mid-sequence denial). A per-step
    // marker (or a channel-create idempotency-by-slug at the effect layer) is
    // the real fix; deferred past restricted-mode alpha.
    submit_built_block(submit, cc)
        .await
        .map_err(|d| anyhow::anyhow!("channel-create denied: {d}"))?;

    let hlc2 = jig_core::HlcTimestamp::now_wall(creator.did().clone());
    let ma = build_member_add(creator, slug, other_member_did, hlc2);
    submit_built_block(submit, ma)
        .await
        .map_err(|d| anyhow::anyhow!("member-add denied: {d}"))?;

    storage.put(ENSURED_NS, slug, b"1", None).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_is_order_independent() {
        assert_eq!(
            dm_channel_slug("did:jig:zA", "did:jig:zB"),
            dm_channel_slug("did:jig:zB", "did:jig:zA")
        );
    }

    #[test]
    fn distinct_pairs_distinct_slugs() {
        assert_ne!(
            dm_channel_slug("did:jig:zA", "did:jig:zB"),
            dm_channel_slug("did:jig:zA", "did:jig:zC")
        );
    }

    #[test]
    fn slug_has_dm_prefix() {
        assert!(dm_channel_slug("did:jig:zA", "did:jig:zB").starts_with("#dm/"));
    }
}
