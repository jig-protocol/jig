//! 1:1 channel-slug derivation for restricted-mode email conversations.
//!
//! The slug is a hash of the sorted DID pair, so it's identical regardless of
//! which DID is "sender" — inbound and outbound both resolve to one channel.
//!
//! Mail threads live under [`THREAD_PREFIX`], not `#dm/`: that prefix is
//! reserved for encrypted direct messages between the two DIDs that derive
//! the slug, and the server refuses any other `#dm/` create.

use sha2::{Digest, Sha256};

/// The prefix of every mail-thread channel the bridge opens.
pub const THREAD_PREFIX: &str = "#email/";

/// Deterministic mail-thread channel slug for a DID pair (order-independent).
pub fn thread_slug(did_a: &str, did_b: &str) -> String {
    let mut pair = [did_a, did_b];
    pair.sort_unstable();
    let mut h = Sha256::new();
    h.update(pair[0].as_bytes());
    h.update(b"|");
    h.update(pair[1].as_bytes());
    let digest = h.finalize();
    format!("{THREAD_PREFIX}{}", hex::encode(&digest[..8]))
}

use jig_bridge_core::{SubmitDenied, SubmitHandle};
use jig_client::Identity;
use jig_client::blocks::{BuiltBlock, build_member_add, build_with_metadata};

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

/// Ensure the 1:1 thread channel `slug` exists with both members, creating it on
/// first contact.
///
/// A thread is a restricted channel, and restricted channels are always MLS
/// (ROADMAP D25). The bridge is not an MLS member yet, so a server enforcing
/// D25 refuses the plaintext create, and inbound mail fails here rather than
/// landing in a channel its operator could read. The thread stays restricted:
/// an open one would let every admitted user read the mail. Idempotent via a BridgeStorage marker so repeat inbound mail
/// on an existing conversation doesn't re-create the channel. `creator` is the
/// bridge's shadow identity (it authors the channel-create — which auto-adds it
/// as owner — and the member-add for the real recipient DID).
pub(crate) async fn ensure_thread_channel(
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
    // In-process, so no `sequencer`: the block reaches this server only.
    let cc = build_with_metadata(
        creator,
        jig_core::BlockKind::ChannelCreate,
        hlc,
        serde_json::json!({"slug": slug, "visibility": "restricted"}),
    );
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
            thread_slug("did:jig:zA", "did:jig:zB"),
            thread_slug("did:jig:zB", "did:jig:zA")
        );
    }

    #[test]
    fn distinct_pairs_distinct_slugs() {
        assert_ne!(
            thread_slug("did:jig:zA", "did:jig:zB"),
            thread_slug("did:jig:zA", "did:jig:zC")
        );
    }

    #[test]
    fn slug_is_a_thread_and_never_a_dm() {
        let slug = thread_slug("did:jig:zA", "did:jig:zB");
        assert!(slug.starts_with(THREAD_PREFIX));
        assert!(!slug.starts_with(jig_core::dm::DM_PREFIX));
    }

    /// The server's slug grammar admits exactly what this function makes:
    /// an `#email/` thread, which it lets only the bridge create.
    #[test]
    fn a_thread_slug_is_in_the_servers_email_class() {
        for (a, b) in [
            ("did:jig:zA", "did:jig:zB"),
            ("did:jig:zbob", "did:jig:zalice"),
        ] {
            let slug = thread_slug(a, b);
            assert_eq!(
                jig_core::slug::classify_slug(&slug),
                Ok(jig_core::slug::SlugClass::Email),
                "{slug}"
            );
        }
        assert_eq!(THREAD_PREFIX, jig_core::slug::EMAIL_PREFIX);
    }
}
