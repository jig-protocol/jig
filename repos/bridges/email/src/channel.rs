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
