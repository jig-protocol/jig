//! Direct-message channel slugs.
//!
//! A DM is an ordinary restricted, encrypted channel whose slug is derived
//! from the two DIDs, so either side lands in the same channel. The server
//! lets only one of the pair create a slug under [`DM_PREFIX`], so nobody else
//! can take a pair's slug first (`jig-pipeline`'s MLS gate).

use crate::crypto::hash_labeled_parts;

/// Every DM slug starts with this; no other channel may.
pub const DM_PREFIX: &str = "#dm/";

/// `#dm/` plus 16 hex digits of a domain-separated hash of the sorted pair of
/// canonical DIDs.
pub fn dm_slug(a: &str, b: &str) -> String {
    let mut pair = [a, b];
    pair.sort_unstable();
    let digest = hash_labeled_parts(&[
        ("domain", b"jig-dm-v1".as_slice()),
        ("a", pair[0].as_bytes()),
        ("b", pair[1].as_bytes()),
    ]);
    format!("{DM_PREFIX}{}", &digest.to_hex()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn either_side_derives_the_same_slug() {
        let a = "did:jig:zAlice";
        let b = "did:jig:zBob";
        assert_eq!(dm_slug(a, b), dm_slug(b, a));
        assert_ne!(dm_slug(a, b), dm_slug(a, "did:jig:zCarol"));
        assert!(dm_slug(a, b).starts_with(DM_PREFIX));
        assert_eq!(dm_slug(a, b).len(), DM_PREFIX.len() + 16);
    }
}
