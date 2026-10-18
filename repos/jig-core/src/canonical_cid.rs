//! The one CID form jig's signed objects carry (JEP-0004 rule 0).
//!
//! A CID inside a deterministic-CBOR payload is a binary **CIDv1** with the **raw** codec
//! (`0x55`) and a **BLAKE3-256** multihash (`0x1e`, 32-byte digest), written as an untagged CBOR
//! byte string. That is how jig computes every CID (`bundle::compute_cid`), and allowing any other
//! form would give one object two encodings. A CIDv0, another codec or another hash is refused,
//! as is a tag-42 or text CID (those are not byte strings, so callers never get here with one).

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

/// Multicodec `raw`.
pub const RAW_CODEC: u64 = 0x55;

/// Multihash code for BLAKE3-256.
pub const BLAKE3_256: u64 = 0x1e;

/// Why bytes are not a canonical CID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CidError {
    #[error("not a binary CID")]
    Malformed,
    #[error("not a CIDv1")]
    NotV1,
    #[error("codec is not raw")]
    NotRaw,
    #[error("multihash is not BLAKE3-256")]
    NotBlake3,
    #[error("the CID does not re-encode to the same bytes")]
    NotCanonical,
}

/// The canonical CID of `bytes`: CIDv1, raw, BLAKE3-256 over the bytes themselves.
pub fn of(bytes: &[u8]) -> Cid {
    Cid::new_v1(RAW_CODEC, Code::Blake3_256.digest(bytes))
}

/// Check that `cid` has the canonical form.
pub fn check(cid: &Cid) -> Result<(), CidError> {
    if cid.version() != cid::Version::V1 {
        return Err(CidError::NotV1);
    }
    if cid.codec() != RAW_CODEC {
        return Err(CidError::NotRaw);
    }
    let hash = cid.hash();
    if hash.code() != BLAKE3_256 || hash.size() != 32 {
        return Err(CidError::NotBlake3);
    }
    Ok(())
}

/// Parse a binary CID from a payload, refusing every form but the canonical one.
pub fn from_bytes(bytes: &[u8]) -> Result<Cid, CidError> {
    let cid = Cid::try_from(bytes).map_err(|_| CidError::Malformed)?;
    check(&cid)?;
    if cid.to_bytes() != bytes {
        return Err(CidError::NotCanonical);
    }
    Ok(cid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cid::multihash::Multihash;

    #[test]
    fn a_canonical_cid_round_trips() {
        let cid = of(b"x");
        assert_eq!(from_bytes(&cid.to_bytes()), Ok(cid));
    }

    #[test]
    fn a_cidv0_is_refused() {
        let v0 = Cid::new_v0(Multihash::<64>::wrap(0x12, &[0; 32]).unwrap()).unwrap();
        assert_eq!(from_bytes(&v0.to_bytes()), Err(CidError::NotV1));
    }

    #[test]
    fn another_codec_is_refused() {
        let dag_cbor = Cid::new_v1(0x71, Code::Blake3_256.digest(b"x"));
        assert_eq!(from_bytes(&dag_cbor.to_bytes()), Err(CidError::NotRaw));
    }

    #[test]
    fn another_multihash_is_refused() {
        let sha2 = Cid::new_v1(RAW_CODEC, Multihash::<64>::wrap(0x12, &[0; 32]).unwrap());
        assert_eq!(from_bytes(&sha2.to_bytes()), Err(CidError::NotBlake3));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = of(b"x").to_bytes();
        bytes.push(0);
        assert!(from_bytes(&bytes).is_err());
    }
}
