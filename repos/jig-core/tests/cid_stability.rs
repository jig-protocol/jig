//! Golden CID stability.
//!
//! A block CID is the protocol's content address: it is the primary key for
//! stored blocks, it is embedded in receipts, and memberships reference the
//! channel-create block by CID. Any change to the multihash code, the digest
//! size, the CID version, the codec, or the multibase encoding silently
//! re-addresses every block that already exists.
//!
//! These tests pin known inputs to literal CID strings so a dependency bump
//! (`cid`, `multihash`, `blake3`) that changes the address cannot land
//! unnoticed. If one of these literals ever has to change, that is a protocol
//! break and needs an explicit migration decision — not an updated expectation.

use cid::Cid;
use jig_core::bundle::{Artifact, BlockBundle, compute_cid, compute_root};

/// CIDv1.
const EXPECTED_CID_VERSION: cid::Version = cid::Version::V1;
/// Raw multicodec (0x55) — blocks are addressed as opaque bytes.
const EXPECTED_CODEC: u64 = 0x55;
/// blake3 multihash code (0x1e).
const EXPECTED_MULTIHASH_CODE: u64 = 0x1e;
/// 32-byte digest.
const EXPECTED_DIGEST_LEN: usize = 32;

const MANIFEST: &[u8] = b"{\"name\":\"jig.test.block\",\"version\":\"0.0.1\"}";
const CODE: &[u8] = b"\0asm\x01\0\0\0";
const RESOURCE: &[u8] = b"hello, jig";

/// Manifest + code only, no additional artifacts.
const GOLDEN_CID_BARE: &str = "bafkr4idnrpp3yaotzk3dy7tib4ngodgd24bdgxcqhd7aewi3dhbsuyke6m";
/// Manifest + code + one labelled resource.
const GOLDEN_CID_WITH_RESOURCE: &str =
    "bafkr4idwa3tmcbkpix4s2yb3qmamr22glza4rjtckyxnmru3iaws7jmpvi";
/// Empty manifest, empty code, no artifacts — the degenerate boundary case.
const GOLDEN_CID_EMPTY: &str = "bafkr4ia27kgxolzmghenlebk5howqhe63bra3qj2mlz6dilq3rl27xqjpu";

fn bare_bundle() -> BlockBundle<'static> {
    BlockBundle {
        manifest_bytes: MANIFEST,
        code_bytes: CODE,
        resources: Vec::new(),
    }
}

fn bundle_with_resource() -> BlockBundle<'static> {
    BlockBundle {
        manifest_bytes: MANIFEST,
        code_bytes: CODE,
        resources: vec![Artifact {
            label: "resource",
            bytes: RESOURCE,
        }],
    }
}

#[test]
fn bare_bundle_cid_is_stable() {
    let cid = bare_bundle().block_cid().expect("cid");
    assert_eq!(
        cid.to_string(),
        GOLDEN_CID_BARE,
        "block CID changed — this re-addresses every stored block and is a protocol break"
    );
}

#[test]
fn bundle_with_resource_cid_is_stable() {
    let cid = bundle_with_resource().block_cid().expect("cid");
    assert_eq!(
        cid.to_string(),
        GOLDEN_CID_WITH_RESOURCE,
        "block CID changed — this re-addresses every stored block and is a protocol break"
    );
}

#[test]
fn empty_bundle_cid_is_stable() {
    let cid = compute_cid(b"", b"", &[]).expect("cid");
    assert_eq!(cid.to_string(), GOLDEN_CID_EMPTY);
}

#[test]
fn cid_shape_is_v1_raw_blake3_256() {
    let cid = bare_bundle().block_cid().expect("cid");
    assert_eq!(cid.version(), EXPECTED_CID_VERSION);
    assert_eq!(cid.codec(), EXPECTED_CODEC);
    assert_eq!(cid.hash().code(), EXPECTED_MULTIHASH_CODE);
    assert_eq!(cid.hash().size() as usize, EXPECTED_DIGEST_LEN);
    assert_eq!(cid.hash().digest().len(), EXPECTED_DIGEST_LEN);
}

/// The digest committed by the CID must remain `blake3(root)`, where `root` is
/// the labelled-parts merkle root. This pins the *hashing*, independently of
/// how the CID happens to be encoded.
#[test]
fn cid_digest_is_blake3_of_root() {
    let root = compute_root(MANIFEST, CODE, &[]);
    let expected = blake3::hash(root.as_bytes());
    let cid = bare_bundle().block_cid().expect("cid");
    assert_eq!(cid.hash().digest(), expected.as_bytes());
}

/// Pin the underlying merkle root too, so a change in `hash_labeled_parts`
/// is distinguishable from a change in the CID encoding layer.
#[test]
fn root_hash_is_stable() {
    assert_eq!(
        compute_root(MANIFEST, CODE, &[]).to_hex().to_string(),
        "fd97e439b2fec9bddef8a5c00759da744b2cbee6375066351aa066143262f4bc"
    );
}

/// Parsing a CID we did not produce must round-trip byte-for-byte. This guards
/// the multibase/base32 decode path that clients and receipts depend on.
#[test]
fn known_cids_round_trip_through_parse() {
    for golden in [
        GOLDEN_CID_BARE,
        GOLDEN_CID_WITH_RESOURCE,
        GOLDEN_CID_EMPTY,
        // sha2-256 raw CID used by the golden receipt fixtures.
        "bafkreigh2akiscaildcw453u6enm6kdwy5cae2f5z5ky3g4zz6p3r6jwhu",
    ] {
        let parsed: Cid = golden.parse().expect("parse golden cid");
        assert_eq!(parsed.to_string(), golden);
        let reparsed = Cid::try_from(parsed.to_bytes().as_slice()).expect("decode cid bytes");
        assert_eq!(reparsed, parsed);
    }
}

/// The binary form must be stable too: receipts and storage keys are derived
/// from `to_bytes()`, and the multibase string is only one of two encodings.
/// `<version><codec><mh-code><mh-len><digest>` = 0x01 0x55 0x1e 0x20 + 32 bytes.
#[test]
fn cid_binary_form_is_stable() {
    let bytes = bare_bundle().block_cid().expect("cid").to_bytes();
    assert_eq!(bytes.len(), 4 + EXPECTED_DIGEST_LEN);
    assert_eq!(&bytes[..4], &[0x01, 0x55, 0x1e, 0x20]);
    assert_eq!(
        hex::encode(&bytes),
        "01551e206d8bdfbc01d3cab63c7e680f1a670cc3d702335c5038fe02591b19c32a6144f3"
    );
}
