//! Proptest generators for property testing.
//!
//! Provides Arbitrary implementations for all core types to enable
//! property-based testing of serialization, validation, and CID stability.

use crate::capability_scope::CapabilityScopePattern;
use crate::manifest::*;
use crate::receipt::{HashAlgorithms, RECEIPT_SCHEMA_VERSION};
use cid::Cid;
use proptest::prelude::*;
use semver::Version;
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// Generate valid DID strings.
fn did_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("did:jig:[a-z0-9]{8,16}").unwrap()
}

/// Generate valid capability names.
fn capability_name_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("core:compute".to_string()),
        Just("net:http:fetch".to_string()),
        Just("storage:read".to_string()),
        Just("storage:write".to_string()),
        Just("log:emit".to_string()),
        Just("message:emit".to_string()),
    ]
}

fn capability_scope_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("https://api.example.com/*".to_string()),
        Just("https://api.example.com/orders/*".to_string()),
        Just("https://api.example.com/orders/confirmed".to_string()),
        Just("storage://cid/*".to_string()),
        Just("storage://cid/abc123".to_string()),
        Just("any://*".to_string()),
    ]
}

/// Generate valid hex strings.
fn hash_hex_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-f0-9]{64}").unwrap()
}

/// Generate valid timestamps.
fn timestamp_strategy() -> impl Strategy<Value = OffsetDateTime> {
    // Generate timestamps in reasonable range (2020-2030)
    (1577836800i64..1893456000i64)
        .prop_map(|secs| OffsetDateTime::from_unix_timestamp(secs).unwrap())
}

/// Generate valid CIDs.
fn cid_strategy() -> impl Strategy<Value = Cid> {
    any::<[u8; 32]>().prop_map(|bytes| {
        use multihash_codetable::{Code, MultihashDigest};
        let mh = Code::Blake3_256.digest(&bytes);
        Cid::new_v1(0x55, mh)
    })
}

impl Arbitrary for Author {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            did_strategy(),
            prop::option::of(prop::string::string_regex("ed25519:[a-f0-9]{64}").unwrap()),
            prop::collection::vec(prop::string::string_regex("[a-z]{4,12}").unwrap(), 0..3),
        )
            .prop_map(|(did, public_key, roles)| Author {
                did: crate::Did::from(did.as_str()),
                public_key,
                roles,
            })
            .boxed()
    }
}

impl Arbitrary for Attestation {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            did_strategy(),
            prop::string::string_regex("[a-z_:]{5,30}").unwrap(),
            prop::option::of(prop::string::string_regex("sig:[a-f0-9]{64}").unwrap()),
            prop::option::of(prop::string::string_regex("https://[a-z.]{5,20}/evidence").unwrap()),
        )
            .prop_map(|(issuer, claim, signature, evidence)| Attestation {
                issuer,
                claim,
                signature,
                evidence,
            })
            .boxed()
    }
}

impl Arbitrary for Capability {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            capability_name_strategy(),
            prop::collection::vec(capability_scope_strategy(), 0..3),
            prop::option::of(100_000u64..10_000_000u64),
            prop::collection::vec(any::<Attestation>(), 0..2),
        )
            .prop_map(|(name, scopes, fuel, attestations)| {
                let scope_patterns = scopes
                    .into_iter()
                    .map(|s| CapabilityScopePattern::parse(&s).unwrap())
                    .collect();
                Capability {
                    name,
                    scope: scope_patterns,
                    fuel,
                    attestations,
                    metadata: BTreeMap::new(), // Keep simple for now
                }
            })
            .boxed()
    }
}

impl Arbitrary for Constraints {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            1_000_000u64..100_000_000u64,
            16u32..256u32,
            50u32..5000u32,
            any::<bool>(),
        )
            .prop_map(
                |(fuel_max, memory_max_mb, execution_timeout_ms, deterministic)| Constraints {
                    fuel_max,
                    memory_max_mb,
                    execution_timeout_ms,
                    deterministic,
                },
            )
            .boxed()
    }
}

impl Arbitrary for Resource {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            prop::string::string_regex("[a-z0-9_]{3,20}\\.(png|jpg|txt)").unwrap(),
            cid_strategy(),
            prop::string::string_regex("(image|text)/[a-z]{3,10}").unwrap(),
        )
            .prop_map(|(name, cid, mime)| Resource {
                name,
                cid,
                mime,
                metadata: BTreeMap::new(),
            })
            .boxed()
    }
}

impl Arbitrary for RenderDescriptor {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            prop::string::string_regex("render::[a-z]{4,12}").unwrap(),
            hash_hex_strategy(),
            prop::string::string_regex("application/[a-z-]{3,20}").unwrap(),
        )
            .prop_map(|(entry, expected_hash, output_type)| RenderDescriptor {
                entry,
                expected_hash,
                output_type,
            })
            .boxed()
    }
}

impl Arbitrary for Provenance {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            timestamp_strategy(),
            prop::collection::vec(cid_strategy(), 0..3),
            prop::option::of(prop::string::string_regex("(low|medium|high)-sec").unwrap()),
        )
            .prop_map(
                |(created_at, useful_work_refs, reputation_tier)| Provenance {
                    created_at,
                    useful_work_refs,
                    reputation_tier,
                },
            )
            .boxed()
    }
}

impl Arbitrary for Privacy {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            prop::string::string_regex("(age|x25519|aes256)").unwrap(),
            prop::collection::vec(did_strategy(), 1..5),
            any::<MetadataVisibility>(),
        )
            .prop_map(|(encryption, recipients, metadata_visibility)| Privacy {
                encryption,
                recipients: recipients
                    .into_iter()
                    .map(|s| crate::Did::from(s.as_str()))
                    .collect(),
                metadata_visibility,
            })
            .boxed()
    }
}

impl Arbitrary for MetadataVisibility {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(MetadataVisibility::Public),
            Just(MetadataVisibility::RecipientsOnly),
            Just(MetadataVisibility::Private),
        ]
        .boxed()
    }
}

impl Arbitrary for BlockManifest {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            (0u64..5u64, 0u64..20u64, 0u64..100u64), // version
            prop::collection::vec(any::<Author>(), 1..3),
            prop::collection::vec(cid_strategy(), 0..3),
            prop::collection::vec(any::<Capability>(), 0..5),
            any::<Constraints>(),
            prop::collection::vec(any::<Resource>(), 0..3),
            prop::option::of(any::<RenderDescriptor>()),
            prop::option::of(any::<Provenance>()),
            prop::collection::vec(any::<Attestation>(), 0..2),
            prop::option::of(any::<Privacy>()),
        )
            .prop_map(
                |(
                    version_tuple,
                    authors,
                    parents,
                    capabilities,
                    constraints,
                    resources,
                    render,
                    provenance,
                    attestations,
                    privacy,
                )| {
                    let (major, minor, patch) = version_tuple;
                    BlockManifest {
                        schema: DEFAULT_SCHEMA.to_string(),
                        block_id: None, // Will be set after CID computation
                        version: Version::new(major, minor, patch),
                        authors,
                        parents,
                        capabilities,
                        constraints,
                        resources,
                        render,
                        provenance,
                        attestations,
                        privacy,
                        metadata: BTreeMap::new(),
                        hlc_ts: None,
                        attested_by: vec![],
                        crdt_kind: None,
                        kind: None,
                    }
                },
            )
            .boxed()
    }
}

impl Arbitrary for crate::receipt::BlockReceipt {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            cid_strategy(),
            did_strategy(),
            timestamp_strategy(),
            hash_hex_strategy(),
            100_000u64..10_000_000u64,
            prop::option::of(8u32..256u32),
            prop::collection::vec(capability_name_strategy(), 0..5),
            prop::option::of(prop::string::string_regex("sig:[a-f0-9]{128}").unwrap()),
        )
            .prop_map(
                |(
                    block_id,
                    host,
                    executed_at,
                    render_hash,
                    fuel_used,
                    memory_peak_mb,
                    capabilities_used,
                    signature,
                )| {
                    crate::receipt::BlockReceipt {
                        receipt_schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
                        block_id,
                        host,
                        executed_at,
                        render_hash,
                        fuel_used,
                        memory_peak_mb,
                        renders_match: None,
                        counters: None,
                        timings_ms: None,
                        limits: None,
                        outcome: None,
                        hash_algorithms: HashAlgorithms::default(),
                        capabilities_used,
                        attestations: vec![],
                        signature,
                        metadata: BTreeMap::new(),
                    }
                },
            )
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #[test]
        fn author_generates_valid(author in any::<Author>()) {
            assert!(author.did.starts_with("did:jig:"));
        }

        #[test]
        fn capability_generates_known(capability in any::<Capability>()) {
            assert!(!capability.name.is_empty());
            // Verify it's a known capability
            let valid_names = [
                "core:compute", "net:http:fetch", "storage:read",
                "storage:write", "log:emit", "message:emit"
            ];
            assert!(valid_names.contains(&capability.name.as_str()));
        }

        #[test]
        fn constraints_are_reasonable(constraints in any::<Constraints>()) {
            assert!(constraints.fuel_max >= 1_000_000);
            assert!(constraints.memory_max_mb >= 16);
            assert!(constraints.execution_timeout_ms >= 50);
        }

        #[test]
        fn manifest_generates_valid(manifest in any::<BlockManifest>()) {
            assert!(!manifest.authors.is_empty());
            assert!(manifest.version.major < 5);
        }

        #[test]
        fn receipt_generates_valid(receipt in any::<crate::receipt::BlockReceipt>()) {
            assert!(!receipt.render_hash.is_empty());
            assert!(receipt.fuel_used >= 100_000);
        }

        /// Test CID stability: serialize → deserialize → serialize produces identical bytes.
        #[test]
        fn manifest_cid_stable_under_reserialize(manifest in any::<BlockManifest>()) {
            let bytes1 = manifest.to_canonical_bytes().unwrap();
            let roundtrip: BlockManifest = serde_json::from_slice(&bytes1).unwrap();
            let bytes2 = roundtrip.to_canonical_bytes().unwrap();

            prop_assert_eq!(bytes1, bytes2, "CID instability detected");
        }

        /// Test that field order is stable.
        #[test]
        fn manifest_field_order_stable(manifest in any::<BlockManifest>()) {
            let json1 = serde_json::to_string(&manifest).unwrap();
            let json2 = serde_json::to_string(&manifest).unwrap();
            prop_assert_eq!(json1, json2, "Field order unstable");
        }

        /// Test receipt roundtrip without data loss.
        #[test]
        fn receipt_validates_after_roundtrip(receipt in any::<crate::receipt::BlockReceipt>()) {
            let json = serde_json::to_string(&receipt).unwrap();
            let parsed: crate::receipt::BlockReceipt = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(receipt, parsed);
        }

        /// Test optional fields are preserved.
        #[test]
        fn optional_fields_preserved(manifest in any::<BlockManifest>()) {
            let bytes = manifest.to_canonical_bytes().unwrap();
            let deserialized: BlockManifest = serde_json::from_slice(&bytes).unwrap();

            prop_assert_eq!(manifest.render.is_some(), deserialized.render.is_some());
            prop_assert_eq!(manifest.provenance.is_some(), deserialized.provenance.is_some());
            prop_assert_eq!(manifest.privacy.is_some(), deserialized.privacy.is_some());
        }

        /// Test CID fields serialize correctly.
        #[test]
        fn cid_fields_stable(manifest in any::<BlockManifest>()) {
            if !manifest.parents.is_empty() {
                let bytes = manifest.to_canonical_bytes().unwrap();
                let deserialized: BlockManifest = serde_json::from_slice(&bytes).unwrap();
                prop_assert_eq!(manifest.parents, deserialized.parents);
            }
        }
    }
}
