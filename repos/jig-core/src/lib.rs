//! Core data structures for the Jig executable internet.
//!
//! This crate defines the canonical block manifest, receipt, hashing utilities, and signing
//! interfaces shared across the protocol. It intentionally avoids network, storage, or registry
//! dependencies so other crates can embed these primitives directly.

pub mod bundle;
pub mod capability_dsl;
pub mod capability_registry;
pub mod capability_scope;
pub mod capability_validation;
pub mod crypto;
pub mod error;
pub mod hlc;
pub mod lint;
pub mod manifest;
#[cfg(test)]
pub mod proptest_generators;
pub mod receipt;
mod serde_helpers;
pub mod signing;
pub mod wasm_validation;

pub use bundle::{Artifact, BlockBundle};
pub use capability_dsl::{build_capability, parse_scopes};
pub use capability_registry::{CapabilityDefinition, CapabilityRegistry};
pub use capability_scope::{
    CAPABILITY_SCOPE_SEPARATOR, CapabilityScopePattern, CapabilityUsageKey,
};
pub use capability_validation::{
    CapabilityReport, check_manifest_capabilities, validate_capability_request,
};
pub use crypto::{HashBuilder, blake3_hash, hash_labeled_parts};
pub use error::{JigError, Result};
pub use hlc::HlcTimestamp;
pub use lint::{BlockLintResult, allowlist_from_manifest, lint_block};
pub use manifest::{
    Attestation, Author, BlockManifest, BlockManifestBuilder, Capability, Constraints, Did,
    MetadataVisibility, Privacy, Provenance, RenderDescriptor, Resource,
};
pub use receipt::{
    BlockReceipt, BlockReceiptBuilder, Counters, CountersBuilder, HashAlgorithms, Limits, Outcome,
    OutcomeStatus, RECEIPT_METADATA_CLOCK_SOURCE, RECEIPT_SCHEMA_VERSION, ReasonCode, Timings,
};
pub use signing::BlockSignature;
pub use wasm_validation::{
    DeterminismPolicy, DeterminismReport, DeterminismViolation, HostImportAllowlist, check_imports,
    infer_limits, validate_determinism, verify_determinism,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_scope::CapabilityUsageKey;
    use semver::Version;
    use serde_json::json;

    #[test]
    fn manifest_builder_produces_canonical_bytes() {
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:alice".into(),
                public_key: Some("pkfp:alice".into()),
                roles: vec!["author".into()],
            })
            .metadata_entry("example", json!({"foo": "bar"}))
            .build()
            .expect("manifest builds");

        let bytes = manifest.to_canonical_bytes().expect("serialize");
        assert!(!bytes.is_empty());
        assert!(
            std::str::from_utf8(&bytes)
                .unwrap()
                .contains("did:jig:alice")
        );
    }

    #[test]
    fn receipt_builder_defaults_execution_time() {
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:alice".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap();

        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &[],
            resources: vec![],
        };

        let block_id = bundle.block_cid().unwrap();
        let receipt = BlockReceipt::builder(block_id)
            .render_hash("abc123")
            .fuel_used(42)
            .host("did:jig:host")
            .build()
            .unwrap();
        assert_eq!(receipt.fuel_used, 42);
    }

    #[test]
    fn hash_builder_orders_entries() {
        let hash1 = HashBuilder::new()
            .push("a", [0u8; 8])
            .push("b", [1u8; 8])
            .finalize();
        let hash2 = HashBuilder::new()
            .push("a", [0u8; 8])
            .push("b", [1u8; 8])
            .finalize();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn wasm_validation_rejects_floats() {
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap();

        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let float_wasm = wat::parse_str(
            r#"(module
                (func (export "add") (param f32 f32) (result f32)
                    local.get 0
                    local.get 1
                    f32.add))
            "#,
        )
        .unwrap();

        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &float_wasm,
            resources: vec![],
        };

        let constraints = Constraints::default(); // deterministic = true
        assert!(bundle.validate_code(&constraints).is_err());
    }

    #[test]
    fn wasm_validation_accepts_deterministic_code() {
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap();

        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let int_wasm = wat::parse_str(
            r#"(module
                (func (export "add") (param i32 i32) (result i32)
                    local.get 0
                    local.get 1
                    i32.add))
            "#,
        )
        .unwrap();

        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &int_wasm,
            resources: vec![],
        };

        let constraints = Constraints::default();
        assert!(bundle.validate_code(&constraints).is_ok());
    }

    #[test]
    fn wasm_validation_enforces_import_allowlist() {
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap();

        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let wasm_with_bad_import = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "random_get" (func $rand (param i32 i32) (result i32)))
                (func (export "main")
                    i32.const 0
                    i32.const 8
                    call $rand
                    drop))
            "#,
        )
        .unwrap();

        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &wasm_with_bad_import,
            resources: vec![],
        };

        let constraints = Constraints {
            deterministic: false, // Even with determinism check off
            ..Default::default()
        };
        assert!(bundle.validate_code(&constraints).is_err());
    }

    #[test]
    fn manifest_validates_capabilities() {
        use crate::manifest::Capability;

        // Valid capability should work
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .capability(Capability {
                name: "core:compute".into(),
                scope: vec![],
                fuel: Some(100_000),
                attestations: vec![],
                metadata: Default::default(),
            })
            .build();

        assert!(manifest.is_ok());

        // Unknown capability should fail
        let bad_manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .capability(Capability {
                name: "unknown:capability".into(),
                ..Default::default()
            })
            .build();

        assert!(bad_manifest.is_err());
    }

    #[test]
    fn receipt_validates_against_manifest() {
        use crate::manifest::Capability;

        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .capability(Capability {
                name: "net:http:fetch".into(),
                ..Default::default()
            })
            .build()
            .unwrap();

        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &[],
            resources: vec![],
        };
        let block_id = bundle.block_cid().unwrap();

        // Receipt using declared capability should validate
        let good_receipt = BlockReceipt::builder(block_id)
            .render_hash("abc123")
            .fuel_used(100)
            .host("did:jig:host")
            .capability("net:http:fetch")
            .build()
            .unwrap();

        assert!(good_receipt.validate_against_manifest(&manifest).is_ok());

        // Receipt using undeclared capability should fail
        let bad_receipt = BlockReceipt::builder(block_id)
            .render_hash("abc123")
            .fuel_used(100)
            .host("did:jig:host")
            .capability("storage:write")
            .build()
            .unwrap();

        assert!(bad_receipt.validate_against_manifest(&manifest).is_err());
    }

    #[test]
    fn receipt_v0_2_with_counters() {
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap();

        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &[],
            resources: vec![],
        };
        let block_id = bundle.block_cid().unwrap();

        // Build v0.2 receipt with counters
        let mut fuel_by_cap = std::collections::BTreeMap::new();
        fuel_by_cap.insert("core:compute".to_string(), 50_000);

        let counters = Counters::builder()
            .fuel_total(50_000)
            .add_fuel(&CapabilityUsageKey::without_scope("core:compute"), 50_000)
            .bytes_tx(1024)
            .bytes_rx(2048)
            .build();

        let receipt = BlockReceipt::builder(block_id)
            .render_hash("abc123")
            .fuel_used(50_000)
            .host("did:jig:host")
            .counters(counters)
            .build()
            .unwrap();

        assert!(receipt.counters.is_some());
        assert_eq!(receipt.counters.as_ref().unwrap().fuel_total, 50_000);
    }

    #[test]
    fn receipt_v0_2_with_outcome() {
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap();

        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &[],
            resources: vec![],
        };
        let block_id = bundle.block_cid().unwrap();

        let outcome = Outcome {
            status: OutcomeStatus::Ok,
            affordances: vec!["email.delivered".to_string()],
            reason: None,
        };

        let receipt = BlockReceipt::builder(block_id)
            .render_hash("abc123")
            .fuel_used(100)
            .host("did:jig:host")
            .outcome(outcome)
            .build()
            .unwrap();

        assert!(receipt.outcome.is_some());
        assert_eq!(receipt.outcome.as_ref().unwrap().status, OutcomeStatus::Ok);
        assert_eq!(receipt.outcome.as_ref().unwrap().affordances.len(), 1);
    }

    #[test]
    fn infer_limits_for_e2ee_scenario() {
        // E2EE scenario: We have encrypted Wasm code and need to set execution limits
        // without inspecting the contents. This is critical for:
        // 1. Security - parametrize fuel based on code structure
        // 2. Analytics - distinguish real failures from insufficient limits
        // 3. Billing - ensure limits are appropriate for the workload

        let complex_wasm = wat::parse_str(
            r#"(module
                (import "jig_host" "log" (func $log (param i32 i32)))
                (import "jig_host" "emit_message" (func $emit (param i32 i32)))
                (memory 50)
                (func (export "main")
                    (local $i i32)
                    (local.set $i (i32.const 0))
                    (block $exit
                        (loop $continue
                            (local.get $i)
                            (i32.const 1000)
                            (i32.lt_s)
                            (if (then
                                (local.get $i)
                                (i32.const 0)
                                (call $log)
                                (local.get $i)
                                (i32.const 1)
                                (i32.add)
                                (local.set $i)
                                (br $continue)
                            ))
                        )
                    )
                    (i32.const 0)
                    (i32.const 0)
                    (call $emit)
                ))
            "#,
        )
        .unwrap();

        // Infer appropriate limits without inspecting code semantics
        let limits = crate::wasm_validation::infer_limits(&complex_wasm).unwrap();

        // Verify limits are reasonable for this workload
        // 2 imports × 50k + loop instructions + base = substantial fuel
        assert!(
            limits.fuel_max > 200_000,
            "should account for imports and complexity"
        );

        // 50 pages × 64KB = 3200KB = ~3.1MB
        assert!(limits.memory_max_mb >= 3, "should respect declared memory");

        // Complex module should get reasonable timeout (base 5s + complexity)
        assert!(
            limits.execution_timeout_ms >= 5000,
            "should have reasonable timeout"
        );

        // This demonstrates the E2EE use case:
        // - We can set appropriate limits without reading block contents
        // - Prevents "was this out-of-fuel real or just bad limits?" ambiguity
        // - Enables confident billing and analytics
    }

    #[test]
    fn receipt_v0_2_fuel_validation() {
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap();

        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &[],
            resources: vec![],
        };
        let block_id = bundle.block_cid().unwrap();

        // Mismatched fuel_total and fuel_used should fail validation
        let counters = Counters::builder().fuel_total(99_999).build();

        let result = BlockReceipt::builder(block_id)
            .render_hash("abc123")
            .fuel_used(100_000)
            .host("did:jig:host")
            .counters(counters)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn capability_report_tracks_imports() {
        use crate::manifest::Capability;

        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .capability(Capability {
                name: "log:emit".into(),
                ..Default::default()
            })
            .build()
            .unwrap();

        // Code uses exactly what manifest declares
        let imports = vec![("jig_host".into(), "log".into())];
        let report = check_manifest_capabilities(&manifest, &imports).unwrap();
        assert!(report.is_valid());
        assert!(report.is_least_privilege());

        // Code uses more than declared (over-privileged)
        let extra_imports = vec![
            ("jig_host".into(), "log".into()),
            ("jig_host".into(), "http_fetch".into()),
        ];
        let report2 = check_manifest_capabilities(&manifest, &extra_imports).unwrap();
        assert!(!report2.is_least_privilege());
        assert_eq!(report2.over_privileged.len(), 1);
    }
}
