//! Core data structures for the Jig executable internet.
//!
//! This crate defines the canonical block manifest, receipt, hashing utilities, and signing
//! interfaces shared across the protocol. It intentionally avoids network, storage, or registry
//! dependencies so other crates can embed these primitives directly.

pub mod admission_pow;
pub mod block_abi;
pub mod block_kind;
pub mod block_receipt;
pub mod bundle;
pub mod canonical_cid;
pub mod capability_registry;
pub mod capability_scope;
pub mod capability_validation;
pub mod component_validation;
#[cfg(feature = "ed25519")]
pub mod contract;
#[cfg(feature = "ed25519")]
pub mod cose;
pub mod crypto;
pub mod dcbor;
pub mod did;
pub mod dm;
pub mod error;
pub mod grant;
pub mod hlc;
#[cfg(feature = "ed25519")]
pub mod key_link;
#[cfg(feature = "keystore")]
pub mod keystore;
pub mod manifest;
#[cfg(feature = "ed25519")]
pub mod naming;
pub mod operator_policy;
pub mod pow;
pub mod program;
#[cfg(test)]
pub mod proptest_generators;
pub mod request_auth;
mod serde_helpers;
pub mod signing;
pub mod slug;
pub mod suite;
pub mod tier;
#[cfg(feature = "ed25519")]
pub mod tls_binding;
pub mod wasm_validation;

pub use block_kind::{BlockKind, BlockKindError};
pub use bundle::{Artifact, BlockBundle};
pub use capability_registry::{CapabilityDefinition, CapabilityRegistry};
pub use capability_scope::{
    CAPABILITY_SCOPE_SEPARATOR, CapabilityScopePattern, CapabilityUsageKey,
};
pub use capability_validation::validate_capability_request;
pub use crypto::{HashBuilder, blake3_hash, hash_labeled_parts};
pub use did::{Did, DidError};
pub use error::{JigError, Result};
pub use hlc::HlcTimestamp;
pub use manifest::{
    Attestation, Author, BlockManifest, BlockManifestBuilder, Capability, Constraints,
    ManifestGateError, MetadataVisibility, Privacy, Provenance, RenderDescriptor, Resource,
};
pub use signing::BlockSignature;
pub use suite::{EncryptionSuite, SuiteNotImplemented, UnknownSuite};
pub use wasm_validation::{
    DeterminismPolicy, DeterminismReport, DeterminismViolation, HostImportAllowlist, check_imports,
    validate_determinism, verify_determinism,
};

#[cfg(test)]
mod tests {
    use super::*;
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
}
