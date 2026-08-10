use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::crypto::hash_labeled_parts;
use crate::error::{JigError, Result};
use crate::manifest::Constraints;
use crate::wasm_validation::{HostImportAllowlist, policy_from_constraints, verify_determinism};

const RAW_CODEC: u64 = 0x55;

/// Reference to an artifact that should be included when computing the block root.
pub struct Artifact<'a> {
    pub label: &'a str,
    pub bytes: &'a [u8],
}

/// Compute the merkle-style root hash for a block given manifest, code, and any additional artifacts.
pub fn compute_root<'a>(
    manifest_bytes: &'a [u8],
    code_bytes: &'a [u8],
    additional_artifacts: &[Artifact<'a>],
) -> blake3::Hash {
    let mut parts: Vec<(&str, &[u8])> = vec![("manifest", manifest_bytes), ("code", code_bytes)];
    for artifact in additional_artifacts {
        parts.push((artifact.label, artifact.bytes));
    }
    hash_labeled_parts(&parts)
}

/// Compute a CID (multibase-blake3-256 raw) for the block artefacts.
pub fn compute_cid<'a>(
    manifest_bytes: &'a [u8],
    code_bytes: &'a [u8],
    additional_artifacts: &[Artifact<'a>],
) -> Result<Cid> {
    let root = compute_root(manifest_bytes, code_bytes, additional_artifacts);
    let mh = Code::Blake3_256.digest(root.as_bytes());
    Ok(Cid::new_v1(RAW_CODEC, mh))
}

/// Convenience wrapper bundling the manifest, code, and resources.
pub struct BlockBundle<'a> {
    pub manifest_bytes: &'a [u8],
    pub code_bytes: &'a [u8],
    pub resources: Vec<Artifact<'a>>,
}

impl<'a> BlockBundle<'a> {
    pub fn root_hash(&self) -> blake3::Hash {
        compute_root(self.manifest_bytes, self.code_bytes, &self.resources)
    }

    pub fn block_cid(&self) -> Result<Cid> {
        compute_cid(self.manifest_bytes, self.code_bytes, &self.resources)
    }

    /// Convenience to compute a hex string for the root hash (useful in render descriptors).
    pub fn root_hash_hex(&self) -> String {
        let hash = self.root_hash();
        hex::encode(hash.as_bytes())
    }

    /// Validate Wasm code for determinism and import safety.
    ///
    /// Checks:
    /// - Determinism (if constraints.deterministic = true)
    /// - Import allowlist compliance
    pub fn validate_code(&self, constraints: &Constraints) -> Result<()> {
        self.validate_code_with_allowlist(constraints, &HostImportAllowlist::default())
    }

    /// Validate code with custom import allowlist.
    pub fn validate_code_with_allowlist(
        &self,
        constraints: &Constraints,
        allowlist: &HostImportAllowlist,
    ) -> Result<()> {
        if self.code_bytes.is_empty() {
            return Ok(()); // No code to validate
        }

        let policy = policy_from_constraints(constraints, allowlist.clone());

        let report = verify_determinism(self.code_bytes, &policy)?;
        if !report.is_compliant() {
            let details = report
                .violations
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(JigError::Validation(format!(
                "non-deterministic wasm: {details}"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Author, BlockManifestBuilder, Constraints};
    use crate::wasm_validation::HostImportAllowlist;
    use semver::Version;

    fn test_manifest() -> (Vec<u8>, Constraints) {
        let manifest = BlockManifestBuilder::default()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .constraints(Constraints {
                fuel_max: 1_000_000,
                memory_max_mb: 32,
                execution_timeout_ms: 250,
                deterministic: true,
            })
            .build()
            .unwrap();
        (manifest.to_canonical_bytes().unwrap(), manifest.constraints)
    }

    fn wasm_importing_http_fetch() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "jig_host" "http_fetch" (func $http_fetch (param i32 i32)))
                (func (export "main")
                    i32.const 0
                    i32.const 0
                    call $http_fetch))"#,
        )
        .unwrap()
    }

    #[test]
    fn validate_code_rejects_http_fetch_without_allowlist() {
        let (manifest_bytes, constraints) = test_manifest();
        let wasm = wasm_importing_http_fetch();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &wasm,
            resources: vec![],
        };

        let result = bundle.validate_code(&constraints);
        assert!(result.is_err());
    }

    #[test]
    fn validate_code_with_allowlist_allows_http_fetch_when_allowlisted() {
        let (manifest_bytes, constraints) = test_manifest();
        let wasm = wasm_importing_http_fetch();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &wasm,
            resources: vec![],
        };

        let allowlist =
            HostImportAllowlist::new().allow_module("jig_host", vec!["http_fetch".into()]);

        let result = bundle.validate_code_with_allowlist(&constraints, &allowlist);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_code_respects_deterministic_flag() {
        let (manifest_bytes, mut constraints) = test_manifest();
        let float_wasm = wat::parse_str(
            r#"(module
                (func (export "add") (param f32 f32) (result f32)
                    local.get 0
                    local.get 1
                    f32.add))"#,
        )
        .unwrap();

        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &float_wasm,
            resources: vec![],
        };

        // Strict (default) rejects floats
        assert!(bundle.validate_code(&constraints).is_err());

        // Relaxed allows floats
        constraints.deterministic = false;
        assert!(bundle.validate_code(&constraints).is_ok());
    }
}
