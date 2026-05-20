use crate::capability_registry::CapabilityRegistry;
use crate::capability_validation::{CapabilityReport, check_manifest_capabilities_with_registry};
use crate::error::Result;
use crate::manifest::{BlockManifest, Constraints};
use crate::wasm_validation::{
    DeterminismReport, HostImportAllowlist, policy_from_constraints, verify_determinism,
};

/// Combined lint report for a block (manifest + code).
#[derive(Debug, Clone)]
pub struct BlockLintResult {
    pub determinism: DeterminismReport,
    pub capabilities: CapabilityReport,
}

impl BlockLintResult {
    pub fn is_clean(&self) -> bool {
        self.determinism.is_compliant()
            && self.capabilities.is_valid()
            && self.capabilities.is_least_privilege()
    }
}

/// Build an import allowlist from manifest-declared capabilities.
pub fn allowlist_from_manifest(
    manifest: &BlockManifest,
    registry: &CapabilityRegistry,
) -> Result<HostImportAllowlist> {
    let mut allowlist = HostImportAllowlist::new();

    for capability in &manifest.capabilities {
        if let Some(def) = registry.get(&capability.name) {
            for (module, func) in &def.required_imports {
                allowlist = allowlist.allow_function(module.clone(), func.clone());
            }
        }
    }

    Ok(allowlist)
}

/// Lint a block manifest and code against determinism and capability rules.
pub fn lint_block(
    manifest: &BlockManifest,
    code_bytes: &[u8],
    constraints: &Constraints,
    registry: &CapabilityRegistry,
) -> Result<BlockLintResult> {
    manifest.validate()?;

    let allowlist = allowlist_from_manifest(manifest, registry)?;
    let policy = policy_from_constraints(constraints, allowlist);
    let determinism = verify_determinism(code_bytes, &policy)?;

    let capabilities =
        check_manifest_capabilities_with_registry(manifest, &determinism.imports, registry)?;

    Ok(BlockLintResult {
        determinism,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability;
    use crate::manifest::{Author, BlockManifestBuilder};
    use semver::Version;

    fn base_manifest() -> BlockManifest {
        BlockManifestBuilder::default()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .capability(capability!("core:compute"))
            .capability(capability!("log:emit"))
            .build()
            .unwrap()
    }

    #[test]
    fn allowlist_merges_capabilities() {
        let manifest = base_manifest();
        let registry = CapabilityRegistry::default();
        let allowlist = allowlist_from_manifest(&manifest, &registry).unwrap();

        assert!(allowlist.is_allowed("jig_host", "log"));
        // core:compute has no imports; ensure allowlist still exists.
        assert!(allowlist.is_allowed("jig_host", "log"));
    }

    #[test]
    fn lint_block_reports_capability_and_determinism() {
        let manifest = base_manifest();
        let registry = CapabilityRegistry::default();
        let constraints = Constraints::default();

        // Deterministic integer-only wasm should pass
        let wasm = wat::parse_str(
            r#"(module
                (import "jig_host" "log" (func $log (param i32 i32)))
                (func (export "main")
                    i32.const 0
                    i32.const 0
                    call $log)
            )"#,
        )
        .unwrap();

        let report = lint_block(&manifest, &wasm, &constraints, &registry).unwrap();
        assert!(report.determinism.is_compliant());
        assert!(report.capabilities.is_valid());
        assert!(report.capabilities.is_least_privilege());
        assert!(report.is_clean());
    }
}
