//! Capability validation helpers.
//!
//! Links manifest-declared capabilities to required host imports
//! and validates capability requests against registry constraints.

use crate::capability_registry::{CapabilityDefinition, CapabilityRegistry};
use crate::error::{JigError, Result};
use crate::manifest::{BlockManifest, Capability, CapabilityName};
use std::collections::HashSet;

#[cfg(test)]
use crate::manifest::Attestation;

/// Report on capability validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    /// Capabilities that are satisfied (known and properly configured)
    pub satisfied: Vec<CapabilityName>,
    /// Capabilities requested but not in registry (unknown)
    pub missing: Vec<CapabilityName>,
    /// Imports present in code but not covered by any capability
    pub over_privileged: Vec<(String, String)>,
    /// Capabilities missing required attestations
    pub attestation_violations: Vec<String>,
}

impl CapabilityReport {
    /// Check if all capabilities are valid (no missing, no violations).
    pub fn is_valid(&self) -> bool {
        self.missing.is_empty() && self.attestation_violations.is_empty()
    }

    /// Check if imports match capabilities (no over-privileged imports).
    pub fn is_least_privilege(&self) -> bool {
        self.over_privileged.is_empty()
    }
}

/// Validate a single capability request against registry.
pub fn validate_capability_request(
    capability: &Capability,
    registry: &CapabilityRegistry,
) -> Result<()> {
    let def = registry
        .get(&capability.name)
        .ok_or_else(|| JigError::Validation(format!("unknown capability: {}", capability.name)))?;

    // Check attestation requirements
    check_attestations(capability, def)?;

    // Validate fuel allocation if specified
    if let Some(requested_fuel) = capability.fuel
        && requested_fuel > def.fuel_cost_estimate * 10
    {
        return Err(JigError::Validation(format!(
            "capability {} requests excessive fuel: {} (estimate: {})",
            capability.name, requested_fuel, def.fuel_cost_estimate
        )));
    }

    Ok(())
}

/// Check manifest capabilities against code imports.
pub fn check_manifest_capabilities(
    manifest: &BlockManifest,
    code_imports: &[(String, String)],
) -> Result<CapabilityReport> {
    check_manifest_capabilities_with_registry(
        manifest,
        code_imports,
        &CapabilityRegistry::default(),
    )
}

/// Check manifest capabilities with custom registry.
pub fn check_manifest_capabilities_with_registry(
    manifest: &BlockManifest,
    code_imports: &[(String, String)],
    registry: &CapabilityRegistry,
) -> Result<CapabilityReport> {
    let mut satisfied = Vec::new();
    let mut missing = Vec::new();
    let mut attestation_violations = Vec::new();

    // Track all imports covered by capabilities
    let mut covered_imports: HashSet<(String, String)> = HashSet::new();

    // Validate each capability
    for capability in &manifest.capabilities {
        match registry.get(&capability.name) {
            Some(def) => {
                // Check attestations
                if let Err(e) = check_attestations(capability, def) {
                    attestation_violations.push(format!("{}: {}", capability.name, e));
                }

                // Mark imports as covered
                for import in &def.required_imports {
                    covered_imports.insert(import.clone());
                }

                satisfied.push(capability.name.clone());
            }
            None => {
                missing.push(capability.name.clone());
            }
        }
    }

    // Find over-privileged imports (imports not covered by any capability)
    let over_privileged: Vec<_> = code_imports
        .iter()
        .filter(|import| !covered_imports.contains(*import))
        .cloned()
        .collect();

    Ok(CapabilityReport {
        satisfied,
        missing,
        over_privileged,
        attestation_violations,
    })
}

/// Validate all capabilities in a manifest.
pub fn validate_all_capabilities(
    capabilities: &[Capability],
    registry: &CapabilityRegistry,
) -> Result<()> {
    for capability in capabilities {
        validate_capability_request(capability, registry)?;
    }
    Ok(())
}

/// Check attestation requirements.
fn check_attestations(capability: &Capability, def: &CapabilityDefinition) -> Result<()> {
    for required_claim in &def.attestation_requirements {
        let has_attestation = capability
            .attestations
            .iter()
            .any(|att| att.claim == *required_claim);

        if !has_attestation {
            return Err(JigError::Validation(format!(
                "missing required attestation: {required_claim}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Author;
    use semver::Version;

    #[test]
    fn validate_known_capability_succeeds() {
        let capability = Capability {
            name: "core:compute".into(),
            scope: vec![],
            fuel: Some(100_000),
            attestations: vec![],
            metadata: Default::default(),
        };

        let registry = CapabilityRegistry::default();
        assert!(validate_capability_request(&capability, &registry).is_ok());
    }

    #[test]
    fn validate_unknown_capability_fails() {
        let capability = Capability {
            name: "unknown:capability".into(),
            scope: vec![],
            fuel: None,
            attestations: vec![],
            metadata: Default::default(),
        };

        let registry = CapabilityRegistry::default();
        assert!(validate_capability_request(&capability, &registry).is_err());
    }

    #[test]
    fn validate_excessive_fuel_fails() {
        let capability = Capability {
            name: "core:compute".into(),
            scope: vec![],
            fuel: Some(100_000_000), // Way over estimate
            attestations: vec![],
            metadata: Default::default(),
        };

        let registry = CapabilityRegistry::default();
        let result = validate_capability_request(&capability, &registry);
        assert!(result.is_err());
    }

    #[test]
    fn missing_attestation_fails() {
        let capability = Capability {
            name: "ai:llm:inference".into(),
            scope: vec![],
            fuel: None,
            attestations: vec![], // Missing required attestation
            metadata: Default::default(),
        };

        let registry = CapabilityRegistry::default();
        assert!(validate_capability_request(&capability, &registry).is_err());
    }

    #[test]
    fn present_attestation_succeeds() {
        let capability = Capability {
            name: "ai:llm:inference".into(),
            scope: vec![],
            fuel: None,
            attestations: vec![Attestation {
                issuer: "did:jig:validator".into(),
                claim: "ai_usage_policy:v1".into(),
                signature: None,
                evidence: None,
            }],
            metadata: Default::default(),
        };

        let registry = CapabilityRegistry::default();
        assert!(validate_capability_request(&capability, &registry).is_ok());
    }

    #[test]
    fn capability_report_detects_missing() {
        // Build manifest without capability validation
        let mut manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap();

        // Manually add unknown capability after building
        manifest.capabilities.push(Capability {
            name: "unknown:cap".into(),
            ..Default::default()
        });

        let imports = vec![];
        let report = check_manifest_capabilities(&manifest, &imports).unwrap();

        assert!(!report.is_valid());
        assert_eq!(report.missing.len(), 1);
        assert_eq!(report.missing[0], "unknown:cap");
    }

    #[test]
    fn capability_report_detects_over_privileged() {
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .capability(Capability {
                name: "core:compute".into(),
                ..Default::default()
            })
            .build()
            .unwrap();

        // Code imports something not covered by capabilities
        let imports = vec![("jig_host".into(), "http_fetch".into())];
        let report = check_manifest_capabilities(&manifest, &imports).unwrap();

        assert!(!report.is_least_privilege());
        assert_eq!(report.over_privileged.len(), 1);
    }

    #[test]
    fn capability_report_all_satisfied() {
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

        let imports = vec![("jig_host".into(), "http_fetch".into())];
        let report = check_manifest_capabilities(&manifest, &imports).unwrap();

        assert!(report.is_valid());
        assert!(report.is_least_privilege());
        assert_eq!(report.satisfied.len(), 1);
    }

    #[test]
    fn validate_all_capabilities_checks_each() {
        let capabilities = vec![
            Capability {
                name: "core:compute".into(),
                ..Default::default()
            },
            Capability {
                name: "net:http:fetch".into(),
                ..Default::default()
            },
        ];

        let registry = CapabilityRegistry::default();
        assert!(validate_all_capabilities(&capabilities, &registry).is_ok());
    }

    #[test]
    fn validate_all_fails_on_first_invalid() {
        let capabilities = vec![
            Capability {
                name: "core:compute".into(),
                ..Default::default()
            },
            Capability {
                name: "unknown:cap".into(),
                ..Default::default()
            },
        ];

        let registry = CapabilityRegistry::default();
        assert!(validate_all_capabilities(&capabilities, &registry).is_err());
    }
}
