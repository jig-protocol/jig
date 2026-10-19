//! Capability validation helpers.
//!
//! Validates manifest-declared capability requests against registry
//! constraints: known names, required attestations, and fuel requests.

use crate::capability_registry::{CapabilityDefinition, CapabilityRegistry};
use crate::error::{JigError, Result};
use crate::manifest::Capability;

#[cfg(test)]
use crate::manifest::Attestation;

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
