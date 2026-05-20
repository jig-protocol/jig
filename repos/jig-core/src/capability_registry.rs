//! Capability registry and definitions.
//!
//! Provides a taxonomy of known capabilities and their requirements,
//! including required host imports, fuel estimates, and attestation needs.

use crate::manifest::CapabilityName;
use std::collections::HashMap;

/// Definition of a known capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDefinition {
    pub name: CapabilityName,
    pub description: String,
    /// Host imports required for this capability: (module, function)
    pub required_imports: Vec<(String, String)>,
    /// Estimated fuel cost for typical usage
    pub fuel_cost_estimate: u64,
    /// Required attestations (e.g., "code_review:v1", "security_audit:v2")
    pub attestation_requirements: Vec<String>,
}

/// Registry of known capabilities.
#[derive(Debug, Clone)]
pub struct CapabilityRegistry {
    capabilities: HashMap<CapabilityName, CapabilityDefinition>,
}

impl CapabilityRegistry {
    /// Create empty registry.
    pub fn new() -> Self {
        Self {
            capabilities: HashMap::new(),
        }
    }

    /// Register a capability definition.
    pub fn register(mut self, def: CapabilityDefinition) -> Self {
        self.capabilities.insert(def.name.clone(), def);
        self
    }

    /// Look up a capability by name.
    pub fn get(&self, name: &str) -> Option<&CapabilityDefinition> {
        self.capabilities.get(name)
    }

    /// Check if a capability is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.capabilities.contains_key(name)
    }

    /// List all registered capability names.
    pub fn names(&self) -> Vec<&str> {
        self.capabilities.keys().map(|s| s.as_str()).collect()
    }

    /// Default registry with built-in Jig capabilities.
    pub fn default_jig_capabilities() -> Self {
        Self::new()
            .register(CapabilityDefinition {
                name: "core:compute".into(),
                description: "Pure computation with no external interactions".into(),
                required_imports: vec![],
                fuel_cost_estimate: 100_000,
                attestation_requirements: vec![],
            })
            .register(CapabilityDefinition {
                name: "net:http:fetch".into(),
                description: "HTTP fetch operations to external URLs".into(),
                required_imports: vec![("jig_host".into(), "http_fetch".into())],
                fuel_cost_estimate: 500_000,
                attestation_requirements: vec![],
            })
            .register(CapabilityDefinition {
                name: "storage:read".into(),
                description: "Read access to content-addressed storage".into(),
                required_imports: vec![
                    ("jig_host".into(), "storage_get".into()),
                    ("jig_host".into(), "read_resource".into()),
                ],
                fuel_cost_estimate: 200_000,
                attestation_requirements: vec![],
            })
            .register(CapabilityDefinition {
                name: "storage:write".into(),
                description: "Write access to content-addressed storage".into(),
                required_imports: vec![("jig_host".into(), "storage_put".into())],
                fuel_cost_estimate: 300_000,
                attestation_requirements: vec![],
            })
            .register(CapabilityDefinition {
                name: "ai:llm:inference".into(),
                description: "Large language model inference calls".into(),
                required_imports: vec![("jig_host".into(), "llm_call".into())],
                fuel_cost_estimate: 5_000_000,
                attestation_requirements: vec!["ai_usage_policy:v1".into()],
            })
            .register(CapabilityDefinition {
                name: "log:emit".into(),
                description: "Emit log messages to host".into(),
                required_imports: vec![("jig_host".into(), "log".into())],
                fuel_cost_estimate: 1_000,
                attestation_requirements: vec![],
            })
            .register(CapabilityDefinition {
                name: "message:emit".into(),
                description: "Emit messages to Jig protocol".into(),
                required_imports: vec![("jig_host".into(), "emit_message".into())],
                fuel_cost_estimate: 50_000,
                attestation_requirements: vec![],
            })
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::default_jig_capabilities()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_builtin_capabilities() {
        let registry = CapabilityRegistry::default();
        assert!(registry.contains("core:compute"));
        assert!(registry.contains("net:http:fetch"));
        assert!(registry.contains("storage:read"));
        assert!(registry.contains("ai:llm:inference"));
    }

    #[test]
    fn registry_lookup_returns_definition() {
        let registry = CapabilityRegistry::default();
        let def = registry.get("net:http:fetch").unwrap();
        assert_eq!(def.name, "net:http:fetch");
        assert_eq!(def.required_imports.len(), 1);
        assert_eq!(
            def.required_imports[0],
            ("jig_host".into(), "http_fetch".into())
        );
    }

    #[test]
    fn registry_returns_none_for_unknown() {
        let registry = CapabilityRegistry::default();
        assert!(registry.get("unknown:capability").is_none());
    }

    #[test]
    fn registry_lists_all_names() {
        let registry = CapabilityRegistry::default();
        let names = registry.names();
        assert!(names.contains(&"core:compute"));
        assert!(names.contains(&"net:http:fetch"));
        assert!(names.len() >= 5); // At least 5 built-in capabilities
    }

    #[test]
    fn custom_registry_can_register_capabilities() {
        let registry = CapabilityRegistry::new().register(CapabilityDefinition {
            name: "custom:test".into(),
            description: "Test capability".into(),
            required_imports: vec![("test".into(), "func".into())],
            fuel_cost_estimate: 1000,
            attestation_requirements: vec![],
        });

        assert!(registry.contains("custom:test"));
        let def = registry.get("custom:test").unwrap();
        assert_eq!(def.fuel_cost_estimate, 1000);
    }

    #[test]
    fn ai_capability_requires_attestation() {
        let registry = CapabilityRegistry::default();
        let def = registry.get("ai:llm:inference").unwrap();
        assert!(!def.attestation_requirements.is_empty());
        assert!(
            def.attestation_requirements
                .contains(&"ai_usage_policy:v1".into())
        );
    }

    #[test]
    fn core_compute_has_no_imports() {
        let registry = CapabilityRegistry::default();
        let def = registry.get("core:compute").unwrap();
        assert!(def.required_imports.is_empty());
    }
}
