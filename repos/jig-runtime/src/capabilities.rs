//! Capability security model
//!
//! This module implements a closed-by-default capability system where WebAssembly modules
//! must explicitly request capabilities and have them granted via allowlists.
//!
//! ## Security Model
//!
//! - **Deny by default**: No capabilities available unless explicitly granted
//! - **Allowlist-based**: Only capabilities in the allowlist can be requested
//! - **Per-execution**: Capabilities are granted per execution context
//! - **Quota enforcement**: Each capability can have usage quotas
//! - **Opaque handles**: Modules receive handles, not direct access

#![allow(dead_code)] // Future implementation

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use jig_core::CapabilityScopePattern;

use crate::config::CapabilityConfig;
use crate::error::{Result, RuntimeError};

/// Global counter for generating unique capability handle IDs
static HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Capability registry managing allowlists and policy enforcement
pub struct CapabilityRegistry {
    /// Allowed capability names
    allowed: HashSet<String>,

    /// Per-capability quotas
    quotas: HashMap<String, CapabilityQuota>,

    /// Allowed scope patterns keyed by capability
    scope_policies: HashMap<String, Vec<CapabilityScopePattern>>,

    /// Deny all by default
    deny_by_default: bool,

    /// Active handles for this execution
    active_handles: HashMap<u64, CapabilityHandle>,
}

impl CapabilityRegistry {
    /// Create a new capability registry from configuration
    pub fn new(config: &CapabilityConfig) -> Result<Self> {
        let mut allowed = HashSet::new();
        for cap in &config.allowed {
            allowed.insert(cap.clone());
        }

        let mut quotas = HashMap::new();
        for (cap_name, quota_config) in &config.quotas {
            quotas.insert(
                cap_name.clone(),
                CapabilityQuota {
                    max_calls: quota_config.max_calls,
                    max_bytes: quota_config.max_bytes,
                    fuel_allocation: quota_config.fuel_allocation,
                    calls_used: 0,
                    bytes_used: 0,
                    fuel_used: 0,
                },
            );
        }

        let mut scope_policies = HashMap::new();
        for (capability, scopes) in &config.scope_policies {
            let patterns = scopes
                .iter()
                .map(|s| {
                    CapabilityScopePattern::parse(s)
                        .map_err(|e| RuntimeError::ValidationError(e.to_string()))
                })
                .collect::<Result<Vec<_>>>()?;
            scope_policies.insert(capability.clone(), patterns);
        }

        Ok(Self {
            allowed,
            quotas,
            scope_policies,
            deny_by_default: config.deny_by_default,
            active_handles: HashMap::new(),
        })
    }

    /// Check if a capability is allowed
    pub fn is_allowed(&self, capability: &str) -> bool {
        if self.deny_by_default {
            self.allowed.contains(capability)
        } else {
            // If not deny-by-default, all capabilities are allowed unless explicitly denied
            !self.allowed.contains(capability)
        }
    }

    /// Request a capability handle
    ///
    /// Returns a handle if the capability is allowed, or an error if denied.
    pub fn request_capability(&mut self, capability: &str) -> Result<CapabilityHandle> {
        // Check allowlist
        if !self.is_allowed(capability) {
            return Err(RuntimeError::CapabilityDenied {
                capability: capability.to_string(),
            });
        }

        // Generate unique handle ID
        let handle_id = HANDLE_COUNTER.fetch_add(1, Ordering::SeqCst);

        // Create handle
        let handle = CapabilityHandle {
            id: handle_id,
            capability: capability.to_string(),
            revoked: false,
        };

        // Store active handle
        self.active_handles.insert(handle_id, handle.clone());

        Ok(handle)
    }

    /// Validate a capability handle
    pub fn validate_handle(&self, handle: &CapabilityHandle) -> Result<()> {
        // Check if handle is in active set and get the registry's copy
        if let Some(registry_handle) = self.active_handles.get(&handle.id) {
            // Check if the registry's copy is revoked
            if registry_handle.revoked {
                return Err(RuntimeError::InvalidCapabilityHandle);
            }
            Ok(())
        } else {
            Err(RuntimeError::InvalidCapabilityHandle)
        }
    }

    /// Revoke a capability handle
    pub fn revoke_handle(&mut self, handle_id: u64) -> Result<()> {
        if let Some(handle) = self.active_handles.get_mut(&handle_id) {
            handle.revoked = true;
            Ok(())
        } else {
            Err(RuntimeError::InvalidCapabilityHandle)
        }
    }

    /// Record capability usage for quota tracking
    pub fn record_usage(
        &mut self,
        capability: &str,
        calls: u32,
        bytes: u64,
        fuel: u64,
    ) -> Result<()> {
        if let Some(quota) = self.quotas.get_mut(capability) {
            quota.calls_used += calls;
            quota.bytes_used += bytes;
            quota.fuel_used += fuel;

            // Check quota limits
            if let Some(max_calls) = quota.max_calls
                && quota.calls_used > max_calls
            {
                return Err(RuntimeError::CapabilityQuotaExceeded {
                    capability: capability.to_string(),
                });
            }

            if let Some(max_bytes) = quota.max_bytes
                && quota.bytes_used > max_bytes
            {
                return Err(RuntimeError::CapabilityQuotaExceeded {
                    capability: capability.to_string(),
                });
            }

            if let Some(fuel_allocation) = quota.fuel_allocation
                && quota.fuel_used > fuel_allocation
            {
                return Err(RuntimeError::CapabilityQuotaExceeded {
                    capability: capability.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Get usage statistics for a capability
    pub fn get_usage(&self, capability: &str) -> Option<CapabilityUsage> {
        self.quotas.get(capability).map(|quota| CapabilityUsage {
            calls: quota.calls_used,
            bytes: quota.bytes_used,
            fuel: quota.fuel_used,
        })
    }

    /// List all allowed capabilities
    pub fn list_allowed(&self) -> Vec<String> {
        self.allowed.iter().cloned().collect()
    }
}

/// Opaque capability handle
///
/// Modules receive handles instead of direct access to capabilities.
/// Handles can be validated and revoked by the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityHandle {
    /// Unique handle ID
    pub id: u64,

    /// Capability name (e.g., "http", "kv", "crypto")
    pub capability: String,

    /// Whether this handle has been revoked
    pub revoked: bool,
}

impl CapabilityHandle {
    /// Check if the handle is still valid
    pub fn is_valid(&self) -> bool {
        !self.revoked
    }
}

/// Per-capability quota tracking
#[derive(Debug, Clone)]
struct CapabilityQuota {
    // Limits
    max_calls: Option<u32>,
    max_bytes: Option<u64>,
    fuel_allocation: Option<u64>,

    // Usage counters
    calls_used: u32,
    bytes_used: u64,
    fuel_used: u64,
}

/// Usage statistics for a capability
#[derive(Debug, Clone)]
pub struct CapabilityUsage {
    pub calls: u32,
    pub bytes: u64,
    pub fuel: u64,
}

// Capability API namespace modules
// These define the public API surface for runtime capabilities.
// Host functions and WIT bindings will be implemented in future milestones.

pub mod http {
    //! HTTP capability interface
    //!
    //! API namespace for controlled HTTP requests with domain allowlists and bandwidth quotas.
    //! Implementation will be provided by capability handlers.
}

pub mod kv {
    //! Key-value storage capability
    //!
    //! API namespace for in-memory key-value storage with namespacing and quotas.
    //! Implementation will be provided by capability handlers.
}

pub mod clock {
    //! Clock capability
    //!
    //! API namespace for deterministic, monotonic time source.
    //! Implementation will be provided by capability handlers.
}

pub mod rand {
    //! Random number generation capability
    //!
    //! API namespace for deterministic randomness from seed in ExecutionContext.
    //! Implementation will be provided by capability handlers.
}

pub mod crypto {
    //! Cryptographic operations capability
    //!
    //! API namespace for hashing and signature verification (no secret key operations).
    //! Implementation will be provided by capability handlers.
}

pub mod env {
    //! Environment variable access capability
    //!
    //! API namespace for read-only access to allowlisted environment variables.
    //! Implementation will be provided by capability handlers.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CapabilityConfig;

    fn test_config() -> CapabilityConfig {
        CapabilityConfig {
            allowed: vec!["http".to_string(), "kv".to_string()],
            quotas: HashMap::new(),
            scope_policies: HashMap::new(),
            deny_by_default: true,
        }
    }

    #[test]
    fn test_registry_creation() {
        let config = test_config();
        let registry = CapabilityRegistry::new(&config);
        assert!(registry.is_ok());
    }

    #[test]
    fn test_allowlist_enforcement() {
        let config = test_config();
        let registry = CapabilityRegistry::new(&config).unwrap();

        // Allowed capabilities
        assert!(registry.is_allowed("http"));
        assert!(registry.is_allowed("kv"));

        // Denied capabilities
        assert!(!registry.is_allowed("filesystem"));
        assert!(!registry.is_allowed("network"));
    }

    #[test]
    fn test_capability_request() {
        let config = test_config();
        let mut registry = CapabilityRegistry::new(&config).unwrap();

        // Request allowed capability
        let handle = registry.request_capability("http");
        assert!(handle.is_ok());
        let handle = handle.unwrap();
        assert_eq!(handle.capability, "http");
        assert!(handle.is_valid());

        // Request denied capability
        let result = registry.request_capability("filesystem");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RuntimeError::CapabilityDenied { .. }
        ));
    }

    #[test]
    fn test_handle_validation() {
        let config = test_config();
        let mut registry = CapabilityRegistry::new(&config).unwrap();

        let handle = registry.request_capability("http").unwrap();
        assert!(registry.validate_handle(&handle).is_ok());
    }

    #[test]
    fn test_handle_revocation() {
        let config = test_config();
        let mut registry = CapabilityRegistry::new(&config).unwrap();

        let handle = registry.request_capability("http").unwrap();
        let handle_id = handle.id;

        // Revoke handle
        assert!(registry.revoke_handle(handle_id).is_ok());

        // Validation should fail after revocation
        assert!(registry.validate_handle(&handle).is_err());
    }

    #[test]
    fn test_quota_tracking() {
        let mut config = test_config();
        config.quotas.insert(
            "http".to_string(),
            crate::config::CapabilityQuota {
                max_calls: Some(10),
                max_bytes: Some(1024),
                fuel_allocation: Some(100000),
            },
        );

        let mut registry = CapabilityRegistry::new(&config).unwrap();

        // Record usage within limits
        assert!(registry.record_usage("http", 5, 512, 50000).is_ok());

        // Check usage stats
        let usage = registry.get_usage("http").unwrap();
        assert_eq!(usage.calls, 5);
        assert_eq!(usage.bytes, 512);
        assert_eq!(usage.fuel, 50000);

        // Exceed call limit
        let result = registry.record_usage("http", 10, 0, 0);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RuntimeError::CapabilityQuotaExceeded { .. }
        ));
    }

    #[test]
    fn test_list_allowed() {
        let config = test_config();
        let registry = CapabilityRegistry::new(&config).unwrap();

        let allowed = registry.list_allowed();
        assert_eq!(allowed.len(), 2);
        assert!(allowed.contains(&"http".to_string()));
        assert!(allowed.contains(&"kv".to_string()));
    }
}
