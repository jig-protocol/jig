//! Capability registry for managing and validating tokens.

use std::collections::HashMap;

use super::token::CapabilityToken;
use crate::error::{Result, ServerError};

/// Registry of capability tokens for the current execution context.
///
/// Deny-by-default: capabilities must be explicitly registered before use.
#[derive(Debug)]
pub struct CapabilityRegistry {
    tokens: HashMap<String, CapabilityToken>,
    usage_counts: HashMap<String, u64>,
}

impl CapabilityRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
            usage_counts: HashMap::new(),
        }
    }

    /// Register a capability token.
    ///
    /// If a token with the same name already exists, it will be replaced.
    pub fn register(&mut self, token: CapabilityToken) {
        let name = token.name().to_string();
        self.tokens.insert(name, token);
    }

    /// Validate that a capability is available and not expired.
    ///
    /// Returns an error if:
    /// - The capability is not registered (denied by default)
    /// - The token has expired
    ///
    /// On success, increments the usage counter for telemetry.
    pub fn validate(&mut self, capability_name: &str) -> Result<()> {
        match self.tokens.get(capability_name) {
            None => Err(ServerError::CapabilityDenied(format!(
                "capability not granted: {capability_name}"
            ))),
            Some(token) if token.is_expired() => Err(ServerError::CapabilityDenied(format!(
                "capability expired: {capability_name}"
            ))),
            Some(_) => {
                // Token is valid - increment usage counter
                *self
                    .usage_counts
                    .entry(capability_name.to_string())
                    .or_insert(0) += 1;
                Ok(())
            }
        }
    }

    /// Revoke a capability token.
    ///
    /// After revocation, attempts to validate the capability will fail.
    pub fn revoke(&mut self, capability_name: &str) {
        self.tokens.remove(capability_name);
    }

    /// Get the usage count for a capability.
    ///
    /// Returns the number of times the capability has been successfully validated.
    pub fn usage_count(&self, capability_name: &str) -> u64 {
        self.usage_counts.get(capability_name).copied().unwrap_or(0)
    }

    /// Get a snapshot of all usage counts for telemetry.
    pub fn usage_snapshot(&self) -> HashMap<String, u64> {
        self.usage_counts.clone()
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn registry_tracks_usage_counts() {
        let mut registry = CapabilityRegistry::new();
        let token = CapabilityToken::new("test", vec!["*"]);
        registry.register(token);

        assert_eq!(registry.usage_count("test"), 0);

        registry.validate("test").unwrap();
        assert_eq!(registry.usage_count("test"), 1);

        registry.validate("test").unwrap();
        assert_eq!(registry.usage_count("test"), 2);
    }

    #[test]
    fn registry_deny_by_default() {
        let registry = CapabilityRegistry::new();
        assert!(registry.tokens.is_empty());
    }

    #[test]
    fn revoked_token_validation_fails() {
        let mut registry = CapabilityRegistry::new();
        registry.register(CapabilityToken::new("test", vec!["*"]));

        assert!(registry.validate("test").is_ok());

        registry.revoke("test");

        assert!(registry.validate("test").is_err());
    }

    #[test]
    fn expired_token_does_not_increment_usage() {
        let mut registry = CapabilityRegistry::new();
        let expired = SystemTime::now() - Duration::from_secs(1);
        let token = CapabilityToken::new("test", vec!["*"]).with_expiry(expired);
        registry.register(token);

        assert!(registry.validate("test").is_err());
        assert_eq!(registry.usage_count("test"), 0);
    }
}
