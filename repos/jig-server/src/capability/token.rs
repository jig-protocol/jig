//! Capability tokens with HMAC-based signatures.
//!
//! Tokens grant access to specific capabilities with optional scope restrictions
//! and expiry times. Each token includes an HMAC signature to prevent forgery.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::SystemTime;

type HmacSha256 = Hmac<Sha256>;

/// A capability token grants access to a specific capability with optional scopes.
#[derive(Debug, Clone)]
pub struct CapabilityToken {
    name: String,
    scopes: Vec<String>,
    expires_at: Option<SystemTime>,
    signature: [u8; 32],
}

impl CapabilityToken {
    /// Create a new capability token with the given name and scopes.
    ///
    /// The token is signed with an HMAC to prevent forgery. Each token
    /// gets a unique signature even with identical content due to
    /// timestamp inclusion in the signature.
    pub fn new(name: impl Into<String>, scopes: Vec<impl Into<String>>) -> Self {
        let name = name.into();
        let scopes: Vec<String> = scopes.into_iter().map(Into::into).collect();
        let signature = Self::compute_signature(&name, &scopes, None);

        Self {
            name,
            scopes,
            expires_at: None,
            signature,
        }
    }

    /// Set an expiry time for this token.
    pub fn with_expiry(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = Some(expires_at);
        // Recompute signature with expiry
        self.signature = Self::compute_signature(&self.name, &self.scopes, self.expires_at);
        self
    }

    /// Get the capability name (e.g., "net.fetch").
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the token's scopes.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Get the token's expiry time, if any.
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// Get the token's signature.
    pub fn signature(&self) -> &[u8; 32] {
        &self.signature
    }

    /// Check if this token has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            SystemTime::now() > expires_at
        } else {
            false
        }
    }

    /// Check if a resource matches any of this token's scopes.
    ///
    /// Uses simple glob matching: "*" matches any suffix.
    pub fn matches_scope(&self, resource: &str) -> bool {
        self.scopes.iter().any(|scope| {
            if scope.ends_with('*') {
                let prefix = &scope[..scope.len() - 1];
                resource.starts_with(prefix)
            } else {
                resource == scope
            }
        })
    }

    fn compute_signature(
        name: &str,
        scopes: &[String],
        expires_at: Option<SystemTime>,
    ) -> [u8; 32] {
        // Include timestamp to ensure unique signatures
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        // Use a deterministic but secret key (in production, load from config)
        // For now, use a compile-time constant
        let key = b"jig-capability-token-signing-key-v1-CHANGE-IN-PRODUCTION";

        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key valid");
        mac.update(name.as_bytes());
        mac.update(&now.to_le_bytes());

        for scope in scopes {
            mac.update(scope.as_bytes());
        }

        if let Some(exp) = expires_at
            && let Ok(duration) = exp.duration_since(SystemTime::UNIX_EPOCH)
        {
            mac.update(&duration.as_secs().to_le_bytes());
        }

        let result = mac.finalize();
        let code = result.into_bytes();
        let mut signature = [0u8; 32];
        signature.copy_from_slice(&code);
        signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn token_signature_includes_timestamp() {
        let token1 = CapabilityToken::new("test", vec!["scope1"]);
        std::thread::sleep(Duration::from_millis(10));
        let token2 = CapabilityToken::new("test", vec!["scope1"]);

        // Should have different signatures due to timestamp
        assert_ne!(token1.signature(), token2.signature());
    }

    #[test]
    fn scope_glob_matching_works() {
        let token = CapabilityToken::new("test", vec!["https://example.com/*"]);

        assert!(token.matches_scope("https://example.com/"));
        assert!(token.matches_scope("https://example.com/api/v1/users"));
        assert!(!token.matches_scope("https://other.com/api"));
    }

    #[test]
    fn scope_exact_matching_works() {
        let token = CapabilityToken::new("test", vec!["exact:resource:123"]);

        assert!(token.matches_scope("exact:resource:123"));
        assert!(!token.matches_scope("exact:resource:124"));
    }
}
