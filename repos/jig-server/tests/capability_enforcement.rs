use jig_server::capability::{CapabilityRegistry, CapabilityToken};
use std::time::{Duration, SystemTime};

#[test]
fn token_creation_with_name_and_scopes() {
    let token = CapabilityToken::new("net.fetch", vec!["https://api.example.com/*"]);
    assert_eq!(token.name(), "net.fetch");
    assert_eq!(token.scopes().len(), 1);
}

#[test]
fn token_with_expiry() {
    let expiry = SystemTime::now() + Duration::from_secs(3600);
    let token =
        CapabilityToken::new("net.fetch", vec!["https://api.example.com/*"]).with_expiry(expiry);
    assert!(token.expires_at().is_some());
}

#[test]
fn registry_validates_present_token() {
    let mut registry = CapabilityRegistry::new();
    let token = CapabilityToken::new("net.fetch", vec!["https://api.example.com/*"]);

    registry.register(token);

    // Should succeed
    assert!(registry.validate("net.fetch").is_ok());
}

#[test]
fn registry_denies_missing_token() {
    let mut registry = CapabilityRegistry::new();

    // Should fail - no token registered
    let result = registry.validate("net.fetch");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("denied"));
}

#[test]
fn registry_denies_expired_token() {
    let mut registry = CapabilityRegistry::new();

    // Token expired 1 hour ago
    let expiry = SystemTime::now() - Duration::from_secs(3600);
    let token =
        CapabilityToken::new("net.fetch", vec!["https://api.example.com/*"]).with_expiry(expiry);

    registry.register(token);

    // Should fail - token expired
    let result = registry.validate("net.fetch");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
}

#[test]
fn registry_validates_non_expired_token() {
    let mut registry = CapabilityRegistry::new();

    // Token expires in 1 hour
    let expiry = SystemTime::now() + Duration::from_secs(3600);
    let token =
        CapabilityToken::new("net.fetch", vec!["https://api.example.com/*"]).with_expiry(expiry);

    registry.register(token);

    // Should succeed - token not expired
    assert!(registry.validate("net.fetch").is_ok());
}

#[test]
fn registry_allows_multiple_capabilities() {
    let mut registry = CapabilityRegistry::new();

    registry.register(CapabilityToken::new(
        "net.fetch",
        vec!["https://api.example.com/*"],
    ));
    registry.register(CapabilityToken::new("storage.read", vec!["cid:*"]));

    assert!(registry.validate("net.fetch").is_ok());
    assert!(registry.validate("storage.read").is_ok());
    assert!(registry.validate("crypto.sign").is_err());
}

#[test]
fn registry_revoke_invalidates_token() {
    let mut registry = CapabilityRegistry::new();

    registry.register(CapabilityToken::new(
        "net.fetch",
        vec!["https://api.example.com/*"],
    ));
    assert!(registry.validate("net.fetch").is_ok());

    registry.revoke("net.fetch");
    assert!(registry.validate("net.fetch").is_err());
}

#[test]
fn token_scope_matching() {
    let token = CapabilityToken::new(
        "net.fetch",
        vec!["https://api.example.com/*", "https://example.org/v1/*"],
    );

    assert!(token.matches_scope("https://api.example.com/users"));
    assert!(token.matches_scope("https://example.org/v1/data"));
    assert!(!token.matches_scope("https://evil.com/steal"));
}

#[test]
fn token_cannot_be_forged() {
    let token1 = CapabilityToken::new("net.fetch", vec!["https://api.example.com/*"]);
    let token2 = CapabilityToken::new("net.fetch", vec!["https://api.example.com/*"]);

    // Tokens should have different signatures even with same content
    assert_ne!(token1.signature(), token2.signature());
}
