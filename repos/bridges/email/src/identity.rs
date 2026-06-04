//! Deterministic shadow-DID derivation. The bridge owns these proxy
//! identities (one per external email); they are NOT real users' keys.
//!
//! A shadow keypair is `HKDF-SHA256(ikm = normalized_email, salt =
//! bridge_secret)` expanded with a fixed info string into 32 seed bytes, used
//! as an ed25519 signing key. Determinism across restarts is the contract:
//! the same (secret, email) always yields the same DID.

use ed25519_dalek::SigningKey;
use jig_core::Did;

/// Derive a stable ed25519 keypair for `email` from `bridge_secret`.
pub fn shadow_signing_key(bridge_secret: &str, email: &str, strip_plus_tags: bool) -> SigningKey {
    let norm = normalize_email(email, strip_plus_tags);
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(bridge_secret.as_bytes()), norm.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(b"jig-bridge-email-shadow", &mut seed)
        .expect("32 is a valid sha256 hkdf output length");
    SigningKey::from_bytes(&seed)
}

/// The canonical shadow DID for `email`.
pub fn shadow_did(bridge_secret: &str, email: &str, strip_plus_tags: bool) -> Did {
    let sk = shadow_signing_key(bridge_secret, email, strip_plus_tags);
    Did::from_ed25519_pubkey(sk.verifying_key().as_bytes())
}

/// Normalize an email for keying: trim + lowercase, and (optionally) strip a
/// `+tag` suffix from the local-part so `alice+news@x` keys the same as
/// `alice@x`.
pub fn normalize_email(email: &str, strip_plus_tags: bool) -> String {
    let e = email.trim().to_lowercase();
    if !strip_plus_tags {
        return e;
    }
    match e.split_once('@') {
        Some((local, domain)) => {
            let base = local.split('+').next().unwrap_or(local);
            format!("{base}@{domain}")
        }
        None => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_email_same_secret_is_deterministic() {
        let a = shadow_did("secret", "Alice@Example.com", false);
        let b = shadow_did("secret", "alice@example.com", false); // case-normalized
        assert_eq!(a.to_did_jig_string(), b.to_did_jig_string());
    }

    #[test]
    fn different_secret_yields_different_did() {
        let a = shadow_did("secret-1", "alice@example.com", false);
        let b = shadow_did("secret-2", "alice@example.com", false);
        assert_ne!(a.to_did_jig_string(), b.to_did_jig_string());
    }

    #[test]
    fn plus_tag_stripping_optional() {
        let tagged = shadow_did("s", "alice+news@example.com", true);
        let plain = shadow_did("s", "alice@example.com", true);
        assert_eq!(tagged.to_did_jig_string(), plain.to_did_jig_string());
        // Without stripping, they differ:
        let tagged2 = shadow_did("s", "alice+news@example.com", false);
        assert_ne!(tagged2.to_did_jig_string(), plain.to_did_jig_string());
    }

    #[test]
    fn did_is_canonical_form() {
        let d = shadow_did("s", "alice@example.com", false);
        assert!(d.to_did_jig_string().starts_with("did:jig:z"));
    }
}
