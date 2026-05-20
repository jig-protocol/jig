//! Crypto helpers for verifying identity claims

use crate::error::{NameServerError, Result};
use crate::types::{Claim, PublicKeyEd25519};
use ed25519_dalek::{Signature, VerifyingKey};

pub fn verify_claim(claim: &Claim) -> Result<()> {
    let pk = VerifyingKey::from_bytes(&claim.key.0)
        .map_err(|e| NameServerError::Crypto(format!("invalid public key: {e}")))?;
    let msg = claim_message_to_sign(claim);
    let sig = Signature::from_slice(&claim.signature)
        .map_err(|e| NameServerError::Crypto(format!("invalid signature: {e}")))?;
    pk.verify_strict(msg.as_bytes(), &sig)
        .map_err(|e| NameServerError::Crypto(format!("signature verification failed: {e}")))
}

pub fn claim_message_to_sign(claim: &Claim) -> String {
    // Stable canonicalization for signing
    format!(
        "subject={};key={};issued_at={};expires_at={};statement={};issuer={}",
        claim.subject.handle,
        hex::encode(claim.key.0),
        claim.issued_at.timestamp(),
        claim.expires_at.map(|d| d.timestamp()).unwrap_or(0),
        claim.statement,
        claim.issuer
    )
}

pub fn parse_public_key_hex(hex_str: &str) -> Result<PublicKeyEd25519> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| NameServerError::BadRequest(format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(NameServerError::BadRequest(
            "ed25519 key must be 32 bytes".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKeyEd25519(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verify_happy_path() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        let claim = Claim {
            subject: crate::types::IdentityHandle {
                handle: "alice@example.com".into(),
            },
            key: PublicKeyEd25519(vk.as_bytes().to_owned()),
            issued_at: Utc::now(),
            expires_at: None,
            statement: "bind handle to key".into(),
            issuer: "alice@example.com".into(),
            signature: vec![],
        };
        let msg = claim_message_to_sign(&claim);
        let sig = sk.sign(msg.as_bytes());
        let mut claim = claim;
        claim.signature = sig.to_bytes().to_vec();
        assert!(verify_claim(&claim).is_ok());
    }
}
