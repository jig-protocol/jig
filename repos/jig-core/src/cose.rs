//! COSE_Sign1 (RFC 9052) with EdDSA over Ed25519, on deterministic CBOR.
//!
//! The one signing envelope for jig's signed objects. A `COSE_Sign1` is the
//! array `[protected, unprotected, payload, signature]`:
//!
//! - `protected` is the deterministic encoding of `{1: -8}` (alg: EdDSA);
//! - `unprotected` is an empty map;
//! - `payload` is the deterministic CBOR of the object, which carries its own
//!   `domain` tag;
//! - `signature` is Ed25519 over the `Sig_structure`
//!   `["Signature1", protected, h'', payload]`, deterministically encoded.
//!
//! Who signed is not in the envelope: every payload names its signer, and the
//! caller verifies against that DID. [`open`] refuses an envelope whose bytes
//! are not deterministic, so one object has exactly one encoding.

use ciborium::value::Value;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

use crate::dcbor::{self, DcborError};
use crate::did::Did;

/// COSE algorithm identifier for EdDSA (RFC 9053).
pub const ALG_EDDSA: i64 = -8;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CoseError {
    #[error(transparent)]
    Cbor(#[from] DcborError),
    #[error("not a COSE_Sign1 with EdDSA")]
    NotSign1,
    #[error("`{0}` is not a did:jig key")]
    BadDid(String),
    #[error("the signature is not by {0}")]
    BadSignature(String),
}

fn protected() -> Vec<u8> {
    dcbor::encode(&Value::Map(vec![(
        Value::Integer(1.into()),
        Value::Integer(ALG_EDDSA.into()),
    )]))
    .expect("a fixed map encodes")
}

fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    dcbor::encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
    .expect("byte strings encode")
}

/// Sign `payload` (already deterministic CBOR) as `key`.
pub fn sign(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
    let protected = protected();
    let sig = key.sign(&sig_structure(&protected, payload));
    dcbor::encode(&Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(Vec::new()),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig.to_bytes().to_vec()),
    ]))
    .expect("byte strings encode")
}

/// A parsed, not yet verified envelope.
pub struct Sign1 {
    pub payload: Vec<u8>,
    signature: [u8; 64],
}

/// Parse an envelope, refusing any that is not deterministic or not EdDSA.
pub fn open(bytes: &[u8]) -> Result<Sign1, CoseError> {
    let Value::Array(parts) = dcbor::decode(bytes)? else {
        return Err(CoseError::NotSign1);
    };
    let [
        Value::Bytes(prot),
        Value::Map(unprot),
        Value::Bytes(payload),
        Value::Bytes(sig),
    ] = parts.as_slice()
    else {
        return Err(CoseError::NotSign1);
    };
    if *prot != protected() || !unprot.is_empty() {
        return Err(CoseError::NotSign1);
    }
    let signature: [u8; 64] = sig.as_slice().try_into().map_err(|_| CoseError::NotSign1)?;
    Ok(Sign1 {
        payload: payload.clone(),
        signature,
    })
}

impl Sign1 {
    /// The envelope's signature is `did`'s, over its payload.
    pub fn verify(&self, did: &str) -> Result<(), CoseError> {
        let key = Did::from_did_jig_string(did)
            .and_then(|d| d.as_bytes())
            .ok()
            .and_then(|k| VerifyingKey::from_bytes(&k).ok())
            .ok_or_else(|| CoseError::BadDid(did.to_string()))?;
        key.verify(
            &sig_structure(&protected(), &self.payload),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| CoseError::BadSignature(did.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn did(key: &SigningKey) -> String {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    #[test]
    fn an_envelope_verifies_for_its_signer_only() {
        let payload = dcbor::encode(&dcbor::text_map(vec![(
            "domain",
            Value::Text("test".into()),
        )]))
        .unwrap();
        let env = sign(&key(1), &payload);
        let opened = open(&env).unwrap();
        assert_eq!(opened.payload, payload);
        assert_eq!(opened.verify(&did(&key(1))), Ok(()));
        assert_eq!(
            opened.verify(&did(&key(2))),
            Err(CoseError::BadSignature(did(&key(2))))
        );
    }

    #[test]
    fn a_tampered_or_reencoded_envelope_is_refused() {
        let payload = dcbor::encode(&Value::Text("x".into())).unwrap();
        let mut env = sign(&key(1), &payload);
        let last = env.len() - 1;
        env[last] ^= 1;
        assert!(matches!(
            open(&env).unwrap().verify(&did(&key(1))),
            Err(CoseError::BadSignature(_))
        ));
        // Not an array of four.
        assert_eq!(
            open(&dcbor::encode(&Value::Array(vec![])).unwrap()).err(),
            Some(CoseError::NotSign1)
        );
    }
}
