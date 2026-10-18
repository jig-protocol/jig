//! COSE signing (RFC 9052) with EdDSA over Ed25519, on deterministic CBOR.
//!
//! The one signing envelope for jig's signed objects. Two structures:
//!
//! - **`COSE_Sign1`**, one signer: `[protected, unprotected, payload, signature]`,
//!   signed over `["Signature1", protected, h'', payload]`.
//! - **`COSE_Sign`**, several signers who must all sign (an identity link, signed by
//!   the old and the new key): `[h'', {}, payload, [[protected, {}, signature], ...]]`,
//!   each signature over `["Signature", h'', protected, h'', payload]`. There is no
//!   "any one of them" mode: [`SignAll::verify_all`] takes the exact list of signers,
//!   in order, and every one must verify.
//!
//! In both, `protected` is the deterministic encoding of `{1: -8}` (alg: EdDSA), every
//! unprotected header is an empty map, there is no external AAD, and the envelope is
//! untagged and itself deterministically encoded. The payload is deterministic CBOR
//! ([`crate::dcbor`]) carrying its own `domain` entry.
//!
//! Who signed is not in the envelope: every payload names its signers, and the caller
//! verifies against those DIDs. [`open_sign1`] and [`open_sign`] refuse an envelope
//! that is not deterministic or uses any other header, so one signed object has
//! exactly one encoding.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::dcbor::{self, DcborError, Value};
use crate::did::Did;

/// COSE algorithm identifier for EdDSA (RFC 9053).
pub const ALG_EDDSA: i64 = -8;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CoseError {
    #[error(transparent)]
    Cbor(#[from] DcborError),
    #[error("not a COSE_Sign1 with EdDSA")]
    NotSign1,
    #[error("not a COSE_Sign with EdDSA")]
    NotSign,
    #[error("`{0}` is not a did:jig key")]
    BadDid(String),
    #[error("the signature is not by {0}")]
    BadSignature(String),
    #[error("the envelope has {got} signatures, not {want}")]
    SignerCount { want: usize, got: usize },
}

fn protected() -> Vec<u8> {
    dcbor::encode(&Value::Map(vec![(Value::int(1), Value::int(ALG_EDDSA))]))
        .expect("a fixed map encodes")
}

fn encode(v: Value) -> Vec<u8> {
    dcbor::encode(&v).expect("arrays of byte strings encode")
}

fn sig1_structure(payload: &[u8]) -> Vec<u8> {
    encode(Value::Array(vec![
        Value::text("Signature1"),
        Value::Bytes(protected()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
}

fn sig_structure(payload: &[u8]) -> Vec<u8> {
    encode(Value::Array(vec![
        Value::text("Signature"),
        Value::Bytes(Vec::new()),
        Value::Bytes(protected()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
}

fn verify_ed25519(did: &str, msg: &[u8], sig: &[u8; 64]) -> Result<(), CoseError> {
    let key = Did::from_did_jig_string(did)
        .and_then(|d| d.as_bytes())
        .ok()
        .and_then(|k| VerifyingKey::from_bytes(&k).ok())
        .ok_or_else(|| CoseError::BadDid(did.to_string()))?;
    key.verify_strict(msg, &Signature::from_bytes(sig))
        .map_err(|_| CoseError::BadSignature(did.to_string()))
}

fn signature(v: &Value) -> Option<[u8; 64]> {
    v.as_bytes()?.try_into().ok()
}

fn is_empty_map(v: &Value) -> bool {
    matches!(v, Value::Map(m) if m.is_empty())
}

/// Sign `payload` (already deterministic CBOR) as `key`: a `COSE_Sign1`.
pub fn sign1(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
    let sig = key.sign(&sig1_structure(payload));
    encode(Value::Array(vec![
        Value::Bytes(protected()),
        Value::Map(Vec::new()),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig.to_bytes().to_vec()),
    ]))
}

/// A parsed, not yet verified `COSE_Sign1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sign1 {
    pub payload: Vec<u8>,
    signature: [u8; 64],
}

/// Parse a `COSE_Sign1`, refusing any that is not deterministic or not as above.
pub fn open_sign1(bytes: &[u8]) -> Result<Sign1, CoseError> {
    let parts = dcbor::decode(bytes)?;
    let [Value::Bytes(prot), unprot, Value::Bytes(payload), sig] =
        parts.as_array().ok_or(CoseError::NotSign1)?
    else {
        return Err(CoseError::NotSign1);
    };
    if *prot != protected() || !is_empty_map(unprot) {
        return Err(CoseError::NotSign1);
    }
    Ok(Sign1 {
        payload: payload.clone(),
        signature: signature(sig).ok_or(CoseError::NotSign1)?,
    })
}

impl Sign1 {
    /// The signature is `did`'s, over the payload.
    pub fn verify(&self, did: &str) -> Result<(), CoseError> {
        verify_ed25519(did, &sig1_structure(&self.payload), &self.signature)
    }
}

/// Sign `payload` as every key in `keys`, in that order: a `COSE_Sign`.
pub fn sign_all(keys: &[&SigningKey], payload: &[u8]) -> Vec<u8> {
    let msg = sig_structure(payload);
    let signatures = keys
        .iter()
        .map(|k| {
            Value::Array(vec![
                Value::Bytes(protected()),
                Value::Map(Vec::new()),
                Value::Bytes(k.sign(&msg).to_bytes().to_vec()),
            ])
        })
        .collect();
    encode(Value::Array(vec![
        Value::Bytes(Vec::new()),
        Value::Map(Vec::new()),
        Value::Bytes(payload.to_vec()),
        Value::Array(signatures),
    ]))
}

/// A parsed, not yet verified `COSE_Sign`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignAll {
    pub payload: Vec<u8>,
    signatures: Vec<[u8; 64]>,
}

/// Parse a `COSE_Sign`, refusing any that is not deterministic or not as above.
pub fn open_sign(bytes: &[u8]) -> Result<SignAll, CoseError> {
    let parts = dcbor::decode(bytes)?;
    let [
        Value::Bytes(body_prot),
        unprot,
        Value::Bytes(payload),
        Value::Array(sigs),
    ] = parts.as_array().ok_or(CoseError::NotSign)?
    else {
        return Err(CoseError::NotSign);
    };
    if !body_prot.is_empty() || !is_empty_map(unprot) {
        return Err(CoseError::NotSign);
    }
    let signatures = sigs
        .iter()
        .map(|s| match s.as_array() {
            Some([Value::Bytes(prot), unprot, sig])
                if *prot == protected() && is_empty_map(unprot) =>
            {
                signature(sig)
            }
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(CoseError::NotSign)?;
    Ok(SignAll {
        payload: payload.clone(),
        signatures,
    })
}

impl SignAll {
    /// Exactly `dids.len()` signatures, the i-th by `dids[i]`, all over the payload.
    pub fn verify_all(&self, dids: &[&str]) -> Result<(), CoseError> {
        if self.signatures.len() != dids.len() {
            return Err(CoseError::SignerCount {
                want: dids.len(),
                got: self.signatures.len(),
            });
        }
        let msg = sig_structure(&self.payload);
        for (did, sig) in dids.iter().zip(&self.signatures) {
            verify_ed25519(did, &msg, sig)?;
        }
        Ok(())
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

    fn payload() -> Vec<u8> {
        dcbor::encode(&Value::text_map([("domain", Value::text("test"))])).unwrap()
    }

    #[test]
    fn a_sign1_verifies_for_its_signer_only() {
        let env = sign1(&key(1), &payload());
        let opened = open_sign1(&env).unwrap();
        assert_eq!(opened.payload, payload());
        assert_eq!(opened.verify(&did(&key(1))), Ok(()));
        assert_eq!(
            opened.verify(&did(&key(2))),
            Err(CoseError::BadSignature(did(&key(2))))
        );
    }

    #[test]
    fn a_tampered_or_reshaped_sign1_is_refused() {
        let mut env = sign1(&key(1), &payload());
        let last = env.len() - 1;
        env[last] ^= 1;
        assert!(matches!(
            open_sign1(&env).unwrap().verify(&did(&key(1))),
            Err(CoseError::BadSignature(_))
        ));
        let reshaped = |parts: Vec<Value>| encode(Value::Array(parts));
        let sig = Value::Bytes(vec![0; 64]);
        for bad in [
            reshaped(vec![]),
            // Another algorithm (ES256, -7).
            reshaped(vec![
                Value::Bytes(encode(Value::Map(vec![(Value::int(1), Value::int(-7))]))),
                Value::Map(vec![]),
                Value::Bytes(payload()),
                sig.clone(),
            ]),
            // A non-empty unprotected header (a kid).
            reshaped(vec![
                Value::Bytes(protected()),
                Value::Map(vec![(Value::int(4), Value::Bytes(b"k".to_vec()))]),
                Value::Bytes(payload()),
                sig.clone(),
            ]),
            // A short signature.
            reshaped(vec![
                Value::Bytes(protected()),
                Value::Map(vec![]),
                Value::Bytes(payload()),
                Value::Bytes(vec![0; 63]),
            ]),
        ] {
            assert_eq!(open_sign1(&bad), Err(CoseError::NotSign1));
        }
        // The tagged form (18) is another encoding of the same envelope.
        let tagged = encode(Value::Tag(
            18,
            Box::new(dcbor::decode(&sign1(&key(1), &payload())).unwrap()),
        ));
        assert_eq!(open_sign1(&tagged), Err(CoseError::NotSign1));
    }

    #[test]
    fn a_sign_needs_every_listed_signer_in_order() {
        let (a, b) = (key(1), key(2));
        let (da, db) = (did(&a), did(&b));
        let env = sign_all(&[&a, &b], &payload());
        let opened = open_sign(&env).unwrap();
        assert_eq!(opened.payload, payload());
        assert_eq!(opened.verify_all(&[&da, &db]), Ok(()));
        // Order, a missing signer, an extra one and a stranger all fail.
        assert!(opened.verify_all(&[&db, &da]).is_err());
        assert_eq!(
            opened.verify_all(&[&da]),
            Err(CoseError::SignerCount { want: 1, got: 2 })
        );
        let one = open_sign(&sign_all(&[&a], &payload())).unwrap();
        assert_eq!(
            one.verify_all(&[&da, &db]),
            Err(CoseError::SignerCount { want: 2, got: 1 })
        );
        let dc = did(&key(3));
        assert_eq!(
            opened.verify_all(&[&da, &dc]),
            Err(CoseError::BadSignature(dc.clone()))
        );
        // A Sign1 signature does not stand in for a Sign signature: the
        // structures are domain-separated by their context strings.
        assert!(open_sign(&sign1(&a, &payload())).is_err());
    }

    /// Fixed-key vectors: a change to the envelope's bytes fails here.
    #[test]
    fn envelopes_match_their_vectors() {
        let p = payload();
        assert_eq!(hex::encode(&p), "a166646f6d61696e6474657374");
        assert_eq!(
            hex::encode(sign1(&key(1), &p)),
            "8443a10127a04da166646f6d61696e64746573745840183eab932f92f3fd421aafadb1b4ebdf1a47134987326172\
             69a6f51a81a16894df92bb35b5a4d10d875ebf09e7f405dff3fa297b62e56a222612b58e3d5b9400"
        );
        assert_eq!(
            hex::encode(sign_all(&[&key(1), &key(2)], &p)),
            "8440a04da166646f6d61696e6474657374828343a10127a058401fb388543b9a3bd4a21b787c9dff4f1171101db6\
             2005a2612c970fff3597bdbd4a7a8ff2c4e4af0b8a75cc5b9266c02f4a730db28524ff000a7f5bf393298f088343\
             a10127a058400b2b1c36c2e7af0b1d996b8677880e83bfe9f629624dd8c8ebcf8619ba62a8165084018445697284\
             74030b9fda9199c08f9c57ca2c4a5024b633bdfe311a5202"
        );
    }
}
