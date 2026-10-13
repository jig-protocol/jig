//! The binding between an MLS leaf and a `did:jig`.
//!
//! A leaf is acceptable only if its basic credential's identity is the
//! canonical spelling of a `did:jig` whose key is the leaf's signature key.
//! Without the check, a group member — or a server forging an external join —
//! could put a leaf in the tree that *says* it is someone else.

use jig_core::Did;
use openmls::prelude::{BasicCredential, Credential, CredentialWithKey, LeafNode};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;

use crate::{MlsError, Result};

/// The credential a DID's leaf carries.
pub fn credential_for(did: &Did) -> Result<CredentialWithKey> {
    let key = did
        .as_bytes()
        .map_err(|e| MlsError::Unbound(format!("{did} is not a key-derived DID: {e}")))?;
    let canonical = Did::from_ed25519_pubkey(&key).to_did_jig_string();
    Ok(CredentialWithKey {
        credential: BasicCredential::new(canonical.into_bytes()).into(),
        signature_key: key.to_vec().into(),
    })
}

/// The DID's own signing key as an MLS signer. `seed` is the 32-byte Ed25519
/// secret the identity file holds.
pub fn signer_from_seed(seed: &[u8; 32], did: &Did) -> Result<SignatureKeyPair> {
    let public = did
        .as_bytes()
        .map_err(|e| MlsError::Unbound(format!("{did} is not a key-derived DID: {e}")))?;
    Ok(SignatureKeyPair::from_raw(
        SignatureScheme::ED25519,
        seed.to_vec(),
        public.to_vec(),
    ))
}

/// The DID a credential names, if and only if `signature_key` is that DID's
/// key. Returns the canonical DID string.
pub fn bound_did(credential: &Credential, signature_key: &[u8]) -> Result<String> {
    let basic = BasicCredential::try_from(credential.clone())
        .map_err(|e| MlsError::Unbound(format!("not a basic credential: {e}")))?;
    let identity = std::str::from_utf8(basic.identity())
        .map_err(|_| MlsError::Unbound("credential identity is not UTF-8".to_string()))?;
    let did = Did::from_did_jig_string(identity)
        .map_err(|e| MlsError::Unbound(format!("`{identity}` is not a did:jig: {e}")))?;
    let key = did
        .as_bytes()
        .map_err(|e| MlsError::Unbound(format!("`{identity}` has no key: {e}")))?;
    let canonical = Did::from_ed25519_pubkey(&key).to_did_jig_string();
    if canonical != identity {
        return Err(MlsError::Unbound(format!(
            "`{identity}` is not in canonical form"
        )));
    }
    if key.as_slice() != signature_key {
        return Err(MlsError::Unbound(format!(
            "`{identity}` does not match the leaf's signature key"
        )));
    }
    Ok(canonical)
}

/// [`bound_did`] for a leaf node.
pub fn leaf_did(leaf: &LeafNode) -> Result<String> {
    bound_did(leaf.credential(), leaf.signature_key().as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(seed: u8) -> Did {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        Did::from_ed25519_pubkey(&key.verifying_key().to_bytes())
    }

    #[test]
    fn a_did_credential_is_bound_to_its_own_key() {
        let d = did(1);
        let c = credential_for(&d).unwrap();
        assert_eq!(
            bound_did(&c.credential, c.signature_key.as_slice()).unwrap(),
            d.to_did_jig_string()
        );
    }

    #[test]
    fn a_credential_naming_someone_else_is_unbound() {
        let alice = credential_for(&did(1)).unwrap();
        let mallory = credential_for(&did(2)).unwrap();
        assert!(matches!(
            bound_did(&alice.credential, mallory.signature_key.as_slice()),
            Err(MlsError::Unbound(_))
        ));
    }

    #[test]
    fn a_non_canonical_spelling_is_unbound() {
        let d = did(1).to_did_jig_string();
        let shouted = format!("did:jig:{}", d["did:jig:".len()..].to_uppercase());
        let key = did(1).as_bytes().unwrap();
        let c: Credential = BasicCredential::new(shouted.into_bytes()).into();
        assert!(matches!(bound_did(&c, &key), Err(MlsError::Unbound(_))));
    }
}
