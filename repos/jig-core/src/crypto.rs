//! Cryptographic helpers for block packaging.
//!
//! Provides BLAKE3 hashing utilities that are reused across manifest, bundle, and receipt code.

use blake3::{Hash, Hasher};

/// Compute a BLAKE3 hash over arbitrary bytes.
#[inline]
pub fn blake3_hash(data: &[u8]) -> Hash {
    blake3::hash(data)
}

/// Compute a domain-separated BLAKE3 hash over a sequence of labelled byte slices.
///
/// Each entry is hashed as: `label || len || bytes`. Length is encoded as little-endian `u64`
/// to make the construction unambiguous.
pub fn hash_labeled_parts(parts: &[(&str, &[u8])]) -> Hash {
    let mut hasher = Hasher::new();
    for (label, bytes) in parts {
        hasher.update(label.as_bytes());
        hasher.update(&bytes.len().to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finalize()
}

/// Convenience for building hash inputs incrementally.
#[derive(Default)]
pub struct HashBuilder(Vec<(String, Vec<u8>)>);

impl HashBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a labelled byte slice.
    pub fn push(mut self, label: impl Into<String>, bytes: impl AsRef<[u8]>) -> Self {
        self.0.push((label.into(), bytes.as_ref().to_vec()));
        self
    }

    /// Finalise into a [`Hash`].
    pub fn finalize(self) -> Hash {
        let borrowed: Vec<(&str, &[u8])> = self
            .0
            .iter()
            .map(|(label, bytes)| (label.as_str(), bytes.as_slice()))
            .collect();
        hash_labeled_parts(&borrowed)
    }
}

#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use super::Hash;
    use crate::error::{JigError, Result};
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
    use rand::{RngCore, rngs::OsRng};

    /// Convenience wrapper around an ed25519 keypair.
    #[derive(Clone)]
    pub struct KeyPair {
        signing: SigningKey,
        verifying: VerifyingKey,
    }

    impl KeyPair {
        /// Generate a new random key pair.
        pub fn generate() -> Self {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            let signing = SigningKey::from_bytes(&seed);
            let verifying = signing.verifying_key();
            Self { signing, verifying }
        }

        /// Export the public key as raw bytes.
        pub fn public_key_bytes(&self) -> [u8; 32] {
            self.verifying.to_bytes()
        }

        /// Sign arbitrary bytes, returning the signature bytes.
        pub fn sign(&self, data: &[u8]) -> Vec<u8> {
            self.signing.sign(data).to_bytes().to_vec()
        }

        /// Sign a [`Hash`] (common when signing merkle roots).
        pub fn sign_hash(&self, hash: &Hash) -> Vec<u8> {
            self.sign(hash.as_bytes())
        }

        /// Verify an ed25519 signature.
        pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
            let sig = Signature::from_slice(signature)
                .map_err(|e| JigError::Crypto(format!("invalid signature: {e}")))?;
            self.verifying
                .verify(data, &sig)
                .map_err(|e| JigError::Crypto(format!("verification failed: {e}")))
        }

        /// Verify a signature against a hash.
        pub fn verify_hash(&self, hash: &Hash, signature: &[u8]) -> Result<()> {
            self.verify(hash.as_bytes(), signature)
        }
    }
}
