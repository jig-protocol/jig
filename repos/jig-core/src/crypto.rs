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
    // rand 0.10 renamed the byte-filling trait `RngCore` -> `Rng` and removed
    // `rngs::OsRng`, re-exporting getrandom's `SysRng` in its place. `SysRng` is
    // fallible-only (`TryRng`), hence `try_fill_bytes` below. This site mints a
    // long-lived identity key, so it must stay on the OS CSPRNG — do not swap it
    // for `rand::rng()` or any seedable RNG.
    use rand::{TryRng, rngs::SysRng};

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
            // rand 0.8's `OsRng` panicked internally when the OS CSPRNG was
            // unavailable; `expect` preserves that behaviour rather than minting
            // a key from a degraded entropy source.
            SysRng
                .try_fill_bytes(&mut seed)
                .expect("OS CSPRNG must be available to generate an identity key");
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

/// Cross-version signing stability.
///
/// ed25519 is fully deterministic from its seed: the same 32 bytes must always
/// yield the same public key and the same signature over the same message. A
/// public key IS a jig identity — `did:jig:z` + base32 of these bytes — and
/// every stored block carries a signature over its canonical bytes. So if
/// either vector below changes, every already-issued DID and every persisted
/// signature is invalidated at once.
///
/// The vectors were captured from **ed25519-dalek 2.0** (workspace commit
/// 777c772, before the 3.0 bump) and are asserted here unchanged, which is what
/// makes this a gate on the upgrade rather than a description of it. Do not
/// regenerate them to make a build pass: a diff here means the library changed
/// something load-bearing, and that is a protocol-compatibility decision, not a
/// test fixture to refresh.
#[cfg(all(test, feature = "ed25519"))]
mod signing_stability {
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    /// Fixed and non-secret, so anyone can reproduce these vectors.
    const SEED: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    const MSG: &[u8] = b"jig signing stability vector, do not change";

    const GOLDEN_PUBKEY: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    const GOLDEN_SIG: &str = "8c704081890ccbe77a4eeb6df42023039bc5ec74b9fe668a9708d51ee073e697\
                              0a31c3815d7c83f03adefa7e10b4ba5c3a22b7c49cf38b01dddc17031e33990e";

    #[test]
    fn seed_derives_the_same_public_key_as_dalek_2() {
        let sk = SigningKey::from_bytes(&SEED);
        assert_eq!(
            hex::encode(sk.verifying_key().to_bytes()),
            GOLDEN_PUBKEY,
            "public key from a fixed seed changed — every existing DID would be invalidated"
        );
    }

    #[test]
    fn seed_produces_the_same_signature_as_dalek_2() {
        let sk = SigningKey::from_bytes(&SEED);
        assert_eq!(
            hex::encode(sk.sign(MSG).to_bytes()),
            GOLDEN_SIG.replace(' ', ""),
            "signature over fixed bytes changed — every persisted block signature would fail"
        );
    }

    /// The direction that actually matters operationally: a signature produced
    /// by the OLD library must still verify under the NEW one, or every block
    /// already on disk becomes unverifiable.
    #[test]
    fn a_dalek_2_signature_still_verifies() {
        let sk = SigningKey::from_bytes(&SEED);
        let old_sig_bytes: Vec<u8> = hex_to_bytes(&GOLDEN_SIG.replace(' ', ""));
        let sig = ed25519_dalek::Signature::from_slice(&old_sig_bytes)
            .expect("golden signature is 64 bytes");
        sk.verifying_key()
            .verify(MSG, &sig)
            .expect("a signature captured under dalek 2.0 must verify under the current version");
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }
}
