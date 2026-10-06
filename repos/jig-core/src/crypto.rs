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
    // fallible-only (`TryRng`), hence `try_fill_bytes` below. The policy — OS
    // CSPRNG, never a seedable RNG — is documented on `generate_signing_key`,
    // which is the only function in the tree that reads this import.
    use rand::{TryRng, rngs::SysRng};
    use zeroize::Zeroize;

    /// Mint fresh ed25519 key material for a long-lived jig identity.
    ///
    /// **This is the only sanctioned keygen path in the protocol, and the only
    /// place the entropy source is chosen.** A public key *is* an identity here
    /// — `did:jig:z` + base32 of these 32 bytes — which makes that choice a
    /// protocol-level decision rather than a local one. Every identity in the
    /// tree funnels through this function: `jig-client`'s keyfiles (and so
    /// `jig init` and `jig keys rotate`), the nameserver's persistent signing
    /// identity, and [`KeyPair::generate`].
    ///
    /// **Forks and algorithm changes belong here, in this one body.** That is
    /// the reason the function exists. Before it, each caller picked its own
    /// source, and they had already drifted: `jig-client` minted long-lived
    /// identity keys from `rand::rng()` — an OS-seeded userspace ChaCha PRNG —
    /// while this crate and the nameserver read the OS CSPRNG directly. Nobody
    /// chose that split; it accumulated, in precisely the place a fork is most
    /// likely to touch.
    ///
    /// Callers that need to *load* an existing key still build it themselves
    /// from stored bytes via `SigningKey::from_bytes`; this function is for
    /// minting new material only.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG is unavailable. `rand` 0.8's `OsRng` panicked
    /// internally on entropy failure and this preserves that contract
    /// deliberately: minting a long-lived identity from a degraded source is
    /// worse than failing to start.
    pub fn generate_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut seed)
            .expect("OS CSPRNG must be available to generate an identity key");
        let signing = SigningKey::from_bytes(&seed);
        // `SigningKey` zeroizes itself on drop; this clears the extra copy the
        // seed buffer holds, which would otherwise outlive it on the stack.
        seed.zeroize();
        signing
    }

    /// Fill `buf` from the OS CSPRNG, the same source as [`generate_signing_key`].
    ///
    /// A handshake nonce is not an identity key, but it is the replay guard on a
    /// signed welcome, so it does not get a second entropy policy.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG is unavailable. Same contract as
    /// [`generate_signing_key`]: a nonce from a degraded source is worse than
    /// failing the handshake.
    pub fn fill_random(buf: &mut [u8]) {
        SysRng
            .try_fill_bytes(buf)
            .expect("OS CSPRNG must be available");
    }

    /// Convenience wrapper around an ed25519 keypair.
    #[derive(Clone)]
    pub struct KeyPair {
        signing: SigningKey,
        verifying: VerifyingKey,
    }

    impl KeyPair {
        /// Generate a new random key pair via [`generate_signing_key`].
        pub fn generate() -> Self {
            let signing = generate_signing_key();
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

/// The sanctioned keygen path, exercised through its public surface.
///
/// These tests do not assert *which* entropy source is used — that is a single
/// documented line in [`ed25519::generate_signing_key`] and asserting on it here
/// would only restate the implementation. What they pin down is the contract
/// every caller depends on: keys are distinct, fully written, and survive the
/// seed round-trip that both persistence paths (client keyfiles, nameserver
/// SQLite blobs) are built on.
#[cfg(all(test, feature = "ed25519"))]
mod keygen {
    use super::ed25519::{KeyPair, generate_signing_key};
    use crate::Did;
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use std::collections::HashSet;

    #[test]
    fn successive_keys_are_distinct() {
        let keys: HashSet<[u8; 32]> = (0..16)
            .map(|_| generate_signing_key().verifying_key().to_bytes())
            .collect();
        assert_eq!(
            keys.len(),
            16,
            "keygen returned a repeated key — the entropy source is degenerate"
        );
    }

    /// An unfilled buffer is the realistic refactor bug here: `[0u8; 32]` is a
    /// perfectly valid ed25519 seed, so a keygen that silently skipped filling
    /// it would mint one shared identity for every user and still pass a
    /// sign/verify test.
    #[test]
    fn a_generated_key_is_not_the_all_zero_seed() {
        let key = generate_signing_key();
        assert_ne!(
            key.to_bytes(),
            [0u8; 32],
            "keygen produced the all-zero seed — the entropy buffer was never filled"
        );
    }

    /// Both persistence paths store the 32 seed bytes and rebuild the key from
    /// them later. If that round-trip ever stopped being identity-preserving,
    /// every stored key would load as a different identity.
    #[test]
    fn a_key_round_trips_through_its_stored_seed_bytes() {
        let key = generate_signing_key();
        let reloaded = SigningKey::from_bytes(&key.to_bytes());
        assert_eq!(
            reloaded.verifying_key().to_bytes(),
            key.verifying_key().to_bytes(),
            "a key rebuilt from its stored seed is a different identity"
        );
    }

    #[test]
    fn a_generated_key_signs_and_verifies() {
        let key = generate_signing_key();
        let msg = b"jig keygen smoke test";
        let sig = key.sign(msg);
        key.verifying_key()
            .verify(msg, &sig)
            .expect("a freshly generated key must verify its own signature");
    }

    #[test]
    fn a_generated_key_derives_a_canonical_did() {
        let did = Did::from_ed25519_pubkey(&generate_signing_key().verifying_key().to_bytes());
        let s = did.to_did_jig_string();
        assert!(
            s.starts_with("did:jig:z"),
            "generated identity must be canonical key-derived form, got `{s}`"
        );
        assert_eq!(
            s.len(),
            61,
            "canonical DID is `did:jig:z` + 52 base32 chars"
        );
    }

    /// [`KeyPair`] is a thin wrapper over the same path; it must not become a
    /// second, quietly divergent keygen.
    #[test]
    fn keypair_generate_produces_distinct_usable_keys() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
        assert_ne!(a.public_key_bytes(), [0u8; 32]);
        let sig = a.sign(b"hello");
        a.verify(b"hello", &sig)
            .expect("keypair verifies its own signature");
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

    /// The chain that actually defines a jig identity is seed → pubkey → DID.
    /// The two tests above freeze the first hop; without this one the last hop
    /// is unpinned, so a change to base32 alphabet, case, or prefix could
    /// silently rename every user while both golden vectors above still pass.
    #[test]
    fn the_golden_pubkey_still_derives_the_same_did() {
        const GOLDEN_DID: &str = "did:jig:zpg2vmlup4zkpsqdywejorkmlu6ib7bj242k35v7a4oiqxlieszsa";

        let sk = SigningKey::from_bytes(&SEED);
        let did = crate::Did::from_ed25519_pubkey(&sk.verifying_key().to_bytes());
        assert_eq!(
            did.to_did_jig_string(),
            GOLDEN_DID,
            "DID derivation changed — every existing identity would be renamed"
        );
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }
}
