//! Identity keys and local state, encrypted at rest.
//!
//! A `.jigkey` file holds one identity's 32-byte Ed25519 seed, sealed under a
//! random **data key**. The data key is wrapped once per **slot**, and any one
//! slot opens the file:
//!
//! - a passphrase slot derives its key-encryption key with Argon2id;
//! - a secret slot takes 32 or more bytes of key material from outside, from
//!   the OS keychain, a systemd credential, or an environment variable. This
//!   module never fetches it: the caller does, so `jig-core` stays free of
//!   platform code.
//!
//! The data key also derives the keys that seal an identity's other local
//! state (MLS groups, the plaintext cache) through [`derive_file_key`],
//! [`seal`] and [`open`].
//!
//! # What this does not protect against
//!
//! Malware running as the user. It can ask the keychain, read a passphrase as
//! it is typed, or read the seed from memory while a process uses it. At-rest
//! encryption protects stolen disks, backups and synced home directories.
//!
//! # Format
//!
//! ```text
//! "jigkey\0" 0x01 | u32 LE header length | header (JSON) | nonce (24) | sealed seed (48)
//! ```
//!
//! The header is stored verbatim and is the payload's associated data, so a
//! slot cannot be added, removed or altered without the payload failing to
//! open. Each wrapped data key is bound to the DID and its own slot's
//! parameters. The AEAD is XChaCha20-Poly1305 throughout; its 192-bit nonces
//! are random.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::ed25519::random_array;
use crate::crypto::hash_labeled_parts;

const MAGIC: &[u8; 8] = b"jigkey\0\x01";
const SEAL_MAGIC: &[u8; 8] = b"jigseal1";
const VERSION: u32 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// Largest header [`JigKey::from_bytes`] will read. A header is a few hundred
/// bytes per slot.
const MAX_HEADER: usize = 64 * 1024;
/// Where nonces, salts and data keys come from: the OS CSPRNG, or a fixed
/// sequence for the format's golden vectors.
trait Entropy {
    fn bytes<const N: usize>(&mut self) -> [u8; N];
}

struct OsEntropy;

impl Entropy for OsEntropy {
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        random_array()
    }
}

/// Shortest secret a secret slot accepts. A secret slot does no stretching, so
/// its input must already be a key; a passphrase belongs in a passphrase slot.
pub const MIN_SECRET_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("not a jigkey file")]
    NotAJigKey,
    #[error("unsupported jigkey version {0}")]
    Version(u32),
    #[error("malformed jigkey: {0}")]
    Malformed(String),
    #[error("no slot opened this key with what was offered")]
    NoSlotOpened,
    #[error("the key file was altered: its contents do not authenticate")]
    Tampered,
    #[error("a secret slot needs at least {MIN_SECRET_LEN} bytes of key material, got {0}")]
    SecretTooShort(usize),
    #[error("Argon2id parameters out of range: {0}")]
    KdfParams(String),
    #[error("refusing to remove the last slot: the key could never be opened again")]
    LastSlot,
    #[error("no slot at index {0}")]
    NoSuchSlot(usize),
    #[error("sealed data is not a jigseal blob")]
    NotSealed,
    #[error("the seed is the key for {actual}, not {claimed}")]
    DidMismatch { claimed: String, actual: String },
}

pub type Result<T> = std::result::Result<T, KeystoreError>;

/// Where a secret slot's key material comes from. Recorded in the header so a
/// caller knows what to fetch; it does not change the cryptography.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretSource {
    /// The OS keychain: service `jig`, account the DID.
    Keychain,
    /// A file, typically a systemd credential (`LoadCredentialEncrypted=`).
    Credential,
    /// An environment variable.
    Env,
}

impl SecretSource {
    fn as_str(self) -> &'static str {
        match self {
            SecretSource::Keychain => "keychain",
            SecretSource::Credential => "credential",
            SecretSource::Env => "env",
        }
    }
}

/// Argon2id cost parameters for a passphrase slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory, in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Default for KdfParams {
    /// RFC 9106's second recommended setting: 64 MiB, three passes, four lanes.
    fn default() -> Self {
        Self {
            m_kib: 64 * 1024,
            t: 3,
            p: 4,
        }
    }
}

impl KdfParams {
    /// Cheap parameters for tests, where the default makes each case slow.
    /// Never use them for a real key.
    #[doc(hidden)]
    pub const fn insecure_for_tests() -> Self {
        Self {
            m_kib: 64,
            t: 1,
            p: 1,
        }
    }

    /// Bounds checked on open as well as on seal, so a crafted header cannot
    /// make a process allocate without limit.
    fn check(&self) -> Result<()> {
        let bad = |why: &str| Err(KeystoreError::KdfParams(why.to_string()));
        if !(1..=16).contains(&self.p) {
            return bad("lanes must be 1 to 16");
        }
        if !(1..=16).contains(&self.t) {
            return bad("passes must be 1 to 16");
        }
        if self.m_kib < 8 * self.p || self.m_kib > 4 * 1024 * 1024 {
            return bad("memory must be 8 KiB per lane up to 4 GiB");
        }
        Ok(())
    }
}

/// A slot to create, with the secret that will open it.
pub enum NewSlot {
    Passphrase {
        passphrase: Zeroizing<String>,
        params: KdfParams,
    },
    Secret {
        source: SecretSource,
        secret: Zeroizing<Vec<u8>>,
    },
}

/// Something offered to open a key. Each is tried against every slot of its
/// kind.
pub enum Unlock {
    Passphrase(Zeroizing<String>),
    Secret(Zeroizing<Vec<u8>>),
}

/// What one slot is, as listed by [`JigKey::slots`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotKind {
    Passphrase(KdfParams),
    Secret(SecretSource),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum SlotRecord {
    Passphrase {
        kdf: String,
        #[serde(flatten)]
        params: KdfParams,
        salt: String,
        nonce: String,
        wrapped: String,
    },
    Secret {
        source: SecretSource,
        nonce: String,
        wrapped: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Header {
    v: u32,
    did: String,
    slots: Vec<SlotRecord>,
}

/// An identity's opened key: its seed, and the data key that derives its file
/// keys. Both are cleared from memory on drop.
pub struct Opened {
    pub seed: Zeroizing<[u8; 32]>,
    data_key: Zeroizing<[u8; 32]>,
}

impl Opened {
    /// The key that seals the file or record type named by `context`.
    pub fn file_key(&self, context: &str) -> FileKey {
        derive_file_key(&self.data_key, context)
    }
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Opened(<redacted>)")
    }
}

/// A sealed identity key, as read from or written to a `.jigkey` file.
#[derive(Debug, Clone)]
pub struct JigKey {
    header: Header,
    header_bytes: Vec<u8>,
    nonce: [u8; NONCE_LEN],
    sealed_seed: Vec<u8>,
}

impl JigKey {
    /// Seal `seed` for `did` under a fresh data key, with one slot per entry
    /// of `slots`. At least one slot is required.
    pub fn seal(did: &str, seed: &[u8; 32], slots: &[NewSlot]) -> Result<(Self, Opened)> {
        // A DID is its key: a file that names another DID would mislabel the
        // key it holds.
        let actual = crate::Did::from_ed25519_pubkey(
            ed25519_dalek::SigningKey::from_bytes(seed)
                .verifying_key()
                .as_bytes(),
        )
        .to_did_jig_string();
        if actual != did {
            return Err(KeystoreError::DidMismatch {
                claimed: did.to_string(),
                actual,
            });
        }
        let opened = Opened {
            seed: Zeroizing::new(*seed),
            data_key: Zeroizing::new(OsEntropy.bytes()),
        };
        let key = Self::build(did, &opened, slots, &mut OsEntropy)?;
        Ok((key, opened))
    }

    fn build(
        did: &str,
        opened: &Opened,
        slots: &[NewSlot],
        rng: &mut impl Entropy,
    ) -> Result<Self> {
        if slots.is_empty() {
            return Err(KeystoreError::LastSlot);
        }
        let records = slots
            .iter()
            .map(|s| wrap_slot(did, &opened.data_key, s, rng))
            .collect::<Result<Vec<_>>>()?;
        Self::assemble(did, opened, records, rng)
    }

    fn assemble(
        did: &str,
        opened: &Opened,
        slots: Vec<SlotRecord>,
        rng: &mut impl Entropy,
    ) -> Result<Self> {
        let header = Header {
            v: VERSION,
            did: did.to_string(),
            slots,
        };
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|e| KeystoreError::Malformed(format!("header: {e}")))?;
        let nonce: [u8; NONCE_LEN] = rng.bytes();
        let key = payload_key(&opened.data_key);
        let sealed_seed = aead_seal(
            &key,
            &nonce,
            &header_aad(&header_bytes),
            opened.seed.as_ref(),
        );
        Ok(Self {
            header,
            header_bytes,
            nonce,
            sealed_seed,
        })
    }

    /// The DID this key belongs to, as its header names it. Authenticated only
    /// once [`JigKey::open`] succeeds.
    pub fn did(&self) -> &str {
        &self.header.did
    }

    /// The slots, in order.
    pub fn slots(&self) -> Vec<SlotKind> {
        self.header
            .slots
            .iter()
            .map(|s| match s {
                SlotRecord::Passphrase { params, .. } => SlotKind::Passphrase(*params),
                SlotRecord::Secret { source, .. } => SlotKind::Secret(*source),
            })
            .collect()
    }

    /// Open the key with the first offer that unwraps a slot, then check the
    /// whole file.
    pub fn open(&self, offers: &[Unlock]) -> Result<Opened> {
        for record in &self.header.slots {
            for offer in offers {
                if let Some(data_key) = unwrap_slot(&self.header.did, record, offer)? {
                    return self.open_with(data_key);
                }
            }
        }
        Err(KeystoreError::NoSlotOpened)
    }

    fn open_with(&self, data_key: Zeroizing<[u8; 32]>) -> Result<Opened> {
        let key = payload_key(&data_key);
        let seed = aead_open(
            &key,
            &self.nonce,
            &header_aad(&self.header_bytes),
            &self.sealed_seed,
        )
        .ok_or(KeystoreError::Tampered)?;
        let seed: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| KeystoreError::Malformed("seed is not 32 bytes".into()))?;
        Ok(Opened {
            seed: Zeroizing::new(seed),
            data_key,
        })
    }

    /// A copy with one more slot. Needs the opened key, so only a holder can
    /// add a way in.
    /// `Tampered` unless `opened` is this key's own data key and seed, so a
    /// slot change never reseals this file under another key's data key.
    fn check_opened(&self, opened: &Opened) -> Result<()> {
        let current = self.open_with(Zeroizing::new(*opened.data_key))?;
        if *current.seed != *opened.seed {
            return Err(KeystoreError::Tampered);
        }
        Ok(())
    }

    pub fn with_slot(&self, opened: &Opened, slot: &NewSlot) -> Result<Self> {
        self.check_opened(opened)?;
        let mut slots = self.header.slots.clone();
        slots.push(wrap_slot(
            &self.header.did,
            &opened.data_key,
            slot,
            &mut OsEntropy,
        )?);
        Self::assemble(&self.header.did, opened, slots, &mut OsEntropy)
    }

    /// A copy without the slot at `index`. Refuses to remove the last one.
    pub fn without_slot(&self, opened: &Opened, index: usize) -> Result<Self> {
        if index >= self.header.slots.len() {
            return Err(KeystoreError::NoSuchSlot(index));
        }
        if self.header.slots.len() == 1 {
            return Err(KeystoreError::LastSlot);
        }
        self.check_opened(opened)?;
        let mut slots = self.header.slots.clone();
        slots.remove(index);
        Self::assemble(&self.header.did, opened, slots, &mut OsEntropy)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MAGIC.len() + 4 + self.header_bytes.len() + NONCE_LEN + self.sealed_seed.len(),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.header_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.header_bytes);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.sealed_seed);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let malformed = |why: &str| KeystoreError::Malformed(why.to_string());
        let rest = bytes
            .strip_prefix(&MAGIC[..7])
            .ok_or(KeystoreError::NotAJigKey)?;
        let (&format, rest) = rest.split_first().ok_or(KeystoreError::NotAJigKey)?;
        if format != MAGIC[7] {
            return Err(KeystoreError::Version(format.into()));
        }
        if rest.len() < 4 {
            return Err(malformed("truncated header length"));
        }
        let (len, rest) = rest.split_at(4);
        let len = u32::from_le_bytes(len.try_into().expect("4 bytes")) as usize;
        if len > MAX_HEADER || rest.len() < len + NONCE_LEN + 32 + TAG_LEN {
            return Err(malformed("truncated or oversized"));
        }
        let (header_bytes, rest) = rest.split_at(len);
        let (nonce, sealed_seed) = rest.split_at(NONCE_LEN);
        if sealed_seed.len() != 32 + TAG_LEN {
            return Err(malformed("trailing bytes after the sealed seed"));
        }
        let header: Header =
            serde_json::from_slice(header_bytes).map_err(|e| malformed(&format!("header: {e}")))?;
        if header.v != VERSION {
            return Err(KeystoreError::Version(header.v));
        }
        if header.slots.is_empty() {
            return Err(malformed("no slots"));
        }
        Ok(Self {
            header,
            header_bytes: header_bytes.to_vec(),
            nonce: nonce.try_into().expect("24 bytes"),
            sealed_seed: sealed_seed.to_vec(),
        })
    }
}

/// A key for one kind of local file or record, derived from a data key.
pub struct FileKey(Zeroizing<[u8; 32]>);

/// Derive the key for `context` (for example `"jig mls state.bin v1"`). Each
/// context gives an independent key.
pub fn derive_file_key(data_key: &[u8; 32], context: &str) -> FileKey {
    FileKey(Zeroizing::new(blake3::derive_key(
        &format!("jig keystore file key: {context}"),
        data_key,
    )))
}

/// Seal `plaintext` under `key`, bound to `aad`.
///
/// Output: `"jigseal1" | nonce (24) | ciphertext`. The caller picks `aad` to
/// bind the blob to its place, for example the DID and the file's role, so a
/// blob cannot be moved between files or identities.
pub fn seal(key: &FileKey, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    seal_with_nonce(key, &random_array(), aad, plaintext)
}

fn seal_with_nonce(
    key: &FileKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let ct = aead_seal(&key.0, nonce, &seal_aad(aad), plaintext);
    let mut out = Vec::with_capacity(SEAL_MAGIC.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(SEAL_MAGIC);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out
}

/// Whether `bytes` looks like a [`seal`] blob. A file that does not was
/// written in clear by an older version.
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(SEAL_MAGIC)
}

/// Open a [`seal`] blob. Any change to the blob or to `aad` fails.
pub fn open(key: &FileKey, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let rest = sealed
        .strip_prefix(SEAL_MAGIC)
        .ok_or(KeystoreError::NotSealed)?;
    if rest.len() < NONCE_LEN + TAG_LEN {
        return Err(KeystoreError::Tampered);
    }
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    aead_open(
        &key.0,
        nonce.try_into().expect("24 bytes"),
        &seal_aad(aad),
        ct,
    )
    .map(Zeroizing::new)
    .ok_or(KeystoreError::Tampered)
}

fn seal_aad(aad: &[u8]) -> Vec<u8> {
    let mut out = SEAL_MAGIC.to_vec();
    out.extend_from_slice(aad);
    out
}

fn header_aad(header_bytes: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(header_bytes);
    out
}

fn payload_key(data_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key("jig keystore payload key v1", data_key))
}

/// What a slot's wrapped data key is bound to: the DID, the slot's kind, and
/// its parameters.
fn slot_aad(did: &str, kind: &str, params: &[u8]) -> [u8; 32] {
    *hash_labeled_parts(&[
        ("domain", b"jig-keystore-slot-v1"),
        ("did", did.as_bytes()),
        ("kind", kind.as_bytes()),
        ("params", params),
    ])
    .as_bytes()
}

fn passphrase_params_bytes(params: &KdfParams, salt: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + salt.len());
    out.extend_from_slice(&params.m_kib.to_le_bytes());
    out.extend_from_slice(&params.t.to_le_bytes());
    out.extend_from_slice(&params.p.to_le_bytes());
    out.extend_from_slice(salt);
    out
}

fn argon2_kek(passphrase: &str, salt: &[u8], params: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    params.check()?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m_kib, params.t, params.p, Some(32))
            .map_err(|e| KeystoreError::KdfParams(e.to_string()))?,
    );
    let mut kek = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, kek.as_mut())
        .map_err(|e| KeystoreError::KdfParams(e.to_string()))?;
    Ok(kek)
}

fn secret_kek(secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if secret.len() < MIN_SECRET_LEN {
        return Err(KeystoreError::SecretTooShort(secret.len()));
    }
    Ok(Zeroizing::new(blake3::derive_key(
        "jig keystore secret slot v1",
        secret,
    )))
}

fn wrap_slot(
    did: &str,
    data_key: &[u8; 32],
    slot: &NewSlot,
    rng: &mut impl Entropy,
) -> Result<SlotRecord> {
    match slot {
        NewSlot::Passphrase { passphrase, params } => {
            let salt: [u8; 16] = rng.bytes();
            let kek = argon2_kek(passphrase, &salt, params)?;
            let nonce: [u8; NONCE_LEN] = rng.bytes();
            let aad = slot_aad(did, "passphrase", &passphrase_params_bytes(params, &salt));
            Ok(SlotRecord::Passphrase {
                kdf: "argon2id".into(),
                params: *params,
                salt: STANDARD.encode(salt),
                nonce: STANDARD.encode(nonce),
                wrapped: STANDARD.encode(aead_seal(&kek, &nonce, &aad, data_key)),
            })
        }
        NewSlot::Secret { source, secret } => {
            let kek = secret_kek(secret)?;
            let nonce: [u8; NONCE_LEN] = rng.bytes();
            let aad = slot_aad(did, source.as_str(), &[]);
            Ok(SlotRecord::Secret {
                source: *source,
                nonce: STANDARD.encode(nonce),
                wrapped: STANDARD.encode(aead_seal(&kek, &nonce, &aad, data_key)),
            })
        }
    }
}

/// The data key if `offer` opens `record`; `None` if it is the wrong kind or
/// the wrong secret. A malformed record is an error.
fn unwrap_slot(
    did: &str,
    record: &SlotRecord,
    offer: &Unlock,
) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let b64 = |field: &str, s: &str| {
        STANDARD
            .decode(s)
            .map_err(|_| KeystoreError::Malformed(format!("slot {field} is not base64")))
    };
    let (kek, nonce, wrapped, aad) = match (record, offer) {
        (
            SlotRecord::Passphrase {
                kdf,
                params,
                salt,
                nonce,
                wrapped,
            },
            Unlock::Passphrase(passphrase),
        ) => {
            if kdf != "argon2id" {
                return Err(KeystoreError::Malformed(format!("unknown kdf `{kdf}`")));
            }
            let salt = b64("salt", salt)?;
            let aad = slot_aad(did, "passphrase", &passphrase_params_bytes(params, &salt));
            (argon2_kek(passphrase, &salt, params)?, nonce, wrapped, aad)
        }
        (
            SlotRecord::Secret {
                source,
                nonce,
                wrapped,
            },
            Unlock::Secret(secret),
        ) => {
            let Ok(kek) = secret_kek(secret) else {
                return Ok(None);
            };
            (kek, nonce, wrapped, slot_aad(did, source.as_str(), &[]))
        }
        _ => return Ok(None),
    };
    let nonce: [u8; NONCE_LEN] = b64("nonce", nonce)?
        .try_into()
        .map_err(|_| KeystoreError::Malformed("slot nonce is not 24 bytes".into()))?;
    let Some(data_key) = aead_open(&kek, &nonce, &aad, &b64("wrapped", wrapped)?) else {
        return Ok(None);
    };
    let data_key: [u8; 32] = data_key
        .as_slice()
        .try_into()
        .map_err(|_| KeystoreError::Malformed("wrapped key is not 32 bytes".into()))?;
    Ok(Some(Zeroizing::new(data_key)))
}

fn aead_seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], msg: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .expect("XChaCha20-Poly1305 encryption does not fail for in-memory buffers")
}

fn aead_open(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:jig:zpg2vmlup4zkpsqdywejorkmlu6ib7bj242k35v7a4oiqxlieszsa";
    /// The seed `jig-core`'s signing vectors use, and the DID it is the key of.
    const SEED: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    fn pass(p: &str) -> NewSlot {
        NewSlot::Passphrase {
            passphrase: Zeroizing::new(p.into()),
            params: KdfParams::insecure_for_tests(),
        }
    }

    fn secret(source: SecretSource, byte: u8) -> NewSlot {
        NewSlot::Secret {
            source,
            secret: Zeroizing::new(vec![byte; 32]),
        }
    }

    fn offer_pass(p: &str) -> Unlock {
        Unlock::Passphrase(Zeroizing::new(p.into()))
    }

    fn offer_secret(byte: u8) -> Unlock {
        Unlock::Secret(Zeroizing::new(vec![byte; 32]))
    }

    fn round_trip(key: &JigKey) -> JigKey {
        JigKey::from_bytes(&key.to_bytes()).unwrap()
    }

    #[test]
    fn each_slot_kind_round_trips() {
        for (slot, offer) in [
            (pass("correct horse"), offer_pass("correct horse")),
            (secret(SecretSource::Keychain, 1), offer_secret(1)),
            (secret(SecretSource::Credential, 2), offer_secret(2)),
            (secret(SecretSource::Env, 3), offer_secret(3)),
        ] {
            let (key, sealed_with) = JigKey::seal(DID, &SEED, &[slot]).unwrap();
            let opened = round_trip(&key).open(&[offer]).unwrap();
            assert_eq!(*opened.seed, SEED);
            assert_eq!(*opened.data_key, *sealed_with.data_key);
        }
    }

    #[test]
    fn a_wrong_passphrase_or_secret_opens_nothing() {
        let (key, _) =
            JigKey::seal(DID, &SEED, &[pass("right"), secret(SecretSource::Env, 1)]).unwrap();
        let err = key
            .open(&[offer_pass("wrong"), offer_secret(2)])
            .unwrap_err();
        assert!(matches!(err, KeystoreError::NoSlotOpened));
    }

    #[test]
    fn either_of_two_slots_opens_the_same_key() {
        let (key, sealed_with) =
            JigKey::seal(DID, &SEED, &[pass("pw"), secret(SecretSource::Keychain, 9)]).unwrap();
        let a = key.open(&[offer_pass("pw")]).unwrap();
        let b = key.open(&[offer_secret(9)]).unwrap();
        assert_eq!(*a.data_key, *sealed_with.data_key);
        assert_eq!(*b.data_key, *sealed_with.data_key);
    }

    #[test]
    fn a_short_secret_is_refused_at_seal() {
        let slot = NewSlot::Secret {
            source: SecretSource::Env,
            secret: Zeroizing::new(vec![1; 31]),
        };
        assert!(matches!(
            JigKey::seal(DID, &SEED, &[slot]).unwrap_err(),
            KeystoreError::SecretTooShort(31)
        ));
    }

    #[test]
    fn a_seed_sealed_under_another_did_is_refused() {
        assert!(matches!(
            JigKey::seal("did:jig:zother", &SEED, &[secret(SecretSource::Env, 1)]).unwrap_err(),
            KeystoreError::DidMismatch { .. }
        ));
    }

    #[test]
    fn slot_changes_need_this_keys_own_opened_key() {
        let (a, _) = JigKey::seal(DID, &SEED, &[secret(SecretSource::Env, 1)]).unwrap();
        let (_, other) = JigKey::seal(DID, &SEED, &[secret(SecretSource::Env, 2)]).unwrap();
        assert!(matches!(
            a.with_slot(&other, &pass("x")).unwrap_err(),
            KeystoreError::Tampered
        ));
        let a = a
            .with_slot(&a.open(&[offer_secret(1)]).unwrap(), &pass("x"))
            .unwrap();
        assert!(matches!(
            a.without_slot(&other, 0).unwrap_err(),
            KeystoreError::Tampered
        ));
    }

    #[test]
    fn no_slots_is_refused() {
        assert!(matches!(
            JigKey::seal(DID, &SEED, &[]).unwrap_err(),
            KeystoreError::LastSlot
        ));
    }

    /// Rewrite the header in place and re-encode, as an attacker with write
    /// access to the file would.
    fn with_header(key: &JigKey, edit: impl FnOnce(&mut serde_json::Value)) -> JigKey {
        let mut v: serde_json::Value = serde_json::from_slice(&key.header_bytes).unwrap();
        edit(&mut v);
        let header_bytes = serde_json::to_vec(&v).unwrap();
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(&key.nonce);
        bytes.extend_from_slice(&key.sealed_seed);
        JigKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn changing_the_did_breaks_every_slot() {
        let (key, _) = JigKey::seal(DID, &SEED, &[secret(SecretSource::Env, 1)]).unwrap();
        let moved = with_header(&key, |v| v["did"] = "did:jig:zother".into());
        assert!(matches!(
            moved.open(&[offer_secret(1)]).unwrap_err(),
            KeystoreError::NoSlotOpened
        ));
    }

    #[test]
    fn relabelling_a_slot_breaks_it() {
        let (key, _) = JigKey::seal(DID, &SEED, &[secret(SecretSource::Keychain, 1)]).unwrap();
        let relabelled = with_header(&key, |v| v["slots"][0]["source"] = "env".into());
        assert!(relabelled.open(&[offer_secret(1)]).is_err());
    }

    #[test]
    fn weakening_passphrase_parameters_breaks_the_slot() {
        let (key, _) = JigKey::seal(DID, &SEED, &[pass("pw")]).unwrap();
        let weaker = with_header(&key, |v| v["slots"][0]["m_kib"] = 32.into());
        assert!(weaker.open(&[offer_pass("pw")]).is_err());
    }

    #[test]
    fn dropping_a_slot_from_the_header_fails_the_payload() {
        // Removing a slot leaves the other slot's wrap intact, but the payload
        // is bound to the header it was sealed with.
        let (key, _) =
            JigKey::seal(DID, &SEED, &[pass("pw"), secret(SecretSource::Env, 1)]).unwrap();
        let fewer = with_header(&key, |v| {
            v["slots"].as_array_mut().unwrap().remove(0);
        });
        assert!(matches!(
            fewer.open(&[offer_secret(1)]).unwrap_err(),
            KeystoreError::Tampered
        ));
    }

    #[test]
    fn a_flipped_payload_bit_is_tampering() {
        let (key, _) = JigKey::seal(DID, &SEED, &[secret(SecretSource::Env, 1)]).unwrap();
        let mut bytes = key.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let key = JigKey::from_bytes(&bytes).unwrap();
        assert!(matches!(
            key.open(&[offer_secret(1)]).unwrap_err(),
            KeystoreError::Tampered
        ));
    }

    #[test]
    fn hostile_kdf_parameters_are_refused_before_hashing() {
        let (key, _) = JigKey::seal(DID, &SEED, &[pass("pw")]).unwrap();
        let huge = with_header(&key, |v| v["slots"][0]["m_kib"] = u32::MAX.into());
        assert!(matches!(
            huge.open(&[offer_pass("pw")]).unwrap_err(),
            KeystoreError::KdfParams(_)
        ));
    }

    #[test]
    fn bad_framing_is_rejected() {
        assert!(matches!(
            JigKey::from_bytes(b"not a key").unwrap_err(),
            KeystoreError::NotAJigKey
        ));
        let (key, _) = JigKey::seal(DID, &SEED, &[secret(SecretSource::Env, 1)]).unwrap();
        let mut bytes = key.to_bytes();
        bytes[7] = 2;
        assert!(matches!(
            JigKey::from_bytes(&bytes).unwrap_err(),
            KeystoreError::Version(2)
        ));
        let bytes = key.to_bytes();
        assert!(JigKey::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = key.to_bytes();
        longer.push(0);
        assert!(JigKey::from_bytes(&longer).is_err());
    }

    #[test]
    fn slots_can_be_added_and_removed_but_not_the_last() {
        let (key, opened) = JigKey::seal(DID, &SEED, &[secret(SecretSource::Keychain, 1)]).unwrap();
        let key = key.with_slot(&opened, &pass("recovery")).unwrap();
        assert_eq!(
            key.slots(),
            vec![
                SlotKind::Secret(SecretSource::Keychain),
                SlotKind::Passphrase(KdfParams::insecure_for_tests())
            ]
        );
        let reopened = round_trip(&key).open(&[offer_pass("recovery")]).unwrap();
        assert_eq!(*reopened.seed, SEED);

        let key = key.without_slot(&opened, 0).unwrap();
        assert!(key.open(&[offer_secret(1)]).is_err());
        assert!(key.open(&[offer_pass("recovery")]).is_ok());
        assert!(matches!(
            key.without_slot(&opened, 0).unwrap_err(),
            KeystoreError::LastSlot
        ));
        assert!(matches!(
            key.without_slot(&opened, 5).unwrap_err(),
            KeystoreError::NoSuchSlot(5)
        ));
    }

    #[test]
    fn sealed_blobs_bind_their_aad() {
        let (_, opened) = JigKey::seal(DID, &SEED, &[secret(SecretSource::Env, 1)]).unwrap();
        let k = opened.file_key("jig mls state.bin v1");
        let blob = seal(&k, b"did|state.bin", b"hello");
        assert!(is_sealed(&blob));
        assert_eq!(&*open(&k, b"did|state.bin", &blob).unwrap(), b"hello");
        assert!(open(&k, b"did|groups.json", &blob).is_err());
        let other = opened.file_key("jig mls groups.json v1");
        assert!(open(&other, b"did|state.bin", &blob).is_err());
        assert!(matches!(
            open(&k, b"x", b"{\"clear\":true}").unwrap_err(),
            KeystoreError::NotSealed
        ));
        assert!(!is_sealed(b"{\"clear\":true}"));
    }

    /// Format freeze. A `.jigkey` written by this version must open, to this
    /// seed, in every later one. A failure means existing key files no longer
    /// open: it is not a fixture to refresh.
    #[test]
    fn golden_jigkey_opens() {
        /// A fixed byte sequence, standing in for the OS CSPRNG.
        struct Counter(u8);
        impl Entropy for Counter {
            fn bytes<const N: usize>(&mut self) -> [u8; N] {
                std::array::from_fn(|_| {
                    self.0 = self.0.wrapping_add(1);
                    self.0
                })
            }
        }
        let opened = Opened {
            seed: Zeroizing::new(SEED),
            data_key: Zeroizing::new(Counter(0x41).bytes()),
        };
        let key = JigKey::build(
            DID,
            &opened,
            &[pass("golden"), secret(SecretSource::Credential, 0x5a)],
            &mut Counter(0),
        )
        .unwrap();
        let bytes = key.to_bytes();
        assert_eq!(hex::encode(&bytes), GOLDEN_JIGKEY, "the writer changed");

        let back = JigKey::from_bytes(&hex::decode(GOLDEN_JIGKEY).unwrap()).unwrap();
        assert_eq!(*back.open(&[offer_pass("golden")]).unwrap().seed, SEED);
        assert_eq!(*back.open(&[offer_secret(0x5a)]).unwrap().seed, SEED);

        let blob = seal_with_nonce(
            &opened.file_key("golden"),
            &Counter(8).bytes(),
            b"aad",
            b"msg",
        );
        assert_eq!(hex::encode(&blob), GOLDEN_BLOB);
        let frozen = hex::decode(GOLDEN_BLOB).unwrap();
        assert_eq!(
            &*open(&opened.file_key("golden"), b"aad", &frozen).unwrap(),
            b"msg"
        );
    }

    const GOLDEN_JIGKEY: &str = "6a69676b65790001cf0100007b2276223a312c22646964223a226469643a6a69673a7a706732766d6c7570347a6b707371647977656a6f726b6d6c7536696237626a3234326b3335763761346f6971786c6965737a7361222c22736c6f7473223a5b7b226b696e64223a2270617373706872617365222c226b6466223a226172676f6e326964222c226d5f6b6962223a36342c2274223a312c2270223a312c2273616c74223a2241514944424155474277674a4367734d4451345045413d3d222c226e6f6e6365223a2245524954464255574678675a4768736348523466494345694979516c4a69636f222c2277726170706564223a2267716b2b346b785058434f772f576d3870455151554535576436536b3750414a725375414458646978374e785239363371715a6e63444e646e726e38356a416f227d2c7b226b696e64223a22736563726574222c22736f75726365223a2263726564656e7469616c222c226e6f6e6365223a224b536f724c4330754c7a41784d6a4d304e5459334f446b364f7a7739506a3941222c2277726170706564223a22482b566d4e7635496f35566163755975496f78313778346465644562566368577a7955576272506553774f38634a6d4c6f6d5537493544745779694f74725955227d5d7d4142434445464748494a4b4c4d4e4f5051525354555657588654b22a99928d6c0b3c9b5949e1728fb109e158186598284c09eb630ee7cb03159352f96e08a8feb3a84d9816020b66";
    const GOLDEN_BLOB: &str = "6a69677365616c31090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2062a0376493495b58ee9f45c5a53fd6fdcf402d";
}
