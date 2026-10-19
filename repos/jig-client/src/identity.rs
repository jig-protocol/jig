//! Identity keys, sealed at rest in `~/.jig/keys/<did>.jigkey`.
//!
//! A `.jigkey` holds the Ed25519 seed under a data key that one of its slots
//! unwraps (`jig_core::keystore`): the OS keychain by default, otherwise a
//! passphrase, a systemd credential or an environment secret. [`KeyAccess`]
//! says which of those this process may use.
//!
//! The data key also derives the keys that seal this identity's MLS state
//! (`crate::secure`).
//!
//! # Older key files
//!
//! Before `.jigkey`, a key was a raw 32-byte seed in `<did>.key`, protected
//! only by mode 0600. [`Identity::open`] seals such a file the first time it
//! loads it and removes the raw file. Removing a file does not erase it from an
//! SSD or a copy-on-write filesystem, so a key that was ever stored raw should
//! be rotated once rotation exists. [`Identity::migrated_from`] says when this
//! happened, so the CLI can say so.
//!
//! Raw storage remains only as an explicit antipattern
//! (`JIG_KEYS_STORAGE=plaintext`), never as a default.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use jig_core::Did;
use jig_core::keystore::{
    FileKey, JigKey, KdfParams, KeystoreError, NewSlot, Opened, SecretSource, SlotKind, Unlock,
};
use zeroize::Zeroizing;

use crate::keychain::{Keychain, KeychainError};

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("keyfile not found for DID `{did}` in {dir:?}")]
    KeyfileNotFound { did: String, dir: PathBuf },
    #[error("keyfile {path:?} has insecure permissions {mode:o} (must be 0600)")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("keyfile {path:?} is malformed: expected 32 bytes, got {len}")]
    Malformed { path: PathBuf, len: usize },
    #[error("{path:?} holds the key for {found}, not {expected}")]
    WrongDid {
        path: PathBuf,
        expected: String,
        found: String,
    },
    #[error(
        "cannot unlock {did}: {hint}. Set JIG_KEY_PASSPHRASE, or JIG_KEY_UNLOCK=env:NAME or \
         credential:PATH, for whichever slot the key has"
    )]
    Locked { did: String, hint: String },
    #[error(
        "no way to seal a key for {did}: no OS keychain is available and no passphrase was \
         given. Run interactively, or set JIG_KEY_PASSPHRASE (or JIG_KEY_UNLOCK for a \
         credential)"
    )]
    NoWayToSeal { did: String },
    #[error("{var}: {reason}")]
    BadEnv { var: &'static str, reason: String },
    #[error("sealed {path:?}, but it does not open again: {reason}")]
    NotVerified { path: PathBuf, reason: String },
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    #[error(transparent)]
    Keychain(#[from] KeychainError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Why [`Prompt::passphrase`] is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptPurpose {
    /// Open an existing key.
    Unlock,
    /// Choose a passphrase for a key being sealed. The prompt should ask twice.
    New,
}

/// Asks the person at the terminal for a passphrase. `None` means they
/// declined.
pub trait Prompt: Send + Sync {
    fn passphrase(
        &self,
        did: &str,
        purpose: PromptPurpose,
    ) -> std::io::Result<Option<Zeroizing<String>>>;
}

/// How keys are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// `.jigkey`, sealed. The default.
    Sealed,
    /// Raw seeds in `<did>.key`. An antipattern, kept only for setups that
    /// cannot use any slot; every load warns.
    Plaintext,
}

/// What this process may use to seal and unlock identity keys.
///
/// [`KeyAccess::from_env`] reads:
///
/// - `JIG_KEYS_STORAGE`: `sealed` (the default) or `plaintext`;
/// - `JIG_KEY_PASSPHRASE`: a passphrase for passphrase slots;
/// - `JIG_KEY_UNLOCK`: `env:NAME` or `credential:PATH`, a secret of at least 32
///   bytes for a secret slot (a systemd credential, a secret manager);
/// - `JIG_KEYCHAIN`: `none` turns the OS keychain off.
pub struct KeyAccess {
    storage: Storage,
    keychain: Option<Arc<dyn Keychain>>,
    passphrase: Option<Zeroizing<String>>,
    secret: Option<(SecretSource, Zeroizing<Vec<u8>>)>,
    prompt: Option<Arc<dyn Prompt>>,
    kdf: KdfParams,
    notice: Option<Arc<Notice>>,
}

/// Where [`KeyAccess`] says that it fell back from one slot to another.
pub type Notice = dyn Fn(&str) + Send + Sync;

/// A fixed secret for [`KeyAccess::insecure_for_tests`]. Public on purpose:
/// anything sealed with it is as good as plaintext.
const TEST_SECRET: [u8; 32] = *b"jig test identity: not a secret!";

impl KeyAccess {
    /// The access this process's environment allows, with the OS keychain if
    /// one is usable. Add a terminal prompt with [`KeyAccess::with_prompt`].
    pub fn from_env() -> Result<Self, IdentityError> {
        let storage = match std::env::var("JIG_KEYS_STORAGE").ok().as_deref() {
            None | Some("") | Some("sealed") => Storage::Sealed,
            Some("plaintext") => Storage::Plaintext,
            Some(other) => {
                return Err(IdentityError::BadEnv {
                    var: "JIG_KEYS_STORAGE",
                    reason: format!("`{other}` is neither `sealed` nor `plaintext`"),
                });
            }
        };
        let keychain = match std::env::var("JIG_KEYCHAIN").ok().as_deref() {
            Some("none") => None,
            _ => crate::keychain::system().map(Arc::from),
        };
        let passphrase = std::env::var("JIG_KEY_PASSPHRASE")
            .ok()
            .filter(|p| !p.is_empty())
            .map(Zeroizing::new);
        let secret = match std::env::var("JIG_KEY_UNLOCK").ok() {
            None => None,
            Some(spec) => Some(read_unlock_spec(&spec)?),
        };
        Ok(Self {
            storage,
            keychain,
            passphrase,
            secret,
            prompt: None,
            kdf: KdfParams::default(),
            notice: None,
        })
    }

    /// Ask `prompt` for a passphrase when nothing else opens or seals a key.
    pub fn with_prompt(mut self, prompt: Arc<dyn Prompt>) -> Self {
        self.prompt = Some(prompt);
        self
    }

    /// Use `keychain` in place of the OS keychain (`None` for no keychain).
    pub fn with_keychain(mut self, keychain: Option<Arc<dyn Keychain>>) -> Self {
        self.keychain = keychain;
        self
    }

    /// Use `passphrase` for passphrase slots.
    pub fn with_passphrase(mut self, passphrase: Zeroizing<String>) -> Self {
        self.passphrase = Some(passphrase);
        self
    }

    /// Tell `notice` when a slot is unavailable and another is used instead,
    /// as well as logging it. A CLI passes something that prints to stderr:
    /// a keychain that times out must not quietly become a passphrase slot.
    pub fn with_notice(mut self, notice: Arc<Notice>) -> Self {
        self.notice = Some(notice);
        self
    }

    fn notice(&self, message: &str) {
        tracing::warn!("{message}");
        if let Some(notice) = &self.notice {
            notice(message);
        }
    }

    /// Argon2id parameters for new passphrase slots.
    pub fn with_kdf(mut self, kdf: KdfParams) -> Self {
        self.kdf = kdf;
        self
    }

    /// Sealed with a fixed, public secret and cheap parameters: the real
    /// format, with none of its protection. Tests only.
    #[doc(hidden)]
    pub fn insecure_for_tests() -> Self {
        Self {
            storage: Storage::Sealed,
            keychain: None,
            passphrase: None,
            secret: Some((SecretSource::Env, Zeroizing::new(TEST_SECRET.to_vec()))),
            prompt: None,
            kdf: KdfParams::insecure_for_tests(),
            notice: None,
        }
    }

    pub fn storage(&self) -> Storage {
        self.storage
    }

    /// The slot a new key is sealed with: an explicit secret, else the OS
    /// keychain, else a passphrase from the environment or the prompt.
    fn new_slot(&self, did: &str) -> Result<NewSlot, IdentityError> {
        if let Some((source, secret)) = &self.secret {
            return Ok(NewSlot::Secret {
                source: *source,
                secret: secret.clone(),
            });
        }
        if let Some(keychain) = &self.keychain {
            let mut secret = Zeroizing::new(vec![0u8; 32]);
            jig_core::crypto::ed25519::fill_random(&mut secret);
            match keychain.set(did, &secret) {
                Ok(()) => {
                    return Ok(NewSlot::Secret {
                        source: SecretSource::Keychain,
                        secret,
                    });
                }
                Err(e) => self.notice(&format!(
                    "{} unavailable, sealing {did} another way: {e}",
                    keychain.name()
                )),
            }
        }
        let passphrase = match &self.passphrase {
            Some(p) => Some(p.clone()),
            None => match &self.prompt {
                Some(prompt) => prompt.passphrase(did, PromptPurpose::New)?,
                None => None,
            },
        };
        match passphrase {
            Some(passphrase) if !passphrase.is_empty() => Ok(NewSlot::Passphrase {
                passphrase,
                params: self.kdf,
            }),
            _ => Err(IdentityError::NoWayToSeal {
                did: did.to_string(),
            }),
        }
    }

    fn open(&self, key: &JigKey) -> Result<Opened, IdentityError> {
        let did = key.did();
        let slots = key.slots();
        let mut offers = Vec::new();
        let mut unavailable = None;
        if let Some((_, secret)) = &self.secret {
            offers.push(Unlock::Secret(secret.clone()));
        }
        if slots.contains(&SlotKind::Secret(SecretSource::Keychain))
            && let Some(keychain) = &self.keychain
        {
            // A keychain that fails is a slot that is unavailable, not an
            // error: another slot may still open the key.
            match keychain.get(did) {
                Ok(Some(secret)) => offers.push(Unlock::Secret(secret)),
                Ok(None) => {}
                Err(e) => {
                    let why = format!("{} unavailable: {e}", keychain.name());
                    self.notice(&why);
                    unavailable = Some(why);
                }
            }
        }
        if let Some(passphrase) = &self.passphrase {
            offers.push(Unlock::Passphrase(passphrase.clone()));
        }
        match key.open(&offers) {
            Err(KeystoreError::NoSlotOpened) => {}
            other => return Ok(other?),
        }
        let has_passphrase = slots.iter().any(|s| matches!(s, SlotKind::Passphrase(_)));
        if has_passphrase && let Some(prompt) = &self.prompt {
            for _ in 0..3 {
                let Some(passphrase) = prompt.passphrase(did, PromptPurpose::Unlock)? else {
                    break;
                };
                match key.open(&[Unlock::Passphrase(passphrase)]) {
                    Err(KeystoreError::NoSlotOpened) => continue,
                    other => return Ok(other?),
                }
            }
        }
        let mut hint = describe_slots(&slots);
        if let Some(why) = unavailable {
            hint.push_str(&format!(" ({why})"));
        }
        Err(IdentityError::Locked {
            did: did.to_string(),
            hint,
        })
    }
}

fn read_unlock_spec(spec: &str) -> Result<(SecretSource, Zeroizing<Vec<u8>>), IdentityError> {
    let bad = |reason: String| IdentityError::BadEnv {
        var: "JIG_KEY_UNLOCK",
        reason,
    };
    let (source, secret) = if let Some(name) = spec.strip_prefix("env:") {
        let value = std::env::var(name).map_err(|_| bad(format!("{name} is not set")))?;
        (SecretSource::Env, Zeroizing::new(value.into_bytes()))
    } else if let Some(path) = spec.strip_prefix("credential:") {
        let bytes = std::fs::read(path).map_err(|e| bad(format!("reading {path}: {e}")))?;
        (SecretSource::Credential, Zeroizing::new(bytes))
    } else {
        // Not the value itself: it may be the secret, pasted in by mistake.
        return Err(bad(
            "must be env:NAME or credential:PATH (the value is not shown, in case it is a \
             secret)"
                .to_string(),
        ));
    };
    if secret.len() < jig_core::keystore::MIN_SECRET_LEN {
        return Err(bad(format!(
            "the secret is {} bytes; a secret slot needs at least {} (use JIG_KEY_PASSPHRASE \
             for a passphrase)",
            secret.len(),
            jig_core::keystore::MIN_SECRET_LEN
        )));
    }
    Ok((source, secret))
}

fn describe_slots(slots: &[SlotKind]) -> String {
    let names: Vec<&str> = slots
        .iter()
        .map(|s| match s {
            SlotKind::Passphrase(_) => "a passphrase",
            SlotKind::Secret(SecretSource::Keychain) => "the OS keychain",
            SlotKind::Secret(SecretSource::Credential) => "a credential file",
            SlotKind::Secret(SecretSource::Env) => "an environment secret",
        })
        .collect();
    format!(
        "its key opens with {}, and none was available",
        names.join(" or ")
    )
}

/// Keys already opened by this process, by key file. `jig` loads one identity
/// several times per command, and each load would otherwise ask the keychain
/// or the person again, and pay for Argon2id again.
static OPENED: LazyLock<Mutex<HashMap<PathBuf, Arc<AtRest>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// An opened key file: the key, the file it came from, and whether the
/// identity's local state is sealed under it (`JigKey::state_sealed`).
pub(crate) struct AtRest {
    opened: Opened,
    path: PathBuf,
    state_sealed: AtomicBool,
}

impl AtRest {
    fn new(opened: Opened, path: &Path, state_sealed: bool) -> Arc<Self> {
        Arc::new(Self {
            opened,
            path: path.to_path_buf(),
            state_sealed: AtomicBool::new(state_sealed),
        })
    }
}

/// A loaded ed25519 identity. Wraps the signing key + derived DID.
///
/// Construct with [`Identity::open`] (existing identity) or
/// [`Identity::create`] (fresh identity, sealed to disk before it returns).
pub struct Identity {
    did: Did,
    signing: SigningKey,
    /// The opened key file, whose data key seals this identity's MLS state.
    /// `None` for an identity that was never stored, or one stored raw.
    at_rest: Option<Arc<AtRest>>,
    migrated_from: Option<PathBuf>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the secret key into logs.
        f.debug_struct("Identity")
            .field("did", &self.did)
            .field("signing", &"<redacted>")
            .finish()
    }
}

/// `<keys_dir>/<did>.jigkey`.
pub fn key_path(keys_dir: &Path, did_str: &str) -> PathBuf {
    keys_dir.join(format!("{did_str}.jigkey"))
}

fn raw_key_path(keys_dir: &Path, did_str: &str) -> PathBuf {
    keys_dir.join(format!("{did_str}.key"))
}

impl Identity {
    /// Load `did_str`'s identity from `keys_dir`.
    ///
    /// Opens `<did>.jigkey` with `access`. Without one, a raw `<did>.key` is
    /// sealed into a `.jigkey` and removed (unless `access` stores plaintext).
    pub fn open(keys_dir: &Path, did_str: &str, access: &KeyAccess) -> Result<Self, IdentityError> {
        let path = key_path(keys_dir, did_str);
        let raw = raw_key_path(keys_dir, did_str);
        // Two processes may find the same raw key at once (`jig tail` and
        // `jig send` just after an upgrade). Each would seal it under its own
        // data key, and the keychain keeps only the last secret stored, so the
        // file that wins the rename may not open. One migrates; the other
        // waits, then opens what the first wrote.
        let stale = stale_temporaries(keys_dir, did_str);
        let lock = if (access.storage == Storage::Sealed && raw.exists()) || !stale.is_empty() {
            Some(lock_did(keys_dir, did_str)?)
        } else {
            None
        };
        // Temporary files a crash left behind; one written in plaintext mode
        // holds the raw seed. Every writer of this DID's files holds the
        // lock, so none of these is still being written.
        if lock.is_some() {
            for tmp in stale_temporaries(keys_dir, did_str) {
                std::fs::remove_file(&tmp)?;
            }
        }
        if path.exists() {
            let opened = open_cached(&path, did_str, access)?;
            let mut identity = Self::from_opened(did_str, &path, opened, None)?;
            // A raw file beside a sealed one is a migration that stopped after
            // sealing. Finish it, but only for the same key, and only once the
            // sealed key is known to be this DID's.
            if lock.is_some()
                && raw.exists()
                && *read_raw_seed(&raw)? == identity.signing.to_bytes()
            {
                std::fs::remove_file(&raw)?;
                identity.migrated_from = Some(raw);
            }
            return Ok(identity);
        }
        if !raw.exists() {
            return Err(IdentityError::KeyfileNotFound {
                did: did_str.to_string(),
                dir: keys_dir.to_path_buf(),
            });
        }
        let seed = read_raw_seed(&raw)?;
        let signing = SigningKey::from_bytes(&seed);
        let did = Did::from_ed25519_pubkey(signing.verifying_key().as_bytes());
        if did.to_did_jig_string() != did_str {
            return Err(IdentityError::WrongDid {
                path: raw,
                expected: did_str.to_string(),
                found: did.to_did_jig_string(),
            });
        }
        if access.storage == Storage::Plaintext {
            tracing::warn!(
                "{} is stored unencrypted (JIG_KEYS_STORAGE=plaintext)",
                raw.display()
            );
            return Ok(Self {
                did,
                signing,
                at_rest: None,
                migrated_from: None,
            });
        }
        // `seal_to` reads the new file back and opens it before this removes
        // the only other copy of the key.
        let opened = seal_to(&path, did_str, &seed, access)?;
        std::fs::remove_file(&raw)?;
        Self::from_opened(did_str, &path, opened, Some(raw))
    }

    /// Generate a fresh identity and seal it into `<keys_dir>/<did>.jigkey`,
    /// creating the directory if needed.
    pub fn create(keys_dir: &Path, access: &KeyAccess) -> Result<Self, IdentityError> {
        create_private_dir(keys_dir)?;
        // Keygen lives in jig-core, deliberately: this call and the nameserver's
        // are the protocol's only two identity-minting sites, and they used to
        // pick their own RNGs (this one reached for `rand::rng()`, a userspace
        // ChaCha PRNG, for a key that lives forever on disk). `jig-client` no
        // longer depends on `rand` at all, so that cannot drift back.
        let signing = jig_core::crypto::ed25519::generate_signing_key();
        let did = Did::from_ed25519_pubkey(signing.verifying_key().as_bytes());
        let did_str = did.to_did_jig_string();
        if access.storage == Storage::Plaintext {
            let raw = raw_key_path(keys_dir, &did_str);
            write_private_atomic(&raw, Zeroizing::new(signing.to_bytes()).as_ref())?;
            tracing::warn!(
                "{} is stored unencrypted (JIG_KEYS_STORAGE=plaintext)",
                raw.display()
            );
            return Ok(Self {
                did,
                signing,
                at_rest: None,
                migrated_from: None,
            });
        }
        let path = key_path(keys_dir, &did_str);
        let opened = seal_to(&path, &did_str, &signing.to_bytes(), access)?;
        Ok(Self {
            did,
            signing,
            at_rest: Some(opened),
            migrated_from: None,
        })
    }

    /// [`Identity::open`] with [`KeyAccess::from_env`]: no terminal prompt.
    pub fn load_from_dir(keys_dir: &Path, did_str: &str) -> Result<Self, IdentityError> {
        Self::open(keys_dir, did_str, &KeyAccess::from_env()?)
    }

    /// [`Identity::create`] with [`KeyAccess::from_env`]: no terminal prompt.
    pub fn generate_and_save(keys_dir: &Path) -> Result<Self, IdentityError> {
        Self::create(keys_dir, &KeyAccess::from_env()?)
    }

    /// [`Identity::create`] under [`KeyAccess::insecure_for_tests`].
    #[doc(hidden)]
    pub fn generate_for_tests(keys_dir: &Path) -> Self {
        Self::create(keys_dir, &KeyAccess::insecure_for_tests()).expect("test identity")
    }

    /// [`Identity::open`] under [`KeyAccess::insecure_for_tests`].
    #[doc(hidden)]
    pub fn load_for_tests(keys_dir: &Path, did_str: &str) -> Self {
        Self::open(keys_dir, did_str, &KeyAccess::insecure_for_tests()).expect("test identity")
    }

    /// Construct an in-memory identity directly from a raw ed25519 signing key,
    /// without touching disk. For ephemeral/derived identities — e.g. the email
    /// bridge's deterministic "shadow" identities — that are never persisted and
    /// don't need keyfile permission discipline. The DID is derived from the
    /// key's public half. Its MLS state, if it has any, is not sealed.
    pub fn from_signing_key(signing: SigningKey) -> Self {
        let did = Did::from_ed25519_pubkey(signing.verifying_key().as_bytes());
        Self {
            did,
            signing,
            at_rest: None,
            migrated_from: None,
        }
    }

    fn from_opened(
        did_str: &str,
        path: &Path,
        opened: Arc<AtRest>,
        migrated_from: Option<PathBuf>,
    ) -> Result<Self, IdentityError> {
        // The header names a DID, but only the seed is authenticated by the
        // slot that opened it. Check the key really is the DID asked for.
        check_did(path, did_str, &opened.opened.seed)?;
        let signing = SigningKey::from_bytes(&opened.opened.seed);
        let did = Did::from_ed25519_pubkey(signing.verifying_key().as_bytes());
        Ok(Self {
            did,
            signing,
            at_rest: Some(opened),
            migrated_from,
        })
    }

    /// Another handle on the same identity, sharing its opened key.
    pub fn duplicate(&self) -> Self {
        Self {
            did: self.did.clone(),
            signing: self.signing.clone(),
            at_rest: self.at_rest.clone(),
            migrated_from: None,
        }
    }

    pub fn did(&self) -> &Did {
        &self.did
    }

    pub fn did_string(&self) -> String {
        self.did.to_did_jig_string()
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    /// The raw keyfile this load sealed and removed, if it did.
    pub fn migrated_from(&self) -> Option<&Path> {
        self.migrated_from.as_deref()
    }

    /// Whether this identity's key, and so its MLS state, is sealed at rest.
    pub fn is_sealed(&self) -> bool {
        self.at_rest.is_some()
    }

    /// The key that seals one kind of this identity's local files, or `None`
    /// when the identity is not sealed at rest.
    pub(crate) fn file_key(&self, context: &str) -> Option<FileKey> {
        self.at_rest.as_ref().map(|o| o.opened.file_key(context))
    }

    /// Whether this identity's local state has been sealed under its key, as
    /// the key file on disk says now. The flag is authenticated: the file
    /// is checked against this identity's data key before it is believed.
    /// A key file that is gone (rotated away) keeps what was known at open.
    pub(crate) fn state_sealed(&self) -> Result<bool, IdentityError> {
        let Some(at) = &self.at_rest else {
            return Ok(false);
        };
        let bytes = match std::fs::read(&at.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(at.state_sealed.load(Ordering::SeqCst));
            }
            Err(e) => return Err(e.into()),
        };
        let key = JigKey::from_bytes(&bytes)?;
        // Builds a flagged copy, which first checks the file opens with this
        // data key: the flag read below is then the file's own.
        key.with_state_sealed(&at.opened)?;
        let sealed = key.state_sealed() || at.state_sealed.load(Ordering::SeqCst);
        at.state_sealed.store(sealed, Ordering::SeqCst);
        Ok(sealed)
    }

    /// Record in the key file that this identity's local state is sealed, so
    /// content found in clear is refused from now on.
    pub(crate) fn mark_state_sealed(&self) -> Result<(), IdentityError> {
        let Some(at) = &self.at_rest else {
            return Ok(());
        };
        let keys_dir = at.path.parent().unwrap_or(Path::new("."));
        let _lock = lock_did(keys_dir, &self.did_string())?;
        let key = JigKey::from_bytes(&std::fs::read(&at.path)?)?;
        let flagged = key.with_state_sealed(&at.opened)?;
        if !key.state_sealed() {
            write_private_atomic(&at.path, &flagged.to_bytes())?;
        }
        at.state_sealed.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// The DID's own key as an MLS group member. The same key signs blocks
    /// and MLS messages — see `jig_mls::credential`. Crate-private so the
    /// seed never leaves this crate.
    pub(crate) fn mls_member(&self) -> Result<jig_mls::member::Member, jig_mls::MlsError> {
        jig_mls::member::Member::new(&self.signing.to_bytes(), &self.did)
    }

    #[cfg(test)]
    pub(crate) fn signing_bytes_for_test(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub(crate) fn restore_mls_member(
        &self,
        snapshot: &[u8],
    ) -> Result<jig_mls::member::Member, jig_mls::MlsError> {
        jig_mls::member::Member::restore(&self.signing.to_bytes(), &self.did, snapshot)
    }
}

/// Seal every `<did>.key.rotated` left by `jig keys rotate` into
/// `<did>.jigkey.rotated`, removing the raw files. Returns the files sealed.
pub fn seal_rotated_keys(
    keys_dir: &Path,
    access: &KeyAccess,
) -> Result<Vec<PathBuf>, IdentityError> {
    if access.storage == Storage::Plaintext {
        return Ok(Vec::new());
    }
    let mut sealed = Vec::new();
    let Ok(entries) = std::fs::read_dir(keys_dir) else {
        return Ok(sealed);
    };
    for entry in entries {
        let raw = entry?.path();
        let Some(did_str) = raw
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".key.rotated"))
            .map(str::to_string)
        else {
            continue;
        };
        let _lock = lock_did(keys_dir, &did_str)?;
        if !raw.exists() {
            // Another process sealed it while this one waited.
            continue;
        }
        let seed = read_raw_seed(&raw)?;
        let signing = SigningKey::from_bytes(&seed);
        let found =
            Did::from_ed25519_pubkey(signing.verifying_key().as_bytes()).to_did_jig_string();
        if found != did_str {
            return Err(IdentityError::WrongDid {
                path: raw,
                expected: did_str,
                found,
            });
        }
        let path = keys_dir.join(format!("{did_str}.jigkey.rotated"));
        seal_to(&path, &did_str, &seed, access)?;
        std::fs::remove_file(&raw)?;
        sealed.push(path);
    }
    Ok(sealed)
}

fn open_cached(
    path: &Path,
    did_str: &str,
    access: &KeyAccess,
) -> Result<Arc<AtRest>, IdentityError> {
    if let Some(hit) = OPENED.lock().expect("key cache poisoned").get(path) {
        return Ok(hit.clone());
    }
    if let Some(mode) = loose_mode(path)? {
        access.notice(&format!(
            "{} has permissions {mode:o}; it is sealed, but should be 0600",
            path.display()
        ));
    }
    let key = JigKey::from_bytes(&std::fs::read(path)?)?;
    let opened = access.open(&key)?;
    // Cache only a key that is the DID asked for: a later open of this path
    // takes the cached key without opening the file again.
    check_did(path, did_str, &opened.seed)?;
    let opened = AtRest::new(opened, path, key.state_sealed());
    OPENED
        .lock()
        .expect("key cache poisoned")
        .insert(path.to_path_buf(), opened.clone());
    Ok(opened)
}

fn seal_to(
    path: &Path,
    did_str: &str,
    seed: &[u8; 32],
    access: &KeyAccess,
) -> Result<Arc<AtRest>, IdentityError> {
    let slot = access.new_slot(did_str)?;
    let check = match &slot {
        NewSlot::Passphrase { passphrase, .. } => Some(Unlock::Passphrase(passphrase.clone())),
        NewSlot::Secret {
            source: SecretSource::Keychain,
            ..
        } => None,
        NewSlot::Secret { secret, .. } => Some(Unlock::Secret(secret.clone())),
    };
    let (key, _) = JigKey::seal(did_str, seed, &[slot])?;
    write_private_atomic(path, &key.to_bytes())?;
    // Open what is now on disk the way the next run will, keychain included:
    // the caller may be about to delete the only other copy of this key.
    let not_verified = |reason: String| IdentityError::NotVerified {
        path: path.to_path_buf(),
        reason,
    };
    let reopened = match reopen_as_written(path, did_str, seed, check, access) {
        Ok(reopened) => reopened,
        Err(e) => {
            // A key file that does not open is worse than none: every later
            // open would try it, fail, and never fall back to the raw key.
            let _ = std::fs::remove_file(path);
            return Err(not_verified(e));
        }
    };
    // Cache the key as it was read back, not the one in memory.
    let opened = AtRest::new(reopened, path, false);
    OPENED
        .lock()
        .expect("key cache poisoned")
        .insert(path.to_path_buf(), opened.clone());
    Ok(opened)
}

/// Open the key just written at `path` with what sealed it, the keychain read
/// back rather than trusted, and check it holds `seed`.
fn reopen_as_written(
    path: &Path,
    did_str: &str,
    seed: &[u8; 32],
    check: Option<Unlock>,
    access: &KeyAccess,
) -> Result<Opened, String> {
    let unlock = match check {
        Some(unlock) => unlock,
        None => {
            let keychain = access
                .keychain
                .as_ref()
                .ok_or_else(|| "the keychain went away".to_string())?;
            let secret = keychain
                .get(did_str)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("{} kept no secret", keychain.name()))?;
            Unlock::Secret(secret)
        }
    };
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let reopened = JigKey::from_bytes(&bytes)
        .and_then(|key| key.open(&[unlock]))
        .map_err(|e| e.to_string())?;
    if *reopened.seed != *seed {
        return Err("it opens to another key".into());
    }
    Ok(reopened)
}

/// Write `bytes` to `path` through an owner-only temporary file and a rename,
/// so a reader sees the old file or the new one, never a partial one. The
/// directory is synced too, so the new name survives a crash: a caller that
/// removes the file it replaced (the raw-key migration) can do so safely.
pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    replace_private(path, bytes)?;
    sync_parent_dir(path)
}

/// [`write_private_atomic`] without the directory sync, for a caller that
/// replaces several files and then calls [`sync_parent_dir`] once.
pub(crate) fn replace_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // A name of its own: another process may be writing the same file, and
    // its temporary file is not this one's to remove.
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(
        ".tmp.{}",
        hex::encode(jig_core::crypto::ed25519::random_array::<8>())
    ));
    let tmp = PathBuf::from(tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Make a rename or removal in `path`'s directory durable. Unix only: Windows
/// cannot open a directory as a file, and its renames are journalled.
pub(crate) fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        std::fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// `<did>.*.tmp.*` files in `keys_dir`: temporary files of this DID's.
fn stale_temporaries(keys_dir: &Path, did_str: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(keys_dir) else {
        return Vec::new();
    };
    let prefix = format!("{did_str}.");
    entries
        .flatten()
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with(&prefix) && name.contains(".tmp.")
        })
        .map(|e| e.path())
        .collect()
}

/// Hold `<did>.lock` in `keys_dir` until the returned file drops. Blocks.
fn lock_did(keys_dir: &Path, did_str: &str) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let f = options.open(keys_dir.join(format!("{did_str}.lock")))?;
    f.lock()?;
    Ok(f)
}

fn check_did(path: &Path, did_str: &str, seed: &[u8; 32]) -> Result<(), IdentityError> {
    let signing = SigningKey::from_bytes(seed);
    let found = Did::from_ed25519_pubkey(signing.verifying_key().as_bytes()).to_did_jig_string();
    if found != did_str {
        return Err(IdentityError::WrongDid {
            path: path.to_path_buf(),
            expected: did_str.to_string(),
            found,
        });
    }
    Ok(())
}

/// `path`'s mode, if anyone but its owner may read or write it.
#[cfg(unix)]
fn loose_mode(path: &Path) -> std::io::Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    Ok((mode & 0o077 != 0).then_some(mode))
}
#[cfg(not(unix))]
fn loose_mode(_path: &Path) -> std::io::Result<Option<u32>> {
    Ok(None)
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn read_raw_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    enforce_secure_permissions(path)?;
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::Malformed {
            path: path.to_path_buf(),
            len: bytes.len(),
        })?;
    Ok(Zeroizing::new(seed))
}

#[cfg(unix)]
fn enforce_secure_permissions(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(IdentityError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}
#[cfg(not(unix))]
fn enforce_secure_permissions(_path: &Path) -> Result<(), IdentityError> {
    Ok(())
}

/// Default keys directory: `~/.jig/keys/`.
pub fn default_keys_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".jig/keys")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::MemoryKeychain;
    use tempfile::tempdir;

    fn no_keychain() -> KeyAccess {
        KeyAccess::insecure_for_tests()
    }

    fn passphrase_only(p: &str) -> KeyAccess {
        KeyAccess {
            storage: Storage::Sealed,
            keychain: None,
            passphrase: Some(Zeroizing::new(p.into())),
            secret: None,
            prompt: None,
            kdf: KdfParams::insecure_for_tests(),
            notice: None,
        }
    }

    fn keychain_only(k: Arc<MemoryKeychain>) -> KeyAccess {
        KeyAccess {
            storage: Storage::Sealed,
            keychain: Some(k),
            passphrase: None,
            secret: None,
            prompt: None,
            kdf: KdfParams::insecure_for_tests(),
            notice: None,
        }
    }

    fn clear_cache() {
        OPENED.lock().unwrap().clear();
    }

    #[test]
    fn create_then_open_round_trips() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_for_tests(dir.path());
        let did_str = id.did_string();
        assert!(key_path(dir.path(), &did_str).exists());
        assert!(!raw_key_path(dir.path(), &did_str).exists());
        clear_cache();
        let reloaded = Identity::load_for_tests(dir.path(), &did_str);
        assert_eq!(reloaded.public_key(), id.public_key());
        assert!(reloaded.is_sealed());
    }

    #[test]
    fn a_key_file_holds_no_seed_in_clear() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_for_tests(dir.path());
        let bytes = std::fs::read(key_path(dir.path(), &id.did_string())).unwrap();
        let seed = id.signing_bytes_for_test();
        assert!(!bytes.windows(32).any(|w| w == seed));
    }

    #[test]
    fn the_keychain_slot_opens_from_the_keychain_alone() {
        let dir = tempdir().unwrap();
        let k = Arc::new(MemoryKeychain::default());
        let id = Identity::create(dir.path(), &keychain_only(k.clone())).unwrap();
        let did_str = id.did_string();
        assert!(k.get(&did_str).unwrap().is_some());
        clear_cache();
        let again = Identity::open(dir.path(), &did_str, &keychain_only(k.clone())).unwrap();
        assert_eq!(again.public_key(), id.public_key());

        clear_cache();
        let empty = Arc::new(MemoryKeychain::default());
        let err = Identity::open(dir.path(), &did_str, &keychain_only(empty)).unwrap_err();
        assert!(matches!(err, IdentityError::Locked { .. }), "{err}");
    }

    #[test]
    fn without_a_keychain_a_passphrase_seals_and_a_wrong_one_is_refused() {
        let dir = tempdir().unwrap();
        let id = Identity::create(dir.path(), &passphrase_only("hunter2")).unwrap();
        clear_cache();
        assert!(Identity::open(dir.path(), &id.did_string(), &passphrase_only("hunter2")).is_ok());
        clear_cache();
        let err =
            Identity::open(dir.path(), &id.did_string(), &passphrase_only("wrong")).unwrap_err();
        assert!(matches!(err, IdentityError::Locked { .. }));
    }

    #[test]
    fn nothing_to_seal_with_is_an_error() {
        let dir = tempdir().unwrap();
        let access = KeyAccess {
            storage: Storage::Sealed,
            keychain: None,
            passphrase: None,
            secret: None,
            prompt: None,
            kdf: KdfParams::insecure_for_tests(),
            notice: None,
        };
        assert!(matches!(
            Identity::create(dir.path(), &access).unwrap_err(),
            IdentityError::NoWayToSeal { .. }
        ));
    }

    struct Answers(Mutex<Vec<&'static str>>);
    impl Prompt for Answers {
        fn passphrase(
            &self,
            _did: &str,
            _purpose: PromptPurpose,
        ) -> std::io::Result<Option<Zeroizing<String>>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .pop()
                .map(|s| Zeroizing::new(s.into())))
        }
    }

    #[test]
    fn the_prompt_seals_and_retries_on_a_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let mut access = passphrase_only("unused");
        access.passphrase = None;
        let access = access.with_prompt(Arc::new(Answers(Mutex::new(vec!["right"]))));
        let id = Identity::create(dir.path(), &access).unwrap();
        clear_cache();
        // Answers pop from the end: wrong, then right.
        let mut access = passphrase_only("unused");
        access.passphrase = None;
        let access = access.with_prompt(Arc::new(Answers(Mutex::new(vec!["right", "wrong"]))));
        assert!(Identity::open(dir.path(), &id.did_string(), &access).is_ok());
    }

    #[test]
    fn a_raw_keyfile_is_sealed_on_first_open_and_removed() {
        let dir = tempdir().unwrap();
        let (raw, did_str) = write_golden_raw(dir.path());
        let id = Identity::open(dir.path(), &did_str, &no_keychain()).unwrap();
        assert_eq!(id.migrated_from(), Some(raw.as_path()));
        assert!(!raw.exists());
        assert!(key_path(dir.path(), &did_str).exists());
        clear_cache();
        let again = Identity::load_for_tests(dir.path(), &did_str);
        assert_eq!(again.did_string(), did_str);
        assert!(again.migrated_from().is_none());
    }

    #[test]
    fn an_interrupted_migration_is_finished_on_the_next_open() {
        let dir = tempdir().unwrap();
        let (raw, did_str) = write_golden_raw(dir.path());
        Identity::open(dir.path(), &did_str, &no_keychain()).unwrap();
        // As if the process died between sealing and removing the raw file.
        write_golden_raw(dir.path());
        let id = Identity::open(dir.path(), &did_str, &no_keychain()).unwrap();
        assert_eq!(id.migrated_from(), Some(raw.as_path()));
        assert!(!raw.exists());
    }

    #[test]
    fn processes_migrating_one_raw_key_at_once_leave_a_key_that_opens() {
        let dir = tempdir().unwrap();
        let (raw, did_str) = write_golden_raw(dir.path());
        let k = Arc::new(MemoryKeychain::default());
        // Without the lock, each would store its own keychain secret and the
        // last one stored need not be the one in the file that won.
        let opens: Vec<_> = (0..4)
            .map(|_| {
                let (dir, did_str, k) = (dir.path().to_path_buf(), did_str.clone(), k.clone());
                std::thread::spawn(move || Identity::open(&dir, &did_str, &keychain_only(k)))
            })
            .collect();
        for open in opens {
            assert_eq!(open.join().unwrap().unwrap().did_string(), did_str);
        }
        assert!(!raw.exists());
        clear_cache();
        let again = Identity::open(dir.path(), &did_str, &keychain_only(k)).unwrap();
        assert_eq!(again.did_string(), did_str);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// Takes the secret and keeps nothing.
    struct ForgetfulKeychain;
    impl Keychain for ForgetfulKeychain {
        fn get(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            Ok(None)
        }
        fn set(&self, _: &str, _: &[u8]) -> Result<(), KeychainError> {
            Ok(())
        }
        fn delete(&self, _: &str) -> Result<(), KeychainError> {
            Ok(())
        }
        fn name(&self) -> &'static str {
            "forgetful keychain"
        }
    }

    #[test]
    fn a_raw_key_stays_until_its_sealed_copy_opens_from_disk() {
        let dir = tempdir().unwrap();
        let (raw, did_str) = write_golden_raw(dir.path());
        let mut access = passphrase_only("unused");
        access.passphrase = None;
        access.keychain = Some(Arc::new(ForgetfulKeychain));
        let err = Identity::open(dir.path(), &did_str, &access).unwrap_err();
        assert!(matches!(err, IdentityError::NotVerified { .. }), "{err}");
        assert!(raw.exists(), "the only working copy of the key was removed");
        assert!(
            !key_path(dir.path(), &did_str).exists(),
            "a key file that does not open was left to shadow the raw key"
        );
        // So the next run, with a keychain that works, still has the key.
        clear_cache();
        let k = Arc::new(MemoryKeychain::default());
        let id = Identity::open(dir.path(), &did_str, &keychain_only(k)).unwrap();
        assert_eq!(id.did_string(), did_str);
        assert!(!raw.exists());
    }

    #[test]
    fn temporary_key_files_a_crash_left_are_removed() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_for_tests(dir.path());
        let did_str = id.did_string();
        // As plaintext mode would leave it: the raw seed, under a temp name.
        let stale = dir
            .path()
            .join(format!("{did_str}.key.tmp.0123456789abcdef"));
        std::fs::write(&stale, [7u8; 32]).unwrap();
        clear_cache();
        Identity::load_for_tests(dir.path(), &did_str);
        assert!(!stale.exists());
    }

    #[test]
    fn the_state_sealed_flag_is_kept_in_the_key_file() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_for_tests(dir.path());
        assert!(!id.state_sealed().unwrap());
        id.mark_state_sealed().unwrap();
        clear_cache();
        let again = Identity::load_for_tests(dir.path(), &id.did_string());
        assert!(again.state_sealed().unwrap());
        // Another handle, opened before the flag was set, reads it from disk.
        assert!(id.duplicate().state_sealed().unwrap());
    }

    #[test]
    fn a_keychain_that_fails_is_reported_not_only_logged() {
        let dir = tempdir().unwrap();
        let said = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut access = passphrase_only("pw");
        access.keychain = Some(Arc::new(BrokenKeychain));
        let heard = said.clone();
        let access = access.with_notice(Arc::new(move |m| heard.lock().unwrap().push(m.into())));
        let id = Identity::create(dir.path(), &access).unwrap();
        let said = said.lock().unwrap();
        assert!(
            said.iter().any(|m| m.contains("broken keychain")),
            "{said:?}"
        );
        drop(said);

        // A key that only the keychain opens names the keychain's failure.
        let k = Arc::new(MemoryKeychain::default());
        let kc = Identity::create(dir.path(), &keychain_only(k)).unwrap();
        clear_cache();
        let mut broken = keychain_only(Arc::new(MemoryKeychain::default()));
        broken.keychain = Some(Arc::new(BrokenKeychain));
        let err = Identity::open(dir.path(), &kc.did_string(), &broken).unwrap_err();
        assert!(err.to_string().contains("locked"), "{err}");
        let _ = id;
    }

    #[test]
    fn a_bad_unlock_spec_does_not_echo_its_value() {
        let err = read_unlock_spec("correct-horse-battery-staple-0123456789").unwrap_err();
        assert!(!err.to_string().contains("correct-horse"), "{err}");
    }

    struct BrokenKeychain;
    impl Keychain for BrokenKeychain {
        fn get(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            Err(KeychainError::Backend("locked".into()))
        }
        fn set(&self, _: &str, _: &[u8]) -> Result<(), KeychainError> {
            Err(KeychainError::Backend("locked".into()))
        }
        fn delete(&self, _: &str) -> Result<(), KeychainError> {
            Ok(())
        }
        fn name(&self) -> &'static str {
            "broken keychain"
        }
    }

    #[test]
    fn a_failing_keychain_falls_back_to_the_passphrase() {
        let dir = tempdir().unwrap();
        let mut access = passphrase_only("pw");
        access.keychain = Some(Arc::new(BrokenKeychain));
        // Sealing skips the keychain that refuses, and uses the passphrase.
        let id = Identity::create(dir.path(), &access).unwrap();
        clear_cache();
        assert!(Identity::open(dir.path(), &id.did_string(), &access).is_ok());
    }

    /// A keychain that never answers, as one waiting on a prompt nobody sees.
    struct StuckKeychain;
    impl Keychain for StuckKeychain {
        fn get(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            std::thread::sleep(std::time::Duration::from_secs(60));
            Ok(None)
        }
        fn set(&self, _: &str, _: &[u8]) -> Result<(), KeychainError> {
            std::thread::sleep(std::time::Duration::from_secs(60));
            Ok(())
        }
        fn delete(&self, _: &str) -> Result<(), KeychainError> {
            Ok(())
        }
        fn name(&self) -> &'static str {
            "stuck keychain"
        }
    }

    #[test]
    fn a_stuck_keychain_with_a_person_present_ends_in_a_passphrase_never_plaintext() {
        let dir = tempdir().unwrap();
        let stuck = crate::keychain::Bounded::new(
            Box::new(StuckKeychain),
            std::time::Duration::from_millis(50),
        );
        let mut access = passphrase_only("unused");
        access.passphrase = None;
        access.keychain = Some(Arc::new(stuck));
        let access = access.with_prompt(Arc::new(Answers(Mutex::new(vec!["typed"]))));
        let id = Identity::create(dir.path(), &access).unwrap();
        assert!(id.is_sealed());
        let key =
            JigKey::from_bytes(&std::fs::read(key_path(dir.path(), &id.did_string())).unwrap())
                .unwrap();
        assert_eq!(
            key.slots(),
            vec![SlotKind::Passphrase(KdfParams::insecure_for_tests())]
        );
        assert!(!raw_key_path(dir.path(), &id.did_string()).exists());
    }

    #[test]
    fn plaintext_storage_keeps_the_raw_file() {
        let dir = tempdir().unwrap();
        let (raw, did_str) = write_golden_raw(dir.path());
        let mut access = no_keychain();
        access.storage = Storage::Plaintext;
        let id = Identity::open(dir.path(), &did_str, &access).unwrap();
        assert!(!id.is_sealed());
        assert!(raw.exists());
        let created = Identity::create(dir.path(), &access).unwrap();
        assert!(raw_key_path(dir.path(), &created.did_string()).exists());
    }

    #[test]
    fn rotated_raw_keys_are_sealed() {
        let dir = tempdir().unwrap();
        let (raw, did_str) = write_golden_raw(dir.path());
        let rotated = dir.path().join(format!("{did_str}.key.rotated"));
        std::fs::rename(&raw, &rotated).unwrap();
        let sealed = seal_rotated_keys(dir.path(), &no_keychain()).unwrap();
        assert_eq!(
            sealed,
            vec![dir.path().join(format!("{did_str}.jigkey.rotated"))]
        );
        assert!(!rotated.exists());
    }

    #[test]
    fn a_key_file_for_another_did_is_refused() {
        let dir = tempdir().unwrap();
        let a = Identity::generate_for_tests(dir.path());
        let b = Identity::generate_for_tests(dir.path());
        std::fs::rename(
            key_path(dir.path(), &b.did_string()),
            key_path(dir.path(), &a.did_string()),
        )
        .unwrap();
        clear_cache();
        let err = Identity::open(dir.path(), &a.did_string(), &no_keychain()).unwrap_err();
        assert!(matches!(err, IdentityError::WrongDid { .. }), "{err}");
    }

    #[test]
    fn signs_and_verifies() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_for_tests(dir.path());
        let msg = b"hello world";
        let sig = id.sign(msg);
        use ed25519_dalek::Verifier;
        assert!(id.public_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn load_missing_keyfile_returns_keyfile_not_found() {
        let dir = tempdir().unwrap();
        let err = Identity::open(dir.path(), "did:jig:znope", &no_keychain()).unwrap_err();
        assert!(matches!(err, IdentityError::KeyfileNotFound { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_raw_keyfile() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let (raw, did_str) = write_golden_raw(dir.path());
        std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = Identity::open(dir.path(), &did_str, &no_keychain()).unwrap_err();
        assert!(matches!(err, IdentityError::InsecurePermissions { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let keys = dir.path().join("keys");
        let id = Identity::generate_for_tests(&keys);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&key_path(&keys, &id.did_string())), 0o600);
        assert_eq!(mode(&keys), 0o700);
    }

    #[test]
    fn debug_does_not_leak_signing_key() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_for_tests(dir.path());
        let debug_str = format!("{id:?}");
        assert!(debug_str.contains("redacted"));
        // Should NOT contain raw key bytes
        assert!(!debug_str.contains("SigningKey"));
    }

    #[test]
    fn default_keys_dir_points_to_dot_jig_keys() {
        let path = default_keys_dir();
        let s = path.to_string_lossy();
        assert!(s.ends_with(".jig/keys") || s.ends_with(".jig\\keys"));
    }

    #[test]
    fn generate_creates_canonical_did_jig_string() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_for_tests(dir.path());
        let did_str = id.did_string();
        assert!(
            did_str.starts_with("did:jig:z"),
            "generated DID must use canonical form, got `{did_str}`"
        );
    }

    #[test]
    fn from_signing_key_derives_matching_did_and_signs() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let expected_did = jig_core::Did::from_ed25519_pubkey(sk.verifying_key().as_bytes());
        let id = Identity::from_signing_key(sk);
        assert_eq!(id.did(), &expected_did);
        assert!(!id.is_sealed());
        // The identity can sign (no panic, produces a 64-byte sig).
        let sig = id.sign(b"hello");
        assert_eq!(sig.to_bytes().len(), 64);
    }

    const SEED: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    const GOLDEN_DID: &str = "did:jig:zpg2vmlup4zkpsqdywejorkmlu6ib7bj242k35v7a4oiqxlieszsa";

    fn write_golden_raw(dir: &Path) -> (PathBuf, String) {
        let path = raw_key_path(dir, GOLDEN_DID);
        std::fs::write(&path, SEED).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (path, GOLDEN_DID.to_string())
    }

    /// Keyfile format freeze.
    ///
    /// A raw `~/.jig/keys/<did>.key` from before `.jigkey` must still load to
    /// its original identity: this seed is the one `jig-core`'s
    /// `signing_stability` vectors use, and the DID they pin. Loading it now
    /// also seals it.
    ///
    /// A failure here means already-issued identities were renamed. It is not a
    /// fixture to refresh.
    #[test]
    fn a_preexisting_keyfile_still_loads_to_its_original_did() {
        let dir = tempdir().unwrap();
        write_golden_raw(dir.path());
        let id = Identity::open(dir.path(), GOLDEN_DID, &no_keychain()).unwrap();
        assert_eq!(
            id.did_string(),
            GOLDEN_DID,
            "a keyfile from before the keygen change loads as a different identity"
        );
    }

    #[test]
    fn malformed_keyfile_returns_malformed_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("did:jig:zbad.key");
        std::fs::write(&path, b"too short").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = Identity::open(dir.path(), "did:jig:zbad", &no_keychain()).unwrap_err();
        assert!(matches!(err, IdentityError::Malformed { len: 9, .. }));
    }

    #[test]
    fn unlock_specs_parse_and_short_secrets_are_refused() {
        let dir = tempdir().unwrap();
        let cred = dir.path().join("cred");
        std::fs::write(&cred, [9u8; 40]).unwrap();
        let (source, secret) = read_unlock_spec(&format!("credential:{}", cred.display())).unwrap();
        assert_eq!(source, SecretSource::Credential);
        assert_eq!(secret.len(), 40);
        std::fs::write(&cred, [9u8; 8]).unwrap();
        assert!(read_unlock_spec(&format!("credential:{}", cred.display())).is_err());
        assert!(read_unlock_spec("file:/x").is_err());
    }
}
