//! A server's or nameserver's own signing key at rest.
//!
//! The key lives in a `.jigkey` (`jig_core::keystore`), like a CLI identity.
//! A server boots unattended, so it never prompts and never uses the OS
//! keychain. It opens the key with what its configuration names:
//!
//! - `[keys] unlock`: `credential:PATH` (a systemd credential), `env:NAME`, or
//!   `passphrase` (read from `JIG_KEY_PASSPHRASE`);
//! - `JIG_KEY_UNLOCK` and `JIG_KEY_PASSPHRASE`, the same as for the CLI.
//!
//! A configured keyfile path names the key either way: `server.key` and
//! `server.jigkey` both mean the sealed `server.jigkey`. A raw 32-byte seed is
//! refused unless `[keys] storage = "plaintext"`, and the refusal names the
//! command that seals it. Migration is explicit for servers: an operator
//! chooses the slot, so nothing is sealed behind their back.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use jig_core::Did;
use jig_core::keystore::{
    JigKey, KdfParams, KeystoreError, NewSlot, SecretSource, SlotKind, Unlock,
};
use zeroize::Zeroizing;

use crate::identity::{
    MIN_PASSPHRASE_CHARS, read_unlock_spec_from, sync_parent_dir, write_private_atomic,
};

#[derive(Debug, thiserror::Error)]
pub enum ServerKeyError {
    #[error(
        "{path:?} is a raw {role} key, stored in clear, and keys are now sealed. Seal it in \
         place with `{tool} keys seal --keyfile {path:?} --slot credential:PATH` (or --slot \
         env:NAME, or --slot passphrase with JIG_KEY_PASSPHRASE set): the {role} keeps its DID, \
         and the raw file is removed. Then set [keys] unlock to the same slot. Or set [keys] \
         storage = \"plaintext\" to keep running it in clear"
    )]
    RawRefused {
        path: PathBuf,
        role: &'static str,
        tool: &'static str,
    },
    #[error(
        "{raw:?} and {sealed:?} both exist, and neither is used while both are there: {verdict}"
    )]
    BothPresent {
        raw: PathBuf,
        sealed: PathBuf,
        verdict: String,
    },
    #[error("{0:?} already exists; it is never overwritten")]
    Exists(PathBuf),
    #[error(
        "no {role} key at {path:?}, and nothing to seal a new one with: set [keys] unlock to \
         credential:PATH, env:NAME or passphrase, or set JIG_KEY_UNLOCK or JIG_KEY_PASSPHRASE"
    )]
    NoWayToSeal { role: &'static str, path: PathBuf },
    #[error(
        "cannot open the {role} key at {path:?}: it has {slots}, and nothing offered opens \
         one. Set [keys] unlock, JIG_KEY_UNLOCK or JIG_KEY_PASSPHRASE for one of them{skipped}"
    )]
    Locked {
        role: &'static str,
        path: PathBuf,
        slots: String,
        /// For an operator command: what was configured but could not be read.
        skipped: String,
    },
    #[error("that --slot does not open the {role} key at {path:?}, which has {slots}")]
    DoesNotOpen {
        role: &'static str,
        path: PathBuf,
        slots: String,
    },
    #[error("{path:?} names {claimed} but holds the key for {found}")]
    WrongDid {
        path: PathBuf,
        claimed: String,
        found: String,
    },
    #[error("{0}")]
    BadUnlock(String),
    #[error(
        "{path:?} ends a chain of {hops} key links, the most a client follows. Rotating again \
         needs --prune-oldest, which stops serving the oldest, from {oldest} (made {since}): a \
         client still pinned on {oldest} is then refused, and re-pinning trusts the server on \
         first use again"
    )]
    TooManyHops {
        path: PathBuf,
        hops: usize,
        oldest: String,
        since: String,
    },
    #[error(
        "{old} already has a key link, {path:?}: one DID never links to two keys (JEP-0012), \
         because two links from one key are what a stolen key looks like"
    )]
    AlreadyLinked { old: String, path: PathBuf },
    #[error("{path:?}: {reason}")]
    BadLink { path: PathBuf, reason: String },
    #[error(
        "{path:?} is outside $CREDENTIALS_DIRECTORY ({dir:?}): under a unit with credentials, \
         [keys] unlock names one of them, not a file beside the key"
    )]
    NotACredential { path: PathBuf, dir: PathBuf },
    #[error("keyfile {path:?} has insecure permissions {mode:o} (must be 0600)")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("keyfile {path:?} is malformed: expected 32 bytes, got {len}")]
    Malformed { path: PathBuf, len: usize },
    #[error("{path:?} did not open again to the same key, so {kept}")]
    NotVerified { path: PathBuf, kept: String },
    #[error("{path:?}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path:?}: {source}")]
    Keystore {
        path: PathBuf,
        source: KeystoreError,
    },
}

type Result<T> = std::result::Result<T, ServerKeyError>;

/// How one binary loads its key.
#[derive(Debug, Clone)]
pub struct ServerKeyOptions {
    /// `server` or `nameserver`, for messages.
    pub role: &'static str,
    /// The binary an operator runs to seal a key: `jig-server`, `jig-nameserver`.
    pub tool: &'static str,
    /// `[keys] unlock`.
    pub unlock: Option<String>,
    /// `[keys] storage = "plaintext"`: run with a raw key, warning on every boot.
    pub plaintext: bool,
    /// Argon2id cost for a new passphrase slot.
    pub kdf: KdfParams,
}

impl ServerKeyOptions {
    pub fn new(role: &'static str, tool: &'static str) -> Self {
        Self {
            role,
            tool,
            unlock: None,
            plaintext: false,
            kdf: KdfParams::default(),
        }
    }
}

/// The sealed file a configured keyfile path names: `server.key` and
/// `server.jigkey` both name `server.jigkey`.
pub fn sealed_path(path: &Path) -> PathBuf {
    if path.extension().is_some_and(|e| e == "jigkey") {
        path.to_path_buf()
    } else {
        path.with_extension("jigkey")
    }
}

/// Where a secret is being read for. At boot every configured secret must be
/// readable and a credential must be one systemd handed this unit (when it
/// handed it any). An operator command, run by hand with the unit stopped,
/// skips a configured secret it cannot read and tries the next.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Use {
    Boot,
    Operator,
}

/// A secret that opens or makes one slot. Read once and cloned where it is
/// needed again: a `credential:` path may be a pipe (`<(systemd-creds
/// decrypt ...)`), which reads only once.
#[derive(Clone)]
enum Spec {
    Secret(SecretSource, Zeroizing<Vec<u8>>),
    Passphrase(Zeroizing<String>),
}

impl Spec {
    /// `credential:PATH`, `env:NAME` or `passphrase`, from `source` (named in
    /// errors: `[keys] unlock`, `JIG_KEY_UNLOCK`, `--slot`).
    fn parse(spec: &str, source: &'static str, used: Use) -> Result<Self> {
        Self::parse_reading(spec, source, used, "JIG_KEY_PASSPHRASE")
    }

    /// [`Spec::parse`], with `passphrase` read from `passphrase_var`: a new
    /// key's passphrase is not the old one's.
    fn parse_reading(
        spec: &str,
        source: &'static str,
        used: Use,
        passphrase_var: &'static str,
    ) -> Result<Self> {
        if spec == "passphrase" {
            let passphrase = std::env::var(passphrase_var).map_err(|_| {
                ServerKeyError::BadUnlock(format!(
                    "{source}: the passphrase slot reads {passphrase_var}, which is not set; \
                     a server never prompts"
                ))
            })?;
            return Ok(Spec::Passphrase(Zeroizing::new(passphrase)));
        }
        let spec = match spec.strip_prefix("credential:") {
            Some(path) => format!(
                "credential:{}",
                credential_path(path, source, used)?.display()
            ),
            None => spec.to_string(),
        };
        // Name only the slot kind: a value with no kind may be the secret
        // itself, pasted in by mistake.
        let (kind, secret) = read_unlock_spec_from(&spec, source)
            .map_err(|e| ServerKeyError::BadUnlock(e.to_string()))?;
        Ok(Spec::Secret(kind, secret))
    }

    fn offer(self) -> Unlock {
        match self {
            Spec::Secret(_, secret) => Unlock::Secret(secret),
            Spec::Passphrase(passphrase) => Unlock::Passphrase(passphrase),
        }
    }

    fn slot(self, kdf: KdfParams) -> Result<NewSlot> {
        Ok(match self {
            Spec::Secret(source, secret) => NewSlot::Secret { source, secret },
            Spec::Passphrase(passphrase) => {
                if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
                    return Err(ServerKeyError::BadUnlock(format!(
                        "a new passphrase slot needs at least {MIN_PASSPHRASE_CHARS} characters"
                    )));
                }
                NewSlot::Passphrase {
                    passphrase,
                    params: kdf,
                }
            }
        })
    }
}

/// The file a `credential:` names, resolved: what is checked is what is read.
///
/// At boot, under a unit with credentials (`$CREDENTIALS_DIRECTORY` set), it
/// must be inside that directory once `..` and symlinks are resolved: anywhere
/// else it is a secret file on disk, likely beside the key it opens. Without
/// one, a plain file is only warned about. An operator command may read a
/// credential through a pipe and is never checked.
fn credential_path(path: &str, source: &'static str, used: Use) -> Result<PathBuf> {
    let given = PathBuf::from(path);
    let resolved = given.canonicalize().ok();
    if used == Use::Boot {
        if resolved.is_none() {
            return Err(ServerKeyError::BadUnlock(format!(
                "{source}: credential {path} does not exist. Under systemd only the unit sees \
                 its credentials, and only when its LoadCredentialEncrypted= line names this one"
            )));
        }
        match std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from) {
            Some(dir)
                if !resolved.as_ref().is_some_and(|real| {
                    dir.canonicalize().is_ok_and(|dir| real.starts_with(dir))
                }) =>
            {
                return Err(ServerKeyError::NotACredential { path: given, dir });
            }
            Some(_) => {}
            None => tracing::warn!(
                "the key opens with a secret read from {path}, a plain file: it protects the \
                 key only as far as that file is kept apart from it. A systemd credential \
                 (LoadCredentialEncrypted=) keeps it encrypted at rest"
            ),
        }
    }
    Ok(resolved.unwrap_or(given))
}

/// What this process was given, in order: `[keys] unlock`, then
/// `JIG_KEY_UNLOCK`, then `JIG_KEY_PASSPHRASE`. At boot any of them that
/// cannot be read is an error. For an operator command it is skipped, and
/// the second value says why, for an error if nothing else opens the key.
fn configured(opts: &ServerKeyOptions, used: Use) -> Result<(Vec<Spec>, String)> {
    let mut specs = Vec::new();
    let mut skipped = Vec::new();
    let given = opts
        .unlock
        .iter()
        .map(|s| ("[keys] unlock", s.clone()))
        .chain(
            std::env::var("JIG_KEY_UNLOCK")
                .ok()
                .map(|s| ("JIG_KEY_UNLOCK", s)),
        );
    for (source, spec) in given {
        match Spec::parse(&spec, source, used) {
            Ok(parsed) => specs.push(parsed),
            Err(e) if used == Use::Operator => skipped.push(e.to_string()),
            Err(e) => return Err(e),
        }
    }
    let named_passphrase = opts.unlock.as_deref() == Some("passphrase");
    if !named_passphrase && let Ok(passphrase) = std::env::var("JIG_KEY_PASSPHRASE") {
        specs.push(Spec::Passphrase(Zeroizing::new(passphrase)));
    }
    let skipped = if skipped.is_empty() {
        String::new()
    } else {
        format!(" (skipped: {})", skipped.join("; "))
    };
    Ok((specs, skipped))
}

/// Open `key`, read from `path`, with what `opts` offers.
fn open_with(
    key: &JigKey,
    path: &Path,
    opts: &ServerKeyOptions,
    used: Use,
) -> Result<jig_core::keystore::Opened> {
    let (specs, skipped) = configured(opts, used)?;
    let offers: Vec<Unlock> = specs.into_iter().map(Spec::offer).collect();
    key.open(&offers).map_err(|e| match e {
        KeystoreError::NoSlotOpened => ServerKeyError::Locked {
            role: opts.role,
            path: path.to_path_buf(),
            slots: describe_slots(&key.slots()),
            skipped,
        },
        source => ServerKeyError::Keystore {
            path: path.to_path_buf(),
            source,
        },
    })
}

/// Why a raw key and its sealed copy are both there, and what to do: only
/// once the two are known to hold the same key is removing the raw one safe.
fn both_present(raw: &Path, sealed: &Path, opts: &ServerKeyOptions, used: Use) -> ServerKeyError {
    let verdict = match (read_raw_seed(raw), read_jigkey(sealed)) {
        (Err(e), _) => format!(
            "{} cannot be read ({e}); keep both and look before removing either",
            raw.display()
        ),
        (Ok(_), Err(e)) => format!(
            "{} is damaged ({e}), perhaps from an interrupted seal: keep {}, move the sealed \
             file aside, and run `{} keys seal` again",
            sealed.display(),
            raw.display(),
            opts.tool
        ),
        (Ok(seed), Ok(key)) => match open_with(&key, sealed, opts, used) {
            Err(e) => format!(
                "{} does not open with what was offered ({e}), so it cannot be compared: keep \
                 {} until it does",
                sealed.display(),
                raw.display()
            ),
            Ok(opened) if *opened.seed == *seed => format!(
                "both hold the same key, {}: remove {} (unlinking it does not erase it)",
                did_of(&seed),
                raw.display()
            ),
            Ok(opened) => format!(
                "they hold different keys: {} is {}, {} is {}. Remove neither until you know \
                 which DID this {} has published",
                raw.display(),
                did_of(&seed),
                sealed.display(),
                did_of(&opened.seed),
                opts.role
            ),
        },
    };
    ServerKeyError::BothPresent {
        raw: raw.to_path_buf(),
        sealed: sealed.to_path_buf(),
        verdict,
    }
}

/// The message for a key that only one slot opens, if it is one: losing that
/// one secret (a TPM with its machine) loses the key.
pub fn single_slot_warning(role: &str, slots: &[SlotKind]) -> Option<String> {
    (slots.len() == 1).then(|| {
        format!(
            "the {role} key has one slot ({}): if that secret is lost, so is the key, and a \
             TPM-bound credential is lost with its machine. Add a second, such as a passphrase \
             kept offline: `keys add-slot --slot passphrase`",
            describe_slots(slots)
        )
    })
}

/// Load the key `path` names, or make and seal one if there is none.
pub fn load_or_create(path: &Path, opts: &ServerKeyOptions) -> Result<SigningKey> {
    let sealed = sealed_path(path);
    let raw = (sealed != path).then_some(path);
    match (sealed.exists(), raw.filter(|r| r.exists())) {
        (true, Some(raw)) => Err(both_present(raw, &sealed, opts, Use::Boot)),
        (true, None) => open_sealed(&sealed, opts),
        (false, Some(raw)) if opts.plaintext => {
            warn_plaintext(raw, opts);
            Ok(SigningKey::from_bytes(&*read_raw_seed(raw)?))
        }
        (false, Some(raw)) => Err(ServerKeyError::RawRefused {
            path: raw.to_path_buf(),
            role: opts.role,
            tool: opts.tool,
        }),
        (false, None) if opts.plaintext => {
            let raw = raw.unwrap_or(path);
            warn_plaintext(raw, opts);
            let signing = jig_core::crypto::ed25519::generate_signing_key();
            jig_core::crypto::ed25519::write_new_key_file(raw, &signing).map_err(|source| {
                ServerKeyError::Io {
                    path: raw.to_path_buf(),
                    source,
                }
            })?;
            Ok(signing)
        }
        (false, None) => create_sealed(&sealed, opts),
    }
}

/// Seal the raw key at `raw` with one slot per entry of `specs` into the
/// `.jigkey` beside it, keeping its DID and its owner, then remove `raw`.
/// Returns the sealed path and the DID.
///
/// The sealed copy is written to a temporary file, synced, read back and
/// opened with every slot named, and only then linked into place, never over
/// an existing file. So a crash or a failed check leaves no `.jigkey` behind,
/// and the raw key stays the one good copy until a verified one exists.
/// Removing `raw` unlinks it; it does not erase the blocks it used.
pub fn seal_raw(
    raw: &Path,
    specs: &[String],
    opts: &ServerKeyOptions,
) -> Result<(PathBuf, String)> {
    let sealed = sealed_path(raw);
    if sealed == raw {
        return Err(ServerKeyError::BadUnlock(format!(
            "{raw:?} is already a .jigkey"
        )));
    }
    if sealed.exists() {
        return Err(if raw.exists() {
            both_present(raw, &sealed, opts, Use::Operator)
        } else {
            ServerKeyError::Exists(sealed)
        });
    }
    if specs.is_empty() {
        return Err(ServerKeyError::BadUnlock(
            "name at least one --slot: credential:PATH, env:NAME or passphrase".to_string(),
        ));
    }
    let seed = read_raw_seed(raw)?;
    let did = did_of(&seed);
    let parsed = specs
        .iter()
        .map(|s| Spec::parse(s, "--slot", Use::Operator))
        .collect::<Result<Vec<_>>>()?;
    let slots = parsed
        .iter()
        .map(|s| s.clone().slot(opts.kdf))
        .collect::<Result<Vec<_>>>()?;
    let (key, _) =
        JigKey::seal(&did, &seed, &slots).map_err(|source| ServerKeyError::Keystore {
            path: sealed.clone(),
            source,
        })?;
    let tmp = temporary(&sealed);
    let staged = (|| {
        write_new(&tmp, &key.to_bytes())?;
        same_owner(&tmp, raw)?;
        // Read back what is on disk, and open it with every slot just named,
        // before the only other copy goes.
        let reopened = read_jigkey(&tmp)?;
        for spec in parsed {
            if !reopened
                .open(&[spec.offer()])
                .is_ok_and(|o| *o.seed == *seed)
            {
                return Err(ServerKeyError::NotVerified {
                    path: sealed.clone(),
                    kept: format!("nothing was written and the raw key {raw:?} was kept"),
                });
            }
        }
        // A link, unlike a rename, fails rather than replace a file that
        // appeared meanwhile.
        std::fs::hard_link(&tmp, &sealed).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ServerKeyError::Exists(sealed.clone())
            } else {
                ServerKeyError::Io {
                    path: sealed.clone(),
                    source: e,
                }
            }
        })
    })();
    let _ = std::fs::remove_file(&tmp);
    staged?;
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| ServerKeyError::Io { path, source }
    };
    sync_parent_dir(&sealed).map_err(io(&sealed))?;
    std::fs::remove_file(raw).map_err(io(raw))?;
    sync_parent_dir(raw).map_err(io(raw))?;
    Ok((sealed, did))
}

/// A name beside `path` for a file being staged, unique to this call.
fn temporary(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(
        ".tmp.{}",
        hex::encode(jig_core::crypto::ed25519::random_array::<8>())
    ));
    PathBuf::from(tmp)
}

/// Give `path` the owner and group of `like`: a key sealed or rewritten by
/// root must stay readable by the server user that owned it. A no-op unless
/// they differ, which only root can change.
fn same_owner(path: &Path, like: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let io = |source| ServerKeyError::Io {
            path: path.to_path_buf(),
            source,
        };
        let want = std::fs::metadata(like).map_err(|source| ServerKeyError::Io {
            path: like.to_path_buf(),
            source,
        })?;
        let have = std::fs::metadata(path).map_err(io)?;
        if (have.uid(), have.gid()) != (want.uid(), want.gid()) {
            std::os::unix::fs::chown(path, Some(want.uid()), Some(want.gid())).map_err(io)?;
        }
    }
    #[cfg(not(unix))]
    let _ = (path, like);
    Ok(())
}

/// Make a new key and seal it at `path` (a `.jigkey`) with one slot per entry
/// of `specs`, for a key ceremony: no copy of the key is ever written in
/// clear. Returns the DID.
pub fn generate_sealed(path: &Path, specs: &[String], kdf: KdfParams) -> Result<String> {
    if specs.is_empty() {
        return Err(ServerKeyError::BadUnlock(
            "name at least one --slot: credential:PATH, env:NAME or passphrase".to_string(),
        ));
    }
    let sealed = sealed_path(path);
    if sealed != path && path.exists() {
        // A raw key beside the new sealed one would make boot refuse both.
        return Err(ServerKeyError::Exists(path.to_path_buf()));
    }
    let path = sealed;
    let slots = specs
        .iter()
        .map(|s| Spec::parse(s, "--slot", Use::Operator)?.slot(kdf))
        .collect::<Result<Vec<_>>>()?;
    let seed = Zeroizing::new(jig_core::crypto::ed25519::generate_signing_key().to_bytes());
    let did = did_of(&seed);
    let (key, _) =
        JigKey::seal(&did, &seed, &slots).map_err(|source| ServerKeyError::Keystore {
            path: path.clone(),
            source,
        })?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|source| ServerKeyError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    }
    write_new(&path, &key.to_bytes())?;
    Ok(did)
}

/// Add a slot made from `new_spec` to the sealed key at `path`, opening it
/// with what `opts` offers. For moving a ceremony key onto its server: seal
/// it offline with a passphrase, then add the server's credential there. A
/// configured secret that cannot be read (a unit's credential, with the unit
/// stopped) is skipped, so `JIG_KEY_PASSPHRASE` still opens it.
///
/// The new slot is checked to open the key, the file is replaced atomically,
/// and it keeps its owner.
pub fn add_slot(path: &Path, opts: &ServerKeyOptions, new_spec: &str) -> Result<String> {
    let path = sealed_path(path);
    let key = read_jigkey(&path)?;
    let keystore = |source| ServerKeyError::Keystore {
        path: path.clone(),
        source,
    };
    let opened = open_with(&key, &path, opts, Use::Operator)?;
    let new = Spec::parse(new_spec, "--slot", Use::Operator)?;
    let updated = key
        .with_slot(&opened, &new.clone().slot(opts.kdf)?)
        .map_err(keystore)?;
    let reopened = JigKey::from_bytes(&updated.to_bytes()).map_err(keystore)?;
    if !reopened
        .open(&[new.offer()])
        .is_ok_and(|o| *o.seed == *opened.seed)
    {
        return Err(ServerKeyError::NotVerified {
            path: path.clone(),
            kept: "the file was left as it was".to_string(),
        });
    }
    let owner = temporary(&path);
    std::fs::hard_link(&path, &owner).map_err(|source| ServerKeyError::Io {
        path: path.clone(),
        source,
    })?;
    let written = write_private_atomic(&path, &updated.to_bytes())
        .map_err(|source| ServerKeyError::Io {
            path: path.clone(),
            source,
        })
        .and_then(|()| same_owner(&path, &owner));
    let _ = std::fs::remove_file(&owner);
    written?;
    Ok(describe_slots(&updated.slots()))
}

/// Where a server's key link is read from: beside its configured keyfile,
/// with `.link` appended (`server.key.link` for `server.key`). The file holds
/// the link's COSE_Sign bytes (JEP-0012).
pub fn key_link_path(keyfile: &Path) -> PathBuf {
    let mut name = keyfile.as_os_str().to_owned();
    name.push(".link");
    PathBuf::from(name)
}

/// What [`rotate`] did.
#[derive(Debug)]
pub struct Rotated {
    pub old_did: String,
    pub new_did: String,
    /// The old key, still sealed with its own slots.
    pub retired: PathBuf,
    /// The new link, from `old_did` to `new_did`.
    pub link: PathBuf,
    /// Where the link it replaced was kept, and the DID that link left.
    pub archived: Option<(PathBuf, String)>,
    /// With `prune_oldest`: where the oldest link went, no longer served, and
    /// the DID it left. A client still pinned on that DID must re-pin.
    pub pruned: Option<(PathBuf, String)>,
}

/// One link of a server's chain, as [`key_chain`] read it.
#[derive(Debug, Clone)]
pub struct ChainLink {
    pub path: PathBuf,
    pub old: String,
    pub new: String,
    pub issued_at: i64,
    /// The COSE_Sign bytes, as served.
    pub bytes: Vec<u8>,
}

/// What a server serves: its key links, oldest first, the last ending at its
/// DID, and what was wrong with any link file it left out.
#[derive(Debug, Default)]
pub struct KeyChain {
    pub links: Vec<ChainLink>,
    /// Each names a file, and why it is not served.
    pub problems: Vec<String>,
}

/// The chain of key links a server with `keyfile` and `server_did` serves
/// (JEP-0012), oldest first: the newest is `<keyfile>.link`, and each one
/// before it is the `<keyfile>.link.N` that moves to the DID the next one
/// leaves. At most [`jig_pipeline::handshake::MAX_KEY_LINK_HOPS`].
///
/// Only the newest decides whether the server can boot: missing, there is no
/// chain; unreadable, unverifiable, not public, or not moving to
/// `server_did`, it is an error, since every client that pinned the old DID
/// would refuse the server. A bad or missing older link only ends the chain
/// there: what is served is still all verified, and clients pinned behind
/// the break get the loud refusal they would get with no chain. Each such
/// file is named in `problems`, for the server to log.
pub fn key_chain(keyfile: &Path, server_did: &str) -> Result<KeyChain> {
    let link_path = key_link_path(keyfile);
    let read = |path: &Path| -> std::result::Result<ChainLink, String> {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        let signed =
            jig_core::key_link::SignedKeyLink::from_envelope(&bytes).map_err(|e| e.to_string())?;
        let link = signed.link();
        if link.audience != jig_core::key_link::Audience::Public {
            return Err("the key link is not a public one".to_string());
        }
        Ok(ChainLink {
            path: path.to_path_buf(),
            old: link.old.clone(),
            new: link.new.clone(),
            issued_at: link.issued_at,
            bytes,
        })
    };
    let files = link_files(&link_path)?;
    let mut chain = KeyChain::default();
    if !link_path.exists() {
        if !files.archives.is_empty() {
            chain.problems.push(format!(
                "{} is missing, so none of the earlier links beside it is served",
                link_path.display()
            ));
        }
        return Ok(chain);
    }
    let newest = read(&link_path).map_err(|reason| ServerKeyError::BadLink {
        path: link_path.clone(),
        reason,
    })?;
    if newest.new != server_did {
        return Err(ServerKeyError::BadLink {
            path: link_path,
            reason: format!(
                "the key link moves to {}, not to this server's DID {server_did}",
                newest.new
            ),
        });
    }
    let mut archives = Vec::new();
    for path in &files.archives {
        match read(path) {
            Ok(link) => archives.push(link),
            Err(reason) => chain
                .problems
                .push(format!("{} is not served: {reason}", path.display())),
        }
    }
    let mut seen = vec![server_did.to_string(), newest.old.clone()];
    let mut links = vec![newest];
    let max = jig_pipeline::handshake::MAX_KEY_LINK_HOPS;
    loop {
        let leaves = links[0].old.clone();
        let into: Vec<&ChainLink> = archives.iter().filter(|l| l.new == leaves).collect();
        let Some(&before) = into.first() else {
            break;
        };
        let stop = |why: String| format!("the chain stops at {leaves}: {why}");
        if into.len() > 1 {
            let names: Vec<String> = into.iter().map(|l| l.path.display().to_string()).collect();
            chain.problems.push(stop(format!(
                "{} all move to it; serve one of them",
                names.join(", ")
            )));
            break;
        }
        if seen.contains(&before.old) {
            chain.problems.push(stop(format!(
                "{} leaves {}, already in the chain",
                before.path.display(),
                before.old
            )));
            break;
        }
        if let Some(fork) = archives
            .iter()
            .chain(links.iter())
            .find(|l| l.old == before.old && l.new != before.new)
        {
            chain.problems.push(stop(format!(
                "{} and {} both leave {}: a fork, never served (JEP-0012)",
                before.path.display(),
                fork.path.display(),
                before.old
            )));
            break;
        }
        if links.len() == max {
            chain.problems.push(stop(format!(
                "a client follows at most {max} links, so {} and any before it are not served",
                before.path.display()
            )));
            break;
        }
        seen.push(before.old.clone());
        links.insert(0, before.clone());
    }
    for unused in archives
        .iter()
        .filter(|a| !links.iter().any(|l| l.path == a.path))
    {
        if !chain
            .problems
            .iter()
            .any(|p| p.contains(&*unused.path.to_string_lossy()))
        {
            chain.problems.push(format!(
                "{} is not served: it moves {} to {}, which no later link leaves",
                unused.path.display(),
                unused.old,
                unused.new
            ));
        }
    }
    chain.links = links;
    Ok(chain)
}

/// Replace the server's key at `keyfile` with a new one sealed with one slot
/// per entry of `specs`, and link the old DID to the new one with a public
/// key link signed by both (JEP-0012), so clients and peers that pinned the
/// old DID follow it. The configured keyfile path, and the config that
/// names it, stay as they are.
///
/// The old key is opened as `opts` says, like [`add_slot`]. A `passphrase`
/// slot for the new key reads `JIG_KEY_NEW_PASSPHRASE`, not the old one's.
///
/// A link already beside the key is kept as `<link>.N`, so the chain the
/// server serves ([`key_chain`]) grows by one: clients pinned on any DID in
/// it follow every hop. A chain already
/// [`jig_pipeline::handshake::MAX_KEY_LINK_HOPS`] long grows only with
/// `prune_oldest`, which moves the oldest link aside as `<link>.pruned-N`,
/// no longer served: a client still pinned on the DID it leaves must re-pin.
/// A DID that any link beside the key, pruned or not, already leaves is never
/// linked again.
///
/// The new key and the link are staged, read back and checked first: every
/// slot opens the new key, and the link verifies from the old DID to the new.
/// Only then is the old key kept as `<stem>.retired-<did tail>.jigkey` and
/// the new key and link renamed into place. The old key is never deleted.
pub fn rotate(
    keyfile: &Path,
    specs: &[String],
    prune_oldest: bool,
    opts: &ServerKeyOptions,
    now: i64,
) -> Result<Rotated> {
    use jig_core::key_link::{Audience, SignedKeyLink};
    let sealed = sealed_path(keyfile);
    if sealed != keyfile && keyfile.exists() {
        return Err(both_present(keyfile, &sealed, opts, Use::Operator));
    }
    let key = read_jigkey(&sealed)?;
    let opened = open_with(&key, &sealed, opts, Use::Operator)?;
    let old_did = did_of(&opened.seed);
    if old_did != key.did() {
        return Err(ServerKeyError::WrongDid {
            path: sealed,
            claimed: key.did().to_string(),
            found: old_did,
        });
    }
    let link_path = key_link_path(keyfile);
    refuse_relink(&links_beside(&link_path)?, &old_did)?;
    // What the server serves now, ending at the key being replaced. A newest
    // link that would stop the server booting stops this too.
    let chain = key_chain(keyfile, &old_did)?;
    let max = jig_pipeline::handshake::MAX_KEY_LINK_HOPS;
    let prune = match chain.links.first() {
        Some(oldest) if chain.links.len() >= max => {
            if !prune_oldest {
                return Err(ServerKeyError::TooManyHops {
                    path: link_path,
                    hops: chain.links.len(),
                    oldest: oldest.old.clone(),
                    since: utc(oldest.issued_at),
                });
            }
            Some(oldest.clone())
        }
        _ => None,
    };
    if specs.is_empty() {
        return Err(ServerKeyError::BadUnlock(
            "name at least one --slot for the new key: credential:PATH, env:NAME or passphrase"
                .to_string(),
        ));
    }
    let parsed = specs
        .iter()
        .map(|s| Spec::parse_reading(s, "--slot", Use::Operator, "JIG_KEY_NEW_PASSPHRASE"))
        .collect::<Result<Vec<_>>>()?;
    let slots = parsed
        .iter()
        .map(|s| s.clone().slot(opts.kdf))
        .collect::<Result<Vec<_>>>()?;
    let new_signing = jig_core::crypto::ed25519::generate_signing_key();
    let new_seed = Zeroizing::new(new_signing.to_bytes());
    let new_did = did_of(&new_seed);
    let (new_key, _) =
        JigKey::seal(&new_did, &new_seed, &slots).map_err(|source| ServerKeyError::Keystore {
            path: sealed.clone(),
            source,
        })?;
    let link = SignedKeyLink::sign(
        &SigningKey::from_bytes(&opened.seed),
        &new_signing,
        Audience::Public,
        now,
    )
    .map_err(|e| ServerKeyError::BadLink {
        path: link_path.clone(),
        reason: e.to_string(),
    })?;

    let tmp_key = temporary(&sealed);
    let tmp_link = temporary(&link_path);
    let staged = (|| {
        write_new(&tmp_key, &new_key.to_bytes())?;
        same_owner(&tmp_key, &sealed)?;
        let reopened = read_jigkey(&tmp_key)?;
        for spec in parsed {
            if !reopened
                .open(&[spec.offer()])
                .is_ok_and(|o| *o.seed == *new_seed)
            {
                return Err(ServerKeyError::NotVerified {
                    path: sealed.clone(),
                    kept: "nothing was changed".to_string(),
                });
            }
        }
        write_new(&tmp_link, link.envelope())?;
        same_owner(&tmp_link, &sealed)?;
        check_link_file(&tmp_link, &old_did, &new_did)
    })();
    let unstage = || {
        let _ = std::fs::remove_file(&tmp_key);
        let _ = std::fs::remove_file(&tmp_link);
    };
    if let Err(e) = staged {
        unstage();
        return Err(e);
    }

    // Keep what is replaced under names nothing else uses, then rename the
    // new files over the old ones: each rename is atomic, and a link,
    // unlike a rename, never replaces a file that is already there.
    // Every name is chosen before the first file is made, so a failure here
    // leaves nothing behind.
    let names = (|| {
        let archive_to = match chain.links.last() {
            Some(_) => Some(next_archive(&link_path)?),
            None => None,
        };
        let prune_to = match &prune {
            Some(_) => Some(next_pruned(&link_path)?),
            None => None,
        };
        Ok::<_, ServerKeyError>((archive_to, prune_to))
    })();
    let (archive_to, prune_to) = match names {
        Ok(names) => names,
        Err(e) => {
            unstage();
            return Err(e);
        }
    };
    let retired = retired_path(&sealed, &old_did);
    if let Err(e) = link_new(&sealed, &retired) {
        unstage();
        return Err(e);
    }
    let archived = match chain.links.last().zip(archive_to) {
        Some((current, to)) => match link_new(&link_path, &to) {
            Ok(archived) => Some((archived, current.old.clone())),
            Err(e) => {
                unstage();
                let _ = std::fs::remove_file(&retired);
                return Err(e);
            }
        },
        None => None,
    };
    // Kept, under a name the chain is not read from.
    let pruned = match prune.zip(prune_to) {
        Some((oldest, to)) => {
            let moved = link_new(&oldest.path, &to).and_then(|to| {
                std::fs::remove_file(&oldest.path)
                    .map(|()| to)
                    .map_err(|source| ServerKeyError::Io {
                        path: oldest.path.clone(),
                        source,
                    })
            });
            match moved {
                Ok(to) => Some((to, oldest.old, oldest.path)),
                Err(e) => {
                    unstage();
                    let _ = std::fs::remove_file(&retired);
                    if let Some((archived, _)) = &archived {
                        let _ = std::fs::remove_file(archived);
                    }
                    return Err(e);
                }
            }
        }
        None => None,
    };
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| ServerKeyError::Io { path, source }
    };
    // A pruned link goes back where it was served from.
    let unprune = || {
        if let Some((to, _, from)) = &pruned {
            let _ = std::fs::rename(to, from);
        }
    };
    if let Err(e) = std::fs::rename(&tmp_key, &sealed) {
        unstage();
        unprune();
        let _ = std::fs::remove_file(&retired);
        if let Some((archived, _)) = &archived {
            let _ = std::fs::remove_file(archived);
        }
        return Err(io(&sealed)(e));
    }
    if let Err(e) = std::fs::rename(&tmp_link, &link_path) {
        // The new key is in place without its link: put the old one back,
        // so the server keeps booting as the DID its clients pinned.
        let restored = std::fs::rename(&retired, &sealed);
        let _ = std::fs::remove_file(&tmp_link);
        unprune();
        if let Some((archived, _)) = &archived {
            let _ = std::fs::remove_file(archived);
        }
        return Err(match restored {
            Ok(()) => ServerKeyError::NotVerified {
                path: link_path,
                kept: format!("the old key was put back ({e})"),
            },
            Err(undo) => ServerKeyError::BadLink {
                path: link_path,
                reason: format!(
                    "{e}, and putting the old key back failed too ({undo}). {sealed:?} now holds \
                     the new key with no link: copy {retired:?} over it before restarting"
                ),
            },
        });
    }
    sync_parent_dir(&sealed).map_err(io(&sealed))?;
    sync_parent_dir(&link_path).map_err(io(&link_path))?;
    Ok(Rotated {
        old_did,
        new_did,
        retired,
        link: link_path,
        archived,
        pruned: pruned.map(|(to, left, _)| (to, left)),
    })
}

/// Link the DID of the sealed key at `old_keyfile` to the DID of the one at
/// `keyfile`, writing the link beside `keyfile` ([`key_link_path`]), where a
/// server configured with `keyfile` serves it. For a key made offline with
/// `keys generate`; [`rotate`] does this and the swap in one step.
///
/// The old key opens as `opts` says. The new key opens with `slot` alone if
/// given (a `passphrase` reads `JIG_KEY_NEW_PASSPHRASE`), else as `opts`
/// says. An existing link is never overwritten, and a DID that a link beside
/// `keyfile` already leaves is never linked again. Returns the two DIDs and
/// the link's path.
pub fn link(
    old_keyfile: &Path,
    keyfile: &Path,
    slot: Option<&str>,
    opts: &ServerKeyOptions,
    now: i64,
) -> Result<(String, String, PathBuf)> {
    use jig_core::key_link::{Audience, SignedKeyLink};
    let open = |path: &Path, spec: Option<Spec>| -> Result<Zeroizing<[u8; 32]>> {
        let path = sealed_path(path);
        let key = read_jigkey(&path)?;
        let opened = match spec {
            Some(spec) => key.open(&[spec.offer()]).map_err(|e| match e {
                KeystoreError::NoSlotOpened => ServerKeyError::DoesNotOpen {
                    role: opts.role,
                    path: path.clone(),
                    slots: describe_slots(&key.slots()),
                },
                source => ServerKeyError::Keystore {
                    path: path.clone(),
                    source,
                },
            })?,
            None => open_with(&key, &path, opts, Use::Operator)?,
        };
        let found = did_of(&opened.seed);
        if found != key.did() {
            return Err(ServerKeyError::WrongDid {
                path,
                claimed: key.did().to_string(),
                found,
            });
        }
        Ok(Zeroizing::new(*opened.seed))
    };
    let new_spec = slot
        .map(|s| Spec::parse_reading(s, "--slot", Use::Operator, "JIG_KEY_NEW_PASSPHRASE"))
        .transpose()?;
    let old_seed = open(old_keyfile, None)?;
    let new_seed = open(keyfile, new_spec)?;
    let (old_did, new_did) = (did_of(&old_seed), did_of(&new_seed));
    let link_path = key_link_path(keyfile);
    if link_path.exists() {
        return Err(ServerKeyError::Exists(link_path));
    }
    refuse_relink(&links_beside(&link_path)?, &old_did)?;
    let link = SignedKeyLink::sign(
        &SigningKey::from_bytes(&old_seed),
        &SigningKey::from_bytes(&new_seed),
        Audience::Public,
        now,
    )
    .map_err(|e| ServerKeyError::BadLink {
        path: link_path.clone(),
        reason: e.to_string(),
    })?;
    let tmp = temporary(&link_path);
    let staged = (|| {
        write_new(&tmp, link.envelope())?;
        same_owner(&tmp, &sealed_path(keyfile))?;
        check_link_file(&tmp, &old_did, &new_did)?;
        link_new(&tmp, &link_path).map(|_| ())
    })();
    let _ = std::fs::remove_file(&tmp);
    staged?;
    sync_parent_dir(&link_path).map_err(|source| ServerKeyError::Io {
        path: link_path.clone(),
        source,
    })?;
    Ok((old_did, new_did, link_path))
}

/// The files beside `link_path` that hold links: the earlier links
/// (`<link_path>.N`) and the pruned ones (`<link_path>.pruned-N`), each list
/// sorted by N.
struct LinkFiles {
    archives: Vec<PathBuf>,
    pruned: Vec<PathBuf>,
}

fn link_files(link_path: &Path) -> Result<LinkFiles> {
    let dir = match link_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = link_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut archives: Vec<(u32, PathBuf)> = Vec::new();
    let mut pruned: Vec<(u32, PathBuf)> = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LinkFiles {
                archives: Vec::new(),
                pruned: Vec::new(),
            });
        }
        Err(source) => return Err(ServerKeyError::Io { path: dir, source }),
    };
    for entry in entries {
        let entry = entry.map_err(|source| ServerKeyError::Io {
            path: dir.clone(),
            source,
        })?;
        let file = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = file.strip_prefix(&name).and_then(|r| r.strip_prefix('.')) else {
            continue;
        };
        let number = |digits: &str| digits.parse::<u32>().ok().filter(|_| !digits.is_empty());
        if let Some(n) = number(rest) {
            archives.push((n, entry.path()));
        } else if let Some(n) = rest.strip_prefix("pruned-").and_then(number) {
            pruned.push((n, entry.path()));
        }
    }
    archives.sort();
    pruned.sort();
    Ok(LinkFiles {
        archives: archives.into_iter().map(|(_, p)| p).collect(),
        pruned: pruned.into_iter().map(|(_, p)| p).collect(),
    })
}

/// Every link beside `link_path`: the newest, the earlier ones and the
/// pruned ones, each verified. A file there that does not verify is an error,
/// not skipped: which DID it leaves cannot be known.
fn links_beside(link_path: &Path) -> Result<Vec<(PathBuf, jig_core::key_link::SignedKeyLink)>> {
    let files = link_files(link_path)?;
    let mut found = Vec::new();
    let paths = std::iter::once(link_path.to_path_buf())
        .chain(files.archives)
        .chain(files.pruned);
    for path in paths {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => return Err(ServerKeyError::Io { path, source }),
        };
        let link = jig_core::key_link::SignedKeyLink::from_envelope(&bytes).map_err(|e| {
            ServerKeyError::BadLink {
                path: path.clone(),
                reason: format!(
                    "{e}. Which DID it leaves cannot be read, so no key is linked until it is \
                     moved aside"
                ),
            }
        })?;
        found.push((path, link));
    }
    Ok(found)
}

/// Refuse to link `old` again if one of `links` already leaves it.
fn refuse_relink(links: &[(PathBuf, jig_core::key_link::SignedKeyLink)], old: &str) -> Result<()> {
    match links.iter().find(|(_, l)| l.link().old == old) {
        Some((path, _)) => Err(ServerKeyError::AlreadyLinked {
            old: old.to_string(),
            path: path.clone(),
        }),
        None => Ok(()),
    }
}

/// Read the link at `path` back and check it is public and moves `old` to
/// `new`, as a booting server will.
fn check_link_file(path: &Path, old: &str, new: &str) -> Result<()> {
    let bytes = std::fs::read(path).map_err(|source| ServerKeyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let bad = |reason: String| ServerKeyError::BadLink {
        path: path.to_path_buf(),
        reason,
    };
    let link =
        jig_core::key_link::SignedKeyLink::from_envelope(&bytes).map_err(|e| bad(e.to_string()))?;
    let link = link.link();
    if link.audience != jig_core::key_link::Audience::Public || link.old != old || link.new != new {
        return Err(bad(
            "it did not read back as the link just signed".to_string()
        ));
    }
    Ok(())
}

/// `<stem>.retired-<last 8 of the DID>.jigkey` beside `sealed`.
fn retired_path(sealed: &Path, did: &str) -> PathBuf {
    let tail = &did[did.len().saturating_sub(8)..];
    let stem = sealed
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    sealed.with_file_name(format!("{stem}.retired-{tail}.jigkey"))
}

fn archive_path(link_path: &Path, n: u32) -> PathBuf {
    let mut name = link_path.as_os_str().to_owned();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

fn pruned_path(link_path: &Path, n: u32) -> PathBuf {
    let mut name = link_path.as_os_str().to_owned();
    name.push(format!(".pruned-{n}"));
    PathBuf::from(name)
}

/// `<link_path>.N` for the N after the highest there is.
fn next_archive(link_path: &Path) -> Result<PathBuf> {
    let n = link_files(link_path)?
        .archives
        .iter()
        .filter_map(|p| p.extension()?.to_str()?.parse::<u32>().ok())
        .max()
        .unwrap_or(0);
    Ok(archive_path(link_path, n + 1))
}

/// `<link_path>.pruned-N` for the N after the highest there is.
fn next_pruned(link_path: &Path) -> Result<PathBuf> {
    let n = link_files(link_path)?
        .pruned
        .iter()
        .filter_map(|p| p.to_str()?.rsplit_once(".pruned-")?.1.parse::<u32>().ok())
        .max()
        .unwrap_or(0);
    Ok(pruned_path(link_path, n + 1))
}

/// Hard-link `from` to `to`, refusing an existing `to`. Returns `to`.
fn link_new(from: &Path, to: &Path) -> Result<PathBuf> {
    std::fs::hard_link(from, to).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            ServerKeyError::Exists(to.to_path_buf())
        } else {
            ServerKeyError::Io {
                path: to.to_path_buf(),
                source: e,
            }
        }
    })?;
    Ok(to.to_path_buf())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn utc(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| format!("{secs} (Unix seconds)"))
}

/// A `keys` subcommand of `jig-server` or `jig-nameserver`, apart from its
/// argument parsing.
pub enum KeysAction {
    /// Seal a raw keyfile beside itself and remove it ([`seal_raw`]).
    Seal {
        keyfile: PathBuf,
        slots: Vec<String>,
    },
    /// Add a slot to a sealed key ([`add_slot`]).
    AddSlot { keyfile: PathBuf, slot: String },
    /// The DID and the slots ([`describe`]).
    Show { keyfile: PathBuf },
    /// Make a new key, sealed, where there is none ([`generate_sealed`]).
    Generate {
        keyfile: PathBuf,
        slots: Vec<String>,
    },
    /// Check that one secret opens the key ([`verify`]).
    Verify { keyfile: PathBuf, slot: String },
    /// Replace the key with a new one and link the old DID to it ([`rotate`]).
    Rotate {
        keyfile: PathBuf,
        slots: Vec<String>,
        prune_oldest: bool,
    },
    /// Link one sealed key's DID to another's ([`link`]).
    Link {
        old_keyfile: PathBuf,
        keyfile: PathBuf,
        slot: Option<String>,
    },
}

/// Run `action`, returning what to print.
pub fn run(action: KeysAction, opts: &ServerKeyOptions) -> Result<String> {
    match action {
        KeysAction::Seal { keyfile, slots } => {
            let (sealed, did) = seal_raw(&keyfile, &slots, opts)?;
            let mut out = format!(
                "sealed {did} into {}\nremoved {}: that unlinks the file but does not erase it \
                 from the disk, nor from backups made before now",
                sealed.display(),
                keyfile.display()
            );
            if let Some(warning) = single_slot_warning(opts.role, &read_jigkey(&sealed)?.slots()) {
                out.push_str(&format!("\nwarning: {warning}"));
            }
            Ok(out)
        }
        KeysAction::AddSlot { keyfile, slot } => {
            let slots = add_slot(&keyfile, opts, &slot)?;
            Ok(format!(
                "{} is now opened by: {slots}",
                sealed_path(&keyfile).display()
            ))
        }
        KeysAction::Show { keyfile } => {
            let (did, slots) = describe(&keyfile)?;
            Ok(format!("{did}\nopened by: {slots}"))
        }
        KeysAction::Verify { keyfile, slot } => {
            let did = verify(&keyfile, &slot, opts)?;
            Ok(format!("{did}\nopened by that --slot"))
        }
        KeysAction::Rotate {
            keyfile,
            slots,
            prune_oldest,
        } => {
            let done = rotate(&keyfile, &slots, prune_oldest, opts, unix_now())?;
            let mut out = format!(
                "rotated {} to {}\nsealed the new key into {}\nwrote the key link to {}\nkept \
                 the old key, still sealed, as {}: move it offline, and keep it",
                done.old_did,
                done.new_did,
                sealed_path(&keyfile).display(),
                done.link.display(),
                done.retired.display()
            );
            if let Some((archived, _)) = &done.archived {
                out.push_str(&format!(
                    "\nkept the previous link as {}, still served: clients pinned on any \
                     earlier DID follow every link",
                    archived.display()
                ));
            }
            if let Some((pruned, left)) = &done.pruned {
                out.push_str(&format!(
                    "\nWARNING: the oldest link, from {left}, is no longer served (kept as {}). \
                     A client still pinned on {left} is refused and must re-pin, which trusts \
                     this server on first use again",
                    pruned.display()
                ));
            }
            out.push_str(&format!(
                "\nrestart the {} to sign as {}; until then it signs as {}",
                opts.role, done.new_did, done.old_did
            ));
            if let Some(warning) =
                single_slot_warning(opts.role, &read_jigkey(&sealed_path(&keyfile))?.slots())
            {
                out.push_str(&format!("\nwarning: {warning}"));
            }
            Ok(out)
        }
        KeysAction::Link {
            old_keyfile,
            keyfile,
            slot,
        } => {
            let (old, new, path) = link(&old_keyfile, &keyfile, slot.as_deref(), opts, unix_now())?;
            Ok(format!(
                "linked {old} to {new}\nwrote the key link to {}",
                path.display()
            ))
        }
        KeysAction::Generate { keyfile, slots } => {
            let did = generate_sealed(&keyfile, &slots, opts.kdf)?;
            let sealed = sealed_path(&keyfile);
            let mut out = format!("{did}\nsealed into {}", sealed.display());
            if let Some(warning) = single_slot_warning(opts.role, &read_jigkey(&sealed)?.slots()) {
                out.push_str(&format!("\nwarning: {warning}"));
            }
            Ok(out)
        }
    }
}

/// The slots of the sealed key at `path`, for an operator: what will open it.
pub fn describe(path: &Path) -> Result<(String, String)> {
    let key = read_jigkey(&sealed_path(path))?;
    Ok((key.did().to_string(), describe_slots(&key.slots())))
}

/// Open the sealed key at `path` with `spec` alone, and nothing configured,
/// so an operator can check a secret (an offline passphrase, a new machine's
/// credential) before relying on it. Returns the DID.
pub fn verify(path: &Path, spec: &str, opts: &ServerKeyOptions) -> Result<String> {
    let path = sealed_path(path);
    let key = read_jigkey(&path)?;
    let offer = Spec::parse(spec, "--slot", Use::Operator)?.offer();
    let opened = key.open(&[offer]).map_err(|e| match e {
        KeystoreError::NoSlotOpened => ServerKeyError::DoesNotOpen {
            role: opts.role,
            path: path.clone(),
            slots: describe_slots(&key.slots()),
        },
        source => ServerKeyError::Keystore {
            path: path.clone(),
            source,
        },
    })?;
    let found = did_of(&opened.seed);
    if found != key.did() {
        return Err(ServerKeyError::WrongDid {
            path,
            claimed: key.did().to_string(),
            found,
        });
    }
    Ok(found)
}

fn open_sealed(path: &Path, opts: &ServerKeyOptions) -> Result<SigningKey> {
    let key = read_jigkey(path)?;
    let opened = open_with(&key, path, opts, Use::Boot)?;
    let found = did_of(&opened.seed);
    if found != key.did() {
        return Err(ServerKeyError::WrongDid {
            path: path.to_path_buf(),
            claimed: key.did().to_string(),
            found,
        });
    }
    if let Some(warning) = single_slot_warning(opts.role, &key.slots()) {
        tracing::warn!("{warning}");
    }
    Ok(SigningKey::from_bytes(&opened.seed))
}

fn create_sealed(path: &Path, opts: &ServerKeyOptions) -> Result<SigningKey> {
    let spec = configured(opts, Use::Boot)?
        .0
        .into_iter()
        .next()
        .ok_or_else(|| ServerKeyError::NoWayToSeal {
            role: opts.role,
            path: path.to_path_buf(),
        })?;
    let signing = jig_core::crypto::ed25519::generate_signing_key();
    let seed = Zeroizing::new(signing.to_bytes());
    let (key, _) =
        JigKey::seal(&did_of(&seed), &seed, &[spec.slot(opts.kdf)?]).map_err(|source| {
            ServerKeyError::Keystore {
                path: path.to_path_buf(),
                source,
            }
        })?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|source| ServerKeyError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    }
    write_new(path, &key.to_bytes())?;
    // What the next boot will read: open it the same way now.
    open_sealed(path, opts)
}

/// Create `path` owner-only and write `bytes`, refusing an existing file: two
/// servers booting at once must not each write a key and keep the other's.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let io = |source| ServerKeyError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            ServerKeyError::Exists(path.to_path_buf())
        } else {
            io(e)
        }
    })?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    sync_parent_dir(path).map_err(io)
}

fn read_jigkey(path: &Path) -> Result<JigKey> {
    let bytes = std::fs::read(path).map_err(|source| ServerKeyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    JigKey::from_bytes(&bytes).map_err(|source| ServerKeyError::Keystore {
        path: path.to_path_buf(),
        source,
    })
}

fn read_raw_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let io = |source| ServerKeyError::Io {
        path: path.to_path_buf(),
        source,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).map_err(io)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ServerKeyError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    let bytes = Zeroizing::new(std::fs::read(path).map_err(io)?);
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ServerKeyError::Malformed {
            path: path.to_path_buf(),
            len: bytes.len(),
        })?;
    Ok(Zeroizing::new(seed))
}

fn warn_plaintext(path: &Path, opts: &ServerKeyOptions) {
    tracing::warn!(
        "[keys] storage = \"plaintext\": the {} key at {} is stored in clear. Anyone who can \
         read the file or a backup of it can sign as this {}. Seal it with `{} keys seal`",
        opts.role,
        path.display(),
        opts.role,
        opts.tool,
    );
}

fn did_of(seed: &[u8; 32]) -> String {
    Did::from_ed25519_pubkey(SigningKey::from_bytes(seed).verifying_key().as_bytes())
        .to_did_jig_string()
}

fn describe_slots(slots: &[SlotKind]) -> String {
    let names: Vec<&str> = slots
        .iter()
        .map(|s| match s {
            SlotKind::Passphrase(_) => "a passphrase slot",
            SlotKind::Secret(SecretSource::Credential) => "a credential slot",
            SlotKind::Secret(SecretSource::Env) => "an env slot",
            SlotKind::Secret(SecretSource::Keychain) => "a keychain slot",
        })
        .collect();
    names.join(", ")
}

/// For tests: the `[keys] unlock` value naming a credential secret in `dir`,
/// written on first use and reused after, so a test server seals its key the
/// way a deployed one does, with no environment variable to race on, and
/// opens it again when it restarts over the same directory.
#[cfg(any(test, feature = "test-support"))]
pub fn credential_for_tests(dir: &Path) -> String {
    let path = dir.join("server-key.credential");
    if !path.exists() {
        let secret = hex::encode(jig_core::crypto::ed25519::random_array::<32>());
        write_new(&path, secret.as_bytes()).expect("writing a test credential");
    }
    format!("credential:{}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(unlock: Option<String>) -> ServerKeyOptions {
        let mut opts = ServerKeyOptions::new("server", "jig-server");
        opts.unlock = unlock;
        opts.kdf = KdfParams::insecure_for_tests();
        opts
    }

    #[cfg(unix)]
    fn write_raw(path: &Path, seed: [u8; 32]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, seed).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn a_configured_path_names_its_jigkey() {
        assert_eq!(
            sealed_path(Path::new("/k/server.key")),
            Path::new("/k/server.jigkey")
        );
        assert_eq!(
            sealed_path(Path::new("/k/server.jigkey")),
            Path::new("/k/server.jigkey")
        );
        assert_eq!(sealed_path(Path::new("/k/ns")), Path::new("/k/ns.jigkey"));
    }

    #[cfg(unix)]
    #[test]
    fn sealing_a_raw_key_keeps_its_did_removes_it_and_boots() {
        let dir = tempfile::tempdir().unwrap();
        let unlock = credential_for_tests(dir.path());
        let raw = dir.path().join("server.key");
        write_raw(&raw, [5u8; 32]);
        let (sealed, did) = seal_raw(&raw, std::slice::from_ref(&unlock), &opts(None)).unwrap();
        assert_eq!(did, did_of(&[5u8; 32]));
        assert!(
            !raw.exists(),
            "the raw copy is removed once the sealed one opens"
        );
        let key = load_or_create(&raw, &opts(Some(unlock))).unwrap();
        assert_eq!(key.to_bytes(), [5u8; 32]);
        assert_eq!(
            describe(&sealed).unwrap(),
            (did, "a credential slot".to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_raw_key_left_beside_its_sealed_copy_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let unlock = credential_for_tests(dir.path());
        let raw = dir.path().join("server.key");
        write_raw(&raw, [5u8; 32]);
        seal_raw(&raw, std::slice::from_ref(&unlock), &opts(None)).unwrap();
        // The same key twice: removing the raw copy is safe, and it says so.
        write_raw(&raw, [5u8; 32]);
        let err = load_or_create(&raw, &opts(Some(unlock.clone()))).unwrap_err();
        assert!(matches!(err, ServerKeyError::BothPresent { .. }), "{err}");
        assert!(err.to_string().contains("same key"), "{err}");
        // Another key beside it: neither is to be removed.
        write_raw(&raw, [8u8; 32]);
        let err = load_or_create(&raw, &opts(Some(unlock.clone()))).unwrap_err();
        assert!(err.to_string().contains("different keys"), "{err}");
        assert!(err.to_string().contains("Remove neither"), "{err}");
        // A damaged sealed copy, as an interrupted write would leave: keep the raw one.
        std::fs::write(sealed_path(&raw), b"{not a key").unwrap();
        let err = load_or_create(&raw, &opts(Some(unlock.clone()))).unwrap_err();
        assert!(err.to_string().contains("damaged"), "{err}");
        // And `keys seal` gives the same diagnosis, never "already exists".
        let err = seal_raw(&raw, &[unlock], &opts(None)).unwrap_err();
        assert!(err.to_string().contains("damaged"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_seal_that_fails_its_check_leaves_no_sealed_file() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("server.key");
        write_raw(&raw, [4u8; 32]);
        // A slot that cannot be read fails before anything is written.
        let err = seal_raw(&raw, &["env:JIG_TEST_NOT_SET_ANYWHERE".into()], &opts(None));
        assert!(err.is_err());
        assert!(
            !sealed_path(&raw).exists(),
            "no sealed file after a failed seal"
        );
        assert!(raw.exists(), "the raw key is kept");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "no temporary file is left behind");
    }

    #[cfg(unix)]
    #[test]
    fn a_credential_readable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cred = dir.path().join("loose");
        std::fs::write(&cred, "a credential secret of at least 32 bytes, loose").unwrap();
        std::fs::set_permissions(&cred, std::fs::Permissions::from_mode(0o644)).unwrap();
        let spec = format!("credential:{}", cred.display());
        for used in [Use::Boot, Use::Operator] {
            let err = Spec::parse(&spec, "[keys] unlock", used).err().unwrap();
            assert!(err.to_string().contains("readable by others"), "{err}");
            assert!(err.to_string().starts_with("[keys] unlock"), "{err}");
        }
    }

    #[test]
    fn an_operator_command_skips_a_credential_it_cannot_read() {
        // A unit's credential, with the unit stopped: at boot that is an
        // error; for add-slot it is skipped, and the refusal says so.
        let dir = tempfile::tempdir().unwrap();
        let boot = credential_for_tests(dir.path());
        let path = dir.path().join("server.key");
        load_or_create(&path, &opts(Some(boot.clone()))).unwrap();
        let gone = opts(Some(
            "credential:/run/credentials/jig-server.service/gone".into(),
        ));
        let err = load_or_create(&path, &gone).unwrap_err();
        assert!(err.to_string().contains("LoadCredentialEncrypted"), "{err}");
        let err = add_slot(&path, &gone, &boot).unwrap_err();
        assert!(matches!(err, ServerKeyError::Locked { .. }), "{err}");
        assert!(err.to_string().contains("skipped"), "{err}");
    }

    #[test]
    fn the_wrong_secret_does_not_open_the_key_and_says_what_would() {
        let dir = tempfile::tempdir().unwrap();
        let unlock = credential_for_tests(dir.path());
        let path = dir.path().join("server.key");
        load_or_create(&path, &opts(Some(unlock))).unwrap();
        let other = tempfile::tempdir().unwrap();
        let wrong = credential_for_tests(other.path());
        let err = load_or_create(&path, &opts(Some(wrong))).unwrap_err();
        assert!(matches!(err, ServerKeyError::Locked { .. }), "{err}");
        assert!(err.to_string().contains("a credential slot"), "{err}");
    }

    #[test]
    fn verify_opens_with_that_slot_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        let good = credential_for_tests(dir.path());
        let did = generate_sealed(
            &path,
            std::slice::from_ref(&good),
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        // What is configured plays no part: only the --slot is tried.
        assert_eq!(verify(&path, &good, &opts(None)).unwrap(), did);
        let other = tempfile::tempdir().unwrap();
        let wrong = credential_for_tests(other.path());
        let err = verify(&path, &wrong, &opts(Some(good))).unwrap_err();
        assert!(matches!(err, ServerKeyError::DoesNotOpen { .. }), "{err}");
        assert!(err.to_string().contains("a credential slot"), "{err}");
    }

    #[test]
    fn generate_refuses_beside_a_raw_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        std::fs::write(&path, [7u8; 32]).unwrap();
        let unlock = credential_for_tests(dir.path());
        let err = run(
            KeysAction::Generate {
                keyfile: path.clone(),
                slots: vec![unlock],
            },
            &opts(None),
        )
        .unwrap_err();
        assert!(
            matches!(err, ServerKeyError::Exists(ref p) if *p == path),
            "{err}"
        );
        assert!(!sealed_path(&path).exists());
    }

    #[test]
    fn a_ceremony_key_is_sealed_offline_then_given_the_servers_slot() {
        let offline = tempfile::tempdir().unwrap();
        let ceremony = credential_for_tests(offline.path());
        let path = offline.path().join("ns.key");
        let did = generate_sealed(
            &path,
            std::slice::from_ref(&ceremony),
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        assert!(!path.exists() && sealed_path(&path).exists());

        // On the server: open with the ceremony secret, add the server's own.
        let server = tempfile::tempdir().unwrap();
        let boot = credential_for_tests(server.path());
        let slots = add_slot(&path, &opts(Some(ceremony)), &boot).unwrap();
        assert_eq!(slots, "a credential slot, a credential slot");
        let key = load_or_create(&path, &opts(Some(boot))).unwrap();
        assert_eq!(
            Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string(),
            did
        );
        assert!(matches!(
            generate_sealed(
                &path,
                &[credential_for_tests(server.path())],
                KdfParams::insecure_for_tests()
            ),
            Err(ServerKeyError::Exists(_))
        ));
    }

    /// A `credential:` path may be a pipe that reads once, as with
    /// `--slot credential:<(systemd-creds decrypt ...)`.
    #[cfg(unix)]
    #[test]
    fn a_credential_that_reads_only_once_still_seals_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("server.key");
        write_raw(&raw, [6u8; 32]);
        let fifo = dir.path().join("cred.fifo");
        let status = std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        let writer = {
            let fifo = fifo.clone();
            std::thread::spawn(move || {
                std::fs::write(&fifo, "a credential secret of at least 32 bytes, once").unwrap()
            })
        };
        let spec = format!("credential:{}", fifo.display());
        seal_raw(&raw, &[spec], &opts(None)).unwrap();
        writer.join().unwrap();
        assert!(!raw.exists());
    }

    #[test]
    fn a_key_with_one_slot_is_warned_about_and_one_with_two_is_not() {
        let one = [SlotKind::Secret(SecretSource::Credential)];
        let warning = single_slot_warning("server", &one).unwrap();
        assert!(warning.contains("add-slot"), "{warning}");
        let two = [
            SlotKind::Secret(SecretSource::Credential),
            SlotKind::Passphrase(KdfParams::insecure_for_tests()),
        ];
        assert!(single_slot_warning("server", &two).is_none());
    }

    #[test]
    fn a_slot_spec_that_is_not_one_is_refused_without_echoing_it() {
        let err = Spec::parse("hunter2-the-secret-itself", "[keys] unlock", Use::Boot)
            .err()
            .unwrap();
        assert!(!err.to_string().contains("hunter2"), "{err}");
    }

    /// A fresh credential secret in its own directory under `dir`.
    fn credential_in(dir: &Path, name: &str) -> String {
        let sub = dir.join(name);
        std::fs::create_dir_all(&sub).unwrap();
        credential_for_tests(&sub)
    }

    fn did_of_key(key: &SigningKey) -> String {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    #[test]
    fn rotating_replaces_the_key_in_place_and_links_the_old_did_to_the_new() {
        use jig_core::key_link::{Audience, SignedKeyLink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        let boot = credential_in(dir.path(), "boot");
        let old = load_or_create(&path, &opts(Some(boot.clone()))).unwrap();
        let next = credential_in(dir.path(), "next");

        let done = rotate(
            &path,
            std::slice::from_ref(&next),
            false,
            &opts(Some(boot.clone())),
            7,
        )
        .unwrap();
        assert_eq!(done.old_did, did_of_key(&old));
        assert!(done.archived.is_none());
        assert_eq!(done.link, dir.path().join("server.key.link"));

        // The configured path now opens to the new key, with the new slot.
        let new = load_or_create(&path, &opts(Some(next.clone()))).unwrap();
        assert_eq!(did_of_key(&new), done.new_did);
        assert_ne!(done.new_did, done.old_did);
        // The link verifies from the old DID to the new, for everyone.
        let link = SignedKeyLink::from_envelope(&std::fs::read(&done.link).unwrap()).unwrap();
        assert_eq!(
            (link.link().old.as_str(), link.link().new.as_str()),
            (done.old_did.as_str(), done.new_did.as_str())
        );
        assert_eq!(link.link().audience, Audience::Public);
        assert_eq!(link.link().issued_at, 7);
        // The old key is kept, sealed, and still opens with its own slot.
        let retired = load_or_create(&done.retired, &opts(Some(boot))).unwrap();
        assert_eq!(did_of_key(&retired), done.old_did);
    }

    /// Rotate the key at `path`, opened by `from`, to one opened by a new
    /// credential named `to`; returns that credential.
    fn rotate_to(dir: &Path, path: &Path, from: &str, to: &str, prune: bool) -> (Rotated, String) {
        let next = credential_in(dir, to);
        let done = rotate(
            path,
            std::slice::from_ref(&next),
            prune,
            &opts(Some(from.to_string())),
            1,
        )
        .unwrap();
        (done, next)
    }

    #[test]
    fn a_second_rotation_grows_the_chain_the_server_serves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        let a = credential_in(dir.path(), "a");
        load_or_create(&path, &opts(Some(a.clone()))).unwrap();
        let (first, b) = rotate_to(dir.path(), &path, &a, "b", false);
        let first_link = std::fs::read(&first.link).unwrap();
        let (second, _) = rotate_to(dir.path(), &path, &b, "c", false);

        assert_eq!(second.old_did, first.new_did);
        let (archived, left) = second.archived.clone().unwrap();
        assert_eq!(archived, dir.path().join("server.key.link.1"));
        assert_eq!(left, first.old_did);
        assert_eq!(std::fs::read(&archived).unwrap(), first_link);
        assert!(first.retired.exists() && second.retired.exists());
        assert!(second.pruned.is_none());

        let chain = key_chain(&path, &second.new_did).unwrap();
        assert!(chain.problems.is_empty(), "{:?}", chain.problems);
        let hops: Vec<(&str, &str)> = chain
            .links
            .iter()
            .map(|l| (l.old.as_str(), l.new.as_str()))
            .collect();
        assert_eq!(
            hops,
            [
                (first.old_did.as_str(), first.new_did.as_str()),
                (second.old_did.as_str(), second.new_did.as_str())
            ]
        );
    }

    #[test]
    fn a_full_chain_grows_again_only_by_pruning_its_oldest_link() {
        let max = jig_pipeline::handshake::MAX_KEY_LINK_HOPS;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        let mut cred = credential_in(dir.path(), "k0");
        load_or_create(&path, &opts(Some(cred.clone()))).unwrap();
        let mut first_did = None;
        for n in 1..=max {
            let (done, next) = rotate_to(dir.path(), &path, &cred, &format!("k{n}"), false);
            first_did.get_or_insert(done.old_did);
            cred = next;
        }
        let first_did = first_did.unwrap();
        let current = describe(&path).unwrap().0;
        assert_eq!(key_chain(&path, &current).unwrap().links.len(), max);

        let next = credential_in(dir.path(), "over");
        let refused = rotate(
            &path,
            std::slice::from_ref(&next),
            false,
            &opts(Some(cred.clone())),
            2,
        )
        .unwrap_err();
        assert!(
            matches!(&refused, ServerKeyError::TooManyHops { hops, oldest, .. }
                if *hops == max && *oldest == first_did),
            "{refused}"
        );
        assert!(refused.to_string().contains("--prune-oldest"), "{refused}");
        assert_eq!(describe(&path).unwrap().0, current, "nothing moved");

        let (done, _) = rotate_to(dir.path(), &path, &cred, "over2", true);
        let (pruned, left) = done.pruned.clone().unwrap();
        assert_eq!(left, first_did);
        assert_eq!(pruned, dir.path().join("server.key.link.pruned-1"));
        assert!(pruned.exists(), "kept, not deleted");
        let chain = key_chain(&path, &done.new_did).unwrap();
        assert_eq!(chain.links.len(), max);
        assert_ne!(chain.links[0].old, first_did);
        assert!(chain.problems.is_empty(), "{:?}", chain.problems);
        // The pruned link still counts: its DID is never linked again.
        assert!(
            links_beside(&key_link_path(&path))
                .unwrap()
                .iter()
                .any(|(_, l)| l.link().old == first_did)
        );
    }

    #[test]
    fn a_broken_earlier_link_shortens_the_chain_and_a_broken_newest_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        let a = credential_in(dir.path(), "a");
        load_or_create(&path, &opts(Some(a.clone()))).unwrap();
        let (_, b) = rotate_to(dir.path(), &path, &a, "b", false);
        let (_, c) = rotate_to(dir.path(), &path, &b, "c", false);
        let (third, _) = rotate_to(dir.path(), &path, &c, "d", false);
        let did = third.new_did.clone();
        assert_eq!(key_chain(&path, &did).unwrap().links.len(), 3);

        // The oldest, corrupt: the two after it are still served.
        let oldest = dir.path().join("server.key.link.1");
        let kept = std::fs::read(&oldest).unwrap();
        std::fs::write(&oldest, b"not a link").unwrap();
        let chain = key_chain(&path, &did).unwrap();
        assert_eq!(chain.links.len(), 2);
        assert!(
            chain
                .problems
                .iter()
                .any(|p| p.contains(&*oldest.to_string_lossy())),
            "{:?}",
            chain.problems
        );
        std::fs::write(&oldest, kept).unwrap();

        // A gap in the middle: only the newest is served, and the link
        // stranded behind the gap is named.
        let middle = dir.path().join("server.key.link.2");
        std::fs::rename(&middle, dir.path().join("elsewhere")).unwrap();
        let chain = key_chain(&path, &did).unwrap();
        assert_eq!(chain.links.len(), 1);
        assert!(
            chain
                .problems
                .iter()
                .any(|p| p.contains(&*oldest.to_string_lossy())),
            "{:?}",
            chain.problems
        );

        // The newest, corrupt: the server must not boot with it.
        std::fs::write(key_link_path(&path), b"not a link").unwrap();
        assert!(matches!(
            key_chain(&path, &did),
            Err(ServerKeyError::BadLink { .. })
        ));
    }

    #[test]
    fn a_did_that_a_link_already_leaves_is_never_linked_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        let a = credential_in(dir.path(), "a");
        load_or_create(&path, &opts(Some(a.clone()))).unwrap();
        let b = credential_in(dir.path(), "b");
        let first = rotate(
            &path,
            std::slice::from_ref(&b),
            false,
            &opts(Some(a.clone())),
            1,
        )
        .unwrap();

        // Link the retired key a second time, to another key made offline.
        let other = dir.path().join("other.key");
        generate_sealed(
            &other,
            std::slice::from_ref(&a),
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        // The link that left it, kept beside the other key as an earlier one.
        std::fs::copy(&first.link, archive_path(&key_link_path(&other), 1)).unwrap();
        let refused = link(&first.retired, &other, None, &opts(Some(a)), 2).unwrap_err();
        assert!(
            matches!(&refused, ServerKeyError::AlreadyLinked { old, .. } if *old == first.old_did),
            "{refused}"
        );
    }

    #[test]
    fn link_writes_beside_the_new_key_and_never_over_a_link() {
        use jig_core::key_link::SignedKeyLink;
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old.key");
        let old_cred = credential_in(dir.path(), "old");
        let old_did = generate_sealed(
            &old,
            std::slice::from_ref(&old_cred),
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        let new = dir.path().join("new.key");
        let new_cred = credential_in(dir.path(), "new");
        let new_did = generate_sealed(
            &new,
            std::slice::from_ref(&new_cred),
            KdfParams::insecure_for_tests(),
        )
        .unwrap();

        // The new key opens only with its own slot.
        assert!(matches!(
            link(
                &old,
                &new,
                Some(&old_cred),
                &opts(Some(old_cred.clone())),
                3
            ),
            Err(ServerKeyError::DoesNotOpen { .. })
        ));
        let (from, to, path) = link(
            &old,
            &new,
            Some(&new_cred),
            &opts(Some(old_cred.clone())),
            3,
        )
        .unwrap();
        assert_eq!(
            (from.as_str(), to.as_str()),
            (old_did.as_str(), new_did.as_str())
        );
        assert_eq!(path, dir.path().join("new.key.link"));
        let link_read = SignedKeyLink::from_envelope(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(link_read.link().new, new_did);

        assert!(matches!(
            link(
                &old,
                &new,
                Some(&new_cred),
                &opts(Some(old_cred.clone())),
                4
            ),
            Err(ServerKeyError::Exists(_))
        ));
        // A key never links to itself.
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            link(&old, &old, None, &opts(Some(old_cred)), 5),
            Err(ServerKeyError::BadLink { .. })
        ));
    }

    #[test]
    fn a_rotation_that_cannot_keep_the_old_key_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        let a = credential_in(dir.path(), "a");
        let old = load_or_create(&path, &opts(Some(a.clone()))).unwrap();
        let before = std::fs::read(sealed_path(&path)).unwrap();
        // Something already holds the name the old key would be kept under.
        let retired = retired_path(&sealed_path(&path), &did_of_key(&old));
        std::fs::write(&retired, b"in the way").unwrap();

        let b = credential_in(dir.path(), "b");
        assert!(matches!(
            rotate(&path, &[b], false, &opts(Some(a)), 1),
            Err(ServerKeyError::Exists(p)) if p == retired
        ));
        assert_eq!(std::fs::read(sealed_path(&path)).unwrap(), before);
        assert!(!key_link_path(&path).exists());
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn a_rotation_whose_new_key_does_not_open_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        let a = credential_in(dir.path(), "a");
        load_or_create(&path, &opts(Some(a.clone()))).unwrap();
        let before = std::fs::read(sealed_path(&path)).unwrap();
        // A passphrase for the new key reads JIG_KEY_NEW_PASSPHRASE, unset here.
        let refused =
            rotate(&path, &["passphrase".to_string()], false, &opts(Some(a)), 1).unwrap_err();
        assert!(
            refused.to_string().contains("JIG_KEY_NEW_PASSPHRASE"),
            "{refused}"
        );
        assert_eq!(std::fs::read(sealed_path(&path)).unwrap(), before);
        assert!(!key_link_path(&path).exists());
    }
}
