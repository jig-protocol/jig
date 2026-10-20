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
    MIN_PASSPHRASE_CHARS, read_unlock_spec, sync_parent_dir, write_private_atomic,
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
        "{raw:?} and {sealed:?} both exist: the raw key is still in clear beside its sealed \
         copy. Remove {raw:?} once the server starts from {sealed:?}"
    )]
    BothPresent { raw: PathBuf, sealed: PathBuf },
    #[error("{0:?} already exists; it is never overwritten")]
    Exists(PathBuf),
    #[error(
        "no {role} key at {path:?}, and nothing to seal a new one with: set [keys] unlock to \
         credential:PATH, env:NAME or passphrase, or set JIG_KEY_UNLOCK or JIG_KEY_PASSPHRASE"
    )]
    NoWayToSeal { role: &'static str, path: PathBuf },
    #[error(
        "cannot open the {role} key at {path:?}: it has {slots}, and nothing offered opens \
         one. Set [keys] unlock, JIG_KEY_UNLOCK or JIG_KEY_PASSPHRASE for one of them"
    )]
    Locked {
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

/// A secret that opens or makes one slot. Read once and cloned where it is
/// needed again: a `credential:` path may be a pipe (`<(systemd-creds
/// decrypt ...)`), which reads only once.
#[derive(Clone)]
enum Spec {
    Secret(SecretSource, Zeroizing<Vec<u8>>),
    Passphrase(Zeroizing<String>),
}

impl Spec {
    /// `credential:PATH`, `env:NAME` or `passphrase`.
    fn parse(spec: &str) -> Result<Self> {
        if spec == "passphrase" {
            let passphrase = std::env::var("JIG_KEY_PASSPHRASE").map_err(|_| {
                ServerKeyError::BadUnlock(
                    "the passphrase slot reads JIG_KEY_PASSPHRASE, which is not set; a server \
                     never prompts"
                        .to_string(),
                )
            })?;
            return Ok(Spec::Passphrase(Zeroizing::new(passphrase)));
        }
        // Name only the slot kind: a value with no kind may be the secret
        // itself, pasted in by mistake.
        let (source, secret) = read_unlock_spec(spec).map_err(|e| {
            let kind = match spec.split_once(':') {
                Some((kind @ ("env" | "credential"), _)) => kind,
                _ => "the unlock value",
            };
            ServerKeyError::BadUnlock(format!("{kind}: {e}"))
        })?;
        Ok(Spec::Secret(source, secret))
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

/// What this process was given, in order: `[keys] unlock`, then
/// `JIG_KEY_UNLOCK`, then `JIG_KEY_PASSPHRASE`.
fn configured(opts: &ServerKeyOptions) -> Result<Vec<Spec>> {
    let mut specs = Vec::new();
    if let Some(spec) = opts.unlock.as_deref() {
        specs.push(Spec::parse(spec)?);
    }
    if let Ok(spec) = std::env::var("JIG_KEY_UNLOCK") {
        specs.push(Spec::parse(&spec)?);
    }
    let named_passphrase = opts.unlock.as_deref() == Some("passphrase");
    if !named_passphrase && let Ok(passphrase) = std::env::var("JIG_KEY_PASSPHRASE") {
        specs.push(Spec::Passphrase(Zeroizing::new(passphrase)));
    }
    Ok(specs)
}

/// At boot, a `credential:` slot should be one systemd hands this unit. Under a
/// unit with credentials (`$CREDENTIALS_DIRECTORY` set) a path outside it is
/// refused: it is a secret file on disk, likely beside the key it opens.
/// Elsewhere it is only warned about. The `keys` commands, run by an operator,
/// are never checked: they may read a credential through a pipe.
fn check_boot_credentials(opts: &ServerKeyOptions) -> Result<()> {
    let specs = opts
        .unlock
        .iter()
        .cloned()
        .chain(std::env::var("JIG_KEY_UNLOCK").ok());
    for spec in specs {
        let Some(path) = spec.strip_prefix("credential:").map(PathBuf::from) else {
            continue;
        };
        match std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from) {
            // Judged on the resolved paths: `$CREDENTIALS_DIRECTORY/../x`, or
            // a symlink in it that points out, is a file outside it. A path
            // that does not resolve is outside too.
            Some(dir)
                if !path.canonicalize().is_ok_and(|real| {
                    dir.canonicalize().is_ok_and(|dir| real.starts_with(dir))
                }) =>
            {
                return Err(ServerKeyError::NotACredential { path, dir });
            }
            Some(_) => {}
            None => tracing::warn!(
                "the {} key opens with a secret read from {}, a plain file: it protects the \
                 key only as far as that file is kept apart from it. A systemd credential \
                 (LoadCredentialEncrypted=) keeps it encrypted at rest",
                opts.role,
                path.display()
            ),
        }
    }
    Ok(())
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
    check_boot_credentials(opts)?;
    let sealed = sealed_path(path);
    let raw = (sealed != path).then_some(path);
    match (sealed.exists(), raw.filter(|r| r.exists())) {
        (true, Some(raw)) => Err(ServerKeyError::BothPresent {
            raw: raw.to_path_buf(),
            sealed,
        }),
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

/// Seal the raw key at `raw` with one slot per entry of `specs`, write it
/// beside `raw` as `.jigkey`, check that it opens to the same key, then remove
/// `raw`. Returns the sealed path and the key's DID.
///
/// Removing `raw` unlinks it; it does not erase the blocks it used.
pub fn seal_raw(raw: &Path, specs: &[String], kdf: KdfParams) -> Result<(PathBuf, String)> {
    let sealed = sealed_path(raw);
    if sealed == raw {
        return Err(ServerKeyError::BadUnlock(format!(
            "{raw:?} is already a .jigkey"
        )));
    }
    if sealed.exists() {
        return Err(ServerKeyError::Exists(sealed));
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
        .map(|s| Spec::parse(s))
        .collect::<Result<Vec<_>>>()?;
    let slots = parsed
        .iter()
        .map(|s| s.clone().slot(kdf))
        .collect::<Result<Vec<_>>>()?;
    let (key, _) =
        JigKey::seal(&did, &seed, &slots).map_err(|source| ServerKeyError::Keystore {
            path: sealed.clone(),
            source,
        })?;
    write_new(&sealed, &key.to_bytes())?;
    // Read back what is on disk, and open it with every slot just named,
    // before the only other copy goes.
    let reopened = read_jigkey(&sealed)?;
    for spec in parsed {
        let opened = reopened.open(&[spec.offer()]);
        if !opened.is_ok_and(|o| *o.seed == *seed) {
            return Err(ServerKeyError::NotVerified {
                path: sealed,
                kept: format!("the raw key {raw:?} was kept"),
            });
        }
    }
    std::fs::remove_file(raw).map_err(|source| ServerKeyError::Io {
        path: raw.to_path_buf(),
        source,
    })?;
    sync_parent_dir(raw).map_err(|source| ServerKeyError::Io {
        path: raw.to_path_buf(),
        source,
    })?;
    Ok((sealed, did))
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
    let path = sealed_path(path);
    let slots = specs
        .iter()
        .map(|s| Spec::parse(s)?.slot(kdf))
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
/// it offline with a passphrase, then add the server's credential there.
/// The file is replaced atomically, and the new slot is checked to open it.
pub fn add_slot(path: &Path, opts: &ServerKeyOptions, new_spec: &str) -> Result<String> {
    let path = sealed_path(path);
    let key = read_jigkey(&path)?;
    let offers: Vec<Unlock> = configured(opts)?.into_iter().map(Spec::offer).collect();
    let keystore = |source| ServerKeyError::Keystore {
        path: path.clone(),
        source,
    };
    let opened = key.open(&offers).map_err(|e| match e {
        KeystoreError::NoSlotOpened => ServerKeyError::Locked {
            role: opts.role,
            path: path.clone(),
            slots: describe_slots(&key.slots()),
        },
        source => keystore(source),
    })?;
    let new = Spec::parse(new_spec)?;
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
    write_private_atomic(&path, &updated.to_bytes()).map_err(|source| ServerKeyError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(describe_slots(&updated.slots()))
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
}

/// Run `action`, returning what to print.
pub fn run(action: KeysAction, opts: &ServerKeyOptions) -> Result<String> {
    match action {
        KeysAction::Seal { keyfile, slots } => {
            let (sealed, did) = seal_raw(&keyfile, &slots, opts.kdf)?;
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
    }
}

/// The slots of the sealed key at `path`, for an operator: what will open it.
pub fn describe(path: &Path) -> Result<(String, String)> {
    let key = read_jigkey(&sealed_path(path))?;
    Ok((key.did().to_string(), describe_slots(&key.slots())))
}

fn open_sealed(path: &Path, opts: &ServerKeyOptions) -> Result<SigningKey> {
    let key = read_jigkey(path)?;
    let offers: Vec<Unlock> = configured(opts)?.into_iter().map(Spec::offer).collect();
    let opened = key.open(&offers).map_err(|e| match e {
        KeystoreError::NoSlotOpened => ServerKeyError::Locked {
            role: opts.role,
            path: path.to_path_buf(),
            slots: describe_slots(&key.slots()),
        },
        source => ServerKeyError::Keystore {
            path: path.to_path_buf(),
            source,
        },
    })?;
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
    let spec = configured(opts)?
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
#[doc(hidden)]
pub fn credential_for_tests(dir: &Path) -> String {
    let path = dir.join("server-key.credential");
    if !path.exists() {
        let secret = hex::encode(jig_core::crypto::ed25519::random_array::<32>());
        std::fs::write(&path, secret).expect("writing a test credential");
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
        let (sealed, did) = seal_raw(
            &raw,
            std::slice::from_ref(&unlock),
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
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
        seal_raw(
            &raw,
            std::slice::from_ref(&unlock),
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        write_raw(&raw, [5u8; 32]);
        assert!(matches!(
            load_or_create(&raw, &opts(Some(unlock))),
            Err(ServerKeyError::BothPresent { .. })
        ));
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
        seal_raw(&raw, &[spec], KdfParams::insecure_for_tests()).unwrap();
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
        let err = Spec::parse("hunter2-the-secret-itself").err().unwrap();
        assert!(!err.to_string().contains("hunter2"), "{err}");
    }
}
