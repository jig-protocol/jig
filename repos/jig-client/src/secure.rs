//! Encrypted channels on the client: MLS group state, and the plaintext a
//! member has read.
//!
//! # Where state lives
//!
//! `~/.jig/mls/<did>/` (mode 0700):
//!
//! - `state.bin` — every group and unused key package this DID holds
//!   (`jig_mls::snapshot` bytes);
//! - `groups.json` — which group backs which channel, keyed by server and slug;
//! - `plaintext.jsonl` — messages already read, by block CID.
//!
//! The plaintext file exists because MLS deletes a message key once it is
//! used: a message decrypts exactly once, and a sender can never decrypt its
//! own. Without it, history would be unreadable the second time a channel is
//! opened.
//!
//! # At rest
//!
//! All three are sealed under keys derived from the identity's `.jigkey`
//! (`jig_core::keystore`): `state.bin` and `groups.json` whole, and
//! `plaintext.jsonl` one record per line, so appends stay appends. Each is
//! bound to the DID and its own file name, so a sealed file cannot be moved
//! to another identity or another role. Files written in clear by an earlier
//! version are sealed when the session opens, once: the identity's key file
//! then records that its state is sealed (`JigKey::state_sealed`, covered by
//! the key file's authentication), and from then on content in clear is an
//! error, so history cannot be slipped in by writing a file in clear. Putting
//! back an older copy of the key file, from before that, undoes it. An identity that is
//! not sealed at rest ([`Identity::from_signing_key`], plaintext key storage)
//! keeps its state in clear.
//!
//! # Concurrency
//!
//! `jig chat` and `jig send` can run for the same DID at once. Every operation
//! takes an exclusive lock on the directory, loads the state, applies itself
//! and saves, so two processes never fork a group by each advancing a stale
//! copy of it. A commit spans several operations and a network round trip, so
//! it also holds a per-channel commit lock throughout ([`Session::commit_lock`]).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use jig_core::{BlockKind, EncryptionSuite};
use jig_mls::member::{Commit, CommitOutcome, CreatedGroup, Member};
use serde::{Deserialize, Serialize};

use crate::Identity;
use crate::open::{Authenticity, OpenedBlock};

#[derive(Debug, thiserror::Error)]
pub enum SecureError {
    #[error(transparent)]
    Mls(#[from] jig_mls::MlsError),
    #[error("MLS state at {path:?}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("no MLS group for {0} on this device; join or be added first")]
    NoGroup(String),
    #[error("malformed MLS field `{0}` in block")]
    Field(&'static str),
    #[error("MLS state at {path:?} does not open: {reason}")]
    Sealed { path: PathBuf, reason: String },
    #[error(
        "{}{} is in clear, but this identity's MLS state is sealed (its key file says so), \
         so it was not written by this identity: an older jig, or someone else, wrote it. \
         It is not read. To go on, move it aside: mv '{}' '{}.clear'. {}",
        path.display(),
        line.map(|l| format!(" line {l}")).unwrap_or_default(),
        path.display(),
        path.display(),
        if path.ends_with(PLAINTEXT) {
            "History read before then cannot be decrypted again."
        } else {
            "This device then has no groups and must rejoin its encrypted channels."
        }
    )]
    InClear { path: PathBuf, line: Option<usize> },
    #[error(transparent)]
    Identity(#[from] crate::identity::IdentityError),
}

pub type Result<T> = std::result::Result<T, SecureError>;

/// What a delivered block meant for this member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Seen {
    /// Not encrypted-channel content: display it as it is.
    Plain,
    /// A control block with nothing to show.
    Control,
    /// Encrypted text this member can read.
    Text { sender: String, text: String },
    /// Encrypted text this member cannot read, and why.
    Sealed { reason: String },
    /// This member is now in the channel's group.
    Joined,
    /// Someone was added; the local group has followed.
    Added { member: String },
    /// Someone was removed, or a departed member's leaf was cleared.
    Removed { member: String },
    /// Someone left. When `tidy` is set, their leaf is still in this member's
    /// copy of the tree and this member should commit its removal.
    Left { member: String, tidy: bool },
    /// This member was removed, or left; its copy of the group is gone.
    Gone,
    /// A membership change this member could not follow.
    Broken { reason: String },
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Groups {
    /// `server|slug` → hex group id.
    groups: HashMap<String, String>,
    /// Membership blocks already applied to a group, by CID, and what each
    /// meant. History is replayed on every read, and a server can deliver an
    /// old block again on purpose: neither may act twice.
    #[serde(default)]
    seen: HashMap<String, Seen>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Read {
    cid: String,
    sender: String,
    text: String,
}

/// A channel's commit lock, held until dropped. See [`Session::commit_lock`].
#[derive(Debug)]
pub struct CommitLock(#[allow(dead_code)] File);

/// One DID's MLS state on this device.
pub struct Session {
    identity: Identity,
    did: String,
    dir: PathBuf,
    /// Plaintext already read, by block CID. A cache of `plaintext.jsonl`,
    /// re-read from disk on a miss in case another process wrote it.
    read: Mutex<HashMap<String, (String, String)>>,
    /// This directory has been sealed: content in clear is refused.
    sealed_only: bool,
}

const STATE: &str = "state.bin";
const GROUPS: &str = "groups.json";
const PLAINTEXT: &str = "plaintext.jsonl";
/// The prefix of a sealed `plaintext.jsonl` record. A record in clear is JSON
/// and starts with `{`.
const SEALED_LINE: &str = "s1:";

/// The key-derivation context for one of this module's files.
fn file_context(file: &str) -> String {
    format!("jig mls {file} v1")
}

/// Default root for MLS state: `~/.jig/mls/`.
pub fn default_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".jig")
        .join("mls")
}

/// A server URL as local state files it: `ws(s)` and `http(s)` spellings,
/// case and a trailing slash all name the same server.
pub fn server_key(server: &str) -> String {
    // The scheme is not part of which server it is: a server that moves from
    // `http://` to `https://` keeps its groups and pins.
    let server = server.trim().trim_end_matches('/').to_ascii_lowercase();
    ["https://", "http://", "wss://", "ws://"]
        .iter()
        .find_map(|scheme| server.strip_prefix(scheme))
        .unwrap_or(&server)
        .to_string()
}

/// A `server|slug` key written under an older [`server_key`], as it is now.
fn rekey(key: &str) -> String {
    match key.split_once('|') {
        Some((server, slug)) => format!("{}|{slug}", server_key(server)),
        None => key.to_string(),
    }
}

/// The key a channel's group is filed under: its server and slug. A slug
/// alone would collide between servers that both have a `#general`.
pub fn group_key(server: &str, slug: &str) -> String {
    format!("{}|{slug}", server_key(server))
}

impl Session {
    /// Open (creating if needed) the MLS state for `identity` under `root`.
    pub fn open(root: &Path, identity: Identity) -> Result<Self> {
        let did = identity.did_string();
        let dir = root.join(&did);
        std::fs::create_dir_all(&dir).map_err(|source| SecureError::Io {
            path: dir.clone(),
            source,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(
                |source| SecureError::Io {
                    path: dir.clone(),
                    source,
                },
            )?;
        }
        let mut session = Self {
            identity,
            did,
            dir,
            read: Mutex::new(HashMap::new()),
            sealed_only: false,
        };
        session.sealed_only = session.seal_clear_files()?;
        session.reload_read()?;
        Ok(session)
    }

    /// Seal any file an earlier version wrote in clear, under the lock, and
    /// say whether this identity's state is sealed (so that clear content is
    /// refused from now on).
    ///
    /// Whether it is sealed is recorded in the identity's key file
    /// (`JigKey::state_sealed`), where it is authenticated: someone who can
    /// write files here cannot clear it, as they could a file of its own.
    fn seal_clear_files(&self) -> Result<bool> {
        let _lock = self.lock()?;
        self.remove_stale_temporaries()?;
        if !self.identity.is_sealed() {
            return Ok(false);
        }
        let sealed_already = self.identity.state_sealed()?;
        for file in [STATE, GROUPS] {
            let path = self.dir.join(file);
            match std::fs::read(&path) {
                Ok(bytes) if !jig_core::keystore::is_sealed(&bytes) => {
                    if sealed_already {
                        return Err(SecureError::InClear { path, line: None });
                    }
                    write_atomic(&path, &self.seal(file, &bytes))?;
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(SecureError::Io { path, source }),
            }
        }
        let path = self.dir.join(PLAINTEXT);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => Some(zeroize::Zeroizing::new(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => return Err(SecureError::Io { path, source }),
        };
        if let Some(text) = text {
            let clear = text
                .lines()
                .position(|l| !l.is_empty() && !l.starts_with(SEALED_LINE));
            if let Some(index) = clear {
                if sealed_already {
                    return Err(SecureError::InClear {
                        path,
                        line: Some(index + 1),
                    });
                }
                let mut sealed = String::new();
                for line in text.lines().filter(|l| !l.is_empty()) {
                    if line.starts_with(SEALED_LINE) {
                        sealed.push_str(line);
                    } else {
                        sealed.push_str(&self.seal_line(line));
                    }
                    sealed.push('\n');
                }
                write_atomic(&path, sealed.as_bytes())?;
            }
        }
        if !sealed_already {
            self.identity.mark_state_sealed()?;
        }
        Ok(true)
    }

    /// Remove temporary files a crash left behind: `<file>.tmp.<random>`, and
    /// `state.tmp` and the like from earlier versions. Callers hold the lock,
    /// and every writer here does, so none of them is still being written.
    fn remove_stale_temporaries(&self) -> Result<()> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Ok(());
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.contains(".tmp.") || name.ends_with(".tmp") {
                let path = entry.path();
                std::fs::remove_file(&path).map_err(|source| SecureError::Io { path, source })?;
            }
        }
        Ok(())
    }

    /// `bytes` sealed for `file`, or as they are when this identity is not
    /// sealed at rest.
    fn seal(&self, file: &str, bytes: &[u8]) -> Vec<u8> {
        match self.identity.file_key(&file_context(file)) {
            Some(key) => jig_core::keystore::seal(&key, &self.aad(file), bytes),
            None => bytes.to_vec(),
        }
    }

    fn aad(&self, file: &str) -> Vec<u8> {
        format!("{}|{file}", self.did).into_bytes()
    }

    /// The contents of `file`, opened if sealed. A file in clear is returned
    /// as it is if this directory has not been sealed yet (an earlier version
    /// wrote it, and the next save seals it), and refused once it has.
    fn unseal(
        &self,
        file: &str,
        path: &Path,
        bytes: Vec<u8>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let sealed_err = |reason: String| SecureError::Sealed {
            path: path.to_path_buf(),
            reason,
        };
        if !jig_core::keystore::is_sealed(&bytes) {
            if self.sealed_only {
                return Err(SecureError::InClear {
                    path: path.to_path_buf(),
                    line: None,
                });
            }
            return Ok(zeroize::Zeroizing::new(bytes));
        }
        let key = self.identity.file_key(&file_context(file)).ok_or_else(|| {
            sealed_err("it is sealed, and this identity's key is not sealed at rest".into())
        })?;
        jig_core::keystore::open(&key, &self.aad(file), &bytes)
            .map_err(|e| sealed_err(e.to_string()))
    }

    fn seal_line(&self, line: &str) -> String {
        format!(
            "{SEALED_LINE}{}",
            STANDARD.encode(self.seal(PLAINTEXT, line.as_bytes()))
        )
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    /// Fresh key packages to publish; their private halves are saved here.
    pub fn key_packages(&self, count: usize, last_resort: bool) -> Result<Vec<Vec<u8>>> {
        self.with_member(|m, _| Ok(m.key_packages(count, last_resort)?))
    }

    /// Whether this device holds the group for `server`/`slug`.
    pub fn has_group(&self, server: &str, slug: &str) -> Result<bool> {
        let key = group_key(server, slug);
        self.with_member(|m, g| Ok(group_of(g, &key).is_some_and(|gid| m.has_group(&gid))))
    }

    /// This device's epoch in the channel's group; `None` with no group here.
    pub fn epoch(&self, server: &str, slug: &str) -> Result<Option<u64>> {
        let key = group_key(server, slug);
        self.with_member(
            |m, g| match group_of(g, &key).filter(|gid| m.has_group(gid)) {
                Some(gid) => Ok(Some(m.epoch(&gid)?)),
                None => Ok(None),
            },
        )
    }

    /// DIDs in this device's copy of the channel's tree.
    pub fn group_members(&self, server: &str, slug: &str) -> Result<Vec<String>> {
        let key = group_key(server, slug);
        self.with_member(|m, g| {
            let gid = group_of(g, &key).ok_or_else(|| SecureError::NoGroup(key.clone()))?;
            Ok(m.members(&gid)?)
        })
    }

    /// Whether this member has a commit for the channel that the server has
    /// neither confirmed nor refused.
    pub fn has_pending_commit(&self, server: &str, slug: &str) -> Result<bool> {
        let key = group_key(server, slug);
        self.with_member(|m, g| {
            Ok(
                group_of(g, &key)
                    .is_some_and(|gid| m.has_group(&gid) && m.has_pending_commit(&gid)),
            )
        })
    }

    /// Start the group for a channel about to be created.
    pub fn create_group(&self, server: &str, slug: &str) -> Result<CreatedGroup> {
        let key = group_key(server, slug);
        self.with_member(|m, g| {
            let created = m.create_group()?;
            g.groups.insert(key, hex::encode(&created.group_id));
            Ok(created)
        })
    }

    /// Drop a channel's group: a create or join the server refused, or a
    /// channel this member left.
    pub fn discard_group(&self, server: &str, slug: &str) -> Result<()> {
        let key = group_key(server, slug);
        self.with_member(|m, g| {
            if let Some(gid) = group_of(g, &key) {
                m.forget(&gid)?;
            }
            g.groups.remove(&key);
            Ok(())
        })
    }

    pub fn prepare_add(
        &self,
        server: &str,
        slug: &str,
        key_package: &[u8],
        did: &str,
    ) -> Result<Commit> {
        self.with_group(server, slug, |m, gid| Ok(m.add(gid, key_package, did)?))
    }

    pub fn prepare_remove(&self, server: &str, slug: &str, did: &str) -> Result<Commit> {
        self.with_group(server, slug, |m, gid| Ok(m.remove(gid, did)?))
    }

    /// Join by external commit from the channel's published group info.
    pub fn prepare_join(&self, server: &str, slug: &str, group_info: &[u8]) -> Result<Commit> {
        let key = group_key(server, slug);
        self.with_member(|m, g| {
            let (gid, commit) = m.join_external(group_info)?;
            g.groups.insert(key, hex::encode(gid));
            Ok(commit)
        })
    }

    /// The server accepted this member's commit.
    pub fn confirm(&self, server: &str, slug: &str) -> Result<()> {
        self.with_group(server, slug, |m, gid| Ok(m.confirm(gid)?))
    }

    /// The server refused this member's commit.
    pub fn abandon(&self, server: &str, slug: &str) -> Result<()> {
        self.with_group(server, slug, |m, gid| Ok(m.abandon(gid)?))
    }

    /// Encrypt `text` for the channel. Returns the MLS message and its epoch.
    pub fn encrypt(&self, server: &str, slug: &str, text: &str) -> Result<(Vec<u8>, u64)> {
        self.with_group(server, slug, |m, gid| Ok(m.encrypt(gid, text.as_bytes())?))
    }

    /// File the plaintext of a block this member sent or read.
    pub fn remember(&self, cid: &str, sender: &str, text: &str) -> Result<()> {
        let path = self.dir.join(PLAINTEXT);
        let _lock = self.lock()?;
        let io = |source| SecureError::Io {
            path: path.clone(),
            source,
        };
        let mut f = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .map_err(io)?;
        drop_torn_tail(&mut f).map_err(io)?;
        let line = zeroize::Zeroizing::new(
            serde_json::to_string(&Read {
                cid: cid.to_string(),
                sender: sender.to_string(),
                text: text.to_string(),
            })
            .expect("plaintext record serializes"),
        );
        let line = if self.identity.is_sealed() {
            self.seal_line(&line)
        } else {
            line.to_string()
        };
        // One write for the record and its newline: two writes can be cut
        // between them, and the next record would land on the same line.
        let record = zeroize::Zeroizing::new(format!("{line}\n"));
        f.write_all(record.as_bytes()).map_err(io)?;
        self.read
            .lock()
            .expect("plaintext cache poisoned")
            .insert(cid.to_string(), (sender.to_string(), text.to_string()));
        Ok(())
    }

    /// Apply a delivered block to this member's state and say what it meant.
    ///
    /// Blocks must come in the channel's order — history first, sorted with
    /// [`replay_order`], then the live stream. A block from a channel this
    /// member has no group for is not an error: it reads as [`Seen::Sealed`]
    /// or [`Seen::Control`].
    pub fn observe(&self, server: &str, block: &OpenedBlock) -> Seen {
        match self.try_observe(server, block) {
            Ok(seen) => seen,
            Err(e) => match block.manifest.kind {
                Some(BlockKind::MemberAdd | BlockKind::MemberRemove) => Seen::Broken {
                    reason: e.to_string(),
                },
                _ => Seen::Sealed {
                    reason: e.to_string(),
                },
            },
        }
    }

    fn try_observe(&self, server: &str, block: &OpenedBlock) -> Result<Seen> {
        let Some(kind) = block.manifest.kind else {
            return Ok(Seen::Plain);
        };
        // Nothing vouches for an unsigned block's author, so it must not move
        // group state: a server could otherwise forge a leave and have this
        // member commit someone's removal with its own key.
        if block.authenticity != Authenticity::Verified {
            let reason = "unsigned block; ignored".to_string();
            if matches!(kind, BlockKind::MemberAdd | BlockKind::MemberRemove) {
                return Ok(Seen::Broken { reason });
            }
            if block.manifest.content_suite().is_encrypted() {
                return Ok(Seen::Sealed { reason });
            }
        }
        let slug = jig_pipeline::ingest::channel_slug_of(kind, &block.manifest)
            .unwrap_or_default()
            .to_string();
        let key = group_key(server, &slug);
        let me = self.did.clone();
        let commit = block.meta_str("mls_commit");
        let member = block
            .meta_str("member_did")
            .map(jig_pipeline::effect::canonical_did_string)
            .unwrap_or_default();

        match kind {
            BlockKind::ChannelCreate | BlockKind::ChannelPromote | BlockKind::ChannelArchive => {
                Ok(Seen::Control)
            }
            BlockKind::MemberAdd => {
                let Some(commit) = commit else {
                    return Ok(Seen::Control);
                };
                let commit = b64(commit, "mls_commit")?;
                self.once(block, &key, |m, g| {
                    let gid = group_of(g, &key).filter(|gid| m.has_group(gid));
                    if member == me {
                        if block.sender == me {
                            // My external join: built and merged locally.
                            return Ok(Seen::Joined);
                        }
                        if gid.is_some() {
                            return Ok(Seen::Control);
                        }
                        let welcome = block
                            .meta_str("mls_welcome")
                            .ok_or(SecureError::Field("mls_welcome"))?;
                        let gid = m.join_welcome(&b64(welcome, "mls_welcome")?)?;
                        g.groups.insert(key.clone(), hex::encode(gid));
                        return Ok(Seen::Joined);
                    }
                    let Some(gid) = gid else {
                        return Ok(Seen::Control);
                    };
                    follow(
                        m,
                        g,
                        &key,
                        &gid,
                        block,
                        &me,
                        &commit,
                        Seen::Added { member },
                    )
                })
            }
            BlockKind::MemberRemove => {
                let Some(commit) = commit else {
                    // A leave: membership is gone, the leaf is not.
                    return self.once(block, &key, |m, g| {
                        let Some(gid) = group_of(g, &key).filter(|gid| m.has_group(gid)) else {
                            return Ok(Seen::Left {
                                member,
                                tidy: false,
                            });
                        };
                        if member == me {
                            m.forget(&gid)?;
                            g.groups.remove(&key);
                            return Ok(Seen::Gone);
                        }
                        let tidy = m.members(&gid)?.contains(&member);
                        Ok(Seen::Left { member, tidy })
                    });
                };
                let commit = b64(commit, "mls_commit")?;
                self.once(block, &key, |m, g| {
                    let Some(gid) = group_of(g, &key).filter(|gid| m.has_group(gid)) else {
                        return Ok(Seen::Control);
                    };
                    follow(
                        m,
                        g,
                        &key,
                        &gid,
                        block,
                        &me,
                        &commit,
                        Seen::Removed { member },
                    )
                })
            }
            _ => {
                let suite = block.manifest.content_suite();
                if !suite.is_encrypted() {
                    return Ok(Seen::Plain);
                }
                // Another encrypted suite is ciphertext this client cannot
                // read, never something to show as it is.
                if suite != EncryptionSuite::Mls {
                    return Ok(Seen::Sealed {
                        reason: format!("suite `{suite}` is not supported by this client"),
                    });
                }
                if let Some((sender, text)) = self.recall(&block.cid)? {
                    return Ok(Seen::Text { sender, text });
                }
                let message = block
                    .meta_str("mls_message")
                    .ok_or(SecureError::Field("mls_message"))?;
                let message = b64(message, "mls_message")?;
                let decrypted = self.with_member(|m, g| {
                    let gid = group_of(g, &key)
                        .filter(|gid| m.has_group(gid))
                        .ok_or_else(|| SecureError::NoGroup(slug.clone()))?;
                    Ok(m.decrypt(&gid, &message)?)
                })?;
                if decrypted.sender != block.sender {
                    return Ok(Seen::Sealed {
                        reason: format!(
                            "MLS sender {} is not the block's author",
                            decrypted.sender
                        ),
                    });
                }
                let text = String::from_utf8_lossy(&decrypted.plaintext).into_owned();
                self.remember(&block.cid, &block.sender, &text)?;
                Ok(Seen::Text {
                    sender: block.sender.clone(),
                    text,
                })
            }
        }
    }

    /// Apply a membership block at most once. A block already applied gets
    /// back what it meant the first time, minus any action it asked for: a
    /// replayed leave never asks for a tidy-up, since the member may have
    /// been re-added since. Only blocks that touched a group this member
    /// holds, before or after, are remembered.
    fn once(
        &self,
        block: &OpenedBlock,
        key: &str,
        f: impl FnOnce(&Member, &mut Groups) -> Result<Seen>,
    ) -> Result<Seen> {
        self.with_member(|m, g| {
            if let Some(seen) = g.seen.get(&block.cid) {
                return Ok(match seen.clone() {
                    Seen::Left { member, .. } => Seen::Left {
                        member,
                        tidy: false,
                    },
                    other => other,
                });
            }
            let held = |g: &Groups| group_of(g, key).is_some_and(|gid| m.has_group(&gid));
            let before = held(g);
            let seen = f(m, g)?;
            if before || held(g) {
                g.seen.insert(block.cid.clone(), seen.clone());
            }
            Ok(seen)
        })
    }

    fn recall(&self, cid: &str) -> Result<Option<(String, String)>> {
        if let Some(hit) = self.read.lock().expect("plaintext cache poisoned").get(cid) {
            return Ok(Some(hit.clone()));
        }
        self.reload_read()?;
        Ok(self
            .read
            .lock()
            .expect("plaintext cache poisoned")
            .get(cid)
            .cloned())
    }

    fn reload_read(&self) -> Result<()> {
        let path = self.dir.join(PLAINTEXT);
        let io = |source| SecureError::Io {
            path: path.clone(),
            source,
        };
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => zeroize::Zeroizing::new(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(io(e)),
        };
        let text = std::str::from_utf8(&bytes).map_err(|e| SecureError::Sealed {
            path: path.clone(),
            reason: e.to_string(),
        })?;
        // Every record ends in a newline. A last one without it was cut short
        // (a kill, a full disk) and is dropped; the next append removes it.
        let complete = match text.rfind('\n') {
            Some(end) => &text[..=end],
            None => "",
        };
        if complete.len() < text.len() {
            tracing::warn!("{}: ignoring a record that was cut short", path.display());
        }
        let mut read = self.read.lock().expect("plaintext cache poisoned");
        for (index, line) in complete.lines().enumerate().filter(|(_, l)| !l.is_empty()) {
            // A sealed record that does not open is an error, never skipped:
            // skipping would hide tampering, and the next write would bury it.
            let line = match line.strip_prefix(SEALED_LINE) {
                Some(encoded) => {
                    let sealed = STANDARD.decode(encoded).map_err(|e| SecureError::Sealed {
                        path: path.clone(),
                        reason: format!("a record is not base64: {e}"),
                    })?;
                    let opened = self.unseal(PLAINTEXT, &path, sealed)?;
                    zeroize::Zeroizing::new(String::from_utf8(opened.to_vec()).map_err(|e| {
                        SecureError::Sealed {
                            path: path.clone(),
                            reason: e.to_string(),
                        }
                    })?)
                }
                None if self.sealed_only => {
                    return Err(SecureError::InClear {
                        path: path.clone(),
                        line: Some(index + 1),
                    });
                }
                None => zeroize::Zeroizing::new(line.to_string()),
            };
            if let Ok(r) = serde_json::from_str::<Read>(&line) {
                read.insert(r.cid, (r.sender, r.text));
            }
        }
        Ok(())
    }

    fn with_group<T>(
        &self,
        server: &str,
        slug: &str,
        f: impl FnOnce(&Member, &[u8]) -> Result<T>,
    ) -> Result<T> {
        let key = group_key(server, slug);
        self.with_member(|m, g| {
            let gid = group_of(g, &key)
                .filter(|gid| m.has_group(gid))
                .ok_or_else(|| SecureError::NoGroup(slug.to_string()))?;
            f(m, &gid)
        })
    }

    /// Lock, load, apply `f`, save. The one way state changes.
    fn with_member<T>(&self, f: impl FnOnce(&Member, &mut Groups) -> Result<T>) -> Result<T> {
        let _lock = self.lock()?;
        let state_path = self.dir.join(STATE);
        let groups_path = self.dir.join(GROUPS);
        let member = match std::fs::read(&state_path) {
            Ok(bytes) => {
                self.identity
                    .restore_mls_member(&self.unseal(STATE, &state_path, bytes)?)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.identity.mls_member()?,
            Err(source) => {
                return Err(SecureError::Io {
                    path: state_path,
                    source,
                });
            }
        };
        // Only a missing file means "no groups yet". Anything else would be
        // saved back over the real mapping below, orphaning every group.
        let mut groups: Groups = match std::fs::read(&groups_path) {
            Ok(bytes) => serde_json::from_slice(&self.unseal(GROUPS, &groups_path, bytes)?)
                .map_err(|e| SecureError::Io {
                    path: groups_path.clone(),
                    source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
                })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Groups::default(),
            Err(source) => {
                return Err(SecureError::Io {
                    path: groups_path,
                    source,
                });
            }
        };
        // Keys written while the scheme was part of them.
        groups.groups = std::mem::take(&mut groups.groups)
            .into_iter()
            .map(|(key, gid)| (rekey(&key), gid))
            .collect();
        let out = f(&member, &mut groups);
        // Save even when `f` failed: openmls may have written state (a staged
        // commit, a consumed key package) before the failure.
        // Both files, then one directory sync: a sync that failed after the
        // first rename must not leave the second file unwritten.
        replace(&state_path, &self.seal(STATE, &member.snapshot()))?;
        replace(
            &groups_path,
            &self.seal(
                GROUPS,
                &serde_json::to_vec_pretty(&groups).expect("groups serialize"),
            ),
        )?;
        crate::identity::sync_parent_dir(&state_path).map_err(|source| SecureError::Io {
            path: self.dir.clone(),
            source,
        })?;
        out
    }

    /// Hold the channel's commit lock until the returned guard drops.
    ///
    /// A commit is a round trip: prepare it here, submit it, then confirm or
    /// abandon it on the answer. Each step locks the state only for itself,
    /// so two processes for this DID could otherwise interleave — one drops
    /// as stale a commit the other is still waiting on, the server takes it
    /// anyway, and this device is left an epoch behind for good, since MLS
    /// never applies a member's own commit from the wire. Hold this across the
    /// whole trip. Blocks until it is free.
    pub fn commit_lock(&self, server: &str, slug: &str) -> Result<CommitLock> {
        let (path, f) = self.commit_lock_file(server, slug)?;
        f.lock()
            .map_err(|source| SecureError::Io { path, source })?;
        Ok(CommitLock(f))
    }

    /// [`Session::commit_lock`] without waiting: `None` while another holder
    /// has it.
    pub fn try_commit_lock(&self, server: &str, slug: &str) -> Result<Option<CommitLock>> {
        let (path, f) = self.commit_lock_file(server, slug)?;
        match f.try_lock() {
            Ok(()) => Ok(Some(CommitLock(f))),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(source)) => Err(SecureError::Io { path, source }),
        }
    }

    fn commit_lock_file(&self, server: &str, slug: &str) -> Result<(PathBuf, File)> {
        // One file per channel, named by a hash: the key holds a URL and a
        // slug, neither of which is a safe file name.
        let name = blake3::hash(group_key(server, slug).as_bytes()).to_hex();
        let path = self.dir.join(format!("commit-{}.lock", &name[..16]));
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|source| SecureError::Io {
                path: path.clone(),
                source,
            })?;
        Ok((path, f))
    }

    fn lock(&self) -> Result<File> {
        let path = self.dir.join("lock");
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|source| SecureError::Io {
                path: path.clone(),
                source,
            })?;
        f.lock()
            .map_err(|source| SecureError::Io { path, source })?;
        Ok(f)
    }
}

/// Apply a commit someone sent, or confirm one this member sent.
#[allow(clippy::too_many_arguments)]
fn follow(
    m: &Member,
    g: &mut Groups,
    key: &str,
    gid: &[u8],
    block: &OpenedBlock,
    me: &str,
    commit: &[u8],
    done: Seen,
) -> Result<Seen> {
    if block.sender == me {
        // My own commit, echoed back. Merging here as well as after the
        // submit covers a client that exited between the two.
        if m.has_pending_commit(gid)
            && jig_mls::member::message_epoch(commit) == Some(m.epoch(gid)?)
        {
            m.confirm(gid)?;
        }
        return Ok(done);
    }
    match m.apply_commit(gid, commit)? {
        CommitOutcome::Applied { .. } | CommitOutcome::AlreadyApplied => Ok(done),
        CommitOutcome::Removed => {
            g.groups.remove(key);
            Ok(Seen::Gone)
        }
    }
}

fn group_of(g: &Groups, key: &str) -> Option<Vec<u8>> {
    g.groups.get(key).and_then(|h| hex::decode(h).ok())
}

fn b64(s: &str, field: &'static str) -> Result<Vec<u8>> {
    STANDARD.decode(s).map_err(|_| SecureError::Field(field))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::identity::write_private_atomic(path, bytes).map_err(|source| SecureError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// [`write_atomic`] without the directory sync; see `with_member`.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::identity::replace_private(path, bytes).map_err(|source| SecureError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// If `f` does not end in a newline, its last record was cut short: cut it
/// off, so the next record starts a line of its own.
fn drop_torn_tail(f: &mut File) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(());
    }
    let mut last = [0u8; 1];
    f.seek(SeekFrom::End(-1))?;
    f.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }
    f.seek(SeekFrom::Start(0))?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    f.read_to_end(&mut bytes)?;
    let keep = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    f.set_len(keep as u64)?;
    tracing::warn!("dropped a plaintext record that was cut short");
    Ok(())
}

/// Whether `blocks` — a channel's history from some point up to now — reach
/// back far enough for a member to follow every commit since.
///
/// A member at epoch `e` needs every commit from the one built on `e` to the
/// newest epoch the history shows. History is ordered by the HLC each author
/// stamped, not by epoch, so one block at or below `e` proves nothing: a
/// commit whose author's clock runs slow can sort behind messages sent after
/// it. The chain itself is the test — a commit built on each epoch from `e` up
/// to the newest. A member with no group yet (`epoch` is `None`) starts from
/// the welcome that adds `me`. The channel's creation block is the start of
/// history: there is nothing further back to fetch.
pub fn history_reaches(blocks: &[OpenedBlock], epoch: Option<u64>, me: &str) -> bool {
    if blocks
        .iter()
        .any(|b| b.manifest.kind == Some(BlockKind::ChannelCreate))
    {
        return true;
    }
    let epoch_in = |b: &OpenedBlock, field| {
        b.meta_str(field)
            .and_then(|s| STANDARD.decode(s).ok())
            .and_then(|bytes| jig_mls::member::message_epoch(&bytes))
    };
    let mut commits = std::collections::HashSet::new();
    let mut newest = None;
    let mut welcomed_at = None;
    for b in blocks {
        if let Some(e) = epoch_in(b, "mls_commit") {
            commits.insert(e);
            newest = newest.max(Some(e + 1));
            let welcomes_me = b.manifest.kind == Some(BlockKind::MemberAdd)
                && b.meta_str("mls_welcome").is_some()
                && b.meta_str("member_did")
                    .map(jig_pipeline::effect::canonical_did_string)
                    .is_some_and(|d| d == me);
            if welcomes_me {
                welcomed_at = welcomed_at.max(Some(e + 1));
            }
        }
        if let Some(e) = epoch_in(b, "mls_message") {
            newest = newest.max(Some(e));
        }
    }
    let Some(from) = epoch.or(welcomed_at) else {
        return false;
    };
    (from..newest.unwrap_or(from)).all(|e| commits.contains(&e))
}

/// Order a channel's history for an MLS member.
///
/// History comes back in the order of each block's HLC, which its *author*
/// stamped. MLS needs commits in epoch order and a message after the commit
/// that created its epoch, so blocks carrying MLS data are ordered by the
/// epoch in their framing — read without decrypting — with messages before
/// the commit that leaves their epoch. A block with no MLS data takes the
/// position of the epoch it was posted in — it sorts among that epoch's
/// messages, ahead of the commit that ends it — so it keeps its place
/// relative to its neighbours.
pub fn replay_order(blocks: Vec<OpenedBlock>) -> Vec<OpenedBlock> {
    let mut current = 0u64;
    let mut keyed: Vec<((u64, u8), usize, OpenedBlock)> = blocks
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            let mls = |field| {
                b.meta_str(field)
                    .and_then(|s| STANDARD.decode(s).ok())
                    .and_then(|bytes| jig_mls::member::message_epoch(&bytes))
            };
            let key = if let Some(e) = mls("mls_message") {
                current = current.max(e);
                (e, 0)
            } else if let Some(e) = mls("mls_commit") {
                current = current.max(e + 1);
                (e, 1)
            } else {
                (current, 0)
            };
            (key, i, b)
        })
        .collect();
    keyed.sort_by_key(|a| (a.0, a.1));
    keyed.into_iter().map(|(_, _, b)| b).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeliveredBlock;
    use crate::blocks::{BuiltBlock, build_sealed_text, build_with_metadata};
    use jig_core::HlcTimestamp;
    use serde_json::json;

    const SERVER: &str = "http://127.0.0.1:7117";

    fn session(root: &Path) -> Session {
        let keys = tempfile::tempdir().unwrap();
        let id = Identity::generate_for_tests(&keys.keep());
        Session::open(root, id).unwrap()
    }

    fn identity_of(s: &Session) -> &Identity {
        &s.identity
    }

    fn deliver(b: &BuiltBlock) -> OpenedBlock {
        crate::open::open(&DeliveredBlock {
            bundle_b64: STANDARD.encode(b.canonical_bytes()),
            sig_b64: Some(STANDARD.encode(&b.sender_sig)),
            receipts: vec![],
            delivery_cid: format!("delivery:{}", b.cid()),
        })
        .unwrap()
    }

    fn hlc(s: &Session) -> HlcTimestamp {
        HlcTimestamp::now_wall(identity_of(s).did().clone())
    }

    fn add_block(owner: &Session, slug: &str, who: &Session) -> BuiltBlock {
        let kp = who.key_packages(1, false).unwrap().remove(0);
        let c = owner.prepare_add(SERVER, slug, &kp, who.did()).unwrap();
        owner.confirm(SERVER, slug).unwrap();
        build_with_metadata(
            identity_of(owner),
            BlockKind::MemberAdd,
            hlc(owner),
            json!({"channel": slug, "member_did": who.did(),
                "mls_commit": STANDARD.encode(&c.commit),
                "mls_welcome": STANDARD.encode(c.welcome.unwrap()),
                "mls_epoch": c.epoch}),
        )
    }

    fn say(from: &Session, slug: &str, text: &str) -> BuiltBlock {
        let (msg, epoch) = from.encrypt(SERVER, slug, text).unwrap();
        let b = build_sealed_text(identity_of(from), slug, &msg, epoch, hlc(from));
        from.remember(&b.cid(), from.did(), text).unwrap();
        b
    }

    #[test]
    fn a_member_reads_what_the_owner_sends_and_rereads_it_from_the_cache() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        let bob = session(root.path());
        alice.create_group(SERVER, "#sealed").unwrap();

        let add = add_block(&alice, "#sealed", &bob);
        assert_eq!(bob.observe(SERVER, &deliver(&add)), Seen::Joined);
        assert_eq!(
            alice.observe(SERVER, &deliver(&add)),
            Seen::Added {
                member: bob.did().to_string()
            },
            "the owner's own commit, echoed back, is already applied"
        );

        let msg = deliver(&say(&alice, "#sealed", "hello bob"));
        let read = Seen::Text {
            sender: alice.did().to_string(),
            text: "hello bob".to_string(),
        };
        assert_eq!(bob.observe(SERVER, &msg), read);
        assert_eq!(
            bob.observe(SERVER, &msg),
            read,
            "second read comes from the cache"
        );
        assert_eq!(
            alice.observe(SERVER, &msg),
            read,
            "the sender reads its own from the cache"
        );

        // A fresh session over the same directory — the next `jig chat` —
        // still has both the group and the plaintext.
        let bob_again = Session::open(root.path(), bob.identity.duplicate()).unwrap();
        assert_eq!(bob_again.observe(SERVER, &msg), read);
        assert!(bob_again.has_group(SERVER, "#sealed").unwrap());
    }

    #[test]
    fn a_non_member_sees_sealed_text() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        let eve = session(root.path());
        alice.create_group(SERVER, "#sealed").unwrap();
        let msg = deliver(&say(&alice, "#sealed", "secret"));
        assert!(matches!(eve.observe(SERVER, &msg), Seen::Sealed { .. }));
    }

    #[test]
    fn a_kicked_member_loses_the_group() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        let bob = session(root.path());
        alice.create_group(SERVER, "#sealed").unwrap();
        bob.observe(SERVER, &deliver(&add_block(&alice, "#sealed", &bob)));

        let c = alice.prepare_remove(SERVER, "#sealed", bob.did()).unwrap();
        alice.confirm(SERVER, "#sealed").unwrap();
        let kick = build_with_metadata(
            identity_of(&alice),
            BlockKind::MemberRemove,
            hlc(&alice),
            json!({"channel": "#sealed", "member_did": bob.did(),
                "mls_commit": STANDARD.encode(&c.commit)}),
        );
        assert_eq!(bob.observe(SERVER, &deliver(&kick)), Seen::Gone);
        assert!(!bob.has_group(SERVER, "#sealed").unwrap());
        let after = deliver(&say(&alice, "#sealed", "bob is gone"));
        assert!(matches!(bob.observe(SERVER, &after), Seen::Sealed { .. }));
    }

    #[test]
    fn a_leave_asks_remaining_members_to_tidy_up() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        let bob = session(root.path());
        alice.create_group(SERVER, "#sealed").unwrap();
        bob.observe(SERVER, &deliver(&add_block(&alice, "#sealed", &bob)));
        let leave = build_with_metadata(
            identity_of(&bob),
            BlockKind::MemberRemove,
            hlc(&bob),
            json!({"channel": "#sealed", "member_did": bob.did()}),
        );
        assert_eq!(
            alice.observe(SERVER, &deliver(&leave)),
            Seen::Left {
                member: bob.did().to_string(),
                tidy: true
            }
        );
        assert_eq!(bob.observe(SERVER, &deliver(&leave)), Seen::Gone);
    }

    fn unsigned(b: &BuiltBlock) -> OpenedBlock {
        crate::open::open(&DeliveredBlock {
            bundle_b64: STANDARD.encode(b.canonical_bytes()),
            sig_b64: None,
            receipts: vec![],
            delivery_cid: format!("delivery:{}", b.cid()),
        })
        .unwrap()
    }

    fn leave_block(who: &Session, slug: &str) -> BuiltBlock {
        build_with_metadata(
            identity_of(who),
            BlockKind::MemberRemove,
            hlc(who),
            json!({"channel": slug, "member_did": who.did()}),
        )
    }

    #[test]
    fn unsigned_blocks_do_not_move_group_state() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        let bob = session(root.path());
        alice.create_group(SERVER, "#sealed").unwrap();
        bob.observe(SERVER, &deliver(&add_block(&alice, "#sealed", &bob)));

        // A server inventing bob's leave cannot get alice to tidy him out.
        let forged = unsigned(&leave_block(&bob, "#sealed"));
        assert!(matches!(
            alice.observe(SERVER, &forged),
            Seen::Broken { .. }
        ));
        let msg = unsigned(&say(&alice, "#sealed", "hi"));
        assert!(matches!(bob.observe(SERVER, &msg), Seen::Sealed { .. }));
        assert!(
            alice
                .group_members(SERVER, "#sealed")
                .unwrap()
                .contains(&bob.did().to_string())
        );
    }

    #[test]
    fn a_replayed_leave_does_not_ask_for_a_tidy_up_again() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        let bob = session(root.path());
        alice.create_group(SERVER, "#sealed").unwrap();
        bob.observe(SERVER, &deliver(&add_block(&alice, "#sealed", &bob)));
        let leave = deliver(&leave_block(&bob, "#sealed"));
        let left = |tidy| Seen::Left {
            member: bob.did().to_string(),
            tidy,
        };
        assert_eq!(alice.observe(SERVER, &leave), left(true));
        assert_eq!(bob.observe(SERVER, &leave), Seen::Gone);
        alice.prepare_remove(SERVER, "#sealed", bob.did()).unwrap();
        alice.confirm(SERVER, "#sealed").unwrap();

        // Bob is added back; the old leave, delivered again, is history.
        bob.observe(SERVER, &deliver(&add_block(&alice, "#sealed", &bob)));
        assert_eq!(alice.observe(SERVER, &leave), left(false));
        assert_eq!(
            bob.observe(SERVER, &leave),
            Seen::Gone,
            "what it meant then, without acting on it now"
        );
        assert!(bob.has_group(SERVER, "#sealed").unwrap());
    }

    /// Every file under the DID's directory, read raw.
    fn files_of(root: &Path, s: &Session) -> Vec<(String, Vec<u8>)> {
        std::fs::read_dir(root.join(s.did()))
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    std::fs::read(&p).unwrap(),
                )
            })
            .collect()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn nothing_under_the_mls_directory_is_in_clear() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        alice.create_group(SERVER, "#sealed-at-rest").unwrap();
        alice
            .remember(
                "bafy-cid",
                "did:jig:zsender",
                "a message nobody else may read",
            )
            .unwrap();
        let files = files_of(root.path(), &alice);
        for name in [STATE, GROUPS, PLAINTEXT] {
            assert!(files.iter().any(|(n, _)| n == name), "{name} written");
        }
        for (name, bytes) in &files {
            assert!(
                !contains(bytes, b"a message nobody else may read"),
                "{name}"
            );
            assert!(!contains(bytes, b"#sealed-at-rest"), "{name}");
            assert!(!name.ends_with(".tmp"), "{name} left behind");
        }
        // Whole-file writes are owner-only from the moment they exist.
        #[cfg(unix)]
        for name in [STATE, GROUPS] {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.path().join(alice.did()).join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
        // And it reads back, in a fresh session.
        let again = Session::open(root.path(), alice.identity.duplicate()).unwrap();
        assert_eq!(
            again.recall("bafy-cid").unwrap(),
            Some((
                "did:jig:zsender".to_string(),
                "a message nobody else may read".to_string()
            ))
        );
        assert!(again.has_group(SERVER, "#sealed-at-rest").unwrap());
    }

    #[test]
    fn files_an_older_version_wrote_in_clear_are_sealed_on_open() {
        let root = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        // An identity stored raw before, as an earlier version left it: its
        // key is sealed on first load, and its MLS state is still in clear.
        let raw = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let did = Identity::from_signing_key(raw.clone()).did_string();
        let raw_path = keys.path().join(format!("{did}.key"));
        std::fs::write(&raw_path, raw.to_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&raw_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let sealed = Identity::load_for_tests(keys.path(), &did);
        // The same identity, unsealed: the state an earlier version wrote.
        let clear = Session::open(
            root.path(),
            Identity::from_signing_key(ed25519_dalek::SigningKey::from_bytes(
                &sealed.signing_bytes_for_test(),
            )),
        )
        .unwrap();
        clear.create_group(SERVER, "#old").unwrap();
        clear
            .remember("cid-1", "did:jig:zs", "old history")
            .unwrap();
        drop(clear);
        assert!(
            files_of(root.path(), &session_for(root.path(), sealed.duplicate()))
                .iter()
                .all(|(n, b)| n == "lock" || !contains(b, b"old history") && !contains(b, b"#old"))
        );
        let reopened = session_for(root.path(), sealed);
        assert!(reopened.has_group(SERVER, "#old").unwrap());
        assert_eq!(
            reopened.recall("cid-1").unwrap().map(|(_, t)| t),
            Some("old history".to_string())
        );
    }

    fn session_for(root: &Path, id: Identity) -> Session {
        Session::open(root, id).unwrap()
    }

    #[test]
    fn a_tampered_record_is_an_error_not_a_skipped_line() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        alice.remember("cid-1", "did:jig:zs", "kept").unwrap();
        let path = root.path().join(alice.did()).join(PLAINTEXT);
        let mut text = std::fs::read_to_string(&path).unwrap();
        // Flip one character of the sealed record.
        let at = text.len() - 3;
        let flipped = if &text[at..at + 1] == "A" { "B" } else { "A" };
        text.replace_range(at..at + 1, flipped);
        std::fs::write(&path, text).unwrap();
        assert!(matches!(
            Session::open(root.path(), alice.identity.duplicate()),
            Err(SecureError::Sealed { .. })
        ));
    }

    #[test]
    fn a_record_cut_short_is_dropped_and_the_next_one_still_reads() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        alice.remember("cid-1", "did:jig:zs", "whole").unwrap();
        let path = root.path().join(alice.did()).join(PLAINTEXT);
        // A record killed before its newline was written.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"s1:AAAAhalf-a-reco").unwrap();
        drop(f);
        let again = Session::open(root.path(), alice.identity.duplicate()).unwrap();
        assert_eq!(
            again.recall("cid-1").unwrap().map(|(_, t)| t),
            Some("whole".into())
        );
        again.remember("cid-2", "did:jig:zs", "after").unwrap();
        let third = Session::open(root.path(), alice.identity.duplicate()).unwrap();
        assert_eq!(
            third.recall("cid-2").unwrap().map(|(_, t)| t),
            Some("after".into())
        );
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("half-a-reco")
        );
    }

    #[test]
    fn once_sealed_content_in_clear_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        alice.create_group(SERVER, "#mine").unwrap();
        alice.remember("cid-1", "did:jig:zs", "real").unwrap();
        let dir = root.path().join(alice.did());

        // A history line slipped in, in clear.
        let plaintext = dir.join(PLAINTEXT);
        let real = std::fs::read(&plaintext).unwrap();
        let mut forged = real.clone();
        forged.extend_from_slice(
            b"{\"cid\":\"cid-2\",\"sender\":\"did:jig:zx\",\"text\":\"forged\"}\n",
        );
        std::fs::write(&plaintext, &forged).unwrap();
        let err = Session::open(root.path(), alice.identity.duplicate())
            .err()
            .expect("a clear line is refused");
        assert!(
            matches!(err, SecureError::InClear { line: Some(2), .. }),
            "{err}"
        );
        assert!(err.to_string().contains("mv "), "{err}");
        std::fs::write(&plaintext, &real).unwrap();

        // A group map in clear.
        let groups = dir.join(GROUPS);
        std::fs::write(&groups, b"{\"groups\":{}}").unwrap();
        assert!(matches!(
            Session::open(root.path(), alice.identity.duplicate()),
            Err(SecureError::InClear { line: None, .. })
        ));

        // Wiping the directory and starting it over in clear does not help:
        // the key file says this identity's state is sealed.
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(PLAINTEXT),
            b"{\"cid\":\"cid-9\",\"sender\":\"did:jig:zx\",\"text\":\"forged\"}\n",
        )
        .unwrap();
        assert!(matches!(
            Session::open(root.path(), alice.identity.duplicate()),
            Err(SecureError::InClear { .. })
        ));
    }

    #[test]
    fn temporary_files_a_crash_left_are_removed_on_open() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        let dir = root.path().join(alice.did());
        for stale in ["state.tmp", "groups.tmp", "state.bin.tmp.0123456789abcdef"] {
            std::fs::write(dir.join(stale), b"left by a crash").unwrap();
        }
        drop(Session::open(root.path(), alice.identity.duplicate()).unwrap());
        let names: Vec<_> = files_of(root.path(), &alice)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(names.iter().all(|n| !n.contains(".tmp")), "{names:?}");
    }

    #[test]
    fn sealed_state_does_not_open_for_another_identity() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        alice.create_group(SERVER, "#a").unwrap();
        let bob = session(root.path());
        let from = root.path().join(alice.did()).join(GROUPS);
        let to = root.path().join(bob.did()).join(GROUPS);
        std::fs::copy(from, to).unwrap();
        assert!(matches!(
            bob.has_group(SERVER, "#a"),
            Err(SecureError::Sealed { .. })
        ));
    }

    #[test]
    fn a_corrupt_group_map_is_an_error_not_an_empty_map() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        alice.create_group(SERVER, "#sealed").unwrap();
        let path = root.path().join(alice.did()).join("groups.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(alice.has_group(SERVER, "#sealed").is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"{not json",
            "left as it was"
        );
    }

    #[test]
    fn replay_puts_commits_before_the_messages_that_need_them() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        let bob = session(root.path());
        let carol = session(root.path());
        alice.create_group(SERVER, "#sealed").unwrap();
        let add_bob = add_block(&alice, "#sealed", &bob);
        let m1 = say(&alice, "#sealed", "one");
        let add_carol = add_block(&alice, "#sealed", &carol);
        let m2 = say(&alice, "#sealed", "two");
        // History as a skewed author clock might order it.
        let shuffled = vec![
            deliver(&m2),
            deliver(&add_carol),
            deliver(&m1),
            deliver(&add_bob),
        ];
        let ordered: Vec<String> = replay_order(shuffled).into_iter().map(|b| b.cid).collect();
        assert_eq!(
            ordered,
            vec![add_bob.cid(), m1.cid(), add_carol.cid(), m2.cid()]
        );
    }

    #[test]
    fn history_reaches_back_to_this_members_epoch() {
        let root = tempfile::tempdir().unwrap();
        let alice = session(root.path());
        let bob = session(root.path());
        let carol = session(root.path());
        alice.create_group(SERVER, "#sealed").unwrap();
        let add_bob = deliver(&add_block(&alice, "#sealed", &bob)); // commit at 0
        let m1 = deliver(&say(&alice, "#sealed", "one")); // epoch 1
        let add_carol = deliver(&add_block(&alice, "#sealed", &carol)); // commit at 1
        let m2 = deliver(&say(&alice, "#sealed", "two")); // epoch 2

        let tail = [add_carol.clone(), m2.clone()];
        assert!(
            history_reaches(&tail, Some(1), alice.did()),
            "has the commit at 1"
        );
        assert!(
            !history_reaches(std::slice::from_ref(&m2), Some(1), alice.did()),
            "missing the commit that left epoch 1"
        );
        assert!(history_reaches(
            &[m1.clone(), add_carol.clone(), m2.clone()],
            Some(1),
            alice.did()
        ));

        // A slow clock put the commit that left epoch 1 behind a message sent
        // after it: holding a message at epoch 1 is not enough.
        assert!(
            !history_reaches(&[m1.clone(), m2.clone()], Some(1), alice.did()),
            "the commit at 1 is still missing"
        );

        // Not in the group yet: the welcome that adds us is what is needed.
        assert!(history_reaches(&tail, None, carol.did()));
        assert!(!history_reaches(&tail, None, bob.did()));
        assert!(history_reaches(
            std::slice::from_ref(&add_bob),
            None,
            bob.did()
        ));
        assert!(
            !history_reaches(&[add_bob, m2], None, bob.did()),
            "welcomed at 1, but the commit at 1 is missing"
        );
    }

    #[test]
    fn one_commit_at_a_time_per_channel_across_sessions() {
        let root = tempfile::tempdir().unwrap();
        let first = session(root.path());
        // A second process for the same DID: same directory, its own handles.
        let second = Session::open(root.path(), first.identity.duplicate()).unwrap();

        let held = first.commit_lock(SERVER, "#a").unwrap();
        assert!(second.try_commit_lock(SERVER, "#a").unwrap().is_none());
        assert!(
            second.try_commit_lock(SERVER, "#b").unwrap().is_some(),
            "another channel is not held up"
        );
        drop(held);
        assert!(second.try_commit_lock(SERVER, "#a").unwrap().is_some());
    }

    #[test]
    fn group_keys_ignore_scheme_spelling_but_not_server() {
        assert_eq!(
            group_key("ws://Host:7117/", "#a"),
            group_key("http://host:7117", "#a")
        );
        assert_ne!(group_key("http://a", "#x"), group_key("http://b", "#x"));
        assert_eq!(
            group_key("https://host:7117", "#a"),
            group_key("http://host:7117", "#a"),
            "a server that turns TLS on is the same server"
        );
    }

    /// Group mappings written while the scheme was part of the key are read
    /// back under today's key, so turning TLS on does not orphan a group.
    #[test]
    fn keys_written_with_a_scheme_are_rekeyed() {
        assert_eq!(
            rekey("http://host:7117|#a"),
            group_key("https://host:7117", "#a")
        );
        assert_eq!(rekey("wss://host|#dm/x|y"), "host|#dm/x|y");
        assert_eq!(rekey("host:7117|#a"), "host:7117|#a");
    }
}
