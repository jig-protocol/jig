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
//! # Concurrency
//!
//! `jig chat` and `jig send` can run for the same DID at once. Every operation
//! takes an exclusive lock on the directory, loads the state, applies itself
//! and saves, so two processes never fork a group by each advancing a stale
//! copy of it. A commit spans several operations and a network round trip, so
//! it also holds a per-channel commit lock throughout ([`Session::commit_lock`]).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead as _, Write as _};
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
        let session = Self {
            identity,
            did,
            dir,
            read: Mutex::new(HashMap::new()),
        };
        session.reload_read()?;
        Ok(session)
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
        let path = self.dir.join("plaintext.jsonl");
        let _lock = self.lock()?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| SecureError::Io {
                path: path.clone(),
                source,
            })?;
        let line = serde_json::to_string(&Read {
            cid: cid.to_string(),
            sender: sender.to_string(),
            text: text.to_string(),
        })
        .expect("plaintext record serializes");
        writeln!(f, "{line}").map_err(|source| SecureError::Io { path, source })?;
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
            if block.manifest.content_suite() == EncryptionSuite::Mls {
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
                if block.manifest.content_suite() != EncryptionSuite::Mls {
                    return Ok(Seen::Plain);
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
        let path = self.dir.join("plaintext.jsonl");
        let Ok(f) = File::open(&path) else {
            return Ok(());
        };
        let mut read = self.read.lock().expect("plaintext cache poisoned");
        for line in std::io::BufReader::new(f).lines() {
            let line = line.map_err(|source| SecureError::Io {
                path: path.clone(),
                source,
            })?;
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
        let state_path = self.dir.join("state.bin");
        let groups_path = self.dir.join("groups.json");
        let member = match std::fs::read(&state_path) {
            Ok(bytes) => self.identity.restore_mls_member(&bytes)?,
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
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| SecureError::Io {
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
        write_atomic(&state_path, &member.snapshot())?;
        write_atomic(
            &groups_path,
            &serde_json::to_vec_pretty(&groups).expect("groups serialize"),
        )?;
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
    let tmp = path.with_extension("tmp");
    let io = |source| SecureError::Io {
        path: path.to_path_buf(),
        source,
    };
    std::fs::write(&tmp, bytes).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)
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
        let id = Identity::generate_and_save(&keys.keep()).unwrap();
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
        let bob_again = Session::open(
            root.path(),
            Identity::from_signing_key(ed25519_dalek::SigningKey::from_bytes(
                &bob.identity.signing_bytes_for_test(),
            )),
        )
        .unwrap();
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
        let second = Session::open(
            root.path(),
            Identity::from_signing_key(ed25519_dalek::SigningKey::from_bytes(
                &first.identity.signing_bytes_for_test(),
            )),
        )
        .unwrap();

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
