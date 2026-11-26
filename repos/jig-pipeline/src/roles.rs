//! Role-based channel authority (JEP-0005 rule 7b).
//!
//! A channel's authority is read from its `ingest` chain, not from a local
//! row that anyone could have edited out of order:
//!
//! - The **root owners** are the creator (the author of `channel-create`)
//!   and the co-owners its creation block lists. They hold the `owner` role,
//!   which carries every right, for the channel's life: nothing unassigns
//!   them.
//! - `role-assign` / `role-unassign` blocks give and take the one other role
//!   v0.2 defines, `admin`, which carries `share` and `membership`. Only an
//!   owner signs them, so admins cannot make admins.
//! - A signer's rights are those **as of the block's position**: the role
//!   blocks with an ingest-record `seq` strictly below it. A block an admin
//!   signed while it was an admin stays valid after the role is taken away;
//!   its next block does not.
//!
//! - A `key-link` block, authored by the new DID with a link whose audience
//!   is this channel, hands the old DID's standing (root or role) to the new
//!   DID from its `seq`, and leaves the old DID with nothing. The creator
//!   rule carries across the link.
//!
//! The position is the record `seq` the sequencer signed, never local
//! insertion order, so every carrier of the chain folds the same roles.

use jig_core::{BlockKind, BlockManifest};

use crate::persist::{SqliteStore, StoredChannel};

/// The metadata key a role block names its role under.
pub const ROLE_KEY: &str = "role";
/// The metadata key a role block names the DID it acts on under.
pub const MEMBER_KEY: &str = "member";

/// A role a `role-assign` can give. v0.2 defines one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// `share` and `membership`.
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
        }
    }

    /// The role a block's `role` field names; `None` for any other string,
    /// including `owner`, which only the creation block confers.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

/// One right a block can need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Right {
    /// Everything; held by the root owners alone. Archive, promote and the
    /// role blocks need it.
    Owner,
    /// Sharing the channel with another server (`channel-share`, a later
    /// slice).
    Share,
    /// Adding and removing members, and the commits those blocks carry.
    Membership,
}

impl Right {
    pub fn as_str(self) -> &'static str {
        match self {
            Right::Owner => "owner",
            Right::Share => "share",
            Right::Membership => "membership",
        }
    }
}

impl std::fmt::Display for Right {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a DID may do in a channel at one position of its chain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rights {
    pub owner: bool,
    pub share: bool,
    pub membership: bool,
}

impl Rights {
    /// No rights at all.
    pub const NONE: Rights = Rights {
        owner: false,
        share: false,
        membership: false,
    };
    /// The `owner` role: every right.
    pub const OWNER: Rights = Rights {
        owner: true,
        share: true,
        membership: true,
    };
    /// The `admin` role.
    pub const ADMIN: Rights = Rights {
        owner: false,
        share: true,
        membership: true,
    };

    /// The rights the channel's terms alone give `did`: every right for a
    /// root owner, none for anyone else. What [`rights_at`] starts its fold
    /// from, and the whole answer for a channel with no role blocks.
    pub fn of_root(channel: &StoredChannel, did: &str) -> Rights {
        if channel.is_root_owner(did) {
            Rights::OWNER
        } else {
            Rights::NONE
        }
    }

    pub fn has(&self, right: Right) -> bool {
        match right {
            Right::Owner => self.owner,
            Right::Share => self.share,
            Right::Membership => self.membership,
        }
    }
}

/// `did`'s rights in `channel_id` as of position `seq` of its ingest chain:
/// the channel's root owners, then every `role-assign` / `role-unassign` /
/// `key-link` whose record `seq` is strictly less than `seq`, in chain order.
///
/// `seq` is the position of the block being judged. For a block not yet
/// sequenced, pass [`NEXT`]: every stored role block is before it.
///
/// A channel this server holds no row for gives nobody any right. Role
/// blocks are folded as stored: each was checked when it was accepted
/// (only an owner signs one, and root owners are never its target), so the
/// fold does not re-judge them.
pub fn rights_at(
    store: &SqliteStore,
    channel_id: &str,
    did: &str,
    seq: u64,
) -> crate::persist::Result<Rights> {
    match store.get_channel_by_id_including_archived(channel_id)? {
        Some(channel) => rights_at_channel(store, &channel, did, seq),
        None => Ok(Rights::NONE),
    }
}

/// [`rights_at`] for a channel row the caller already holds.
pub fn rights_at_channel(
    store: &SqliteStore,
    channel: &StoredChannel,
    did: &str,
    seq: u64,
) -> crate::persist::Result<Rights> {
    Ok(fold(
        channel,
        did,
        store.list_role_blocks_before(&channel.id, seq)?,
    ))
}

/// What `did` holds in a channel at one position of its chain, as the role
/// and key-link blocks before it leave it ([`standing`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Standing {
    /// A root owner: the creator or a listed co-owner, or the DID one of
    /// them linked to (rule 7b: the creator rule carries across the link).
    pub root: bool,
    pub role: Option<Role>,
    /// The DID was linked away to another (rule 7b): it holds nothing here
    /// from the link on, whatever is assigned to it later.
    pub linked_away: bool,
}

impl Standing {
    pub fn rights(&self) -> Rights {
        match (self.root, self.role) {
            (true, _) => Rights::OWNER,
            (false, Some(Role::Admin)) => Rights::ADMIN,
            (false, None) => Rights::NONE,
        }
    }

    /// Whether the DID holds anything a key link could carry.
    pub fn holds_anything(&self) -> bool {
        self.root || self.role.is_some()
    }
}

/// Fold `blocks` (the channel's role and key-link blocks before some
/// position, in chain order) into `did`'s rights, starting from the channel's
/// terms. Shared by [`rights_at`] and the in-transaction check that lands a
/// block ([`crate::persist::RightGuard`]), so the two can never disagree.
pub fn fold(
    channel: &StoredChannel,
    did: &str,
    blocks: impl IntoIterator<Item = (BlockKind, BlockManifest)>,
) -> Rights {
    standing(channel, did, blocks).rights()
}

/// [`fold`], keeping what the DID holds rather than only its rights.
///
/// A `key-link` (rule 7b) hands the old DID's standing, root or role, to the
/// new DID, and leaves the old one with nothing. Role blocks that name a DID
/// already linked away are ignored: a retired key never regains a right.
pub fn standing(
    channel: &StoredChannel,
    did: &str,
    blocks: impl IntoIterator<Item = (BlockKind, BlockManifest)>,
) -> Standing {
    let mut held: std::collections::HashMap<String, Standing> = std::collections::HashMap::new();
    let mut links: Vec<(String, String)> = Vec::new();
    for (kind, manifest) in blocks {
        match kind {
            BlockKind::KeyLink => {
                let Some((old, new)) = key_link_of(&manifest, &channel.id) else {
                    continue;
                };
                links.push((old.clone(), new.clone()));
                let from = held.get(&old).copied().unwrap_or_default();
                if from.linked_away {
                    continue;
                }
                held.insert(new, from);
                held.insert(
                    old,
                    Standing {
                        linked_away: true,
                        ..Standing::default()
                    },
                );
            }
            BlockKind::RoleAssign | BlockKind::RoleUnassign => {
                let Some(target) = role_target(&manifest) else {
                    continue;
                };
                let entry = held.entry(target).or_default();
                if entry.linked_away {
                    continue;
                }
                match kind {
                    BlockKind::RoleAssign => entry.role = role_of(&manifest).or(entry.role),
                    _ if role_of(&manifest) == entry.role => entry.role = None,
                    _ => {}
                }
            }
            _ => {}
        }
    }
    let mut standing = held.get(did).copied().unwrap_or_default();
    // Root owners are read as every reader of the chain reads them.
    standing.root = jig_core::sequencer_move::is_root_owner(root_terms(channel), links, did);
    standing
}

/// The root owners the channel's creation block names: its creator, then
/// its co-owners. What [`jig_core::sequencer_move::root_owners`] carries
/// along the channel's key links.
pub fn root_terms(channel: &StoredChannel) -> Vec<String> {
    std::iter::once(channel.owner_did.clone())
        .filter(|d| !d.is_empty())
        .chain(channel.co_owners.iter().cloned())
        .collect()
}

/// [`standing`] at position `seq` of `channel`'s chain, read from `store`.
pub fn standing_at(
    store: &SqliteStore,
    channel: &StoredChannel,
    did: &str,
    seq: u64,
) -> crate::persist::Result<Standing> {
    Ok(standing(
        channel,
        did,
        store.list_role_blocks_before(&channel.id, seq)?,
    ))
}

/// The `(old, new)` DIDs, canonical, of a stored `key-link` block of
/// `channel_id`. It was checked when it was accepted
/// ([`jig_core::sequencer_move::KeyLinkBlock`]); one that no longer reads
/// moves nothing.
pub fn key_link_of(manifest: &BlockManifest, channel_id: &str) -> Option<(String, String)> {
    let author = manifest.authors.first()?.did.to_did_jig_string();
    let (old, new) =
        jig_core::sequencer_move::key_link_dids(&manifest.metadata, &author, channel_id)?;
    Some((
        crate::effect::canonical_did_string(&old),
        crate::effect::canonical_did_string(&new),
    ))
}

/// Whether a `key-link` by `author` may land in `channel` now (JEP-0005
/// rule 7b), with the reason it may not. The link must read for this
/// channel with `author` as its new DID; the old DID must hold something
/// here (a root, a role or membership) and not be linked away already; the
/// new DID must hold nothing yet, so a link never merges two standings.
///
/// An `mls` channel is refused before this check
/// ([`crate::ingest::IngestError::MlsKeyLinkUnsupported`]).
pub fn check_key_link(
    store: &SqliteStore,
    channel: &StoredChannel,
    manifest: &BlockManifest,
    author: &str,
) -> crate::persist::Result<Result<(), String>> {
    let block =
        match jig_core::sequencer_move::KeyLinkBlock::from_metadata(&manifest.metadata, author) {
            Ok(block) => block,
            Err(e) => return Ok(Err(e.to_string())),
        };
    if block.channel_id != channel.id {
        return Ok(Err("the link is for another channel".to_string()));
    }
    let canonical = crate::effect::canonical_did_string;
    let (old, new) = (
        canonical(&block.link.link().old),
        canonical(&block.link.link().new),
    );
    if old == new {
        return Ok(Err("the link leads nowhere".to_string()));
    }
    let blocks = store.list_role_blocks_before(&channel.id, NEXT)?;
    let was = standing(channel, &old, blocks.clone());
    let is = standing(channel, &new, blocks);
    if was.linked_away {
        return Ok(Err(format!("{old} was already linked to another key here")));
    }
    if !was.holds_anything() && !store.is_member_by_id(&channel.id, &old)? {
        return Ok(Err(format!("{old} holds nothing in this channel to link")));
    }
    if is.linked_away || is.holds_anything() || store.is_member_by_id(&channel.id, &new)? {
        return Ok(Err(format!("{new} already has a place in this channel")));
    }
    Ok(Ok(()))
}

/// The position after every block stored so far: what [`rights_at`] takes
/// for a block that has no record yet.
pub const NEXT: u64 = i64::MAX as u64;

/// The DID a role block acts on, canonical.
pub fn role_target(manifest: &BlockManifest) -> Option<String> {
    manifest
        .metadata
        .get(MEMBER_KEY)
        .and_then(|v| v.as_str())
        .map(crate::effect::canonical_did_string)
}

/// The role a role block names, if it is one v0.2 defines.
pub fn role_of(manifest: &BlockManifest) -> Option<Role> {
    manifest
        .metadata
        .get(ROLE_KEY)
        .and_then(|v| v.as_str())
        .and_then(Role::parse)
}
