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
/// the channel's root owners, then every `role-assign` / `role-unassign`
/// whose record `seq` is strictly less than `seq`, in chain order.
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
    let root = Rights::of_root(channel, did);
    if root.owner {
        return Ok(root);
    }
    let mut role: Option<Role> = None;
    for (kind, manifest) in store.list_role_blocks_before(&channel.id, seq)? {
        let Some(target) = role_target(&manifest) else {
            continue;
        };
        if target != did {
            continue;
        }
        match kind {
            BlockKind::RoleAssign => role = role_of(&manifest).or(role),
            BlockKind::RoleUnassign if role_of(&manifest) == role => role = None,
            _ => {}
        }
    }
    Ok(match role {
        Some(Role::Admin) => Rights::ADMIN,
        None => Rights::NONE,
    })
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
