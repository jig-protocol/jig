//! Gate 3 for writes: may this sender post to, or change, this channel?
//!
//! The read gate in `jig-server` decides from the memberships table. That is
//! only as strong as whatever decides who gets *into* the table, and
//! `member-add` is an ordinary signed block on the public submit path — so
//! this decision runs inside ingest, the one choke point every surface
//! (REST, WSS, admin, bridge) passes through. Content is gated for the same
//! reason in the other direction: a restricted channel whose members can be
//! messaged by anyone with a keypair is a private club with an open
//! letterbox.
//!
//! Pure on purpose, like its read-side counterpart: the channel row and the
//! sender's membership are resolved by the caller, so this is testable without
//! a store and cannot deadlock on one.

use jig_core::{BlockKind, BlockManifest};

use crate::persist::StoredChannel;
use crate::roles::{Right, Rights};
use crate::visibility::is_open;

/// Why a block was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteRefusal {
    /// The sender holds neither the owner role nor a role granting the right
    /// this change needs (`membership` for a member-add or member-remove;
    /// the owner role for promote and archive).
    NotChannelOwner { slug: String, sender: String },
    /// The sender is neither a member nor an owner of the restricted channel
    /// it tried to post to.
    NotChannelMember { slug: String, sender: String },
    /// A root owner tried to leave. A channel always has its owners; retiring
    /// it is `channel-archive`.
    OwnerCannotLeave { slug: String },
    /// The sender lacks `right` for a block that needs it: today a
    /// `role-assign` or `role-unassign` from anyone but an owner (JEP-0005
    /// rule 7b: only owners assign roles; admins cannot make admins).
    MissingRight {
        slug: String,
        sender: String,
        right: Right,
    },
    /// A role block named a root owner (the creator or a listed co-owner),
    /// whose role is fixed for the channel's life.
    RootOwnerRole { slug: String, member: String },
    /// A role block named a role v0.2 does not define (only `admin` can be
    /// assigned), or none.
    UnknownRole { role: String },
    /// A role block named no `member` DID.
    MissingRoleMember,
    /// A contract record (`contract-accept`, `contract-refuse`,
    /// `contract-end`) from anyone but the channel's sequencer: the server
    /// that took part in the contract is the only one that can record it.
    SequencerOnly { slug: String, sender: String },
    /// A share block or contract record whose metadata does not say what its
    /// kind needs, or whose envelopes do not check out.
    BadContractBlock { detail: String },
}

/// The membership facts a decision can turn on, resolved by the caller.
///
/// A bare `bool` converts to the sender's membership with no target — what
/// every kind but `member-remove` needs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Membership {
    /// The sender is a member of the channel.
    pub sender: bool,
    /// `member_did` (the member being removed) is a member of the channel.
    pub target: bool,
}

impl From<bool> for Membership {
    fn from(sender: bool) -> Self {
        Self {
            sender,
            target: false,
        }
    }
}

/// Kinds that CHANGE a channel, each with its own rule below. Every other
/// kind that names a channel is treated as content going INTO it — including
/// kinds this gate has never heard of. Enumerating content kinds instead
/// would leave any newly allowed kind (a fed-hello carrying `channel`, say)
/// free to land in a restricted timeline.
pub fn changes_the_channel(kind: BlockKind) -> bool {
    matches!(
        kind,
        BlockKind::MemberAdd
            | BlockKind::MemberRemove
            | BlockKind::ChannelPromote
            | BlockKind::ChannelCreate
            | BlockKind::ChannelArchive
            | BlockKind::RoleAssign
            | BlockKind::RoleUnassign
            | BlockKind::ChannelShare
            | BlockKind::ChannelUnshare
            | BlockKind::ContractAccept
            | BlockKind::ContractRefuse
            | BlockKind::ContractEnd
    )
}

/// Whether [`authorize_block`] will need to know who is a member — so the
/// caller runs the membership queries only when the answer can matter:
/// something going into a restricted channel, or any removal.
pub fn needs_membership(kind: BlockKind, channel: Option<&StoredChannel>) -> bool {
    channel.is_some()
        && (kind == BlockKind::MemberRemove
            || (!changes_the_channel(kind) && channel.is_some_and(|c| !is_open(&c.visibility))))
}

/// [`authorize_block_with`] with the rights the channel's terms alone give
/// the sender ([`Rights::of_root`]): a root owner holds every right, anyone
/// else none. Right for a channel with no role blocks; ingest, which can
/// read the chain, passes the folded rights instead.
pub fn authorize_block(
    kind: BlockKind,
    sender: &str,
    manifest: &BlockManifest,
    channel: Option<&StoredChannel>,
    membership: impl Into<Membership>,
) -> Result<(), WriteRefusal> {
    let rights = channel
        .map(|c| Rights::of_root(c, sender))
        .unwrap_or_default();
    authorize_block_with(kind, sender, manifest, channel, membership, rights)
}

/// Decide whether the block described by `manifest` may be applied to `channel`.
///
/// `rights` are the sender's rights as of this block's position in the
/// channel's ingest chain ([`crate::roles::rights_at`]). Rules:
/// - Anything going INTO a **restricted** channel — `text-render`, the email
///   kinds, and any other kind that names a channel — is for members and
///   owners. Into an open channel, anyone.
/// - `member-add` where the sender adds **itself** to an **open** channel is
///   allowed — the IRC `/join`, and what `jig channel join` does.
/// - Every other `member-add` — anyone onto a restricted channel, or someone
///   else onto any channel — needs the `membership` right (an owner or an
///   admin). Membership drives delivery (fanout and bridge dispatch), so
///   letting strangers enrol third parties would let them subscribe anyone
///   to anything.
/// - `channel-promote` (restricted → open) and `channel-archive` need the
///   owner role. The archive effect re-checks ownership itself; the check
///   here is what turns a stranger's attempt into a typed 403 rather than an
///   effect-layer 500.
/// - `role-assign` / `role-unassign` need the owner role (admins cannot make
///   admins), name a role v0.2 defines (`admin`), and never name a root
///   owner, whose role is fixed (JEP-0005 rule 7b).
/// - `channel-create` names a channel that does not exist yet; ingest
///   refuses a slug this server already sequences.
/// - `member-remove`: a member may remove **itself** (leave), except a root
///   owner, who archives instead. A holder of `membership` may remove anyone
///   else but a root owner. Nobody removes a root owner. On an encrypted
///   channel, any member may also remove someone who is **no longer** a
///   member: that block only carries the MLS commit dropping a departed
///   member's leaf, which the departed member cannot send themselves (RFC
///   9420 forbids committing your own removal).
///
/// `sender` must be the author DID the signature VERIFIED, in canonical form —
/// never the spelling the manifest carries, which is the author's choice and
/// decodes to the same key whatever its case. Rows are written canonical, so
/// comparing the manifest's spelling would lock an owner who wrote `zABC…`
/// out of changing their own channel.
///
/// `channel` is `None` when the slug resolved to nothing; that is the effect
/// layer's error to raise, not an authorization decision, so it passes here.
/// `sender_is_member` is consulted only where [`needs_membership`] says it
/// matters; callers may pass `false` elsewhere.
pub fn authorize_block_with(
    kind: BlockKind,
    sender: &str,
    manifest: &BlockManifest,
    channel: Option<&StoredChannel>,
    membership: impl Into<Membership>,
    rights: Rights,
) -> Result<(), WriteRefusal> {
    let Some(channel) = channel else {
        return Ok(());
    };
    let membership = membership.into();
    let sender_is_member = membership.sender;
    let sender = sender.to_string();
    let refuse = |sender: String| {
        Err(WriteRefusal::NotChannelOwner {
            slug: channel.slug.clone(),
            sender,
        })
    };

    match kind {
        BlockKind::MemberAdd => {
            let adding_self = manifest
                .metadata
                .get("member_did")
                .and_then(|v| v.as_str())
                .is_some_and(|member| crate::effect::canonical_did_string(member) == sender);
            if (adding_self && is_open(&channel.visibility)) || rights.membership {
                return Ok(());
            }
            refuse(sender)
        }
        BlockKind::MemberRemove => {
            let target = manifest
                .metadata
                .get("member_did")
                .and_then(|v| v.as_str())
                .map(crate::effect::canonical_did_string);
            // No `member_did` removes nobody; refuse rather than let the
            // effect layer fail on it.
            let Some(target) = target else {
                return refuse(sender);
            };
            if target == sender {
                if channel.is_root_owner(&sender) {
                    return Err(WriteRefusal::OwnerCannotLeave {
                        slug: channel.slug.clone(),
                    });
                }
                return if sender_is_member {
                    Ok(())
                } else {
                    Err(WriteRefusal::NotChannelMember {
                        slug: channel.slug.clone(),
                        sender,
                    })
                };
            }
            if channel.is_root_owner(&target) {
                return refuse(sender);
            }
            if rights.membership {
                return Ok(());
            }
            let tidy_up = !membership.target
                && sender_is_member
                && channel.suite == jig_core::EncryptionSuite::Mls.as_str();
            if tidy_up { Ok(()) } else { refuse(sender) }
        }
        BlockKind::ChannelPromote | BlockKind::ChannelArchive => {
            if rights.owner {
                Ok(())
            } else {
                refuse(sender)
            }
        }
        BlockKind::RoleAssign | BlockKind::RoleUnassign => {
            if !rights.owner {
                return Err(WriteRefusal::MissingRight {
                    slug: channel.slug.clone(),
                    sender,
                    right: Right::Owner,
                });
            }
            let role = manifest
                .metadata
                .get(crate::roles::ROLE_KEY)
                .and_then(|v| v.as_str());
            if role.and_then(crate::roles::Role::parse).is_none() {
                return Err(WriteRefusal::UnknownRole {
                    role: role.unwrap_or_default().to_string(),
                });
            }
            let Some(member) = crate::roles::role_target(manifest) else {
                return Err(WriteRefusal::MissingRoleMember);
            };
            if channel.is_root_owner(&member) {
                return Err(WriteRefusal::RootOwnerRole {
                    slug: channel.slug.clone(),
                    member,
                });
            }
            Ok(())
        }
        BlockKind::ChannelShare | BlockKind::ChannelUnshare => {
            if !rights.share {
                return Err(WriteRefusal::MissingRight {
                    slug: channel.slug.clone(),
                    sender,
                    right: Right::Share,
                });
            }
            crate::contracts::share_request(kind, manifest)
                .map(|_| ())
                .map_err(|e| WriteRefusal::BadContractBlock {
                    detail: e.to_string(),
                })
        }
        BlockKind::ContractAccept | BlockKind::ContractRefuse | BlockKind::ContractEnd => {
            let sequencer = crate::effect::canonical_did_string(&channel.sequencer_did);
            if sender != sequencer {
                return Err(WriteRefusal::SequencerOnly {
                    slug: channel.slug.clone(),
                    sender,
                });
            }
            let channel_id =
                channel
                    .id
                    .parse::<cid::Cid>()
                    .map_err(|e| WriteRefusal::BadContractBlock {
                        detail: format!("the channel's id is not a CID: {e}"),
                    })?;
            crate::contracts::check_record(kind, manifest, &channel_id, &sequencer).map_err(|e| {
                WriteRefusal::BadContractBlock {
                    detail: e.to_string(),
                }
            })
        }
        BlockKind::ChannelCreate => Ok(()),
        _ => {
            if is_open(&channel.visibility) || rights.owner || sender_is_member {
                Ok(())
            } else {
                Err(WriteRefusal::NotChannelMember {
                    slug: channel.slug.clone(),
                    sender,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::Author;
    use semver::Version;
    use serde_json::json;

    const OWNER: &str = "did:jig:zOwner";
    const STRANGER: &str = "did:jig:zStranger";

    fn channel(visibility: &str) -> StoredChannel {
        StoredChannel {
            id: "bafy-channel".to_string(),
            slug: "#room".to_string(),
            visibility: visibility.to_string(),
            created_at: 0,
            owner_did: OWNER.to_string(),
            suite: "none".to_string(),
            sequencer_did: String::new(),
            co_owners: Vec::new(),
        }
    }

    fn manifest_with(kind: BlockKind, sender: &str, metadata: serde_json::Value) -> BlockManifest {
        let mut builder = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: sender.into(),
                public_key: None,
                roles: vec![],
            });
        if let serde_json::Value::Object(map) = metadata {
            for (k, v) in map {
                builder = builder.metadata_entry(&k, v);
            }
        }
        builder.build().unwrap().with_kind(kind)
    }

    fn member_add(sender: &str, member: &str) -> BlockManifest {
        manifest_with(
            BlockKind::MemberAdd,
            sender,
            json!({"channel": "#room", "member_did": member}),
        )
    }

    fn promote(sender: &str) -> BlockManifest {
        manifest_with(
            BlockKind::ChannelPromote,
            sender,
            json!({"channel": "#room"}),
        )
    }

    /// The sender as the gate receives it: what the signature verified,
    /// which in these tests is the author the manifest was built with.
    fn sender_of(m: &BlockManifest) -> String {
        m.authors[0].did.to_string()
    }

    fn refused(sender: &str) -> Result<(), WriteRefusal> {
        Err(WriteRefusal::NotChannelOwner {
            slug: "#room".to_string(),
            sender: sender.to_string(),
        })
    }

    #[test]
    fn self_join_on_an_open_channel_is_allowed() {
        let m = member_add(STRANGER, STRANGER);
        assert_eq!(
            authorize_block(
                BlockKind::MemberAdd,
                &sender_of(&m),
                &m,
                Some(&channel("open")),
                false
            ),
            Ok(())
        );
    }

    #[test]
    fn self_join_on_a_restricted_channel_is_refused() {
        let m = member_add(STRANGER, STRANGER);
        assert_eq!(
            authorize_block(
                BlockKind::MemberAdd,
                &sender_of(&m),
                &m,
                Some(&channel("restricted")),
                false
            ),
            refused(STRANGER)
        );
    }

    #[test]
    fn a_stranger_cannot_add_someone_else_even_to_an_open_channel() {
        let m = member_add(STRANGER, "did:jig:zVictim");
        assert_eq!(
            authorize_block(
                BlockKind::MemberAdd,
                &sender_of(&m),
                &m,
                Some(&channel("open")),
                false
            ),
            refused(STRANGER)
        );
    }

    #[test]
    fn the_owner_may_add_anyone_to_a_restricted_channel() {
        let m = member_add(OWNER, "did:jig:zFriend");
        assert_eq!(
            authorize_block(
                BlockKind::MemberAdd,
                &sender_of(&m),
                &m,
                Some(&channel("restricted")),
                false
            ),
            Ok(())
        );
    }

    /// `member_did` is attacker-controlled. A block that omits it cannot be
    /// "adding itself", so it falls through to the owner check.
    #[test]
    fn a_member_add_with_no_member_did_is_not_a_self_join() {
        let m = manifest_with(BlockKind::MemberAdd, STRANGER, json!({"channel": "#room"}));
        assert_eq!(
            authorize_block(
                BlockKind::MemberAdd,
                &sender_of(&m),
                &m,
                Some(&channel("open")),
                false
            ),
            refused(STRANGER)
        );
    }

    /// Fail closed on the visibility string, exactly as the read gate does.
    #[test]
    fn an_unrecognised_visibility_is_treated_as_restricted() {
        let m = member_add(STRANGER, STRANGER);
        assert_eq!(
            authorize_block(
                BlockKind::MemberAdd,
                &sender_of(&m),
                &m,
                Some(&channel("Open")),
                false
            ),
            refused(STRANGER)
        );
    }

    #[test]
    fn promote_is_owner_only() {
        let restricted = channel("restricted");
        assert_eq!(
            authorize_block(
                BlockKind::ChannelPromote,
                STRANGER,
                &promote(STRANGER),
                Some(&restricted),
                false
            ),
            refused(STRANGER)
        );
        assert_eq!(
            authorize_block(
                BlockKind::ChannelPromote,
                OWNER,
                &promote(OWNER),
                Some(&restricted),
                false
            ),
            Ok(())
        );
    }

    fn member_remove(sender: &str, member: &str) -> BlockManifest {
        manifest_with(
            BlockKind::MemberRemove,
            sender,
            json!({"channel": "#room", "member_did": member}),
        )
    }

    fn remove(
        sender: &str,
        member: &str,
        chan: &StoredChannel,
        sender_is_member: bool,
        target_is_member: bool,
    ) -> Result<(), WriteRefusal> {
        authorize_block(
            BlockKind::MemberRemove,
            sender,
            &member_remove(sender, member),
            Some(chan),
            Membership {
                sender: sender_is_member,
                target: target_is_member,
            },
        )
    }

    const MEMBER: &str = "did:jig:zMember";
    const OTHER: &str = "did:jig:zOther";

    #[test]
    fn a_member_may_leave_but_a_stranger_cannot_leave_what_it_never_joined() {
        let c = channel("restricted");
        assert_eq!(remove(MEMBER, MEMBER, &c, true, true), Ok(()));
        assert_eq!(
            remove(STRANGER, STRANGER, &c, false, false),
            Err(WriteRefusal::NotChannelMember {
                slug: "#room".to_string(),
                sender: STRANGER.to_string()
            })
        );
    }

    #[test]
    fn the_owner_cannot_leave_or_be_removed() {
        let c = channel("open");
        assert_eq!(
            remove(OWNER, OWNER, &c, true, true),
            Err(WriteRefusal::OwnerCannotLeave {
                slug: "#room".to_string()
            })
        );
        assert_eq!(remove(MEMBER, OWNER, &c, true, true), refused(MEMBER));
    }

    #[test]
    fn only_the_owner_removes_a_member() {
        let c = channel("open");
        assert_eq!(remove(OWNER, MEMBER, &c, true, true), Ok(()));
        assert_eq!(remove(OTHER, MEMBER, &c, true, true), refused(OTHER));
        assert_eq!(remove(STRANGER, MEMBER, &c, false, true), refused(STRANGER));
    }

    /// On an encrypted channel a departed member's leaf has to be removed by
    /// someone still in the group; any member may send that commit. Never on
    /// an unencrypted channel, where there is nothing to tidy.
    #[test]
    fn any_member_may_tidy_up_a_departed_member_of_an_encrypted_channel() {
        let mut c = channel("restricted");
        assert_eq!(remove(OTHER, MEMBER, &c, true, false), refused(OTHER));
        c.suite = "mls".to_string();
        assert_eq!(remove(OTHER, MEMBER, &c, true, false), Ok(()));
        assert_eq!(
            remove(STRANGER, MEMBER, &c, false, false),
            refused(STRANGER),
            "a non-member cannot commit to the group"
        );
        assert_eq!(
            remove(OTHER, MEMBER, &c, true, true),
            refused(OTHER),
            "a current member is the owner's call"
        );
    }

    #[test]
    fn member_remove_needs_membership_facts_on_any_channel() {
        assert!(needs_membership(
            BlockKind::MemberRemove,
            Some(&channel("open"))
        ));
        assert!(!needs_membership(BlockKind::MemberRemove, None));
    }

    /// A channel row with no owner recorded must not match an author-less
    /// manifest: "we don't know who owns this" is not permission.
    #[test]
    fn an_empty_owner_did_grants_nobody() {
        let mut c = channel("restricted");
        c.owner_did.clear();
        // A verified sender is never empty (the signature needs a key), but
        // an owner_did column can be: it must match nobody, not "".
        let m = promote(STRANGER);
        assert!(authorize_block(BlockKind::ChannelPromote, "", &m, Some(&c), false).is_err());
        assert!(authorize_block(BlockKind::ChannelPromote, STRANGER, &m, Some(&c), false).is_err());
    }

    #[test]
    fn an_unresolved_channel_is_not_this_gates_decision() {
        let m = member_add(STRANGER, STRANGER);
        assert_eq!(
            authorize_block(BlockKind::MemberAdd, &sender_of(&m), &m, None, false),
            Ok(())
        );
    }

    /// A kind this gate has no special rule for is content as far as a
    /// restricted channel is concerned: the timeline it lands in is the
    /// members' timeline, whatever the kind is called.
    #[test]
    fn an_unlisted_kind_naming_a_restricted_channel_is_gated_as_content() {
        let m = manifest_with(BlockKind::FedHello, STRANGER, json!({"channel": "#room"}));
        assert_eq!(
            authorize_block(
                BlockKind::FedHello,
                &sender_of(&m),
                &m,
                Some(&channel("restricted")),
                false
            ),
            not_member(STRANGER)
        );
        assert_eq!(
            authorize_block(
                BlockKind::FedHello,
                &sender_of(&m),
                &m,
                Some(&channel("open")),
                false
            ),
            Ok(())
        );
        assert!(needs_membership(
            BlockKind::FedHello,
            Some(&channel("restricted"))
        ));
    }

    #[test]
    fn archive_is_owner_only_at_the_gate_too() {
        let m = manifest_with(
            BlockKind::ChannelArchive,
            STRANGER,
            json!({"channel": "#room"}),
        );
        assert_eq!(
            authorize_block(
                BlockKind::ChannelArchive,
                &sender_of(&m),
                &m,
                Some(&channel("open")),
                false
            ),
            refused(STRANGER)
        );
        let m = manifest_with(
            BlockKind::ChannelArchive,
            OWNER,
            json!({"channel": "#room"}),
        );
        assert_eq!(
            authorize_block(
                BlockKind::ChannelArchive,
                &sender_of(&m),
                &m,
                Some(&channel("open")),
                false
            ),
            Ok(())
        );
    }

    // ---- roles (JEP-0005 rule 7b) ----------------------------------------

    const ADMIN: &str = "did:jig:zAdmin";
    const CO_OWNER: &str = "did:jig:zCoOwner";

    fn role_block(kind: BlockKind, sender: &str, role: &str, member: &str) -> BlockManifest {
        manifest_with(
            kind,
            sender,
            json!({"channel": "#room", "role": role, "member": member}),
        )
    }

    fn with_co_owner(visibility: &str) -> StoredChannel {
        let mut c = channel(visibility);
        c.co_owners = vec![CO_OWNER.to_string()];
        c
    }

    #[test]
    fn an_admin_may_add_and_remove_members() {
        let c = channel("restricted");
        let add = member_add(ADMIN, "did:jig:zFriend");
        assert_eq!(
            authorize_block_with(
                BlockKind::MemberAdd,
                ADMIN,
                &add,
                Some(&c),
                false,
                Rights::ADMIN
            ),
            Ok(())
        );
        let rm = member_remove(ADMIN, MEMBER);
        assert_eq!(
            authorize_block_with(
                BlockKind::MemberRemove,
                ADMIN,
                &rm,
                Some(&c),
                Membership {
                    sender: true,
                    target: true
                },
                Rights::ADMIN
            ),
            Ok(())
        );
        assert_eq!(
            authorize_block_with(
                BlockKind::MemberAdd,
                ADMIN,
                &add,
                Some(&c),
                false,
                Rights::NONE
            ),
            refused(ADMIN),
            "without the role, the same block is refused"
        );
    }

    #[test]
    fn an_admin_may_not_promote_archive_or_remove_an_owner() {
        let c = with_co_owner("restricted");
        for kind in [BlockKind::ChannelPromote, BlockKind::ChannelArchive] {
            let m = manifest_with(kind, ADMIN, json!({"channel": "#room"}));
            assert_eq!(
                authorize_block_with(kind, ADMIN, &m, Some(&c), false, Rights::ADMIN),
                refused(ADMIN),
                "{kind:?} is owner-only"
            );
        }
        for owner in [OWNER, CO_OWNER] {
            let rm = member_remove(ADMIN, owner);
            assert_eq!(
                authorize_block_with(
                    BlockKind::MemberRemove,
                    ADMIN,
                    &rm,
                    Some(&c),
                    Membership {
                        sender: true,
                        target: true
                    },
                    Rights::ADMIN
                ),
                refused(ADMIN)
            );
        }
    }

    #[test]
    fn only_owners_assign_roles() {
        let c = channel("open");
        for kind in [BlockKind::RoleAssign, BlockKind::RoleUnassign] {
            let by_admin = role_block(kind, ADMIN, "admin", MEMBER);
            assert_eq!(
                authorize_block_with(kind, ADMIN, &by_admin, Some(&c), false, Rights::ADMIN),
                Err(WriteRefusal::MissingRight {
                    slug: "#room".to_string(),
                    sender: ADMIN.to_string(),
                    right: Right::Owner,
                }),
                "admins cannot make or unmake admins"
            );
            let by_owner = role_block(kind, OWNER, "admin", MEMBER);
            assert_eq!(
                authorize_block(kind, OWNER, &by_owner, Some(&c), false),
                Ok(())
            );
        }
    }

    #[test]
    fn a_co_owner_holds_every_right_from_the_terms_alone() {
        let c = with_co_owner("restricted");
        let assign = role_block(BlockKind::RoleAssign, CO_OWNER, "admin", MEMBER);
        assert_eq!(
            authorize_block(BlockKind::RoleAssign, CO_OWNER, &assign, Some(&c), false),
            Ok(())
        );
        let archive = manifest_with(
            BlockKind::ChannelArchive,
            CO_OWNER,
            json!({"channel": "#room"}),
        );
        assert_eq!(
            authorize_block(
                BlockKind::ChannelArchive,
                CO_OWNER,
                &archive,
                Some(&c),
                false
            ),
            Ok(())
        );
        assert_eq!(
            remove(CO_OWNER, CO_OWNER, &c, true, true),
            Err(WriteRefusal::OwnerCannotLeave {
                slug: "#room".to_string()
            }),
            "a co-owner is a root owner and cannot leave"
        );
    }

    #[test]
    fn the_creator_and_a_co_owner_cannot_be_unassigned() {
        let c = with_co_owner("open");
        for kind in [BlockKind::RoleUnassign, BlockKind::RoleAssign] {
            for root in [OWNER, CO_OWNER] {
                let m = role_block(kind, OWNER, "admin", root);
                assert_eq!(
                    authorize_block(kind, OWNER, &m, Some(&c), false),
                    Err(WriteRefusal::RootOwnerRole {
                        slug: "#room".to_string(),
                        member: root.to_string(),
                    }),
                    "{kind:?} naming root owner {root}"
                );
            }
        }
    }

    #[test]
    fn a_role_block_names_a_defined_role_and_a_member() {
        let c = channel("open");
        let owner_role = role_block(BlockKind::RoleAssign, OWNER, "owner", MEMBER);
        assert_eq!(
            authorize_block(BlockKind::RoleAssign, OWNER, &owner_role, Some(&c), false),
            Err(WriteRefusal::UnknownRole {
                role: "owner".to_string()
            }),
            "owner is conferred by the creation block only"
        );
        let no_member = manifest_with(
            BlockKind::RoleAssign,
            OWNER,
            json!({"channel": "#room", "role": "admin"}),
        );
        assert_eq!(
            authorize_block(BlockKind::RoleAssign, OWNER, &no_member, Some(&c), false),
            Err(WriteRefusal::MissingRoleMember)
        );
        assert!(changes_the_channel(BlockKind::RoleAssign));
        assert!(!needs_membership(
            BlockKind::RoleAssign,
            Some(&channel("restricted"))
        ));
    }

    // ---- content ----------------------------------------------------------

    fn post(sender: &str) -> BlockManifest {
        manifest_with(
            BlockKind::TextRender,
            sender,
            json!({"channel": "#room", "body": "hi"}),
        )
    }

    fn not_member(sender: &str) -> Result<(), WriteRefusal> {
        Err(WriteRefusal::NotChannelMember {
            slug: "#room".to_string(),
            sender: sender.to_string(),
        })
    }

    #[test]
    fn anyone_may_post_to_an_open_channel() {
        assert_eq!(
            authorize_block(
                BlockKind::TextRender,
                STRANGER,
                &post(STRANGER),
                Some(&channel("open")),
                false
            ),
            Ok(())
        );
    }

    #[test]
    fn a_stranger_may_not_post_to_a_restricted_channel() {
        assert_eq!(
            authorize_block(
                BlockKind::TextRender,
                STRANGER,
                &post(STRANGER),
                Some(&channel("restricted")),
                false
            ),
            not_member(STRANGER)
        );
    }

    #[test]
    fn members_and_the_owner_may_post_to_a_restricted_channel() {
        let restricted = channel("restricted");
        assert_eq!(
            authorize_block(
                BlockKind::TextRender,
                OWNER,
                &post(OWNER),
                Some(&restricted),
                false
            ),
            Ok(()),
            "the owner needs no membership row"
        );
        assert_eq!(
            authorize_block(
                BlockKind::TextRender,
                STRANGER,
                &post(STRANGER),
                Some(&restricted),
                true
            ),
            Ok(()),
            "a member may post"
        );
    }

    /// The membership query is the only I/O this gate ever asks for; it must
    /// be asked for exactly when the answer can change the decision.
    #[test]
    fn membership_is_needed_only_for_content_into_restricted_channels() {
        let restricted = channel("restricted");
        let open = channel("open");
        assert!(needs_membership(BlockKind::TextRender, Some(&restricted)));
        assert!(needs_membership(BlockKind::EmailRender, Some(&restricted)));
        assert!(!needs_membership(BlockKind::TextRender, Some(&open)));
        assert!(!needs_membership(BlockKind::MemberAdd, Some(&restricted)));
        assert!(!needs_membership(BlockKind::TextRender, None));
        // Unknown visibility is restricted here too, so the lookup happens.
        assert!(needs_membership(
            BlockKind::TextRender,
            Some(&channel("Open"))
        ));
    }

    #[test]
    fn sharing_needs_the_share_right() {
        use crate::roles::Rights;
        let to = crate::contracts::tests::did(&crate::contracts::tests::parties().follower);
        let share = manifest_with(
            BlockKind::ChannelShare,
            STRANGER,
            json!({"channel": "#room", "to": to, "grant": "write"}),
        );
        let unshare = manifest_with(
            BlockKind::ChannelUnshare,
            STRANGER,
            json!({"channel": "#room", "to": to}),
        );
        assert!(changes_the_channel(BlockKind::ChannelShare));
        for m in [&share, &unshare] {
            let kind = m.kind.unwrap();
            let gate = |rights| {
                authorize_block_with(kind, STRANGER, m, Some(&channel("open")), true, rights)
            };
            assert_eq!(
                gate(Rights::NONE),
                Err(WriteRefusal::MissingRight {
                    slug: "#room".into(),
                    sender: STRANGER.into(),
                    right: Right::Share,
                }),
                "a member without the right, even on an open channel: {kind:?}"
            );
            assert_eq!(gate(Rights::ADMIN), Ok(()), "{kind:?}");
            assert_eq!(gate(Rights::OWNER), Ok(()), "{kind:?}");
        }
        // The right is checked before the metadata, so a stranger learns
        // nothing from a malformed share.
        let no_grant = manifest_with(
            BlockKind::ChannelShare,
            OWNER,
            json!({"channel": "#room", "to": to}),
        );
        assert!(matches!(
            authorize_block_with(
                BlockKind::ChannelShare,
                OWNER,
                &no_grant,
                Some(&channel("open")),
                true,
                Rights::OWNER
            ),
            Err(WriteRefusal::BadContractBlock { .. })
        ));
    }

    #[test]
    fn only_the_sequencer_records_a_contract() {
        use crate::contracts::tests::{accept_record, did, parties};
        use crate::roles::Rights;
        let p = parties();
        let sequencer = did(&p.owner);
        let mut ch = channel("restricted");
        ch.id = p.channel_id.to_string();
        ch.sequencer_did = sequencer.clone();
        let record = accept_record(&p);
        // The sequencer, signing the records it took part in.
        assert_eq!(
            authorize_block_with(
                BlockKind::ContractAccept,
                &sequencer,
                &record,
                Some(&ch),
                false,
                Rights::NONE
            ),
            Ok(())
        );
        // Anyone else, the channel's owner included, whatever its rights.
        for sender in [OWNER, STRANGER] {
            assert_eq!(
                authorize_block_with(
                    BlockKind::ContractAccept,
                    sender,
                    &record,
                    Some(&ch),
                    true,
                    Rights::OWNER
                ),
                Err(WriteRefusal::SequencerOnly {
                    slug: "#room".into(),
                    sender: sender.into(),
                })
            );
        }
        // Signed messages for another channel.
        ch.id = jig_core::canonical_cid::of(b"elsewhere").to_string();
        assert!(matches!(
            authorize_block_with(
                BlockKind::ContractAccept,
                &sequencer,
                &record,
                Some(&ch),
                false,
                Rights::NONE
            ),
            Err(WriteRefusal::BadContractBlock { .. })
        ));
    }
}
