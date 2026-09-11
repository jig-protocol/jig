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
use crate::visibility::is_open;

/// Why a block was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteRefusal {
    /// The sender is not `channels.owner_did` for the channel it tried to change.
    NotChannelOwner { slug: String, sender: String },
    /// The sender is neither a member nor the owner of the restricted channel
    /// it tried to post to.
    NotChannelMember { slug: String, sender: String },
}

/// Kinds that CHANGE a channel, each with its own rule below. Every other
/// kind that names a channel is treated as content going INTO it — including
/// kinds this gate has never heard of. Enumerating content kinds instead
/// would leave any newly allowed kind (a fed-hello carrying `channel`, say)
/// free to land in a restricted timeline.
fn changes_the_channel(kind: BlockKind) -> bool {
    matches!(
        kind,
        BlockKind::MemberAdd
            | BlockKind::ChannelPromote
            | BlockKind::ChannelCreate
            | BlockKind::ChannelArchive
    )
}

/// Whether [`authorize_block`] will need to know if the sender is a member —
/// so the caller runs the membership query only when the answer can matter:
/// something going into a restricted channel.
pub fn needs_membership(kind: BlockKind, channel: Option<&StoredChannel>) -> bool {
    !changes_the_channel(kind) && channel.is_some_and(|c| !is_open(&c.visibility))
}

/// Decide whether the block described by `manifest` may be applied to `channel`.
///
/// Rules:
/// - Anything going INTO a **restricted** channel — `text-render`, the email
///   kinds, and any other kind that names a channel — is for members and the
///   owner. Into an open channel, anyone.
/// - `member-add` where the sender adds **itself** to an **open** channel is
///   allowed — the IRC `/join`, and what `jig channel join` does.
/// - Every other `member-add` — anyone onto a restricted channel, or someone
///   else onto any channel — is the owner's call. Membership drives delivery
///   (fanout and bridge dispatch), so letting strangers enrol third parties
///   would let them subscribe anyone to anything.
/// - `channel-promote` (restricted → open) and `channel-archive` are the
///   owner's call. The archive effect re-checks ownership itself; the check
///   here is what turns a stranger's attempt into a typed 403 rather than an
///   effect-layer 500.
/// - `channel-create` names a channel that does not exist yet; the store's
///   unique slug refuses a duplicate.
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
pub fn authorize_block(
    kind: BlockKind,
    sender: &str,
    manifest: &BlockManifest,
    channel: Option<&StoredChannel>,
    sender_is_member: bool,
) -> Result<(), WriteRefusal> {
    let Some(channel) = channel else {
        return Ok(());
    };
    let sender = sender.to_string();

    match kind {
        BlockKind::MemberAdd => {
            let adding_self = manifest
                .metadata
                .get("member_did")
                .and_then(|v| v.as_str())
                .is_some_and(|member| crate::effect::canonical_did_string(member) == sender);
            if adding_self && is_open(&channel.visibility) {
                return Ok(());
            }
            require_owner(channel, &sender)
        }
        BlockKind::ChannelPromote | BlockKind::ChannelArchive => require_owner(channel, &sender),
        BlockKind::ChannelCreate => Ok(()),
        _ => {
            if is_open(&channel.visibility) || is_owner(channel, &sender) || sender_is_member {
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

/// An empty `owner_did` would match an author-less manifest. It matches
/// nobody: "we don't know who owns this" is not permission — the same
/// reasoning as the archive check.
fn is_owner(channel: &StoredChannel, sender: &str) -> bool {
    !channel.owner_did.is_empty() && channel.owner_did == sender
}

fn require_owner(channel: &StoredChannel, sender: &str) -> Result<(), WriteRefusal> {
    if is_owner(channel, sender) {
        Ok(())
    } else {
        Err(WriteRefusal::NotChannelOwner {
            slug: channel.slug.clone(),
            sender: sender.to_string(),
        })
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
}
