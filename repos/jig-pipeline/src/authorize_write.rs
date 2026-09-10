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

/// Kinds that carry content INTO a channel, as opposed to changing it.
fn is_content(kind: BlockKind) -> bool {
    matches!(
        kind,
        BlockKind::TextRender | BlockKind::EmailRender | BlockKind::EmailEncrypted
    )
}

/// Whether [`authorize_block`] will need to know if the sender is a member —
/// so the caller runs the membership query only when the answer can matter:
/// content, into a restricted channel.
pub fn needs_membership(kind: BlockKind, channel: Option<&StoredChannel>) -> bool {
    is_content(kind) && channel.is_some_and(|c| !is_open(&c.visibility))
}

/// Decide whether the block described by `manifest` may be applied to `channel`.
///
/// Rules:
/// - Content (`text-render` and the email kinds) into a **restricted** channel
///   is for members and the owner. Into an open channel, anyone.
/// - `member-add` where the sender adds **itself** to an **open** channel is
///   allowed — the IRC `/join`, and what `jig channel join` does.
/// - Every other `member-add` — anyone onto a restricted channel, or someone
///   else onto any channel — is the owner's call. Membership drives delivery
///   (fanout and bridge dispatch), so letting strangers enrol third parties
///   would let them subscribe anyone to anything.
/// - `channel-promote` (restricted → open) is the owner's call.
/// - Every other kind is not this gate's concern. `channel-archive` keeps its
///   own owner check in the effect layer; `channel-create` names a channel that
///   does not exist yet.
///
/// `channel` is `None` when the slug resolved to nothing; that is the effect
/// layer's error to raise, not an authorization decision, so it passes here.
/// `sender_is_member` is consulted only where [`needs_membership`] says it
/// matters; callers may pass `false` elsewhere.
pub fn authorize_block(
    kind: BlockKind,
    manifest: &BlockManifest,
    channel: Option<&StoredChannel>,
    sender_is_member: bool,
) -> Result<(), WriteRefusal> {
    let Some(channel) = channel else {
        return Ok(());
    };
    let sender = sender_did(manifest);

    match kind {
        BlockKind::MemberAdd => {
            let adding_self = manifest
                .metadata
                .get("member_did")
                .and_then(|v| v.as_str())
                .is_some_and(|member| member == sender);
            if adding_self && is_open(&channel.visibility) {
                return Ok(());
            }
            require_owner(channel, &sender)
        }
        BlockKind::ChannelPromote => require_owner(channel, &sender),
        kind if is_content(kind) => {
            if is_open(&channel.visibility) || is_owner(channel, &sender) || sender_is_member {
                Ok(())
            } else {
                Err(WriteRefusal::NotChannelMember {
                    slug: channel.slug.clone(),
                    sender,
                })
            }
        }
        _ => Ok(()),
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

fn sender_did(m: &BlockManifest) -> String {
    m.authors
        .first()
        .map(|a| a.did.to_string())
        .unwrap_or_default()
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
            authorize_block(BlockKind::MemberAdd, &m, Some(&channel("open")), false),
            Ok(())
        );
    }

    #[test]
    fn self_join_on_a_restricted_channel_is_refused() {
        let m = member_add(STRANGER, STRANGER);
        assert_eq!(
            authorize_block(
                BlockKind::MemberAdd,
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
            authorize_block(BlockKind::MemberAdd, &m, Some(&channel("open")), false),
            refused(STRANGER)
        );
    }

    #[test]
    fn the_owner_may_add_anyone_to_a_restricted_channel() {
        let m = member_add(OWNER, "did:jig:zFriend");
        assert_eq!(
            authorize_block(
                BlockKind::MemberAdd,
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
            authorize_block(BlockKind::MemberAdd, &m, Some(&channel("open")), false),
            refused(STRANGER)
        );
    }

    /// Fail closed on the visibility string, exactly as the read gate does.
    #[test]
    fn an_unrecognised_visibility_is_treated_as_restricted() {
        let m = member_add(STRANGER, STRANGER);
        assert_eq!(
            authorize_block(BlockKind::MemberAdd, &m, Some(&channel("Open")), false),
            refused(STRANGER)
        );
    }

    #[test]
    fn promote_is_owner_only() {
        let restricted = channel("restricted");
        assert_eq!(
            authorize_block(
                BlockKind::ChannelPromote,
                &promote(STRANGER),
                Some(&restricted),
                false
            ),
            refused(STRANGER)
        );
        assert_eq!(
            authorize_block(
                BlockKind::ChannelPromote,
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
        // The builder refuses an author-less manifest, but serde does not
        // (`authors` is `#[serde(default)]`), so one can arrive on the wire.
        let mut m = promote(STRANGER);
        m.authors.clear();
        assert!(authorize_block(BlockKind::ChannelPromote, &m, Some(&c), false).is_err());
    }

    #[test]
    fn an_unresolved_channel_is_not_this_gates_decision() {
        let m = member_add(STRANGER, STRANGER);
        assert_eq!(
            authorize_block(BlockKind::MemberAdd, &m, None, false),
            Ok(())
        );
    }

    #[test]
    fn kinds_outside_this_gate_pass_through() {
        let m = manifest_with(BlockKind::FedHello, STRANGER, json!({"channel": "#room"}));
        assert_eq!(
            authorize_block(BlockKind::FedHello, &m, Some(&channel("restricted")), false),
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
