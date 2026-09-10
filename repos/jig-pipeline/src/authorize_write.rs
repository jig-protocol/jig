//! Gate 3 for control-plane writes: may this sender change this channel?
//!
//! The read gate in `jig-server` decides from the memberships table. That is
//! only as strong as whatever decides who gets *into* the table, and
//! `member-add` is an ordinary signed block on the public submit path — so
//! this decision runs inside ingest, the one choke point every surface
//! (REST, WSS, admin, bridge) passes through.
//!
//! Pure on purpose, like its read-side counterpart: the channel row is
//! resolved by the caller, so this is testable without a store and cannot
//! deadlock on one.

use jig_core::{BlockKind, BlockManifest};

use crate::persist::StoredChannel;

/// Why a control-plane block was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteRefusal {
    /// The sender is not `channels.owner_did` for the channel it tried to change.
    NotChannelOwner { slug: String, sender: String },
}

/// Decide whether the block described by `manifest` may be applied to `channel`.
///
/// Rules:
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
pub fn authorize_control_block(
    kind: BlockKind,
    manifest: &BlockManifest,
    channel: Option<&StoredChannel>,
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
        _ => Ok(()),
    }
}

/// Whether a stored visibility string means "open", **failing closed**: any
/// value that is not exactly `open` is treated as restricted. Must agree with
/// `jig_server::auth::Visibility::parse`; the server carries a test that holds
/// the two to the same answers.
pub fn is_open(visibility: &str) -> bool {
    visibility == "open"
}

fn require_owner(channel: &StoredChannel, sender: &str) -> Result<(), WriteRefusal> {
    // An empty owner_did would match an author-less manifest. Refuse rather
    // than treat "we don't know who owns this" as permission — the same
    // reasoning as the archive check.
    if channel.owner_did.is_empty() || channel.owner_did != sender {
        return Err(WriteRefusal::NotChannelOwner {
            slug: channel.slug.clone(),
            sender: sender.to_string(),
        });
    }
    Ok(())
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
            authorize_control_block(BlockKind::MemberAdd, &m, Some(&channel("open"))),
            Ok(())
        );
    }

    #[test]
    fn self_join_on_a_restricted_channel_is_refused() {
        let m = member_add(STRANGER, STRANGER);
        assert_eq!(
            authorize_control_block(BlockKind::MemberAdd, &m, Some(&channel("restricted"))),
            refused(STRANGER)
        );
    }

    #[test]
    fn a_stranger_cannot_add_someone_else_even_to_an_open_channel() {
        let m = member_add(STRANGER, "did:jig:zVictim");
        assert_eq!(
            authorize_control_block(BlockKind::MemberAdd, &m, Some(&channel("open"))),
            refused(STRANGER)
        );
    }

    #[test]
    fn the_owner_may_add_anyone_to_a_restricted_channel() {
        let m = member_add(OWNER, "did:jig:zFriend");
        assert_eq!(
            authorize_control_block(BlockKind::MemberAdd, &m, Some(&channel("restricted"))),
            Ok(())
        );
    }

    /// `member_did` is attacker-controlled. A block that omits it cannot be
    /// "adding itself", so it falls through to the owner check.
    #[test]
    fn a_member_add_with_no_member_did_is_not_a_self_join() {
        let m = manifest_with(BlockKind::MemberAdd, STRANGER, json!({"channel": "#room"}));
        assert_eq!(
            authorize_control_block(BlockKind::MemberAdd, &m, Some(&channel("open"))),
            refused(STRANGER)
        );
    }

    /// Fail closed on the visibility string, exactly as the read gate does.
    #[test]
    fn an_unrecognised_visibility_is_treated_as_restricted() {
        let m = member_add(STRANGER, STRANGER);
        assert_eq!(
            authorize_control_block(BlockKind::MemberAdd, &m, Some(&channel("Open"))),
            refused(STRANGER)
        );
    }

    #[test]
    fn promote_is_owner_only() {
        let restricted = channel("restricted");
        assert_eq!(
            authorize_control_block(
                BlockKind::ChannelPromote,
                &promote(STRANGER),
                Some(&restricted)
            ),
            refused(STRANGER)
        );
        assert_eq!(
            authorize_control_block(
                BlockKind::ChannelPromote,
                &promote(OWNER),
                Some(&restricted)
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
        assert!(authorize_control_block(BlockKind::ChannelPromote, &m, Some(&c)).is_err());
    }

    #[test]
    fn an_unresolved_channel_is_not_this_gates_decision() {
        let m = member_add(STRANGER, STRANGER);
        assert_eq!(
            authorize_control_block(BlockKind::MemberAdd, &m, None),
            Ok(())
        );
    }

    #[test]
    fn kinds_outside_the_control_plane_pass_through() {
        let m = member_add(STRANGER, STRANGER);
        assert_eq!(
            authorize_control_block(BlockKind::TextRender, &m, Some(&channel("restricted"))),
            Ok(())
        );
    }
}
