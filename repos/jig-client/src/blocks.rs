//! Block bundle builders for the canonical v0.0.2 block kinds.
//!
//! Used by `jig-cli` and the email bridge — anywhere
//! a signed block needs to be constructed before submission. Each helper
//! returns a `(manifest_bytes, code_bytes)` pair plus the signed sig over
//! canonical bytes. Callers can submit via WSS or REST as appropriate.

use jig_core::{Author, BlockKind, BlockManifest, HlcTimestamp};
use serde_json::{Value, json};

use crate::identity::Identity;

/// A built + signed bundle ready for submission. The `manifest_bytes` and
/// `code_bytes` fields can be wrapped into a `jig_core::BlockBundle` at the
/// call site (BlockBundle has lifetime borrows so we don't construct it here).
#[derive(Debug, Clone)]
pub struct BuiltBlock {
    pub manifest_bytes: Vec<u8>,
    pub code_bytes: Vec<u8>,
    pub sender_sig: Vec<u8>,
}

impl BuiltBlock {
    /// Concatenated canonical bytes used for signature verification on the
    /// server side. Must match `jig-pipeline::ingest::bundle_canonical_bytes`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let payload = (self.manifest_bytes.clone(), self.code_bytes.clone());
        serde_json::to_vec(&payload).expect("canonical bytes serialize")
    }
}

/// Build a signed `text-render` block: the v0.0.2 chat-message block.
/// Channel slug carried via metadata key `"channel"`; body via `"body"`.
pub fn build_text_render(
    sender: &Identity,
    channel_slug: &str,
    body: &str,
    hlc: HlcTimestamp,
) -> BuiltBlock {
    build_text_render_with_nickname(sender, channel_slug, body, None, hlc)
}

/// Same as [`build_text_render`], plus an optional `nickname` metadata entry.
///
/// ⚠️ DANGER — passing `Some(..)` ACTIVATES SERVER-SIDE TOFU ENFORCEMENT.
/// The server's identity check is currently dormant *by absence*:
/// jig-pipeline's `ingest()` only calls `ctx.identity.verify(..)` when the
/// `nickname` metadata key is present. So this argument is not cosmetic — it
/// is the trigger. Any caller that starts sending `Some(..)` silently opts
/// the whole channel into trust-on-first-use binding of nickname → DID, which
/// can produce hard `IDENTITY_ERROR`s in ordinary situations: e.g. one human
/// on two machines mints two DIDs, and the second one is rejected under the
/// nickname the first one claimed.
///
/// NOTHING SHOULD CALL THIS WITH `Some` YET. It exists so that a future lane
/// can opt in deliberately, with the TOFU story (key sync / rebinding /
/// recovery) designed first. Until then, use [`build_text_render`].
///
/// (A server may soften this with `identity.naively_allow_unknown_handles_
/// fallback = true`, which downgrades rejection to a warning — but that is an
/// unsafe v0.0.x carve-out and must not be assumed on the receiving side.)
pub fn build_text_render_with_nickname(
    sender: &Identity,
    channel_slug: &str,
    body: &str,
    nickname: Option<&str>,
    hlc: HlcTimestamp,
) -> BuiltBlock {
    let mut meta = json!({
        "channel": channel_slug,
        "body": body,
    });
    if let Some(n) = nickname {
        meta["nickname"] = json!(n);
    }
    build_with_metadata(sender, BlockKind::TextRender, hlc, meta)
}

/// Build a signed `channel-create` block. v0.0.2 sends this through the
/// `/api/v1/channels` REST endpoint. v0.0.3 makes
/// channel-create a real Wasm block submitted via `submit`.
pub fn build_channel_create(
    sender: &Identity,
    slug: &str,
    visibility: &str,
    hlc: HlcTimestamp,
) -> BuiltBlock {
    build_with_metadata(
        sender,
        BlockKind::ChannelCreate,
        hlc,
        json!({
            "slug": slug,
            "visibility": visibility,
        }),
    )
}

/// Build a signed `member-add` block.
pub fn build_member_add(
    sender: &Identity,
    channel_slug: &str,
    member_did: &str,
    hlc: HlcTimestamp,
) -> BuiltBlock {
    build_with_metadata(
        sender,
        BlockKind::MemberAdd,
        hlc,
        json!({
            "channel": channel_slug,
            "member_did": member_did,
        }),
    )
}

/// Build a signed `channel-archive` block — the v0.0.2 channel delete.
///
/// Archiving is a soft delete: the server hides the channel but keeps every
/// block and receipt. Only the channel's owner DID can archive it, enforced
/// server-side against `channels.owner_did`.
pub fn build_channel_archive(
    sender: &Identity,
    channel_slug: &str,
    hlc: HlcTimestamp,
) -> BuiltBlock {
    build_with_metadata(
        sender,
        BlockKind::ChannelArchive,
        hlc,
        json!({ "channel": channel_slug }),
    )
}

/// Build a signed `fed-hello` block — emitted by jig-server when initiating
/// a federation handshake. Sender is the server's own identity.
pub fn build_fed_hello(
    sender: &Identity,
    server_url: &str,
    alias: Option<&str>,
    hlc: HlcTimestamp,
) -> BuiltBlock {
    let mut meta = json!({"server_url": server_url});
    if let Some(a) = alias {
        meta["alias"] = json!(a);
    }
    build_with_metadata(sender, BlockKind::FedHello, hlc, meta)
}

/// Build and sign a block of any `kind` with arbitrary metadata.
///
/// The typed builders above are thin wrappers over this. Public so tests can
/// build exactly the shapes a hostile client would — the server must not
/// depend on clients using the typed builders.
pub fn build_with_metadata(
    sender: &Identity,
    kind: BlockKind,
    hlc: HlcTimestamp,
    metadata: Value,
) -> BuiltBlock {
    let mut builder = BlockManifest::builder()
        .version(semver::Version::new(0, 1, 0))
        .author(Author {
            did: sender.did().clone(),
            public_key: None,
            roles: vec![],
        });
    if let Value::Object(map) = metadata {
        for (k, v) in map {
            builder = builder.metadata_entry(&k, v);
        }
    }
    let manifest = builder
        .build()
        .expect("manifest builds")
        .with_kind(kind)
        .with_hlc(hlc);
    let manifest_bytes = manifest.to_canonical_bytes().expect("canonical bytes");
    // v0.0.2: no per-block Wasm; canonical wasm artifact bundled separately
    let code_bytes: Vec<u8> = vec![];
    let payload = (manifest_bytes.clone(), code_bytes.clone());
    let canonical = serde_json::to_vec(&payload).expect("payload serialize");
    let sig = sender.sign(&canonical).to_bytes().to_vec();
    BuiltBlock {
        manifest_bytes,
        code_bytes,
        sender_sig: sig,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use jig_core::Did;
    use tempfile::tempdir;

    fn test_identity() -> Identity {
        let dir = tempdir().unwrap();
        // Keep the tempdir on disk so the keyfile survives — tests only.
        let dir_path = dir.keep();
        Identity::generate_and_save(&dir_path).unwrap()
    }

    fn test_hlc(id: &Identity) -> HlcTimestamp {
        HlcTimestamp {
            wall_ms: 1_747_680_000_000,
            logical: 0,
            server_did: id.did().clone(),
        }
    }

    #[test]
    fn build_text_render_carries_kind_and_channel_metadata() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);
        let manifest: BlockManifest = serde_json::from_slice(&block.manifest_bytes).unwrap();
        assert_eq!(manifest.kind, Some(BlockKind::TextRender));
        assert_eq!(
            manifest.metadata.get("channel").and_then(|v| v.as_str()),
            Some("#hello")
        );
        assert_eq!(
            manifest.metadata.get("body").and_then(|v| v.as_str()),
            Some("hi")
        );
    }

    /// The dormant-identity-check contract: plain `build_text_render` must
    /// never emit a `nickname` key, or every existing caller would silently
    /// switch on server-side TOFU enforcement.
    #[test]
    fn build_text_render_never_sets_nickname_metadata() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);
        let manifest: BlockManifest = serde_json::from_slice(&block.manifest_bytes).unwrap();
        assert!(!manifest.metadata.contains_key("nickname"));
    }

    #[test]
    fn build_text_render_with_nickname_sets_nickname_when_some() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render_with_nickname(&id, "#hello", "hi", Some("dj"), hlc);
        let manifest: BlockManifest = serde_json::from_slice(&block.manifest_bytes).unwrap();
        assert_eq!(manifest.kind, Some(BlockKind::TextRender));
        assert_eq!(
            manifest.metadata.get("nickname").and_then(|v| v.as_str()),
            Some("dj")
        );
    }

    #[test]
    fn build_text_render_with_nickname_omits_nickname_when_none() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render_with_nickname(&id, "#hello", "hi", None, hlc);
        let manifest: BlockManifest = serde_json::from_slice(&block.manifest_bytes).unwrap();
        assert!(!manifest.metadata.contains_key("nickname"));
        assert_eq!(
            manifest.metadata.get("channel").and_then(|v| v.as_str()),
            Some("#hello")
        );
    }

    /// Delegation must be byte-identical, not merely similar — the canonical
    /// bytes are what the sender signature covers.
    #[test]
    fn build_text_render_delegates_identically_to_none_variant() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let legacy = build_text_render(&id, "#hello", "hi", hlc.clone());
        let delegated = build_text_render_with_nickname(&id, "#hello", "hi", None, hlc);
        assert_eq!(legacy.canonical_bytes(), delegated.canonical_bytes());
    }

    #[test]
    fn build_text_render_signature_verifies_against_sender_pubkey() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);
        let sig = ed25519_dalek::Signature::from_slice(&block.sender_sig).unwrap();
        id.public_key()
            .verify(&block.canonical_bytes(), &sig)
            .expect("signature must verify against sender pubkey");
    }

    #[test]
    fn build_channel_create_metadata_includes_slug_and_visibility() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_channel_create(&id, "#room", "restricted", hlc);
        let manifest: BlockManifest = serde_json::from_slice(&block.manifest_bytes).unwrap();
        assert_eq!(manifest.kind, Some(BlockKind::ChannelCreate));
        assert_eq!(
            manifest.metadata.get("slug").and_then(|v| v.as_str()),
            Some("#room")
        );
        assert_eq!(
            manifest.metadata.get("visibility").and_then(|v| v.as_str()),
            Some("restricted")
        );
    }

    #[test]
    fn build_member_add_metadata_includes_channel_and_member() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_member_add(&id, "#hello", "did:jig:zDeji", hlc);
        let manifest: BlockManifest = serde_json::from_slice(&block.manifest_bytes).unwrap();
        assert_eq!(manifest.kind, Some(BlockKind::MemberAdd));
        assert_eq!(
            manifest.metadata.get("channel").and_then(|v| v.as_str()),
            Some("#hello")
        );
        assert_eq!(
            manifest.metadata.get("member_did").and_then(|v| v.as_str()),
            Some("did:jig:zDeji")
        );
    }

    #[test]
    fn build_channel_archive_metadata_uses_the_channel_key() {
        // `channel` (not `slug`) — matches member-add / channel-promote, which
        // is what the server-side apply reads and what the admin endpoint
        // cross-checks against the URL slug.
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_channel_archive(&id, "#scratch", hlc);
        let manifest: BlockManifest = serde_json::from_slice(&block.manifest_bytes).unwrap();
        assert_eq!(manifest.kind, Some(BlockKind::ChannelArchive));
        assert_eq!(
            manifest.metadata.get("channel").and_then(|v| v.as_str()),
            Some("#scratch")
        );
    }

    #[test]
    fn build_channel_archive_signature_verifies_against_sender_pubkey() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_channel_archive(&id, "#scratch", hlc);
        let sig = ed25519_dalek::Signature::from_slice(&block.sender_sig).unwrap();
        id.public_key()
            .verify(&block.canonical_bytes(), &sig)
            .expect("signature must verify against sender pubkey");
    }

    #[test]
    fn build_fed_hello_omits_alias_when_none() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_fed_hello(&id, "wss://server-a", None, hlc);
        let manifest: BlockManifest = serde_json::from_slice(&block.manifest_bytes).unwrap();
        assert_eq!(manifest.kind, Some(BlockKind::FedHello));
        assert_eq!(
            manifest.metadata.get("server_url").and_then(|v| v.as_str()),
            Some("wss://server-a")
        );
        assert!(!manifest.metadata.contains_key("alias"));
    }

    #[test]
    fn build_fed_hello_includes_alias_when_some() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_fed_hello(&id, "wss://server-a", Some("a.jig"), hlc);
        let manifest: BlockManifest = serde_json::from_slice(&block.manifest_bytes).unwrap();
        assert_eq!(
            manifest.metadata.get("alias").and_then(|v| v.as_str()),
            Some("a.jig")
        );
    }

    #[test]
    fn built_block_canonical_bytes_are_deterministic() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block_a = build_text_render(&id, "#hello", "hi", hlc.clone());
        let block_b = build_text_render(&id, "#hello", "hi", hlc);
        assert_eq!(block_a.canonical_bytes(), block_b.canonical_bytes());
    }

    #[test]
    fn sender_did_matches_identity_did() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);
        let manifest: BlockManifest = serde_json::from_slice(&block.manifest_bytes).unwrap();
        let sender: Did = manifest.authors[0].did.clone();
        assert_eq!(sender, *id.did());
    }
}
