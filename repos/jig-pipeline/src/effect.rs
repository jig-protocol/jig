//! Apply-effect dispatch by block kind.
//!
//! After ingest verifies + executes (or synthesizes) a block, this module
//! mutates the derived-state tables (channels, memberships, peers,
//! alias_attestations) based on the block kind. v0.0.2 wire-format
//! conventions are documented in the per-kind functions below — they
//! key off `manifest.metadata` since the manifest doesn't yet have
//! first-class `channel_id` etc. fields.
//!
//! When channel-ops become real Wasm blocks in v0.0.3+, the metadata
//! conventions migrate into the block's typed input schema; this module's
//! dispatch logic stays the same shape.

use jig_core::{BlockBundle, BlockKind, BlockManifest};
use std::sync::Arc;

use crate::persist::{
    SqliteStore, StoredAliasAttestation, StoredChannel, StoredMembership, StoredPeer,
};

/// Apply per-block-kind effects to derived-state tables.
///
/// No-op for blocks whose state semantics are entirely captured in the
/// `blocks` + `receipts` tables (text-render, time-attestation, email-*,
/// receipt). Mutating effects fire for channel ops, federation handshake,
/// and nameserver ops.
pub async fn apply_effect(
    store: &Arc<SqliteStore>,
    bundle: &BlockBundle<'_>,
    _receipt_bytes: &[u8],
    block_cid: &str,
) -> anyhow::Result<()> {
    let manifest: BlockManifest = serde_json::from_slice(bundle.manifest_bytes)?;
    let Some(kind) = manifest.kind else {
        // No kind field — pre-v0.0.2 fixture or malformed; no effect.
        return Ok(());
    };

    match kind {
        // Pure receipt-only kinds: nothing to mutate in derived state.
        BlockKind::TextRender
        | BlockKind::TimeAttestation
        | BlockKind::EmailRender
        | BlockKind::EmailEncrypted
        | BlockKind::Receipt => Ok(()),

        BlockKind::ChannelCreate => apply_channel_create(store, &manifest, block_cid),
        BlockKind::MemberAdd => apply_member_add(store, &manifest, block_cid),
        BlockKind::ChannelPromote => apply_channel_promote(store, &manifest),
        BlockKind::FedHello => apply_fed_hello(store, &manifest, block_cid),

        BlockKind::NsRegister | BlockKind::NsAttestation => apply_ns_attestation(store, &manifest),
        BlockKind::NsRotate => apply_ns_rotate(store, &manifest),
        BlockKind::NsRenew => apply_ns_renew(store, &manifest),
    }
}

fn meta_str<'a>(m: &'a BlockManifest, key: &str) -> Option<&'a str> {
    m.metadata.get(key).and_then(|v| v.as_str())
}

fn meta_i64(m: &BlockManifest, key: &str) -> Option<i64> {
    m.metadata.get(key).and_then(|v| v.as_i64())
}

fn sender_did_string(m: &BlockManifest) -> String {
    m.authors
        .first()
        .map(|a| a.did.to_string())
        .unwrap_or_default()
}

fn apply_channel_create(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    block_cid: &str,
) -> anyhow::Result<()> {
    let slug = meta_str(m, "slug")
        .ok_or_else(|| anyhow::anyhow!("channel-create missing `slug` in metadata"))?;
    let visibility = meta_str(m, "visibility").unwrap_or("open");
    let now = chrono::Utc::now().timestamp();
    let owner_did = sender_did_string(m);

    store.upsert_channel(&StoredChannel {
        id: block_cid.to_string(),
        slug: slug.to_string(),
        visibility: visibility.to_string(),
        created_at: now,
        owner_did: owner_did.clone(),
    })?;
    store.upsert_membership(&StoredMembership {
        channel_id: block_cid.to_string(),
        member_did: owner_did,
        role: "owner".to_string(),
        joined_at: now,
        source_block_cid: block_cid.to_string(),
    })?;
    Ok(())
}

fn apply_member_add(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    block_cid: &str,
) -> anyhow::Result<()> {
    let channel_slug = meta_str(m, "channel")
        .ok_or_else(|| anyhow::anyhow!("member-add missing `channel` in metadata"))?;
    let member_did = meta_str(m, "member_did")
        .ok_or_else(|| anyhow::anyhow!("member-add missing `member_did` in metadata"))?;
    let channel = store
        .get_channel_by_slug(channel_slug)?
        .ok_or_else(|| anyhow::anyhow!("member-add references unknown channel `{channel_slug}`"))?;
    store.upsert_membership(&StoredMembership {
        channel_id: channel.id,
        member_did: member_did.to_string(),
        role: "member".to_string(),
        joined_at: chrono::Utc::now().timestamp(),
        source_block_cid: block_cid.to_string(),
    })?;
    Ok(())
}

fn apply_channel_promote(store: &Arc<SqliteStore>, m: &BlockManifest) -> anyhow::Result<()> {
    let channel_slug = meta_str(m, "channel")
        .ok_or_else(|| anyhow::anyhow!("channel-promote missing `channel` in metadata"))?;
    let mut channel = store.get_channel_by_slug(channel_slug)?.ok_or_else(|| {
        anyhow::anyhow!("channel-promote references unknown channel `{channel_slug}`")
    })?;
    channel.visibility = "open".to_string();
    store.upsert_channel(&channel)?;
    Ok(())
}

fn apply_fed_hello(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    block_cid: &str,
) -> anyhow::Result<()> {
    let server_url = meta_str(m, "server_url")
        .ok_or_else(|| anyhow::anyhow!("fed-hello missing `server_url` in metadata"))?;
    let alias = meta_str(m, "alias").map(String::from);
    store.upsert_peer(&StoredPeer {
        server_url: server_url.to_string(),
        server_did: sender_did_string(m),
        last_handshake_cid: Some(block_cid.to_string()),
        status: "active".to_string(),
        alias,
    })?;
    Ok(())
}

fn apply_ns_attestation(store: &Arc<SqliteStore>, m: &BlockManifest) -> anyhow::Result<()> {
    let alias = meta_str(m, "alias")
        .ok_or_else(|| anyhow::anyhow!("ns-attestation missing `alias` in metadata"))?;
    let ns_did = meta_str(m, "ns_did").unwrap_or("").to_string();
    let valid_from = chrono::Utc::now().timestamp();
    // Default 90d (7_776_000s) if not specified.
    let valid_until = meta_i64(m, "valid_until").unwrap_or(valid_from + 7_776_000);
    store.upsert_alias_attestation(&StoredAliasAttestation {
        did: sender_did_string(m),
        alias: alias.to_string(),
        ns_did,
        valid_from,
        valid_until,
        attestation_bytes: serde_json::to_vec(&m.metadata)?,
    })?;
    Ok(())
}

fn apply_ns_rotate(store: &Arc<SqliteStore>, m: &BlockManifest) -> anyhow::Result<()> {
    // v0.0.2: rotation creates a new attestation under the new pubkey.
    // The actual key-replacement semantics (revoking the old key) are
    // a Phase E (jig-nameserver) concern. Here we just record the
    // new attestation if one is provided.
    apply_ns_attestation(store, m)
}

fn apply_ns_renew(store: &Arc<SqliteStore>, m: &BlockManifest) -> anyhow::Result<()> {
    // Renew = refresh the validity window of an existing attestation.
    // v0.0.2: just upsert with a new valid_from + extended valid_until.
    apply_ns_attestation(store, m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::{Author, BlockManifest as M};
    use semver::Version;
    use serde_json::json;

    fn store() -> Arc<SqliteStore> {
        Arc::new(SqliteStore::open_in_memory().unwrap())
    }

    fn manifest_with(kind: BlockKind, sender: &str, metadata: serde_json::Value) -> M {
        let mut builder = M::builder().version(Version::new(0, 1, 0)).author(Author {
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

    fn as_bundle(manifest: M) -> (Vec<u8>, Vec<u8>) {
        // returns (manifest_bytes, code_bytes) — caller threads into BlockBundle
        (manifest.to_canonical_bytes().unwrap(), vec![])
    }

    #[tokio::test]
    async fn channel_create_inserts_channel_and_owner_membership() {
        let s = store();
        let m = manifest_with(
            BlockKind::ChannelCreate,
            "did:jig:zOwner",
            json!({"slug": "#hello", "visibility": "open"}),
        );
        let (mb, cb) = as_bundle(m);
        let bundle = BlockBundle {
            manifest_bytes: &mb,
            code_bytes: &cb,
            resources: vec![],
        };
        apply_effect(&s, &bundle, &[], "bafy_create").await.unwrap();
        let ch = s.get_channel_by_slug("#hello").unwrap().unwrap();
        assert_eq!(ch.id, "bafy_create");
        assert_eq!(ch.visibility, "open");
        assert_eq!(ch.owner_did, "did:jig:zOwner");
        let members = s.list_members("bafy_create").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].role, "owner");
    }

    #[tokio::test]
    async fn member_add_inserts_membership_for_existing_channel() {
        let s = store();
        // First create channel
        let create = manifest_with(
            BlockKind::ChannelCreate,
            "did:jig:zOwner",
            json!({"slug": "#hello", "visibility": "restricted"}),
        );
        let (mb1, cb1) = as_bundle(create);
        apply_effect(
            &s,
            &BlockBundle {
                manifest_bytes: &mb1,
                code_bytes: &cb1,
                resources: vec![],
            },
            &[],
            "bafy_create",
        )
        .await
        .unwrap();

        // Then add member
        let add = manifest_with(
            BlockKind::MemberAdd,
            "did:jig:zOwner",
            json!({"channel": "#hello", "member_did": "did:jig:zDeji"}),
        );
        let (mb2, cb2) = as_bundle(add);
        apply_effect(
            &s,
            &BlockBundle {
                manifest_bytes: &mb2,
                code_bytes: &cb2,
                resources: vec![],
            },
            &[],
            "bafy_add",
        )
        .await
        .unwrap();

        let members = s.list_members("bafy_create").unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.iter().any(|m| m.member_did == "did:jig:zDeji"));
    }

    #[tokio::test]
    async fn channel_promote_flips_visibility_to_open() {
        let s = store();
        let create = manifest_with(
            BlockKind::ChannelCreate,
            "did:jig:zO",
            json!({"slug": "#private", "visibility": "restricted"}),
        );
        let (mb1, cb1) = as_bundle(create);
        apply_effect(
            &s,
            &BlockBundle {
                manifest_bytes: &mb1,
                code_bytes: &cb1,
                resources: vec![],
            },
            &[],
            "bafy_c",
        )
        .await
        .unwrap();

        let promote = manifest_with(
            BlockKind::ChannelPromote,
            "did:jig:zO",
            json!({"channel": "#private"}),
        );
        let (mb2, cb2) = as_bundle(promote);
        apply_effect(
            &s,
            &BlockBundle {
                manifest_bytes: &mb2,
                code_bytes: &cb2,
                resources: vec![],
            },
            &[],
            "bafy_p",
        )
        .await
        .unwrap();

        let ch = s.get_channel_by_slug("#private").unwrap().unwrap();
        assert_eq!(ch.visibility, "open");
    }

    #[tokio::test]
    async fn fed_hello_records_peer() {
        let s = store();
        let m = manifest_with(
            BlockKind::FedHello,
            "did:jig:zPeerA",
            json!({"server_url": "wss://peer-a.jig.onl", "alias": "peer-a.jig"}),
        );
        let (mb, cb) = as_bundle(m);
        apply_effect(
            &s,
            &BlockBundle {
                manifest_bytes: &mb,
                code_bytes: &cb,
                resources: vec![],
            },
            &[],
            "bafy_hello",
        )
        .await
        .unwrap();
        let peers = s.list_peers().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].server_url, "wss://peer-a.jig.onl");
        assert_eq!(peers[0].server_did, "did:jig:zPeerA");
        assert_eq!(peers[0].alias.as_deref(), Some("peer-a.jig"));
        assert_eq!(peers[0].status, "active");
    }

    #[tokio::test]
    async fn ns_register_records_alias_attestation() {
        let s = store();
        let m = manifest_with(
            BlockKind::NsRegister,
            "did:jig:zDj",
            json!({"alias": "dj@dj.jig", "ns_did": "did:jig:zNs"}),
        );
        let (mb, cb) = as_bundle(m);
        apply_effect(
            &s,
            &BlockBundle {
                manifest_bytes: &mb,
                code_bytes: &cb,
                resources: vec![],
            },
            &[],
            "bafy_reg",
        )
        .await
        .unwrap();
        let now = chrono::Utc::now().timestamp();
        let att = s.find_alias_attestation("dj@dj.jig", now).unwrap().unwrap();
        assert_eq!(att.did, "did:jig:zDj");
        assert_eq!(att.ns_did, "did:jig:zNs");
        assert!(att.valid_until > now);
    }

    #[tokio::test]
    async fn text_render_no_effect() {
        let s = store();
        let m = manifest_with(
            BlockKind::TextRender,
            "did:jig:zS",
            json!({"channel": "#hello"}),
        );
        let (mb, cb) = as_bundle(m);
        apply_effect(
            &s,
            &BlockBundle {
                manifest_bytes: &mb,
                code_bytes: &cb,
                resources: vec![],
            },
            &[],
            "bafy_tr",
        )
        .await
        .unwrap();
        // No channel created, no membership, no peer, no attestation
        assert!(s.list_channels().unwrap().is_empty());
        assert!(s.list_peers().unwrap().is_empty());
    }

    #[tokio::test]
    async fn channel_create_missing_slug_errors() {
        let s = store();
        let m = manifest_with(
            BlockKind::ChannelCreate,
            "did:jig:zO",
            json!({"visibility": "open"}), // no slug!
        );
        let (mb, cb) = as_bundle(m);
        let err = apply_effect(
            &s,
            &BlockBundle {
                manifest_bytes: &mb,
                code_bytes: &cb,
                resources: vec![],
            },
            &[],
            "bafy_bad",
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("slug"));
    }
}
