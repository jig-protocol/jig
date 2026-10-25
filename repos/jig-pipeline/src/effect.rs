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
        | BlockKind::Receipt
        // The log is the state: the current manifest is its newest block.
        | BlockKind::ServerManifest => Ok(()),

        BlockKind::ChannelCreate => apply_channel_create(store, &manifest, block_cid),
        BlockKind::MemberAdd => apply_member_add(store, &manifest, block_cid),
        BlockKind::MemberRemove => apply_member_remove(store, &manifest, block_cid),
        BlockKind::ChannelPromote => apply_channel_promote(store, &manifest, block_cid),
        BlockKind::ChannelArchive => apply_channel_archive(store, &manifest, block_cid),
        // A role lives in the channel's ingest chain, which is its record;
        // `roles::rights_at` reads it from there, so there is no row to keep.
        BlockKind::RoleAssign | BlockKind::RoleUnassign => Ok(()),
        // A share's state is its blocks: the requests, and the sequencer's
        // records of what came of them (`crate::contracts`).
        BlockKind::ChannelShare
        | BlockKind::ChannelUnshare
        | BlockKind::ContractAccept
        | BlockKind::ContractRefuse
        | BlockKind::ContractEnd => Ok(()),
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

/// The block's author, in canonical spelling.
///
/// Rows written from it are what the gates later compare a caller's canonical
/// DID against. Ingest refuses a manifest whose DIDs are spelled any other
/// way ([`crate::ingest::IngestError::NonCanonicalDid`]), so this only
/// re-checks. Legacy, non-key-derived DIDs (`did:jig:alice`) have no
/// canonical form and pass through unchanged.
fn sender_did_string(m: &BlockManifest) -> String {
    canonical_did_string(
        &m.authors
            .first()
            .map(|a| a.did.to_string())
            .unwrap_or_default(),
    )
}

/// See [`sender_did_string`]. Public so ingest persists `blocks.sender_did`
/// in the same form the effect layer writes `owner_did` and `member_did`.
/// A key-derived DID in another spelling is not canonical and is returned as
/// it came, so it matches no row.
pub fn canonical_did_string(raw: &str) -> String {
    jig_core::Did::from_did_jig_string(raw)
        .map(|d| d.to_did_jig_string())
        .unwrap_or_else(|_| raw.to_string())
}

/// The channel a block of `kind` acts on, resolved by the same rule ingest
/// gated it with ([`crate::ingest::channel_id_of`]), so an effect never lands
/// on a different channel than the one the write gate examined.
///
/// `Ok(None)` when the metadata names a channel this server does not hold
/// (or, unless `including_archived`, one that is archived). An error when the
/// metadata names no channel at all.
fn channel_of(
    store: &SqliteStore,
    kind: BlockKind,
    m: &BlockManifest,
    block_cid: &str,
    including_archived: bool,
) -> anyhow::Result<(String, Option<StoredChannel>)> {
    let named = crate::ingest::channel_id_of(store, kind, m, block_cid)?
        .ok_or_else(|| anyhow::anyhow!("{} missing `channel` in metadata", kind.as_str()))?;
    let row = match named.id.as_deref() {
        Some(id) if including_archived => store.get_channel_by_id_including_archived(id)?,
        Some(id) => store.get_channel_by_id(id)?,
        None => None,
    };
    Ok((named.named, row))
}

fn apply_channel_create(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    block_cid: &str,
) -> anyhow::Result<()> {
    // The gate is ingest's (`ingest::channel_terms` refuses a sequencer that
    // is not this server). Here the row records the terms the block carries:
    // its declared sequencer, else this store's server (or, before boot
    // adopts one, the placeholder that means the same).
    let sequencer = meta_str(m, crate::ingest::SEQUENCER_KEY)
        .map(canonical_did_string)
        .unwrap_or_else(|| store.local_sequencer().to_string());
    apply_channel_create_under(store, m, block_cid, &sequencer)
}

/// A channel-create's row and its root owners' memberships, under
/// `sequencer`: this server for a channel it sequences, the owner for one it
/// carries (JEP-0005 rule 3).
fn apply_channel_create_under(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    block_cid: &str,
    sequencer: &str,
) -> anyhow::Result<()> {
    let slug = meta_str(m, "slug")
        .ok_or_else(|| anyhow::anyhow!("channel-create missing `slug` in metadata"))?;
    let visibility = meta_str(m, "visibility").unwrap_or("open");
    let suite = crate::mls_gate::requested_suite(m)
        .map_err(|_| anyhow::anyhow!("channel-create names an unknown suite"))?;
    let now = chrono::Utc::now().timestamp();
    let owner_did = sender_did_string(m);
    let terms = crate::ingest::channel_terms(m, sequencer)
        .map_err(|e| anyhow::anyhow!("channel-create terms: {e}"))?;

    store.upsert_channel(&StoredChannel {
        id: block_cid.to_string(),
        slug: slug.to_string(),
        visibility: visibility.to_string(),
        created_at: now,
        owner_did: owner_did.clone(),
        suite: suite.as_str().to_string(),
        sequencer_did: terms.sequencer,
        co_owners: terms.co_owners.clone(),
    })?;
    // The creator and every co-owner are members, with role `owner`: a
    // co-owner holds every right, so it can read what it can write and
    // manage.
    for member_did in std::iter::once(owner_did).chain(terms.co_owners) {
        store.upsert_membership(&StoredMembership {
            channel_id: block_cid.to_string(),
            member_did,
            role: "owner".to_string(),
            joined_at: now,
            source_block_cid: block_cid.to_string(),
        })?;
    }
    Ok(())
}

fn apply_member_add(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    block_cid: &str,
) -> anyhow::Result<()> {
    let (named, channel) = channel_of(store, BlockKind::MemberAdd, m, block_cid, false)?;
    let channel = channel
        .ok_or_else(|| anyhow::anyhow!("member-add references unknown channel `{named}`"))?;
    member_add_on(store, m, block_cid, &channel)
}

fn member_add_on(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    block_cid: &str,
    channel: &StoredChannel,
) -> anyhow::Result<()> {
    let member_did = meta_str(m, "member_did")
        .map(canonical_did_string)
        .ok_or_else(|| anyhow::anyhow!("member-add missing `member_did` in metadata"))?;
    store.upsert_membership(&StoredMembership {
        channel_id: channel.id.clone(),
        member_did,
        role: "member".to_string(),
        joined_at: chrono::Utc::now().timestamp(),
        source_block_cid: block_cid.to_string(),
    })?;
    Ok(())
}

/// Drop a membership. Authorization (owner, self, or tidy-up) was decided by
/// the write gate; removing someone who is already gone is a no-op, which is
/// exactly the tidy-up case on an encrypted channel.
fn apply_member_remove(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    block_cid: &str,
) -> anyhow::Result<()> {
    let (_, channel) = channel_of(store, BlockKind::MemberRemove, m, block_cid, false)?;
    member_remove_on(store, m, channel.as_ref())
}

fn member_remove_on(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    channel: Option<&StoredChannel>,
) -> anyhow::Result<()> {
    let member_did = meta_str(m, "member_did")
        .map(canonical_did_string)
        .ok_or_else(|| anyhow::anyhow!("member-remove missing `member_did` in metadata"))?;
    if let Some(channel) = channel {
        store.remove_membership_by_id(&channel.id, &member_did)?;
    }
    Ok(())
}

fn apply_channel_promote(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    block_cid: &str,
) -> anyhow::Result<()> {
    let (named, channel) = channel_of(store, BlockKind::ChannelPromote, m, block_cid, false)?;
    let channel = channel
        .ok_or_else(|| anyhow::anyhow!("channel-promote references unknown channel `{named}`"))?;
    promote_on(store, channel)
}

fn promote_on(store: &Arc<SqliteStore>, mut channel: StoredChannel) -> anyhow::Result<()> {
    channel.visibility = "open".to_string();
    store.upsert_channel(&channel)?;
    Ok(())
}

/// Retire a channel: soft delete, owner only.
///
/// ## Why archive rather than delete rows
///
/// Blocks are content-addressed and referenced from outside the channel row:
/// `receipts.block_cid` has a foreign key onto `blocks(cid)`, federated peers
/// already hold copies of anything that was fanned out, and a block CID may be
/// cited by later blocks. So the three candidate semantics are:
///
/// * **Delete the channel row only** — leaves `blocks` rows whose `channel_id`
///   resolves to nothing. History becomes unreachable but still occupies the
///   database, and re-creating the slug silently adopts the orphans. Worst of
///   both worlds.
/// * **Cascade to blocks** — irreversible destruction of shared history from a
///   single unauthenticated request, breaks receipt FKs, and does not even buy
///   privacy since peers keep their copies. Not something a v0.0.x admin
///   endpoint should be able to do.
/// * **Archive (chosen)** — flip `channels.archived_at`. The channel vanishes
///   from `jig channel list` and stops resolving as an active channel, so the
///   reported problem (a stray channel nobody can remove) is fixed, while every
///   block, receipt and CID reference stays intact and the decision is
///   reversible by an operator with database access.
///
/// ## Why the owner check lives here
///
/// The `/api/v1/channels*` endpoints are unauthenticated, so anything they can
/// reach must authorize itself. `ingest()` has already verified the sender's
/// ed25519 signature against the pubkey embedded in their DID by the time this
/// runs, which makes `manifest.authors[0].did` a trustworthy identity — and
/// this runs *before* the block is persisted, so a rejection leaves no trace.
/// The HTTP handler repeats the check only to return a precise 403/404.
fn apply_channel_archive(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    block_cid: &str,
) -> anyhow::Result<()> {
    let (named, channel) = channel_of(store, BlockKind::ChannelArchive, m, block_cid, true)?;
    let channel = channel
        .ok_or_else(|| anyhow::anyhow!("channel-archive references unknown channel `{named}`"))?;
    let channel_slug = channel.slug.as_str();

    let sender = sender_did_string(m);
    // An empty owner_did would make an author-less manifest match; refuse
    // rather than treat "we don't know who owns this" as permission.
    if !channel.is_root_owner(&sender) {
        anyhow::bail!("channel-archive rejected: `{sender}` is not the owner of `{channel_slug}`");
    }

    archive_on(store, &channel)
}

fn archive_on(store: &Arc<SqliteStore>, channel: &StoredChannel) -> anyhow::Result<()> {
    if !store.archive_channel_by_id(&channel.id, chrono::Utc::now().timestamp())? {
        anyhow::bail!("channel `{}` is already archived", channel.slug);
    }
    Ok(())
}

/// The effect of a block in a channel this server carries for its owner
/// (JEP-0005 rules 3 and 22a), on `channel`, the row the owner's record put
/// it in; for a channel-create, the row it makes, under `sequencer`.
///
/// No ownership check: the owner ran its full gate before it sequenced the
/// block, and its signed order is what this server follows. Kinds that are
/// not channel content, the nameserver's and the federation handshake's,
/// are refused: they have no place in a channel's chain.
pub fn apply_carried_effect(
    store: &Arc<SqliteStore>,
    m: &BlockManifest,
    block_cid: &str,
    channel: Option<&StoredChannel>,
    sequencer: &str,
) -> anyhow::Result<()> {
    let kind = m
        .kind
        .ok_or_else(|| anyhow::anyhow!("a carried block declares no kind"))?;
    let carried = || channel.ok_or_else(|| anyhow::anyhow!("no carried channel for the block"));
    match kind {
        BlockKind::ChannelCreate => apply_channel_create_under(store, m, block_cid, sequencer),
        BlockKind::MemberAdd => member_add_on(store, m, block_cid, carried()?),
        BlockKind::MemberRemove => member_remove_on(store, m, channel),
        BlockKind::ChannelPromote => promote_on(store, carried()?.clone()),
        BlockKind::ChannelArchive => archive_on(store, carried()?),
        BlockKind::TextRender
        | BlockKind::EmailRender
        | BlockKind::EmailEncrypted
        | BlockKind::TimeAttestation
        | BlockKind::Receipt
        | BlockKind::RoleAssign
        | BlockKind::RoleUnassign
        | BlockKind::ChannelShare
        | BlockKind::ChannelUnshare
        | BlockKind::ContractAccept
        | BlockKind::ContractRefuse
        | BlockKind::ContractEnd => Ok(()),
        BlockKind::FedHello
        | BlockKind::NsRegister
        | BlockKind::NsRotate
        | BlockKind::NsRenew
        | BlockKind::NsAttestation
        | BlockKind::ServerManifest => {
            anyhow::bail!("a `{}` block is not channel content", kind.as_str())
        }
    }
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

    /// Apply a single manifest through `apply_effect`, returning its result.
    async fn apply(s: &Arc<SqliteStore>, m: M, cid: &str) -> anyhow::Result<()> {
        let (mb, cb) = as_bundle(m);
        apply_effect(
            s,
            &BlockBundle {
                manifest_bytes: &mb,
                code_bytes: &cb,
                resources: vec![],
            },
            &[],
            cid,
        )
        .await
    }

    async fn store_with_channel(slug: &str, owner: &str) -> Arc<SqliteStore> {
        let s = store();
        let create = manifest_with(
            BlockKind::ChannelCreate,
            owner,
            json!({"slug": slug, "visibility": "open"}),
        );
        apply(&s, create, "bafy_create").await.unwrap();
        s
    }

    #[tokio::test]
    async fn channel_archive_by_the_owner_archives_the_channel() {
        let s = store_with_channel("#scratch", "did:jig:zOwner").await;
        let archive = manifest_with(
            BlockKind::ChannelArchive,
            "did:jig:zOwner",
            json!({"channel": "#scratch"}),
        );
        apply(&s, archive, "bafy_archive").await.unwrap();

        assert!(s.list_channels().unwrap().is_empty());
        assert!(s.channel_archived_at("#scratch").unwrap().is_some());
    }

    /// The security-relevant case. The admin endpoints are unauthenticated, so
    /// this check in the apply layer — which runs only after ingest has verified
    /// the sender signature — is the authoritative one.
    #[tokio::test]
    async fn channel_archive_by_a_non_owner_is_rejected() {
        let s = store_with_channel("#scratch", "did:jig:zOwner").await;
        let archive = manifest_with(
            BlockKind::ChannelArchive,
            "did:jig:zAttacker",
            json!({"channel": "#scratch"}),
        );
        let err = apply(&s, archive, "bafy_archive").await.unwrap_err();
        assert!(
            err.to_string().contains("owner"),
            "error must name the owner check; got: {err}"
        );
        assert_eq!(
            s.list_channels().unwrap().len(),
            1,
            "a rejected archive must leave the channel alone"
        );
        assert_eq!(s.channel_archived_at("#scratch").unwrap(), None);
    }

    #[tokio::test]
    async fn channel_archive_of_an_unknown_channel_errors() {
        let s = store();
        let archive = manifest_with(
            BlockKind::ChannelArchive,
            "did:jig:zOwner",
            json!({"channel": "#never-existed"}),
        );
        let err = apply(&s, archive, "bafy_archive").await.unwrap_err();
        assert!(
            err.to_string().contains("#never-existed"),
            "error must name the missing channel; got: {err}"
        );
    }

    #[tokio::test]
    async fn channel_archive_missing_channel_metadata_errors() {
        let s = store_with_channel("#scratch", "did:jig:zOwner").await;
        let archive = manifest_with(BlockKind::ChannelArchive, "did:jig:zOwner", json!({}));
        let err = apply(&s, archive, "bafy_archive").await.unwrap_err();
        assert!(err.to_string().contains("channel"), "got: {err}");
    }

    #[tokio::test]
    async fn member_add_to_an_archived_channel_is_rejected() {
        let s = store_with_channel("#scratch", "did:jig:zOwner").await;
        let archive = manifest_with(
            BlockKind::ChannelArchive,
            "did:jig:zOwner",
            json!({"channel": "#scratch"}),
        );
        apply(&s, archive, "bafy_archive").await.unwrap();

        let add = manifest_with(
            BlockKind::MemberAdd,
            "did:jig:zOwner",
            json!({"channel": "#scratch", "member_did": "did:jig:zDeji"}),
        );
        let err = apply(&s, add, "bafy_add").await.unwrap_err();
        assert!(err.to_string().contains("unknown channel"), "got: {err}");
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
