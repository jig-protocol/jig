//! The server's manifest log (JEP-0002 rule 12; design D11 item 13).
//!
//! At boot, [`publish`] creates the log (a channel-create by the server, at
//! [`LOG_SLUG`], open to every reader) the first time, and appends a
//! `server-manifest` block whenever what the server advertises differs from
//! the newest one. Every welcome then cites that block by CID and `seq`. What
//! a server advertises comes from its config and build, so it only changes
//! across a restart.
//!
//! The blocks go through `ingest` like any other, so they are sequenced and
//! chained. Its gate refuses every other writer and kind
//! (`jig_pipeline::ingest`'s manifest-log check).

use std::sync::Arc;

use anyhow::Context as _;
use base64::Engine as _;
use jig_core::{Author, BlockBundle, BlockKind, BlockManifest};
use jig_pipeline::handshake::{ManifestRef, implemented_suite_names};
use jig_pipeline::ingest::{IngestSource, ingest};
use jig_pipeline::server_manifest::{LOG_SLUG, METADATA_KEY, PeerPolicy, ServerManifest};

use crate::v0_0_2::AppState;

/// What this server advertises now: the facts every welcome signs. Peer
/// policy is published empty until lane F fills it (F2 task 3).
pub fn current(state: &AppState) -> ServerManifest {
    let mut capabilities = crate::v0_0_2_ws::handshake_capabilities(state);
    // A kind listed twice in config is one kind; the document holds each once.
    dedup(&mut capabilities.block_kinds);
    let mut suites = implemented_suite_names();
    dedup(&mut suites);
    ServerManifest {
        versions: vec![u64::from(jig_pipeline::envelope::ENVELOPE_VERSION)],
        suites,
        capabilities,
        peer_policy: PeerPolicy::default(),
    }
}

fn dedup(items: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    items.retain(|item| seen.insert(item.clone()));
}

/// Create the manifest log if it is missing, publish [`current`] if it is not
/// the newest manifest there, and make the newest the one welcomes cite.
pub async fn publish(state: &Arc<AppState>) -> anyhow::Result<ManifestRef> {
    let store = &state.ingest_ctx.store;
    let document = current(state)
        .encode()
        .context("encoding this server's manifest")?;
    let server_did = state.server_did.to_did_jig_string();
    match store.get_channel_by_slug_including_archived(LOG_SLUG)? {
        None => {
            submit(state, log_create(state)?)
                .await
                .context("creating the manifest log")?;
        }
        // A channel created at the slug before it was reserved: move it,
        // with everything in it, under the reserved prefix, where only the
        // server writes, and start the log. Nothing anyone signed is lost.
        Some(channel) if channel.owner_did != server_did => {
            let quarantine = quarantine_slug(&channel.id);
            tracing::warn!(
                owner = %jig_core::did::log_tag(&channel.owner_did),
                to = %quarantine,
                "an existing channel held the manifest log's reserved slug; moved it"
            );
            store.quarantine_channel(
                LOG_SLUG,
                &quarantine,
                chrono::Utc::now().timestamp_millis(),
            )?;
            submit(state, log_create(state)?)
                .await
                .context("creating the manifest log")?;
        }
        Some(_) => {}
    }

    let newest = store
        .list_blocks_by_channel(LOG_SLUG, 1, None)?
        .pop()
        .filter(|b| b.block_kind == BlockKind::ServerManifest.as_str());
    let cid = match newest {
        Some(block) if document_of(&block.bundle_bytes).as_deref() == Some(&document[..]) => {
            block.cid
        }
        _ => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&document);
            let cid = submit(
                state,
                block(state, BlockKind::ServerManifest, |m| {
                    m.metadata_entry(METADATA_KEY, serde_json::json!(encoded))
                })?,
            )
            .await
            .context("publishing this server's manifest")?;
            tracing::info!(%cid, "published a new server-manifest");
            cid
        }
    };
    let seq = store
        .get_ingest_record(&cid)?
        .context("the server-manifest has no ingest record")?
        .seq;
    let current = ManifestRef { cid, seq };
    *state
        .manifest
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(current.clone());
    Ok(current)
}

/// Where a channel that held [`LOG_SLUG`] before it was reserved is moved.
const QUARANTINE_PREFIX: &str = "#jig/quarantine-";

/// The slug the channel `channel_id` is moved to: [`QUARANTINE_PREFIX`] and
/// 12 lowercase hex characters of the BLAKE3 of its id, so two channels
/// never share one and the slug fits the reserved grammar
/// (`#jig/[a-z0-9_-]{1,59}`).
fn quarantine_slug(channel_id: &str) -> String {
    let hash = hex::encode(blake3::hash(channel_id.as_bytes()).as_bytes());
    format!("{QUARANTINE_PREFIX}{}", &hash[..12])
}

/// The manifest log's channel-create.
fn log_create(state: &AppState) -> anyhow::Result<Vec<u8>> {
    block(state, BlockKind::ChannelCreate, |m| {
        m.metadata_entry("slug", serde_json::json!(LOG_SLUG))
            .metadata_entry("visibility", serde_json::json!("open"))
    })
}

/// A block of `kind` in the manifest log, authored by this server.
fn block(
    state: &AppState,
    kind: BlockKind,
    fill: impl FnOnce(jig_core::BlockManifestBuilder) -> jig_core::BlockManifestBuilder,
) -> anyhow::Result<Vec<u8>> {
    let builder = BlockManifest::builder()
        .version(semver::Version::new(0, 1, 0))
        .author(Author {
            did: state.server_did.to_did_jig_string().into(),
            public_key: None,
            roles: vec!["jig-server".to_string()],
        })
        .metadata_entry("channel", serde_json::json!(LOG_SLUG));
    let manifest = fill(builder).build()?.with_kind(kind);
    Ok(manifest.to_canonical_bytes()?)
}

/// Sign `manifest_bytes` with the server key and ingest it as the server.
async fn submit(state: &AppState, manifest_bytes: Vec<u8>) -> anyhow::Result<String> {
    use ed25519_dalek::Signer as _;
    let code_bytes: Vec<u8> = Vec::new();
    let canonical = serde_json::to_vec(&(&manifest_bytes, &code_bytes))?;
    let sig = state
        .ingest_ctx
        .server_key
        .sign(&canonical)
        .to_bytes()
        .to_vec();
    let bundle = BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    };
    Ok(ingest(&state.ingest_ctx, bundle, sig, IngestSource::AdminEndpoint).await?)
}

/// The document a stored `server-manifest` block carries.
fn document_of(bundle_bytes: &[u8]) -> Option<Vec<u8>> {
    let (manifest_bytes, _code): (Vec<u8>, Vec<u8>) = serde_json::from_slice(bundle_bytes).ok()?;
    let manifest: BlockManifest = serde_json::from_slice(&manifest_bytes).ok()?;
    let b64 = manifest.metadata.get(METADATA_KEY)?.as_str()?;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_log_is_created_once_and_a_manifest_published_only_on_change() {
        let state = Arc::new(AppState::for_test().unwrap());
        let first = publish(&state).await.unwrap();
        assert_eq!(first.seq, 1, "record 0 is the log's channel-create");
        let store = &state.ingest_ctx.store;
        let channel = store.get_channel_by_slug(LOG_SLUG).unwrap().unwrap();
        assert_eq!(channel.owner_did, state.server_did.to_did_jig_string());
        assert!(jig_pipeline::visibility::is_open(&channel.visibility));

        // Nothing changed: nothing published, the same block cited.
        assert_eq!(publish(&state).await.unwrap(), first);
        assert_eq!(*state.manifest.read().unwrap(), Some(first.clone()));
        let block = store.get_block(&first.cid).unwrap().unwrap();
        let doc = ServerManifest::decode(&document_of(&block.bundle_bytes).unwrap()).unwrap();
        assert_eq!(doc.encode(), current(&state).encode(), "the same facts");

        // A changed advertisement is a new block, chained after the last.
        let mut changed = AppState::for_test().unwrap();
        changed.ingest_ctx = state.ingest_ctx.clone();
        changed.server_did = state.server_did.clone();
        // A repeat is not a change.
        changed
            .config
            .server
            .allowed_block_kinds
            .push("member-add".into());
        let repeated = Arc::new(changed);
        assert_eq!(publish(&repeated).await.unwrap(), first);
        let mut changed = Arc::try_unwrap(repeated).ok().unwrap();
        changed
            .config
            .server
            .allowed_block_kinds
            .push("ns-register".into());
        let changed = Arc::new(changed);
        let second = publish(&changed).await.unwrap();
        assert_ne!(second.cid, first.cid);
        assert_eq!(second.seq, 2);
    }

    #[tokio::test]
    async fn a_channel_already_at_the_reserved_slug_is_moved_not_lost() {
        let state = Arc::new(AppState::for_test().unwrap());
        let store = &state.ingest_ctx.store;
        let stranger = jig_core::Did::from_ed25519_pubkey(&[7u8; 32]).to_did_jig_string();
        store
            .upsert_channel(&jig_pipeline::persist::StoredChannel {
                id: "bafyOldChannelAtTheReservedSlug".into(),
                slug: LOG_SLUG.into(),
                visibility: "open".into(),
                created_at: 1,
                owner_did: stranger.clone(),
                suite: "none".into(),
                sequencer_did: String::new(),
                co_owners: Vec::new(),
            })
            .unwrap();

        let current = publish(&state).await.expect("boot goes on");
        let log = store.get_channel_by_slug(LOG_SLUG).unwrap().unwrap();
        assert_eq!(log.owner_did, state.server_did.to_did_jig_string());
        assert_eq!(current.seq, 1);
        let moved = store
            .list_channels_including_archived()
            .unwrap()
            .into_iter()
            .find(|c| c.owner_did == stranger)
            .expect("the old channel is kept");
        assert_eq!(
            moved.slug,
            quarantine_slug("bafyOldChannelAtTheReservedSlug")
        );
        // A slug the grammar (#233) gives to the server.
        assert_eq!(
            jig_core::slug::classify_slug(&moved.slug),
            Ok(jig_core::slug::SlugClass::Server),
            "{}",
            moved.slug
        );
        assert!(moved.slug.starts_with(QUARANTINE_PREFIX), "{}", moved.slug);
        assert!(
            store.channel_archived_at(&moved.slug).unwrap().is_some(),
            "frozen"
        );
    }

    #[tokio::test]
    async fn every_welcome_cites_the_current_manifest() {
        let state = Arc::new(AppState::for_test().unwrap());
        let current = publish(&state).await.unwrap();
        let app = axum::Router::new()
            .route(
                "/api/v1/ws",
                axum::routing::get(crate::v0_0_2_ws::ws_handler),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/v1/ws"))
            .await
            .unwrap();
        let welcome = crate::v0_0_2_federation::complete_client_handshake(&mut ws, None)
            .await
            .unwrap();
        assert_eq!(welcome.manifest, Some(current));
    }

    #[tokio::test]
    async fn nobody_else_writes_the_manifest_log() {
        let state = Arc::new(AppState::for_test().unwrap());
        publish(&state).await.unwrap();
        let stranger = jig_core::crypto::ed25519::generate_signing_key();
        let stranger_did = jig_core::Did::from_ed25519_pubkey(stranger.verifying_key().as_bytes())
            .to_did_jig_string();
        let as_stranger = |kind: BlockKind, slug_key: &str, slug: &str| {
            use ed25519_dalek::Signer as _;
            let manifest = BlockManifest::builder()
                .version(semver::Version::new(0, 1, 0))
                .author(Author {
                    did: stranger_did.clone().into(),
                    public_key: None,
                    roles: vec![],
                })
                .metadata_entry(slug_key, serde_json::json!(slug))
                .metadata_entry("visibility", serde_json::json!("open"))
                .build()
                .unwrap()
                .with_kind(kind)
                .to_canonical_bytes()
                .unwrap();
            let canonical = serde_json::to_vec(&(&manifest, &Vec::<u8>::new())).unwrap();
            (manifest, stranger.sign(&canonical).to_bytes().to_vec())
        };
        for (kind, key, slug) in [
            (BlockKind::TextRender, "channel", LOG_SLUG),
            (BlockKind::ServerManifest, "channel", LOG_SLUG),
            (BlockKind::ChannelCreate, "slug", "#jig/other"),
            // The prefix is reserved whatever its case.
            (BlockKind::ChannelCreate, "slug", "#JIG/manifest"),
        ] {
            let (manifest, sig) = as_stranger(kind, key, slug);
            let err = ingest(
                &state.ingest_ctx,
                BlockBundle {
                    manifest_bytes: &manifest,
                    code_bytes: &[],
                    resources: vec![],
                },
                sig,
                IngestSource::LocalClient { conn_id: 1 },
            )
            .await
            .unwrap_err();
            // A create under `#jig/` is the slug grammar's to refuse.
            assert!(
                matches!(
                    err,
                    jig_pipeline::ingest::IngestError::ManifestLog { .. }
                        | jig_pipeline::ingest::IngestError::InvalidSlug { .. }
                ),
                "{kind:?} into {slug}: {err}"
            );
        }
    }
}
