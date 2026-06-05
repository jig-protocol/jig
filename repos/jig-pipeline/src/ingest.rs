//! Unified block ingest pipeline.
//!
//! Every block — local-client-submitted, federated-peer-relayed, or
//! admin-endpoint-injected — flows through `ingest()`. The same function
//! drives `jig-server` and (with a different allowed_block_kinds list)
//! `jig-nameserver`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jig_core::{BlockBundle, Did};
use std::sync::Arc;

use crate::fanout::Fanout;
use crate::hlc::HlcClock;
use crate::identity::IdentityResolver;
use crate::persist::{SqliteStore, StoredBlock, StoredReceipt};

/// Where a block came from. Discriminates broadcast policy: federated-peer
/// blocks are NOT re-broadcast to peers (avoids loops); local + admin
/// blocks ARE broadcast to peers.
#[derive(Debug, Clone)]
pub enum IngestSource {
    LocalClient {
        conn_id: u64,
    },
    FederatedPeer {
        peer_did: Did,
        peer_url: String,
    },
    AdminEndpoint,
    /// Submitted by an in-process bridge (e.g. the email bridge translating
    /// inbound mail). Behaves like a local submission for fanout + origin
    /// tagging.
    Bridge,
}

/// All resources the ingest pipeline needs. Constructed once at server
/// boot from `JigServerConfig` (jig-config v0_0_2_server module).
pub struct IngestContext {
    pub store: Arc<SqliteStore>,
    pub identity: Arc<dyn IdentityResolver>,
    pub hlc_clock: Arc<HlcClock>,
    pub allowed_block_kinds: Vec<String>,
    pub server_did: Did,
    pub server_key: ed25519_dalek::SigningKey,
    pub fanout: Arc<Fanout>,
    pub server_url: String,
    /// Antipattern carve-out: when true, identity mismatches at the
    /// resolver step are logged as warnings and the block is admitted
    /// anyway. Wired from `[identity] naively_allow_unknown_handles_fallback`.
    /// Surfaces in `unsafe_options_active`.
    pub naively_allow_unknown_handles_fallback: bool,
    // Wasm runtime is optional in v0.0.2 B6: Wasm-executable block kinds
    // fall back to the synthetic-receipt path. Phase D wires in the real
    // jig-runtime once text-render.wasm is loaded as a canonical artifact.
}

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("disallowed block kind: `{kind}`")]
    DisallowedBlockKind { kind: String },
    #[error("malformed bundle: {0}")]
    BundleMalformed(String),
    #[error("manifest missing kind field — v0.0.2 blocks must declare kind")]
    KindRequired,
    #[error(transparent)]
    Identity(#[from] crate::identity::IdentityError),
    #[error(transparent)]
    Persist(#[from] crate::persist::PersistError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Block ingest entry point. Returns the CID of the persisted block on success.
///
/// Pipeline (each step bails on first error):
///
/// 1. Verify the sender's ed25519 signature over canonical bundle bytes.
/// 2. Resolve identity: if `manifest.metadata["nickname"]` is present, the
///    configured `IdentityResolver` locks the binding (TOFU first-sight) or
///    rejects a mismatched DID. Bypassed when `naively_allow_unknown_handles_fallback`.
/// 3. Validate `block_kind` against `allowed_block_kinds`.
/// 4. Update the local HLC clock against the received timestamp.
/// 5. Build a server-signed synthetic receipt (Wasm exec wired in Phase D).
/// 6. Apply effects (channels/memberships/peers — Task B7 stub).
/// 7. Persist block + receipt.
/// 8. Fanout: local subscribers always; federated peers only if source
///    isn't itself a federated peer (loop avoidance).
pub async fn ingest(
    ctx: &IngestContext,
    bundle: BlockBundle<'_>,
    sig: Vec<u8>,
    source: IngestSource,
) -> Result<String, IngestError> {
    // Parse the manifest from canonical bytes on the bundle.
    let manifest = parse_manifest(bundle.manifest_bytes)?;

    // Step 1: signature verification
    verify_sig(bundle.manifest_bytes, bundle.code_bytes, &manifest, &sig)?;

    // Step 2: identity resolution (TOFU lock / nameserver verify).
    //
    // v0.0.2 blocks have no first-class nickname field; we read it from
    // `manifest.metadata["nickname"]` when present. Blocks that omit the
    // nickname are not subject to the lock at ingest time — the carve-out
    // is documented in the H5 integration test. v0.0.3+ promotes channel/
    // membership blocks to carry the identifier explicitly.
    if let Some(nickname) = manifest.metadata.get("nickname").and_then(|v| v.as_str()) {
        let sender_did = manifest
            .authors
            .first()
            .map(|a| a.did.to_string())
            .unwrap_or_default();
        match ctx.identity.verify(nickname, &sender_did).await {
            Ok(()) => {}
            Err(err) => {
                if ctx.naively_allow_unknown_handles_fallback {
                    tracing::warn!(
                        nickname = %nickname,
                        sender_did = %sender_did,
                        error = %err,
                        "identity.naively_allow_unknown_handles_fallback=true: \
                         admitting block despite identity-resolver rejection \
                         (unsafe carve-out; lift in v0.0.3+)"
                    );
                } else {
                    return Err(IngestError::Identity(err));
                }
            }
        }
    }

    // Step 3: block-kind whitelist
    let kind = manifest.kind.ok_or(IngestError::KindRequired)?;
    let kind_str = kind.as_str();
    if !ctx.allowed_block_kinds.iter().any(|k| k == kind_str) {
        return Err(IngestError::DisallowedBlockKind {
            kind: kind_str.to_string(),
        });
    }

    // Step 3: HLC update on receive
    let wall_now_ms = chrono::Utc::now().timestamp_millis() as u64;
    if let Some(recv_ts) = manifest.hlc_ts.clone() {
        let _local = ctx.hlc_clock.update_on_receive(recv_ts, wall_now_ms);
    } else {
        ctx.hlc_clock.observe_at_wall_ms(wall_now_ms);
    }

    // Step 4: Wasm-exec or synthetic-receipt branch.
    //
    // v0.0.2 B6: all kinds — including TextRender which `is_wasm_executable()`
    // returns true for — use the synthetic receipt path. Phase D replaces this
    // for TextRender once text-render.wasm is loaded into jig-runtime.
    let block_cid = bundle
        .block_cid()
        .map(|c| c.to_string())
        .unwrap_or_else(|_| "bafy_invalid".to_string());
    let (receipt_bytes, render_hash, is_synthetic) =
        build_synth_receipt(&block_cid, &ctx.server_did, &ctx.server_key);

    // Step 5: apply effect (B7 stub returns Ok)
    let canonical = bundle_canonical_bytes(bundle.manifest_bytes, bundle.code_bytes)
        .map_err(IngestError::BundleMalformed)?;
    crate::effect::apply_effect(&ctx.store, &bundle, &receipt_bytes, &block_cid).await?;

    // Step 6: persist block + receipt
    let sender_did_str = manifest
        .authors
        .first()
        .map(|a| a.did.to_string())
        .unwrap_or_default();
    let hlc = manifest.hlc_ts.as_ref();
    let stored_block = StoredBlock {
        cid: block_cid.clone(),
        // Lift the channel slug from manifest metadata into the first-class
        // column so channel-scoped fanout + the bridge sink can find it.
        // text-render / member-add use metadata["channel"]; channel-create
        // uses metadata["slug"].
        channel_id: manifest
            .metadata
            .get("channel")
            .or_else(|| manifest.metadata.get("slug"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        block_kind: kind_str.to_string(),
        sender_did: sender_did_str,
        sender_sig: sig,
        bundle_bytes: canonical,
        is_synthetic,
        hlc_wall_ms: hlc.map(|h| h.wall_ms).unwrap_or(0),
        hlc_logical: hlc.map(|h| h.logical).unwrap_or(0),
        hlc_origin: hlc.map(|h| h.server_did.to_string()).unwrap_or_default(),
        posted_at: chrono::Utc::now().timestamp(),
        origin_server: match &source {
            IngestSource::FederatedPeer { peer_url, .. } => peer_url.clone(),
            _ => ctx.server_url.clone(),
        },
        federated_from: match &source {
            IngestSource::FederatedPeer { peer_url, .. } => Some(peer_url.clone()),
            _ => None,
        },
    };
    ctx.store.insert_block(&stored_block)?;

    let receipt_cid = format!("r_{}", &block_cid[..16.min(block_cid.len())]);
    let stored_receipt = StoredReceipt {
        cid: receipt_cid,
        block_cid: block_cid.clone(),
        server_id: ctx.server_did.to_string(),
        receipt_bytes,
        render_hash,
        produced_at: chrono::Utc::now().timestamp(),
    };
    ctx.store.insert_receipt(&stored_receipt)?;

    // Channel membership for bridge-sink dispatch. `channel_id` here is the
    // channel SLUG (lifted from manifest metadata), but memberships are keyed
    // by the channel's CID (its channel-create block CID). Resolve slug -> CID
    // via get_channel_by_slug before listing members; empty if the channel row
    // doesn't exist yet or has no members.
    let member_dids: Vec<String> = match stored_block.channel_id.as_deref() {
        Some(slug) => match ctx.store.get_channel_by_slug(slug) {
            Ok(Some(chan)) => ctx
                .store
                .list_members(&chan.id)
                .map(|ms| ms.into_iter().map(|m| m.member_did).collect())
                .unwrap_or_default(),
            _ => Vec::new(),
        },
        None => Vec::new(),
    };

    // Step 7: fanout — broadcast policy depends on source
    match source {
        IngestSource::FederatedPeer { .. } => {
            // Federated source: locals + bridge sinks, but NOT re-broadcast to
            // peers (would cause a relay loop).
            ctx.fanout
                .broadcast_local_only(&stored_block, &stored_receipt)
                .await
                .map_err(IngestError::Other)?;
            ctx.fanout
                .dispatch_to_bridges_public(&stored_block, &stored_receipt, &member_dids)
                .await;
        }
        IngestSource::LocalClient { .. } | IngestSource::AdminEndpoint | IngestSource::Bridge => {
            ctx.fanout
                .broadcast_with_members(&stored_block, &stored_receipt, &member_dids)
                .await
                .map_err(IngestError::Other)?;
        }
    }

    Ok(block_cid)
}

// ---- Bundle / manifest helpers --------------------------------------------

/// Parse the manifest from raw bytes. The manifest_bytes field of BlockBundle
/// is the canonical JSON serialisation of BlockManifest.
fn parse_manifest(manifest_bytes: &[u8]) -> Result<jig_core::BlockManifest, IngestError> {
    serde_json::from_slice(manifest_bytes)
        .map_err(|e| IngestError::BundleMalformed(format!("manifest parse: {e}")))
}

/// Canonical bytes over which signatures and CIDs are computed.
///
/// Serialise (manifest_bytes, code_bytes) as a JSON tuple — the same
/// representation used by the test bundle builder so signatures produced
/// in tests match what ingest verifies.
fn bundle_canonical_bytes(manifest_bytes: &[u8], code_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let payload = (manifest_bytes, code_bytes);
    serde_json::to_vec(&payload).map_err(|e| e.to_string())
}

/// Verify the sender's ed25519 signature over the bundle's canonical bytes.
///
/// The signer is the first author in the manifest. If the DID is not in
/// canonical `did:jig:z<base32>` form (e.g. a legacy test DID), decoding
/// fails and we return `InvalidSignature` — no opaque-label fallback,
/// because the ingest pipeline must never accept an unverifiable signature.
fn verify_sig(
    manifest_bytes: &[u8],
    code_bytes: &[u8],
    manifest: &jig_core::BlockManifest,
    sig: &[u8],
) -> Result<(), IngestError> {
    let sender_did = manifest
        .authors
        .first()
        .map(|a| a.did.clone())
        .unwrap_or_default();

    let pubkey_bytes = sender_did
        .as_bytes()
        .map_err(|_| IngestError::InvalidSignature)?;
    let pubkey =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| IngestError::InvalidSignature)?;
    let signature = Signature::from_slice(sig).map_err(|_| IngestError::InvalidSignature)?;
    let canonical = bundle_canonical_bytes(manifest_bytes, code_bytes)
        .map_err(|_| IngestError::InvalidSignature)?;
    pubkey
        .verify(&canonical, &signature)
        .map_err(|_| IngestError::InvalidSignature)?;
    Ok(())
}

/// Build a server-signed synthetic receipt for blocks that lack a Wasm artifact.
///
/// The receipt carries the server DID and a signature over a small JSON
/// payload so clients can verify the server received and persisted the block.
/// Phase D replaces this for `TextRender` once text-render.wasm is loaded.
fn build_synth_receipt(
    block_cid: &str,
    server_did: &Did,
    server_key: &ed25519_dalek::SigningKey,
) -> (Vec<u8>, Option<String>, bool) {
    use ed25519_dalek::Signer;

    let canonical = serde_json::to_vec(&serde_json::json!({
        "v": "0.2-synthetic",
        "block_cid": block_cid,
        "server_did": server_did.to_string(),
        "synthetic": true,
        "produced_at": chrono::Utc::now().timestamp(),
    }))
    .expect("synthetic receipt JSON is always valid");

    let sig = server_key.sign(&canonical);

    let wrapped = serde_json::json!({
        "canonical_hex": hex::encode(&canonical),
        "sig_hex": hex::encode(sig.to_bytes()),
    });
    let bytes = serde_json::to_vec(&wrapped).expect("synthetic receipt wrap is always valid");

    // render_hash is None for synthetic receipts (no Wasm execution output).
    (bytes, None, true)
}

// ---- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use jig_core::{Author, BlockKind, BlockManifest};
    use semver::Version;

    /// Generate a random SigningKey without requiring the rand_core feature
    /// on ed25519-dalek. We generate 32 raw bytes via rand and pass them to
    /// `SigningKey::from_bytes`.
    fn random_signing_key() -> SigningKey {
        let secret: [u8; 32] = rand::random();
        SigningKey::from_bytes(&secret)
    }

    fn test_ctx() -> IngestContext {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let server_key = random_signing_key();
        let server_did = Did::from_ed25519_pubkey(server_key.verifying_key().as_bytes());
        IngestContext {
            store: store.clone(),
            identity: Arc::new(crate::identity::TofuResolver::new(store)),
            hlc_clock: Arc::new(HlcClock::new(server_did.clone())),
            allowed_block_kinds: vec!["text-render".to_string()],
            server_did,
            server_key,
            fanout: Arc::new(Fanout::new()),
            server_url: "ws://127.0.0.1:7117".to_string(),
            naively_allow_unknown_handles_fallback: false,
        }
    }

    /// Build manifest bytes, code bytes, and a valid signature for a given BlockKind.
    fn build_bundle_parts(
        signing_key: &SigningKey,
        kind: BlockKind,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let sender_did = Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: sender_did,
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap()
            .with_kind(kind);
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let code_bytes: Vec<u8> = vec![];
        let canonical = serde_json::to_vec(&(&manifest_bytes, &code_bytes)).unwrap();
        let sig = signing_key.sign(&canonical).to_bytes().to_vec();
        (manifest_bytes, code_bytes, sig)
    }

    /// Like `build_bundle_parts` but sets `metadata["channel"]` so we can test
    /// the channel_id lift. jig-pipeline can't use jig-client (dep cycle), so
    /// we set metadata directly on the manifest.
    fn build_bundle_parts_with_channel(
        signing_key: &SigningKey,
        kind: BlockKind,
        channel: &str,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let sender_did = Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());
        let mut manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: sender_did,
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap()
            .with_kind(kind);
        manifest
            .metadata
            .insert("channel".to_string(), serde_json::json!(channel));
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let code_bytes: Vec<u8> = vec![];
        let canonical = serde_json::to_vec(&(&manifest_bytes, &code_bytes)).unwrap();
        let sig = signing_key.sign(&canonical).to_bytes().to_vec();
        (manifest_bytes, code_bytes, sig)
    }

    /// Ingest from owned vecs. Uses Box::leak to satisfy BlockBundle's reference
    /// lifetimes — intentional test-only leak (bounded; one per test invocation).
    async fn do_ingest(
        ctx: &IngestContext,
        manifest_bytes: Vec<u8>,
        code_bytes: Vec<u8>,
        sig: Vec<u8>,
        source: IngestSource,
    ) -> Result<String, IngestError> {
        let manifest_static: &'static [u8] = Box::leak(manifest_bytes.into_boxed_slice());
        let code_static: &'static [u8] = Box::leak(code_bytes.into_boxed_slice());
        let bundle = BlockBundle {
            manifest_bytes: manifest_static,
            code_bytes: code_static,
            resources: vec![],
        };
        ingest(ctx, bundle, sig, source).await
    }

    #[tokio::test]
    async fn ingest_persists_block_and_receipt() {
        let ctx = test_ctx();
        let sender_key = random_signing_key();
        let (mb, cb, sig) = build_bundle_parts(&sender_key, BlockKind::TextRender);

        let block_cid = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap();

        assert!(ctx.store.get_block(&block_cid).unwrap().is_some());
        let receipts = ctx.store.get_receipts_for_block(&block_cid).unwrap();
        assert_eq!(receipts.len(), 1);
        // Synthetic receipts have no render hash
        assert!(receipts[0].render_hash.is_none());
    }

    #[tokio::test]
    async fn ingest_rejects_disallowed_kind() {
        let ctx = test_ctx(); // allowed_block_kinds = ["text-render"]
        let sender_key = random_signing_key();
        let (mb, cb, sig) = build_bundle_parts(&sender_key, BlockKind::ChannelCreate);

        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap_err();
        assert!(matches!(err, IngestError::DisallowedBlockKind { .. }));
    }

    #[tokio::test]
    async fn ingest_rejects_bad_signature() {
        let ctx = test_ctx();
        let sender_key = random_signing_key();
        let (mb, cb, _good_sig) = build_bundle_parts(&sender_key, BlockKind::TextRender);
        let bad_sig = vec![0u8; 64];

        let err = do_ingest(
            &ctx,
            mb,
            cb,
            bad_sig,
            IngestSource::LocalClient { conn_id: 1 },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IngestError::InvalidSignature));
    }

    #[tokio::test]
    async fn ingest_lifts_channel_id_from_metadata() {
        let ctx = test_ctx(); // allows "text-render"
        let sender_key = random_signing_key();
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&sender_key, BlockKind::TextRender, "#hello");
        let cid = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap();
        let stored = ctx.store.get_block(&cid).unwrap().unwrap();
        assert_eq!(stored.channel_id.as_deref(), Some("#hello"));
    }

    #[tokio::test]
    async fn ingest_dispatches_to_bridge_sink_for_managed_member() {
        use crate::persist::{StoredChannel, StoredMembership};
        let ctx = test_ctx(); // allows "text-render"
        let bob_key = random_signing_key();
        let bob_did = Did::from_ed25519_pubkey(bob_key.verifying_key().as_bytes()).to_string();

        // A shadow DID for alice, registered as a bridge sink.
        let shadow = "did:jig:zShadowAlice".to_string();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ctx.fanout.register_bridge_did(shadow.clone(), tx).await;

        // Channel "#dm/x" with members [bob, shadow].
        ctx.store
            .upsert_channel(&StoredChannel {
                id: "#dm/x".into(),
                slug: "#dm/x".into(),
                visibility: "restricted".into(),
                created_at: 0,
                owner_did: bob_did.clone(),
            })
            .unwrap();
        for did in [bob_did.clone(), shadow.clone()] {
            ctx.store
                .upsert_membership(&StoredMembership {
                    channel_id: "#dm/x".into(),
                    member_did: did,
                    role: "member".into(),
                    joined_at: 0,
                    source_block_cid: "seed".into(),
                })
                .unwrap();
        }

        // bob posts a text-render to #dm/x.
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&bob_key, BlockKind::TextRender, "#dm/x");
        do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("bridge sink should receive within timeout")
            .expect("a delivery");
        assert_eq!(got.0.channel_id.as_deref(), Some("#dm/x"));
        assert_eq!(got.0.sender_did, bob_did);
    }

    #[tokio::test]
    async fn bridge_sink_resolves_slug_to_channel_cid_for_members() {
        // Regression: memberships are keyed by the channel's CID, not its slug.
        // The prior dispatch used `list_members(slug)` which returns nothing when
        // `channel.id != channel.slug` (the realistic shape from channel-create).
        // This test stores channel.id = "bafyCID_xyz" and channel.slug = "#dm/z"
        // and verifies the bridge sink still fires.
        use crate::persist::{StoredChannel, StoredMembership};
        let ctx = test_ctx(); // allows "text-render"
        let bob_key = random_signing_key();
        let bob_did = Did::from_ed25519_pubkey(bob_key.verifying_key().as_bytes()).to_string();

        // A shadow DID for alice, registered as a bridge sink.
        let shadow = "did:jig:zShadowAliceCID".to_string();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ctx.fanout.register_bridge_did(shadow.clone(), tx).await;

        // Channel stored with a CID as id (distinct from slug) — realistic
        // shape written by channel-create effect handling.
        let channel_cid = "bafyCID_xyz".to_string();
        ctx.store
            .upsert_channel(&StoredChannel {
                id: channel_cid.clone(),
                slug: "#dm/z".into(),
                visibility: "restricted".into(),
                created_at: 0,
                owner_did: bob_did.clone(),
            })
            .unwrap();
        // Memberships are keyed by the CID, not the slug.
        for did in [bob_did.clone(), shadow.clone()] {
            ctx.store
                .upsert_membership(&StoredMembership {
                    channel_id: channel_cid.clone(),
                    member_did: did,
                    role: "member".into(),
                    joined_at: 0,
                    source_block_cid: "seed".into(),
                })
                .unwrap();
        }

        // bob posts a text-render to #dm/z (the slug — what manifest metadata carries).
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&bob_key, BlockKind::TextRender, "#dm/z");
        do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("bridge sink should receive within timeout — slug->CID resolution must fire")
            .expect("a delivery");
        assert_eq!(got.0.channel_id.as_deref(), Some("#dm/z"));
        assert_eq!(got.0.sender_did, bob_did);
    }

    #[tokio::test]
    async fn ingest_bridge_source_broadcasts_like_local() {
        // A block ingested with IngestSource::Bridge should reach a local
        // channel subscriber (full broadcast), same as LocalClient.
        let ctx = test_ctx();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ctx.fanout
            .subscribe_local(
                crate::fanout::SubscriptionScope::Channel("#dm/y".to_string()),
                tx,
            )
            .await;
        let key = random_signing_key();
        let (mb, cb, sig) = build_bundle_parts_with_channel(&key, BlockKind::TextRender, "#dm/y");
        do_ingest(&ctx, mb, cb, sig, IngestSource::Bridge)
            .await
            .unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("local sub should receive")
            .expect("a delivery");
        assert_eq!(got.0.channel_id.as_deref(), Some("#dm/y"));
    }
}
