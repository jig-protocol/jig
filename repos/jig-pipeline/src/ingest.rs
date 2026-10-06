//! Unified block ingest pipeline.
//!
//! Every block — local-client-submitted, federated-peer-relayed, or
//! admin-endpoint-injected — flows through `ingest()`. The same function
//! drives `jig-server` and (with a different allowed_block_kinds list)
//! `jig-nameserver`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jig_core::{BlockBundle, BlockKind, Did};
use std::sync::Arc;

use crate::fanout::{DeliveryPolicy, Fanout};
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
/// Gate 2 for writes: will this server deal with `sender_did` at all?
///
/// The decision lives with the server (it owns the policy and the reputation
/// view); the pipeline only asks. Called on the author DID **after** the
/// block's signature has verified against it — so the DID is established,
/// never merely claimed — and before anything is looked up, applied or
/// signed.
pub trait Admission: Send + Sync {
    fn admit(&self, sender_did: &str) -> Result<(), AdmissionRefusal>;
}

/// Why admission said no. Mirrors the server's admission outcomes without
/// the pipeline depending on the server's types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRefusal {
    /// This server does not admit identities it has no record of.
    Unknown,
    /// The sender's score under `ruleset_key` is below this server's floor.
    BelowRuleset { ruleset_key: String },
    /// This server refuses the sender outright.
    Banned,
}

impl std::fmt::Display for AdmissionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("this server does not admit unknown identities"),
            Self::BelowRuleset { ruleset_key } => write!(
                f,
                "reputation under ruleset {ruleset_key} is below this server's floor"
            ),
            Self::Banned => f.write_str("this identity is refused by this server"),
        }
    }
}

/// The admission policy of a context that has none: everyone is admitted.
/// The nameserver and tests use it; the server installs its own.
pub struct AdmitEveryone;

impl Admission for AdmitEveryone {
    fn admit(&self, _sender_did: &str) -> Result<(), AdmissionRefusal> {
        Ok(())
    }
}

pub struct IngestContext {
    pub store: Arc<SqliteStore>,
    pub identity: Arc<dyn IdentityResolver>,
    /// Gate 2 for every write, whichever surface it arrived on.
    pub admission: Arc<dyn Admission>,
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
    /// Executes canonical Wasm block modules, holding them pre-compiled.
    ///
    /// `None` is a statement that this server does not execute Wasm-backed kinds
    /// — the nameserver, whose `allowed_block_kinds` excludes `text-render`, has
    /// no use for a text-render module and should not pay to compile one.
    ///
    /// It is **not** a fallback to the synthetic-receipt path. A `text-render`
    /// block arriving with no executor is rejected
    /// ([`IngestError::NoExecutor`]), because silently issuing a receipt with no
    /// `render_hash` is exactly the carve-out this replaced: it would look like
    /// success while the block never executed.
    pub executor: Option<Arc<crate::executor::BlockExecutor>>,
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
    /// The manifest's schema or encryption suite is one this server does not
    /// speak. Checked before the signature: what the signature covers is
    /// defined by the schema.
    #[error(transparent)]
    ManifestGate(#[from] jig_core::ManifestGateError),
    /// A channel-scoped block named a channel this server has no row for.
    /// The message is user-facing: it is what a mistyped `jig send` prints.
    #[error(
        "unknown channel '{slug}': create it with `jig channel create` or check `jig channel list`"
    )]
    UnknownChannel { slug: String },
    /// A block of a kind that must execute arrived at a server with no executor
    /// configured. Deliberately an error rather than a synthetic-receipt
    /// fallback — see [`IngestContext::executor`].
    #[error(
        "this server has no Wasm executor configured, so it cannot accept `{kind}` \
         blocks (they must execute to produce a render_hash)"
    )]
    NoExecutor { kind: String },
    /// A required metadata field is absent. `text-render` carries its message in
    /// `metadata.body`; without it there is nothing to render, and rendering the
    /// empty string instead would silently hash a message nobody sent.
    #[error("`{kind}` block is missing required metadata field `{field}`")]
    MissingMetadata { kind: String, field: String },
    /// The module ran but did not produce a usable result.
    ///
    /// Rejecting is deliberate: a receipt without a real `render_hash` cannot
    /// participate in cross-server parity, so admitting the block would record a
    /// message that no peer can verify against. The cost is that a transient host
    /// problem (the wall-clock epoch deadline firing under extreme load) rejects
    /// a legitimate message — visible and loud, rather than a quietly degraded
    /// receipt.
    #[error("executing the `{kind}` module failed: {detail}")]
    RenderFailed { kind: String, detail: String },
    /// A control-plane block was signed by someone the channel does not
    /// answer to. See [`crate::authorize_write`] for the rules.
    #[error("`{kind}` on `{slug}` refused: `{sender}` is not the channel owner")]
    NotChannelOwner {
        kind: String,
        slug: String,
        sender: String,
    },
    /// Gate 2 refused the block's author. Precedes every other check but
    /// the signature: a refused caller learns nothing about channels here.
    #[error("`{sender}` is not admitted: {refusal}")]
    NotAdmitted {
        sender: String,
        refusal: AdmissionRefusal,
    },
    /// The named channel was archived: retired, its history kept, nothing new
    /// accepted into it — by any kind, from any source.
    #[error("channel '{slug}' is archived and accepts no new blocks")]
    ChannelArchived { slug: String },
    /// This exact block (by CID) was already ingested. Refused before any
    /// effect runs: an accepted control-plane block is otherwise a standing
    /// authorization anyone holding its bytes can replay — re-enrolling a
    /// member the owner has since removed, for instance.
    #[error("block `{cid}` was already ingested")]
    DuplicateBlock { cid: String },
    /// A channel-create for a slug this server already has, live or archived.
    /// Archived slugs stay taken: the old timeline still lives under them.
    #[error("channel '{slug}' already exists")]
    ChannelExists { slug: String },
    /// Content for a restricted channel from someone who is neither a member
    /// nor its owner. See [`crate::authorize_write`].
    #[error("`{kind}` on `{slug}` refused: `{sender}` is not a member of the channel")]
    NotChannelMember {
        kind: String,
        slug: String,
        sender: String,
    },
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
/// 4. Reject channel-scoped blocks naming a channel this server has no row
///    for (see [`requires_existing_channel`] for the per-source policy).
/// 5. Update the local HLC clock against the received timestamp.
/// 6. Build a server-signed receipt. `text-render` EXECUTES the server's own
///    canonical Wasm module and signs the resulting `render_hash`; other kinds
///    are control-plane blocks with no rendered output and take the synthetic
///    path.
/// 7. Apply effects (channels/memberships/peers — Task B7 stub).
/// 8. Persist block + receipt.
/// 9. Fanout: local subscribers always; federated peers only if source
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
    let sender = verify_sig(bundle.manifest_bytes, bundle.code_bytes, &manifest, &sig)?;

    // Step 1b: admission, on the DID the signature just established. Before
    // the identity resolver, the kind whitelist and every channel lookup: a
    // caller this server will not deal with gets exactly one answer, whatever
    // they asked.
    if let Err(refusal) = ctx.admission.admit(sender.as_str()) {
        tracing::info!(sender = %sender, refusal = %refusal, "write refused at admission");
        return Err(IngestError::NotAdmitted {
            sender: sender.to_did_jig_string(),
            refusal,
        });
    }

    // Step 2: identity resolution (TOFU lock / nameserver verify).
    //
    // v0.0.2 blocks have no first-class nickname field; we read it from
    // `manifest.metadata["nickname"]` when present. Blocks that omit the
    // nickname are not subject to the lock at ingest time — the carve-out
    // is documented in the H5 integration test. v0.0.3+ promotes channel/
    // membership blocks to carry the identifier explicitly.
    if let Some(nickname) = manifest.metadata.get("nickname").and_then(|v| v.as_str()) {
        // The canonical DID the signature established — so a pin is written
        // and compared in one spelling, whatever the manifest carried.
        let sender_did = sender.to_did_jig_string();
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

    // Step 3b: channel-existence guard for channel-scoped kinds.
    //
    // Resolved once here and reused for the bridge-sink member lookup after
    // persist, so the guard costs no extra query. `channel_slug_of` is the ONE
    // rule for which metadata key names a block's channel; the persisted
    // `channel_id` below uses the same call, so the channel that is gated is
    // the channel the block lands in.
    let channel_slug = channel_slug_of(kind, &manifest);
    let mut resolved_channel = match channel_slug {
        Some(slug) => ctx.store.get_channel_by_slug(slug)?,
        None => None,
    };
    // A live row is what writes need. No live row but an archived one means
    // the channel was retired: nothing goes into it, from any source, of any
    // kind — otherwise a kind the write gate does not know would resolve to
    // "no channel", pass the gate, and land in the archived timeline the read
    // gate still guards.
    if let Some(slug) = channel_slug
        && resolved_channel.is_none()
        && kind != BlockKind::ChannelCreate
        && ctx
            .store
            .get_channel_by_slug_including_archived(slug)?
            .is_some()
    {
        return Err(IngestError::ChannelArchived {
            slug: slug.to_string(),
        });
    }
    if let Some(slug) = channel_slug
        && resolved_channel.is_none()
        && requires_existing_channel(kind, &source)
    {
        return Err(IngestError::UnknownChannel {
            slug: slug.to_string(),
        });
    }

    // Step 3c: write authorization — may this sender post to, or change,
    // this channel?
    //
    // Here rather than in `apply_effect` so a refusal is a typed error every
    // surface classifies the same way, instead of an `anyhow` 500. Runs before
    // the receipt is built: a block this server will not apply must not carry
    // this server's signature. The membership query runs only when the
    // decision can turn on it (content into a restricted channel).
    let sender_is_member =
        if crate::authorize_write::needs_membership(kind, resolved_channel.as_ref()) {
            match channel_slug {
                Some(slug) => ctx.store.is_member(slug, sender.as_str())?,
                None => false,
            }
        } else {
            false
        };
    if let Err(refusal) = crate::authorize_write::authorize_block(
        kind,
        sender.as_str(),
        &manifest,
        resolved_channel.as_ref(),
        sender_is_member,
    ) {
        use crate::authorize_write::WriteRefusal;
        // The audit record of what actually happened, independent of what any
        // surface tells the caller — the same rule the read gates follow.
        tracing::info!(kind = kind_str, refusal = ?refusal, "write refused");
        let kind = kind_str.to_string();
        return Err(match refusal {
            WriteRefusal::NotChannelOwner { slug, sender } => {
                IngestError::NotChannelOwner { kind, slug, sender }
            }
            WriteRefusal::NotChannelMember { slug, sender } => {
                IngestError::NotChannelMember { kind, slug, sender }
            }
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
    // `text-render` executes for real: the server runs its OWN canonical module
    // over the message body and signs the resulting `render_hash`. That hash is
    // computed INSIDE the sandbox, which is what lets two servers agree on it
    // without trusting each other.
    //
    // Every other kind still takes the synthetic path. Those are control-plane
    // blocks (channel-create, member-add, …) whose effect is applied by
    // `apply_effect`; they have no rendered output to hash. Promoting them is a
    // separate piece of work, not an oversight.
    let block_cid = bundle
        .block_cid()
        .map(|c| c.to_string())
        .unwrap_or_else(|_| "bafy_invalid".to_string());

    // Step 3d: a block is ingested once. The `blocks.cid` primary key would
    // refuse the second insert anyway, but `apply_effect` runs BEFORE that
    // insert, so without this check a replayed member-add had already
    // re-created the membership by the time the insert failed.
    if ctx.store.get_block(&block_cid)?.is_some() {
        return Err(IngestError::DuplicateBlock { cid: block_cid });
    }
    // Step 3e: a slug names one channel. Without this, `apply_effect` hits the
    // `channels.slug` UNIQUE constraint and the caller gets an opaque 500.
    // After the signature, admission and write gates, so an unauthenticated
    // caller cannot use it to probe which slugs exist.
    if kind == BlockKind::ChannelCreate
        && let Some(slug) = channel_slug
        && ctx
            .store
            .get_channel_by_slug_including_archived(slug)?
            .is_some()
    {
        return Err(IngestError::ChannelExists {
            slug: slug.to_string(),
        });
    }
    let (receipt_bytes, render_hash, is_synthetic) = match kind {
        BlockKind::TextRender => build_render_receipt(ctx, &manifest, &block_cid, kind_str).await?,
        _ => build_synth_receipt(&block_cid, &ctx.server_did, &ctx.server_key),
    };

    // Step 5: apply effect (B7 stub returns Ok)
    let canonical = bundle_canonical_bytes(bundle.manifest_bytes, bundle.code_bytes)
        .map_err(IngestError::BundleMalformed)?;
    crate::effect::apply_effect(&ctx.store, &bundle, &receipt_bytes, &block_cid).await?;

    // Step 6: persist block + receipt
    // Canonical, from the verified key — the spelling every gate compares.
    let sender_did_str = sender.to_did_jig_string();
    let hlc = manifest.hlc_ts.as_ref();
    let stored_block = StoredBlock {
        cid: block_cid.clone(),
        // Lift the channel slug from manifest metadata into the first-class
        // column so channel-scoped fanout + the bridge sink can find it. Same
        // rule as step 3b, by construction: a block is stored under exactly
        // the channel the write gate examined.
        channel_id: channel_slug.map(|s| s.to_string()),
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
    // by the channel's CID (its channel-create block CID). Step 3b resolved
    // the row BEFORE `apply_effect`; a control-plane block has just changed
    // that row (channel-create wrote it, channel-promote flipped its
    // visibility), so it is resolved again for those kinds. Content kinds
    // change nothing and keep the row already in hand.
    //
    // The same facts decide who may RECEIVE the block: they become the
    // `DeliveryPolicy` fanout checks per subscriber, so the delivery loop
    // itself does no I/O. A store error here must narrow delivery, never
    // widen it — a policy that names nobody is what "we could not find out"
    // looks like to an identified subscriber.
    let mut lookup_failed = false;
    let effect_may_have_changed_the_row = !matches!(
        kind,
        BlockKind::TextRender | BlockKind::EmailRender | BlockKind::EmailEncrypted
    );
    if (resolved_channel.is_none() || effect_may_have_changed_the_row)
        && let Some(slug) = stored_block.channel_id.as_deref()
    {
        // Archived rows included: a channel-archive has just set
        // `archived_at`, and its own block must still be delivered under the
        // channel's policy rather than to everyone because the live lookup
        // stopped finding it.
        match ctx.store.get_channel_by_slug_including_archived(slug) {
            Ok(row) => resolved_channel = row,
            Err(e) => {
                tracing::warn!(slug, error = %e, "channel lookup failed at fanout; denying");
                lookup_failed = true;
            }
        }
    }
    let policy = if lookup_failed {
        Some(DeliveryPolicy::default())
    } else {
        resolved_channel.as_ref().map(|chan| {
            let member_dids = ctx
                .store
                .list_members(&chan.id)
                .map(|ms| ms.into_iter().map(|m| m.member_did).collect())
                .unwrap_or_else(|e| {
                    tracing::warn!(slug = %chan.slug, error = %e, "member lookup failed at fanout; denying members");
                    Vec::new()
                });
            DeliveryPolicy::for_channel(chan, member_dids)
        })
    };

    // Step 7: fanout — broadcast policy depends on source
    match source {
        IngestSource::FederatedPeer { .. } => {
            // Federated source: locals + bridge sinks, but NOT re-broadcast to
            // peers (would cause a relay loop).
            ctx.fanout
                .broadcast_local_only(&stored_block, &stored_receipt, policy.as_ref())
                .await
                .map_err(IngestError::Other)?;
            ctx.fanout
                .dispatch_to_bridges_public(&stored_block, &stored_receipt, policy.as_ref())
                .await;
        }
        IngestSource::LocalClient { .. } | IngestSource::AdminEndpoint | IngestSource::Bridge => {
            ctx.fanout
                .broadcast_with_members(&stored_block, &stored_receipt, policy.as_ref())
                .await
                .map_err(IngestError::Other)?;
        }
    }

    Ok(block_cid)
}

/// The channel a block belongs to, from its manifest metadata — the one rule
/// shared by the write gate, the persisted `channel_id` column, fanout and
/// the metrics label.
///
/// `channel-create` names the channel it creates under `slug`; every other
/// kind names the channel it acts on under `channel`. The key is chosen by
/// KIND, never by "whichever is present": when the gate read one key and the
/// store wrote another, a block could be authorized against no channel and
/// then land in a restricted one.
pub fn channel_slug_of(kind: BlockKind, manifest: &jig_core::BlockManifest) -> Option<&str> {
    manifest
        .metadata
        .get(channel_metadata_key(kind))
        .and_then(|v| v.as_str())
}

/// The metadata key under which a block of `kind` names its channel. See
/// [`channel_slug_of`]; exposed for callers that peek at raw metadata.
pub fn channel_metadata_key(kind: BlockKind) -> &'static str {
    match kind {
        BlockKind::ChannelCreate => "slug",
        _ => "channel",
    }
}

/// Whether a block of `kind` arriving from `source` must name a channel that
/// already exists on this server.
///
/// Locally-submitted `text-render` is the case that matters: before this check,
/// a mistyped slug persisted an orphan block and handed the sender a CID, so a
/// typo was indistinguishable from a delivered message.
///
/// Federated blocks are deliberately EXEMPT. Channel and membership state does
/// not replicate between peers — jig-server's federation relay persists inbound
/// blocks without running `apply_effect` — so a peer's block routinely names a
/// channel this server has no row for. Gating on local channel state would
/// reject legitimate federated traffic.
///
/// Bridges are deliberately NOT exempt. The email bridge awaits
/// `ensure_dm_channel` (a real channel-create through this same pipeline) before
/// it submits a `text-render`, so an unknown channel from a bridge means the
/// ensure step silently failed — worth surfacing loudly rather than writing an
/// orphan block nobody will ever read.
///
/// `channel-create` names the channel it is creating, so it is exempt. The
/// membership and lifecycle kinds are NOT: they used to resolve the channel
/// inside `apply_effect` and surface a miss as an untyped 500, and the admin
/// archive route compensated with its own store lookup ahead of `ingest` —
/// which made that route an oracle for channel existence and ownership to
/// callers who had proved nothing. The typed 404 here is what lets every
/// surface answer only after the signature and admission have passed.
fn requires_existing_channel(kind: BlockKind, source: &IngestSource) -> bool {
    if matches!(source, IngestSource::FederatedPeer { .. }) {
        return false;
    }
    matches!(
        kind,
        BlockKind::TextRender
            | BlockKind::MemberAdd
            | BlockKind::ChannelPromote
            | BlockKind::ChannelArchive
    )
}

// ---- Bundle / manifest helpers --------------------------------------------

/// Parse the manifest from raw bytes. The manifest_bytes field of BlockBundle
/// is the canonical JSON serialisation of BlockManifest.
fn parse_manifest(manifest_bytes: &[u8]) -> Result<jig_core::BlockManifest, IngestError> {
    let manifest: jig_core::BlockManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| IngestError::BundleMalformed(format!("manifest parse: {e}")))?;
    manifest.check_gates()?;
    Ok(manifest)
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
/// Verify the author's signature and return the author's DID in canonical
/// form — rebuilt from the key the signature verified against, not the
/// spelling the manifest carried, so every downstream comparison sees one
/// form.
fn verify_sig(
    manifest_bytes: &[u8],
    code_bytes: &[u8],
    manifest: &jig_core::BlockManifest,
    sig: &[u8],
) -> Result<Did, IngestError> {
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
    Ok(Did::from_ed25519_pubkey(&pubkey_bytes))
}

/// Execute the canonical text-render module and build a server-signed receipt
/// carrying the resulting `render_hash`.
///
/// Returns `(receipt_bytes, Some(render_hash), is_synthetic = false)`.
///
/// # What is signed, and why the shape matters
///
/// The payload separates two kinds of claim, because they have different
/// standing:
///
/// - `render` — the `render_hash`, the identity of the module that produced it,
///   and the rendered length. Reproducible: any conforming runtime executing the
///   same module over the same body derives the same hash, so this is what
///   federated servers compare. The module identity is inside the SIGNED bytes
///   deliberately; an unsigned provenance claim is not worth having, since a
///   mismatch between peers is only diagnosable if you can trust which code each
///   one ran.
/// - `engine` — the engine name, its version, and fuel consumed. **Local
///   telemetry, never comparable across servers.** There is no cross-runtime
///   metering standard, no published conversion between engines, and wasmtime has
///   changed its own cost schedule. Recording the version beside the number is
///   what keeps it honest; nesting it separately is what stops a future reader
///   mistaking it for part of the agreed value.
///
/// See `docs/investigations/2026-08-11-fuel-portability.md`.
async fn build_render_receipt(
    ctx: &IngestContext,
    manifest: &jig_core::BlockManifest,
    block_cid: &str,
    kind_str: &str,
) -> Result<(Vec<u8>, Option<String>, bool), IngestError> {
    use ed25519_dalek::Signer;

    let executor = ctx
        .executor
        .as_ref()
        .ok_or_else(|| IngestError::NoExecutor {
            kind: kind_str.to_string(),
        })?;

    // The body is required. Rendering the empty string in its absence would hash
    // a message nobody sent and report it as a successful render.
    let body = manifest
        .metadata
        .get("body")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IngestError::MissingMetadata {
            kind: kind_str.to_string(),
            field: "body".to_string(),
        })?;

    let channel = manifest
        .metadata
        .get("channel")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let sender_did = manifest
        .authors
        .first()
        .map(|a| a.did.to_string())
        .unwrap_or_default();
    let hlc = manifest.hlc_ts.as_ref();

    // Only `body_raw` reaches the hash — `text_block::execute_pure` derives
    // `canonical_text` from it alone. The rest is passed faithfully so the guest
    // has full context if a future module version wants it, and so a receipt
    // reader can see what the module was given.
    let input = text_block::Input {
        sender_did,
        channel_id: channel.to_string(),
        body_raw: body.to_string(),
        hlc_wall_ms: hlc.map(|h| h.wall_ms).unwrap_or(0),
        hlc_logical: hlc.map(|h| h.logical).unwrap_or(0),
        hlc_origin: hlc.map(|h| h.server_did.to_string()).unwrap_or_default(),
        client_version: manifest.version.to_string(),
    };

    // Off the async worker: `render_text` is synchronous end to end. It parks on
    // a condvar waiting for a concurrency slot and then runs the guest on that
    // same thread, so calling it inline would hold a tokio worker for the whole
    // wait plus execution. Execution is bounded by the epoch deadline; the slot
    // wait is NOT bounded, so under load enough workers could park to stall the
    // runtime — including the tasks that would have freed the slots.
    let executor = Arc::clone(executor);
    let kind_owned = kind_str.to_string();
    let rendered = tokio::task::spawn_blocking(move || executor.render_text(&input))
        .await
        // A join error means the blocking task panicked or the pool shut down.
        // Distinct from a render failure, and worth saying so: it points at the
        // host, not the block.
        .map_err(|e| IngestError::RenderFailed {
            kind: kind_owned.clone(),
            detail: format!("render task did not complete: {e}"),
        })?
        .map_err(|e| IngestError::RenderFailed {
            kind: kind_owned,
            detail: e.to_string(),
        })?;

    let canonical = serde_json::to_vec(&serde_json::json!({
        "v": "0.3-render",
        "block_cid": block_cid,
        "server_did": ctx.server_did.to_string(),
        "synthetic": false,
        "render": {
            "hash": rendered.output.render_hash,
            "module": rendered.module_id,
            "length_bytes": rendered.output.length_bytes,
        },
        "engine": {
            "name": "wasmtime",
            "runtime_version": jig_runtime::RUNTIME_VERSION,
            "fuel_used": rendered.fuel_used,
        },
        "produced_at": chrono::Utc::now().timestamp(),
    }))
    .expect("render receipt JSON is always valid");

    let sig = ctx.server_key.sign(&canonical);
    let wrapped = serde_json::json!({
        "canonical_hex": hex::encode(&canonical),
        "sig_hex": hex::encode(sig.to_bytes()),
    });
    let bytes = serde_json::to_vec(&wrapped).expect("render receipt wrap is always valid");

    Ok((bytes, Some(rendered.output.render_hash), false))
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
        test_ctx_allowing(&["text-render"])
    }

    fn test_ctx_allowing(kinds: &[&str]) -> IngestContext {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let server_key = random_signing_key();
        let server_did = Did::from_ed25519_pubkey(server_key.verifying_key().as_bytes());
        IngestContext {
            store: store.clone(),
            admission: Arc::new(AdmitEveryone),
            identity: Arc::new(crate::identity::TofuResolver::new(store)),
            hlc_clock: Arc::new(HlcClock::new(server_did.clone())),
            allowed_block_kinds: kinds.iter().map(|k| k.to_string()).collect(),
            server_did,
            server_key,
            fanout: Arc::new(Fanout::new()),
            server_url: "ws://127.0.0.1:7117".to_string(),
            naively_allow_unknown_handles_fallback: false,
            // Shared, so the ~16ms module compile is paid once for the whole
            // test binary rather than per test.
            executor: Some(crate::executor::BlockExecutor::shared()),
        }
    }

    /// Seed a channel row directly, standing in for a prior channel-create
    /// ingest. Returns the channel's id (its notional channel-create CID).
    fn seed_channel(ctx: &IngestContext, slug: &str) -> String {
        seed_channel_owned_by(ctx, slug, "did:jig:zSeedOwner")
    }

    fn seed_channel_owned_by(ctx: &IngestContext, slug: &str, owner_did: &str) -> String {
        let id = format!("bafySeed_{}", slug.trim_start_matches('#'));
        ctx.store
            .upsert_channel(&crate::persist::StoredChannel {
                id: id.clone(),
                slug: slug.to_string(),
                visibility: "open".into(),
                created_at: 0,
                owner_did: owner_did.into(),
            })
            .unwrap();
        id
    }

    fn did_of(key: &SigningKey) -> String {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    /// A body for helper-built blocks.
    ///
    /// `text-render` now REQUIRES `metadata.body` — it is what gets rendered, and
    /// ingest rejects a text-render block without it rather than hashing the
    /// empty string. Helpers therefore always set one, so tests build blocks a
    /// real client could have sent.
    const TEST_BODY: &str = "test message";

    /// Build manifest bytes, code bytes, and a valid signature for a given BlockKind.
    fn build_bundle_parts(
        signing_key: &SigningKey,
        kind: BlockKind,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        build_bundle_parts_with_meta(signing_key, kind, &[("body", TEST_BODY)])
    }

    /// Like `build_bundle_parts` but sets `metadata["channel"]` so we can test
    /// the channel_id lift. jig-pipeline can't use jig-client (dep cycle), so
    /// we set metadata directly on the manifest.
    fn build_bundle_parts_with_channel(
        signing_key: &SigningKey,
        kind: BlockKind,
        channel: &str,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        build_bundle_parts_with_meta(
            signing_key,
            kind,
            &[("channel", channel), ("body", TEST_BODY)],
        )
    }

    /// Like `build_bundle_parts` but seeds arbitrary string metadata entries —
    /// channel-create needs `slug`, member-add needs `channel` + `member_did`.
    fn build_bundle_parts_with_meta(
        signing_key: &SigningKey,
        kind: BlockKind,
        entries: &[(&str, &str)],
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
        for (k, v) in entries {
            manifest
                .metadata
                .insert((*k).to_string(), serde_json::json!(v));
        }
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

        // The reversal of the v0.0.2 carve-out: a text-render block EXECUTES, so
        // its receipt carries a real render_hash. This assertion used to require
        // `is_none()` — the whole point of #5 was that it should not.
        let hash = receipts[0]
            .render_hash
            .as_deref()
            .expect("text-render must produce a render_hash; synthetic receipts are gone");

        // It must be the hash of the actual body, verified independently of the
        // guest's own claim rather than merely being non-empty.
        let expected = text_block::execute_pure(&text_block::Input {
            sender_did: String::new(),
            channel_id: String::new(),
            body_raw: TEST_BODY.to_string(),
            hlc_wall_ms: 0,
            hlc_logical: 0,
            hlc_origin: String::new(),
            client_version: String::new(),
        })
        .render_hash;
        assert_eq!(
            hash, expected,
            "render_hash must be blake3 of the canonical body text"
        );

        // Also stored as a real receipt, not a synthetic one.
        let stored = ctx.store.get_block(&block_cid).unwrap().unwrap();
        assert!(
            !stored.is_synthetic,
            "a block that executed must not be marked synthetic"
        );
    }

    /// Absent `metadata.body`, there is nothing to render. Ingest must say so
    /// rather than hash the empty string and report success.
    #[tokio::test]
    async fn ingest_rejects_text_render_without_a_body() {
        let ctx = test_ctx();
        seed_channel(&ctx, "#hello");
        let sender_key = random_signing_key();
        // Deliberately only a channel, no body.
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &sender_key,
            BlockKind::TextRender,
            &[("channel", "#hello")],
        );

        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap_err();

        assert!(
            matches!(&err, IngestError::MissingMetadata { field, .. } if field == "body"),
            "expected MissingMetadata for `body`, got {err:?}"
        );
        assert!(
            ctx.store
                .list_blocks_by_channel("#hello", 10, None)
                .unwrap()
                .is_empty(),
            "a rejected block must not be persisted"
        );
    }

    /// A server with no executor must refuse text-render outright. The tempting
    /// alternative — fall back to a synthetic receipt — would reinstate exactly
    /// the carve-out #5 removed, while looking like success.
    #[tokio::test]
    async fn ingest_rejects_text_render_when_no_executor_is_configured() {
        let mut ctx = test_ctx();
        ctx.executor = None;
        seed_channel(&ctx, "#hello");
        let sender_key = random_signing_key();
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&sender_key, BlockKind::TextRender, "#hello");

        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap_err();

        assert!(
            matches!(&err, IngestError::NoExecutor { kind } if kind == "text-render"),
            "expected NoExecutor, got {err:?}"
        );
    }

    /// Two servers rendering the same body must produce the same hash, and a
    /// different body must produce a different one. This is cross-server parity
    /// in miniature — the property H3 checks across a real federation pair, and
    /// which was previously vacuous because both sides produced `None`.
    #[tokio::test]
    async fn identical_bodies_agree_and_different_bodies_diverge() {
        async fn hash_for(body: &str) -> String {
            let ctx = test_ctx();
            seed_channel(&ctx, "#hello");
            let key = random_signing_key();
            let (mb, cb, sig) = build_bundle_parts_with_meta(
                &key,
                BlockKind::TextRender,
                &[("channel", "#hello"), ("body", body)],
            );
            let cid = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
                .await
                .expect("ingest");
            ctx.store.get_receipts_for_block(&cid).unwrap()[0]
                .render_hash
                .clone()
                .expect("render_hash present")
        }

        // Distinct IngestContexts stand in for distinct servers: different server
        // DIDs, different signing keys, different stores.
        let a = hash_for("the same message").await;
        let b = hash_for("the same message").await;
        assert_eq!(a, b, "two servers must agree on the same body");

        let c = hash_for("the same message.").await;
        assert_ne!(a, c, "a one-character change must change the hash");
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

    /// Correctly signed, but at a schema or suite this server does not speak:
    /// refused at the gate, never persisted.
    #[tokio::test]
    async fn ingest_refuses_manifests_failing_the_gates() {
        let ctx = test_ctx();
        let sender_key = random_signing_key();
        let (mb, _, _) = build_bundle_parts(&sender_key, BlockKind::TextRender);
        let base: serde_json::Value = serde_json::from_slice(&mb).unwrap();

        let mut future_schema = base.clone();
        future_schema["schema"] = "https://jig.dev/schema/block-manifest/v0.2".into();
        let mut mls = base;
        mls["privacy"] = serde_json::json!({ "encryption": "mls" });

        for (manifest, expect_schema) in [(future_schema, true), (mls, false)] {
            let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
            let code_bytes: Vec<u8> = vec![];
            let canonical = serde_json::to_vec(&(&manifest_bytes, &code_bytes)).unwrap();
            let sig = sender_key.sign(&canonical).to_bytes().to_vec();

            let err = do_ingest(
                &ctx,
                manifest_bytes,
                code_bytes,
                sig,
                IngestSource::LocalClient { conn_id: 1 },
            )
            .await
            .unwrap_err();
            match err {
                IngestError::ManifestGate(jig_core::ManifestGateError::UnsupportedSchema(_)) => {
                    assert!(expect_schema)
                }
                IngestError::ManifestGate(jig_core::ManifestGateError::SuiteNotImplemented(_)) => {
                    assert!(!expect_schema)
                }
                other => panic!("expected a gate refusal, got {other:?}"),
            }
        }
    }

    // ---- Channel-existence guard -----------------------------------------

    #[tokio::test]
    async fn ingest_rejects_text_render_to_unknown_channel() {
        // The headline bug: a typo'd channel slug used to persist an orphan
        // block and return a CID, so a mistyped send was indistinguishable
        // from a working one.
        let ctx = test_ctx();
        let sender_key = random_signing_key();
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&sender_key, BlockKind::TextRender, "#gigeu");

        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap_err();

        assert!(
            matches!(&err, IngestError::UnknownChannel { slug } if slug == "#gigeu"),
            "expected UnknownChannel, got {err:?}"
        );
        // The message must name the slug and point at a recovery action.
        let msg = err.to_string();
        assert!(msg.contains("#gigeu"), "error must name the slug: {msg}");
        assert!(
            msg.contains("jig channel create") && msg.contains("jig channel list"),
            "error must be actionable: {msg}"
        );
        // Nothing may be persisted for a rejected block.
        assert!(
            ctx.store
                .list_blocks_by_channel("#gigeu", 10, None)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn ingest_accepts_text_render_to_existing_channel() {
        // Regression guard for the fix above.
        let ctx = test_ctx();
        seed_channel(&ctx, "#hello");
        let sender_key = random_signing_key();
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&sender_key, BlockKind::TextRender, "#hello");

        let cid = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .expect("existing channel must still accept text-render");
        assert!(ctx.store.get_block(&cid).unwrap().is_some());
    }

    #[tokio::test]
    async fn channel_create_bootstraps_on_a_server_with_no_channels() {
        // Bootstrap guard: channel-create names the channel it is creating, so
        // it must never be subject to the pre-existence check.
        let ctx = test_ctx_allowing(&["channel-create"]);
        assert!(ctx.store.list_channels().unwrap().is_empty());
        let owner_key = random_signing_key();
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &owner_key,
            BlockKind::ChannelCreate,
            &[("slug", "#first"), ("visibility", "open")],
        );

        do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .expect("channel-create must bootstrap on an empty server");
        assert!(ctx.store.get_channel_by_slug("#first").unwrap().is_some());
    }

    #[tokio::test]
    async fn member_add_by_the_owner_against_existing_channel_still_ingests() {
        let ctx = test_ctx_allowing(&["member-add"]);
        let owner_key = random_signing_key();
        let channel_id = seed_channel_owned_by(&ctx, "#hello", &did_of(&owner_key));
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &owner_key,
            BlockKind::MemberAdd,
            &[("channel", "#hello"), ("member_did", "did:jig:zDeji")],
        );

        do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .expect("member-add by the owner against an existing channel must succeed");
        let members = ctx.store.list_members(&channel_id).unwrap();
        assert!(members.iter().any(|m| m.member_did == "did:jig:zDeji"));
    }

    /// Gate 2 on writes: a validly signed block from a sender this server
    /// refuses is turned away before the kind whitelist, the channel lookup
    /// or the receipt — and nothing is persisted.
    #[tokio::test]
    async fn a_refused_sender_is_turned_away_before_anything_else() {
        struct BanOne(String);
        impl Admission for BanOne {
            fn admit(&self, did: &str) -> Result<(), AdmissionRefusal> {
                if did == self.0 {
                    Err(AdmissionRefusal::Banned)
                } else {
                    Ok(())
                }
            }
        }

        let banned_key = random_signing_key();
        let mut ctx = test_ctx();
        ctx.admission = Arc::new(BanOne(did_of(&banned_key)));
        // The channel does NOT exist: a caller admission refuses must get
        // NotAdmitted, never UnknownChannel — order is a security property.
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &banned_key,
            BlockKind::TextRender,
            &[
                ("channel", "#nowhere"),
                ("nickname", "banned-nick"),
                ("body", "hi"),
            ],
        );

        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .expect_err("a banned sender must be refused");
        assert!(
            matches!(
                &err,
                IngestError::NotAdmitted {
                    refusal: AdmissionRefusal::Banned,
                    ..
                }
            ),
            "got {err:?}"
        );
        assert!(
            ctx.store
                .list_blocks_by_channel("#nowhere", 10, None)
                .unwrap()
                .is_empty(),
            "a refused block must not persist"
        );
        assert!(
            ctx.store.get_tofu_key("banned-nick").unwrap().is_none(),
            "a refused block must not leave a TOFU pin behind"
        );

        // Someone else is admitted by the same policy (and then hits the
        // existence guard, proving admission ran first and only for the ban).
        let other = random_signing_key();
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&other, BlockKind::TextRender, "#nowhere");
        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .expect_err("unknown channel");
        assert!(
            matches!(err, IngestError::UnknownChannel { .. }),
            "got {err:?}"
        );
    }

    /// An archived channel takes nothing new, whatever the kind. Without this
    /// a kind the write gate has no rule for resolved to "no channel" and
    /// landed in the archived — still restricted — timeline.
    #[tokio::test]
    async fn nothing_can_be_posted_into_an_archived_channel() {
        let ctx = test_ctx_allowing(&["member-add", "fed-hello"]);
        let owner_key = random_signing_key();
        seed_channel_owned_by(&ctx, "#retired", &did_of(&owner_key));
        assert!(ctx.store.archive_channel("#retired", 1).unwrap());

        for (key, kind, meta) in [
            (
                &owner_key,
                BlockKind::MemberAdd,
                vec![("channel", "#retired"), ("member_did", "did:jig:zX")],
            ),
            (
                &random_signing_key(),
                BlockKind::FedHello,
                vec![("channel", "#retired"), ("server_url", "ws://x")],
            ),
        ] {
            let (mb, cb, sig) = build_bundle_parts_with_meta(key, kind, &meta);
            let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
                .await
                .expect_err("an archived channel must refuse");
            assert!(
                matches!(err, IngestError::ChannelArchived { .. }),
                "{kind:?}: expected ChannelArchived, got {err:?}"
            );
        }
    }

    /// A second channel-create for a taken slug — a fresh block, not a replay —
    /// is a typed `ChannelExists`, not a UNIQUE-constraint `Other`, and the
    /// original owner keeps the channel. Archived slugs stay taken.
    #[tokio::test]
    async fn channel_create_for_a_taken_slug_is_channel_exists() {
        let ctx = test_ctx_allowing(&["channel-create"]);
        let owner = random_signing_key();
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &owner,
            BlockKind::ChannelCreate,
            &[("slug", "#hello"), ("visibility", "open")],
        );
        do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .expect("first create");

        for key in [random_signing_key(), owner.clone()] {
            let (mb, cb, sig) = build_bundle_parts_with_meta(
                &key,
                BlockKind::ChannelCreate,
                &[("slug", "#hello"), ("visibility", "restricted")],
            );
            let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
                .await
                .expect_err("slug is taken");
            assert!(
                matches!(&err, IngestError::ChannelExists { slug } if slug == "#hello"),
                "got {err:?}"
            );
        }
        let row = ctx.store.get_channel_by_slug("#hello").unwrap().unwrap();
        assert_eq!(row.owner_did, did_of(&owner));
        assert_eq!(row.visibility, "open");

        seed_channel_owned_by(&ctx, "#retired", &did_of(&owner));
        assert!(ctx.store.archive_channel("#retired", 1).unwrap());
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &owner,
            BlockKind::ChannelCreate,
            &[("slug", "#retired"), ("visibility", "open")],
        );
        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .expect_err("an archived slug stays taken");
        assert!(
            matches!(err, IngestError::ChannelExists { .. }),
            "got {err:?}"
        );
    }

    /// Replaying an accepted member-add must not re-enrol a member who has
    /// since been removed. The bytes are genuine and owner-signed; what makes
    /// them invalid the second time is that they were already applied.
    #[tokio::test]
    async fn a_replayed_member_add_does_not_re_enrol_a_removed_member() {
        let ctx = test_ctx_allowing(&["member-add"]);
        let owner_key = random_signing_key();
        let channel_id = seed_channel_owned_by(&ctx, "#hello", &did_of(&owner_key));
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &owner_key,
            BlockKind::MemberAdd,
            &[("channel", "#hello"), ("member_did", "did:jig:zDeji")],
        );

        do_ingest(
            &ctx,
            mb.clone(),
            cb.clone(),
            sig.clone(),
            IngestSource::LocalClient { conn_id: 1 },
        )
        .await
        .expect("first ingest");
        assert!(ctx.store.is_member("#hello", "did:jig:zDeji").unwrap());
        assert!(
            ctx.store
                .remove_membership("#hello", "did:jig:zDeji")
                .unwrap()
        );

        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .expect_err("the same block a second time must be refused");
        assert!(
            matches!(err, IngestError::DuplicateBlock { .. }),
            "got {err:?}"
        );
        assert!(
            !ctx.store.is_member("#hello", "did:jig:zDeji").unwrap(),
            "a refused replay must leave the revocation in place"
        );
        assert_eq!(ctx.store.list_members(&channel_id).unwrap().len(), 0);
    }

    /// Gate 3 for writes runs inside ingest, so every surface gets it. A validly
    /// signed member-add from a DID that does not own the channel is refused
    /// with a typed error, and the memberships table is untouched.
    #[tokio::test]
    async fn member_add_by_a_non_owner_is_refused_at_ingest() {
        let ctx = test_ctx_allowing(&["member-add"]);
        let channel_id = seed_channel(&ctx, "#hello");
        let stranger_key = random_signing_key();
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &stranger_key,
            BlockKind::MemberAdd,
            &[("channel", "#hello"), ("member_did", "did:jig:zDeji")],
        );

        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .expect_err("a non-owner must not enrol anyone");
        assert!(
            matches!(err, IngestError::NotChannelOwner { .. }),
            "expected NotChannelOwner, got {err:?}"
        );
        assert!(
            ctx.store.list_members(&channel_id).unwrap().is_empty(),
            "a refused block must leave no membership behind"
        );
    }

    #[tokio::test]
    async fn federated_text_render_to_unknown_channel_is_admitted() {
        // Deliberate exemption: channel state does not replicate between peers
        // (see jig-server v0_0_2_federation docs), so a peer's block routinely
        // names a channel this server has no row for. Rejecting would break
        // federation; we admit and let fanout match on the slug.
        let ctx = test_ctx();
        let sender_key = random_signing_key();
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&sender_key, BlockKind::TextRender, "#remote-only");

        let cid = do_ingest(
            &ctx,
            mb,
            cb,
            sig,
            IngestSource::FederatedPeer {
                peer_did: Did::default(),
                peer_url: "wss://peer-a.jig.onl".into(),
            },
        )
        .await
        .expect("federated blocks must not be gated on local channel state");
        assert!(ctx.store.get_block(&cid).unwrap().is_some());
    }

    #[tokio::test]
    async fn bridge_text_render_to_unknown_channel_is_rejected() {
        // Bridges are NOT exempt: the email bridge awaits `ensure_dm_channel`
        // (a real channel-create through this same pipeline) before submitting
        // a text-render, so an unknown channel here is a bridge bug, not a
        // legitimate case.
        let ctx = test_ctx();
        let sender_key = random_signing_key();
        let (mb, cb, sig) = build_bundle_parts_with_channel(
            &sender_key,
            BlockKind::TextRender,
            "#dm/never-ensured",
        );

        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::Bridge)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, IngestError::UnknownChannel { slug } if slug == "#dm/never-ensured"),
            "expected UnknownChannel, got {err:?}"
        );
    }

    #[tokio::test]
    async fn ingest_lifts_channel_id_from_metadata() {
        let ctx = test_ctx(); // allows "text-render"
        seed_channel(&ctx, "#hello");
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
        ctx.fanout.register_bridge_did(shadow.clone(), tx);

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
        ctx.fanout.register_bridge_did(shadow.clone(), tx);

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
        seed_channel(&ctx, "#dm/y");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ctx.fanout
            .subscribe_local(
                crate::fanout::SubscriptionScope::Channel("#dm/y".to_string()),
                crate::fanout::SubscriberIdentity::Unchecked,
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
