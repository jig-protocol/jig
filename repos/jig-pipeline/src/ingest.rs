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

    /// [`Self::admit`] for the author of a block that reached this server
    /// through a federated peer or an in-process bridge rather than from the
    /// author directly. A server may ask less of such an author (proof of
    /// work it had no chance to do); by default it asks the same.
    fn admit_relayed(&self, sender_did: &str) -> Result<(), AdmissionRefusal> {
        self.admit(sender_did)
    }
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
    /// The sender is over its rate; a later retry may succeed.
    RateLimited,
    /// The sender is new here and owes `bits` of proof of work first.
    ProofRequired { bits: u8 },
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
            Self::RateLimited => f.write_str("too many requests from this identity; slow down"),
            Self::ProofRequired { bits } => write!(
                f,
                "this server admits a new identity after {bits} bits of proof of work: \
                 POST /api/v1/admission"
            ),
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
    /// A write into the server's manifest log, or under its reserved slugs,
    /// that is not the server's own (JEP-0002 rule 12).
    #[error("refused for the manifest log: {reason}")]
    ManifestLog { reason: String },
    #[error("malformed bundle: {0}")]
    BundleMalformed(String),
    #[error("manifest missing kind field — v0.0.2 blocks must declare kind")]
    KindRequired,
    /// A DID in the manifest decodes to a key but is not spelled the way that
    /// key encodes (an upper-cased body, say). The block is signed, so this
    /// server cannot re-spell it, and a peer would refuse it anyway.
    #[error("`{field}` is not a did:jig in its canonical lowercase spelling")]
    NonCanonicalDid { field: String },
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
    /// The owner tried to leave its own channel; it archives it instead.
    #[error("the owner cannot leave '{slug}'; archive the channel instead")]
    OwnerCannotLeave { slug: String },
    /// A `channel-create` named a sequencer other than this server. This
    /// server creates only channels it sequences (JEP-0005 rule 5); a
    /// channel sequenced elsewhere reaches it by contract.
    #[error(
        "channel-create names sequencer `{sequencer}`, but this server is `{server}`; \
         create the channel on its sequencer, or omit `sequencer`"
    )]
    NotSequencer { sequencer: String, server: String },
    /// A channel term (`sequencer`, `co_owners`) is malformed.
    #[error("channel-create term `{field}` is invalid: {detail}")]
    InvalidTerms { field: String, detail: String },
    /// The signer lacks the right the block needs as of its position in the
    /// channel's ingest chain (JEP-0005 rule 7b).
    #[error("`{kind}` on `{slug}` refused: `{sender}` does not hold the `{right}` right")]
    MissingRight {
        kind: String,
        slug: String,
        sender: String,
        right: String,
    },
    /// A role block named a root owner of the channel (its creator or a
    /// co-owner listed at creation), whose role is fixed.
    #[error("`{member}` is a root owner of '{slug}'; its role cannot be assigned or removed")]
    RootOwnerRole { slug: String, member: String },
    /// A role block named a role this version does not define.
    #[error("unknown role `{role}`: the only role that can be assigned is `admin`")]
    UnknownRole { role: String },
    /// A contract record from anyone but the channel's sequencer.
    #[error(
        "`{kind}` on `{slug}` refused: only the channel's sequencer records a contract, not `{sender}`"
    )]
    SequencerOnly {
        kind: String,
        slug: String,
        sender: String,
    },
    /// A share block or contract record that does not say what its kind
    /// needs, or whose signed messages do not check out.
    #[error("`{kind}` refused: {detail}")]
    BadContractBlock { kind: String, detail: String },
    /// A `channel-create` whose slug is outside the slug grammar, or in a
    /// reserved namespace its author may not create in
    /// ([`jig_core::slug::check_create`]).
    #[error("channel slug {slug:?} is refused: {reason}")]
    InvalidSlug { slug: String, reason: String },
    /// A `channel-create` named a suite that is not in the registry.
    #[error("unknown encryption suite `{suite}`")]
    UnknownSuite { suite: String },
    /// The block's encryption suite is not the channel's. Includes plaintext
    /// into an encrypted channel, which is refused rather than stored.
    #[error("channel '{slug}' is `{channel}`; a `{block}` block cannot be posted to it")]
    SuiteMismatch {
        slug: String,
        channel: String,
        block: String,
    },
    /// A restricted `channel-create` whose suite is not `mls`. Restricted
    /// channels are always end-to-end encrypted (ROADMAP D25).
    #[error(
        "channel '{slug}' is restricted, and restricted channels are end-to-end encrypted: \
         create it with suite `mls`, or make it open for plaintext"
    )]
    RestrictedRequiresMls { slug: String },
    /// Content for a restricted channel created as plaintext before D25. The
    /// channel is frozen: its history stays, nothing new is accepted.
    #[error(
        "channel '{slug}' is restricted but was created unencrypted, so it takes no new \
         content; make a new restricted channel (always end-to-end encrypted) or an open one"
    )]
    PlaintextRestrictedFrozen { slug: String },
    /// The MLS payload of a block on an encrypted channel failed validation.
    #[error("MLS payload refused: {detail}")]
    MlsRejected { detail: String },
    /// A commit built on an epoch the channel has left — someone else
    /// committed first. The sender catches up and rebuilds it.
    #[error("channel '{slug}' is at MLS epoch {current}; this block is for epoch {got}")]
    StaleEpoch {
        slug: String,
        current: u64,
        got: u64,
    },
    /// The block claims a time further ahead of this server's clock than the
    /// bound its welcome advertises (JEP-0002 rule 13). The sender's clock is
    /// probably wrong; `server_ms` says what this server's says.
    #[error(
        "the block's timestamp is {ahead_ms} ms ahead of this server's clock (bound \
         {bound_ms} ms; server time {server_ms} ms since the epoch); check the device clock"
    )]
    ClockSkew {
        ahead_ms: u64,
        bound_ms: u64,
        server_ms: u64,
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

    // Step 1: signature verification, after the DIDs it and every later step
    // compare are known to be in their one spelling.
    check_manifest_dids(&manifest)?;
    let sender = verify_sig(bundle.manifest_bytes, bundle.code_bytes, &manifest, &sig)?;

    // Step 1b: admission, on the DID the signature just established. Before
    // the identity resolver, the kind whitelist and every channel lookup: a
    // caller this server will not deal with gets exactly one answer, whatever
    // they asked.
    // The server always admits itself: its own blocks (the manifest log,
    // fed-hello) are signed with its key.
    let own = sender.to_did_jig_string() == ctx.server_did.to_did_jig_string();
    let admitted = match source {
        _ if own => Ok(()),
        IngestSource::FederatedPeer { .. } | IngestSource::Bridge => {
            ctx.admission.admit_relayed(sender.as_str())
        }
        IngestSource::LocalClient { .. } | IngestSource::AdminEndpoint => {
            ctx.admission.admit(sender.as_str())
        }
    };
    if let Err(refusal) = admitted {
        tracing::info!(
            sender = %jig_core::did::log_tag(sender.as_str()),
            refusal = %refusal,
            "write refused at admission"
        );
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
                        sender = %jig_core::did::log_tag(&sender_did),
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

    // Step 3: block-kind whitelist, after the manifest log's own gate: the
    // server's writes into its log pass whatever kinds it relays.
    let kind = manifest.kind.ok_or(IngestError::KindRequired)?;
    let kind_str = kind.as_str();
    let own_log = manifest_log_write(ctx, kind, &manifest, &sender)?;
    if !own_log && !ctx.allowed_block_kinds.iter().any(|k| k == kind_str) {
        return Err(IngestError::DisallowedBlockKind {
            kind: kind_str.to_string(),
        });
    }

    // The store's local channels are the ones this server sequences; make
    // sure it knows which server that is before any slug is resolved (a
    // no-op once boot or an earlier block has said so).
    let server_did = ctx.server_did.to_did_jig_string();
    ctx.store.adopt_local_sequencer(&server_did)?;

    // The block's CID, needed this early because a channel-create's channel
    // IS that block: its `channel_id` is its own CID (JEP-0005 rule 1).
    let block_cid = bundle
        .block_cid()
        .map(|c| c.to_string())
        .unwrap_or_else(|_| "bafy_invalid".to_string());

    // Step 3b: channel-existence guard for channel-scoped kinds.
    //
    // Resolved once here and reused for the bridge-sink member lookup after
    // persist, so the guard costs no extra query. `channel_id_of` is the ONE
    // rule for which channel a block names; the persisted `channel_id` below
    // is its answer, so the channel that is gated is the channel the block
    // lands in.
    let block_channel = channel_id_of(&ctx.store, kind, &manifest, &block_cid)?;
    let channel_id = block_channel.as_ref().and_then(|c| c.id.as_deref());
    let channel_named = block_channel.as_ref().map(|c| c.named.as_str());
    let mut resolved_channel = match channel_id {
        Some(id) => ctx.store.get_channel_by_id(id)?,
        None => None,
    };
    // A live row is what writes need. An id with no live row means the
    // channel was retired (`channel_id_of` resolves archived rows too):
    // nothing goes into it, from any source, of any kind — otherwise a kind
    // the write gate does not know would resolve to "no channel", pass the
    // gate, and land in the archived timeline the read gate still guards.
    if let Some(named) = channel_named
        && channel_id.is_some()
        && resolved_channel.is_none()
        && kind != BlockKind::ChannelCreate
    {
        return Err(IngestError::ChannelArchived {
            slug: named.to_string(),
        });
    }
    if let Some(named) = channel_named
        && channel_id.is_none()
        && requires_existing_channel(kind, &source)
    {
        return Err(IngestError::UnknownChannel {
            slug: named.to_string(),
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
    let membership = if crate::authorize_write::needs_membership(kind, resolved_channel.as_ref()) {
        match channel_id {
            Some(id) => crate::authorize_write::Membership {
                sender: ctx.store.is_member_by_id(id, sender.as_str())?,
                target: match manifest.metadata.get("member_did").and_then(|v| v.as_str()) {
                    Some(target) if kind == BlockKind::MemberRemove => ctx
                        .store
                        .is_member_by_id(id, &crate::effect::canonical_did_string(target))?,
                    _ => false,
                },
            },
            None => Default::default(),
        }
    } else {
        Default::default()
    };
    // The sender's rights as of this block's position in the channel's
    // chain (JEP-0005 rule 7b): it has no record yet, so every role block
    // already sequenced comes before it. Read only when a decision can
    // turn on them.
    let rights = match resolved_channel.as_ref() {
        Some(chan)
            if kind != BlockKind::ChannelCreate
                && (crate::authorize_write::changes_the_channel(kind)
                    || crate::authorize_write::needs_membership(kind, Some(chan))) =>
        {
            crate::roles::rights_at_channel(&ctx.store, chan, sender.as_str(), crate::roles::NEXT)?
        }
        _ => crate::roles::Rights::default(),
    };
    if let Err(refusal) = crate::authorize_write::authorize_block_with(
        kind,
        sender.as_str(),
        &manifest,
        resolved_channel.as_ref(),
        membership,
        rights,
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
            WriteRefusal::OwnerCannotLeave { slug } => IngestError::OwnerCannotLeave { slug },
            WriteRefusal::MissingRight {
                slug,
                sender,
                right,
            } => IngestError::MissingRight {
                kind,
                slug,
                sender,
                right: right.to_string(),
            },
            WriteRefusal::RootOwnerRole { slug, member } => {
                IngestError::RootOwnerRole { slug, member }
            }
            WriteRefusal::UnknownRole { role } => IngestError::UnknownRole { role },
            WriteRefusal::MissingRoleMember => IngestError::MissingMetadata {
                kind,
                field: crate::roles::MEMBER_KEY.to_string(),
            },
            WriteRefusal::SequencerOnly { slug, sender } => {
                IngestError::SequencerOnly { kind, slug, sender }
            }
            WriteRefusal::BadContractBlock { detail } => {
                IngestError::BadContractBlock { kind, detail }
            }
        });
    }

    // Whether that decision rested on a role rather than on the channel's
    // terms alone. If so, the role must still hold at the seq the block is
    // given: the landing below re-checks it inside the transaction that
    // assigns that seq, which is the authoritative check (JEP-0005 rule 7b).
    // Only `membership` and `share` are granted by a role and can be taken
    // away; the owner role is fixed by the terms.
    let guarded_right = match kind {
        BlockKind::MemberAdd | BlockKind::MemberRemove => Some(crate::roles::Right::Membership),
        BlockKind::ChannelShare | BlockKind::ChannelUnshare => Some(crate::roles::Right::Share),
        _ => None,
    };
    let guard_refusal = match (resolved_channel.as_ref(), guarded_right) {
        (Some(chan), Some(right))
            if crate::authorize_write::authorize_block_with(
                kind,
                sender.as_str(),
                &manifest,
                Some(chan),
                membership,
                crate::roles::Rights::of_root(chan, sender.as_str()),
            )
            .is_err() =>
        {
            Some(match right {
                crate::roles::Right::Share => IngestError::MissingRight {
                    kind: kind_str.to_string(),
                    slug: chan.slug.clone(),
                    sender: sender.as_str().to_string(),
                    right: right.to_string(),
                },
                _ => IngestError::NotChannelOwner {
                    kind: kind_str.to_string(),
                    slug: chan.slug.clone(),
                    sender: sender.as_str().to_string(),
                },
            })
        }
        _ => None,
    };

    // Step 3c': a channel-create's terms (JEP-0005 rules 5 and 6). This
    // server creates only channels it sequences; the co-owners are fixed
    // here for the channel's life.
    if kind == BlockKind::ChannelCreate {
        // The slug's canonical grammar applies to new channels only; rows
        // from before it keep their slugs (lookups stay exact-match). Then
        // who may create each class.
        check_create_slug(
            channel_slug_of(kind, &manifest).unwrap_or_default(),
            &sender.to_did_jig_string(),
            &server_did,
            &source,
        )?;
        channel_terms(&manifest, &server_did)?;
    }

    // Step 3: HLC update on receive, within the advertised skew bound. A
    // block's own time is its author's claim (TM-02); the server adopts it
    // only when it is no further ahead than the bound (TM-01). The past is
    // unbounded: a message composed offline may arrive late.
    let wall_now_ms = chrono::Utc::now().timestamp_millis() as u64;
    if let Some(ts) = manifest.hlc_ts.as_ref() {
        let bound_ms = ctx.hlc_clock.max_future_skew_ms();
        let ahead_ms = ts.wall_ms.saturating_sub(wall_now_ms);
        if ahead_ms > bound_ms {
            return Err(IngestError::ClockSkew {
                ahead_ms,
                bound_ms,
                server_ms: wall_now_ms,
            });
        }
    }
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
        && let Some(slug) = channel_slug_of(kind, &manifest)
        && ctx
            .store
            .get_channel_by_slug_including_archived(slug)?
            .is_some()
    {
        return Err(IngestError::ChannelExists {
            slug: slug.to_string(),
        });
    }
    // Step 3f: the channel's suite, and on an encrypted channel the MLS
    // payload. After every authorization gate, so validating a commit is work
    // done only for a sender who may make the change; before the receipt, so
    // a refused block never carries this server's signature.
    let mls_group = match &resolved_channel {
        Some(chan) if chan.suite == jig_core::EncryptionSuite::Mls.as_str() => {
            ctx.store.get_mls_group_by_id(&chan.id)?
        }
        _ => None,
    };
    // How errors name the channel: its slug when this server holds it,
    // otherwise whatever the block's metadata said.
    let channel_label = resolved_channel
        .as_ref()
        .map(|c| c.slug.clone())
        .or_else(|| channel_named.map(str::to_string))
        .unwrap_or_default();
    let mls_plan = crate::mls_gate::plan(
        kind,
        &sender.to_did_jig_string(),
        &manifest,
        resolved_channel.as_ref(),
        mls_group.as_ref(),
    )
    .map_err(|refusal| suite_refusal(refusal, &channel_label))?;

    let mut render_input = match (&mls_plan, kind) {
        (crate::mls_gate::MlsPlan::Sealed, _) => None,
        (_, BlockKind::TextRender) => Some(text_render_input(ctx, &manifest, kind_str)?),
        _ => None,
    };
    if render_input.is_some() && matches!(mls_plan, crate::mls_gate::MlsPlan::Advance { .. }) {
        return Err(IngestError::MlsRejected {
            detail: "an MLS commit cannot be a text-render block".to_string(),
        });
    }
    if let Some(input) = &render_input {
        check_text_render(ctx, input, &block_cid).await?;
    }
    let (receipt_bytes, render_hash, is_synthetic) = match (&mls_plan, kind) {
        // Ciphertext cannot be executed, and the server does not pretend to.
        (crate::mls_gate::MlsPlan::Sealed, _) => (
            crate::receipts::sealed(&block_cid, &ctx.server_key)
                .map_err(|e| anyhow::anyhow!("signing the sealed receipt: {e}"))?,
            None,
            true,
        ),
        // Rendered after landing, from the block's ingest record (`render_after_landing`).
        (_, BlockKind::TextRender) => (Vec::new(), None, false),
        _ => (
            crate::receipts::accepted(&block_cid, &ctx.server_key)
                .map_err(|e| anyhow::anyhow!("signing the accepted receipt: {e}"))?,
            None,
            true,
        ),
    };

    let canonical = bundle_canonical_bytes(bundle.manifest_bytes, bundle.code_bytes)
        .map_err(IngestError::BundleMalformed)?;
    // Canonical, from the verified key — the spelling every gate compares.
    let sender_did_str = sender.to_did_jig_string();
    let hlc = manifest.hlc_ts.as_ref();
    let stored_block = StoredBlock {
        cid: block_cid.clone(),
        // The channel's id (its creation-block CID), so channel-scoped
        // fanout, history and the bridge sink find it. Step 3b's answer, by
        // construction: a block is stored under exactly the channel the write
        // gate examined.
        channel_id: channel_id.map(str::to_string),
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
    let receipt_cid = format!("r_{}", &block_cid[..16.min(block_cid.len())]);
    let mut stored_receipt = StoredReceipt {
        cid: receipt_cid,
        block_cid: block_cid.clone(),
        server_id: ctx.server_did.to_string(),
        receipt_bytes,
        render_hash,
        produced_at: chrono::Utc::now().timestamp(),
    };

    // Step 5b: the block's `ingest` record (JEP-0002 rule 9), when this server
    // holds the channel and so sequences it. A channel-create starts its own
    // chain; a block for a channel this server has no row for (a relayed
    // post for a remote channel) carries its owner's record, not one of ours.
    let record_channel = if kind == BlockKind::ChannelCreate {
        Some(block_cid.clone())
    } else {
        resolved_channel.as_ref().map(|chan| chan.id.clone())
    };
    let ingest_hlc = ctx
        .hlc_clock
        .tick(chrono::Utc::now().timestamp_millis() as u64);
    let signer = record_channel.map(|channel_id| crate::ingest_record::RecordSigner {
        channel_id,
        key: &ctx.server_key,
        ingest_wall_ms: ingest_hlc.wall_ms,
        ingest_logical: ingest_hlc.logical,
    });
    let signer = signer.filter(|_| stored_block.channel_id.is_some());
    let sender_did = sender.to_did_jig_string();
    let guard = match (&guard_refusal, resolved_channel.as_ref(), guarded_right) {
        (Some(_), Some(chan), Some(right)) => Some(crate::persist::RightGuard {
            channel: chan,
            did: &sender_did,
            right,
        }),
        _ => None,
    };

    #[cfg(test)]
    run_before_landing_hook();

    match mls_plan {
        // Step 5/6 for a commit on an encrypted channel: the group's advance,
        // the membership change and the block land in one transaction (see
        // `SqliteStore::land_mls_commit` for why nothing less will do). A
        // commit that lost the race to another one writes nothing.
        crate::mls_gate::MlsPlan::Advance {
            slug,
            from_epoch,
            state,
            to_epoch,
            group_info,
        } => {
            let membership =
                membership_change(kind, &manifest, resolved_channel.as_ref(), &block_cid);
            // An advance needs the channel's row, so `channel_id` is set.
            let group_key = channel_id.unwrap_or_default();
            let landing = ctx.store.land_mls_commit_guarded(
                group_key,
                from_epoch,
                &state,
                to_epoch,
                group_info.as_deref(),
                &membership,
                &stored_block,
                &stored_receipt,
                signer.as_ref(),
                guard.as_ref(),
            )?;
            if landing == crate::persist::Landing::Unauthorized {
                return Err(refused_at_landing(guard_refusal, kind_str));
            }
            if landing == crate::persist::Landing::LostRace {
                let current = ctx
                    .store
                    .get_mls_group_by_id(group_key)?
                    .map(|g| g.epoch)
                    .unwrap_or_default();
                return Err(IngestError::StaleEpoch {
                    slug,
                    current,
                    got: from_epoch,
                });
            }
        }
        // A membership or share block whose authority rests on a role: its
        // effect, block and record land in one transaction, and only if the
        // role still holds at the seq it is given.
        _ if guard.is_some() => {
            let Some(signer) = signer.as_ref() else {
                return Err(refused_at_landing(guard_refusal, kind_str));
            };
            if guarded_right == Some(crate::roles::Right::Membership)
                && !manifest.metadata.contains_key("member_did")
            {
                return Err(IngestError::MissingMetadata {
                    kind: kind_str.to_string(),
                    field: "member_did".to_string(),
                });
            }
            let membership =
                membership_change(kind, &manifest, resolved_channel.as_ref(), &block_cid);
            let record = match ctx.store.insert_block_sequenced_guarded(
                &stored_block,
                signer,
                &membership,
                guard.as_ref(),
            )? {
                crate::persist::Landing::Landed(record) => record,
                _ => return Err(refused_at_landing(guard_refusal, kind_str)),
            };
            if let Some(input) = render_input.take() {
                stored_receipt = receipt_after_landing(ctx, input, &block_cid, record).await;
            }
            if !stored_receipt.receipt_bytes.is_empty() {
                ctx.store.insert_receipt_once(&stored_receipt)?;
            }
        }
        plan => {
            if let crate::mls_gate::MlsPlan::Genesis(mut group) = plan {
                // The group is keyed by the channel's id: this block's CID.
                // A channel-create that fails after this leaves a row its
                // retry overwrites (`put_mls_group` replaces).
                group.channel_id = block_cid.clone();
                ctx.store.put_mls_group(&group)?;
            }
            // Step 5: apply effect
            crate::effect::apply_effect(
                &ctx.store,
                &bundle,
                &stored_receipt.receipt_bytes,
                &block_cid,
            )
            .await?;
            // Step 6: persist block (+ its record) + receipt
            let record = match signer.as_ref() {
                Some(signer) => Some(ctx.store.insert_block_sequenced(&stored_block, signer)?),
                None => {
                    ctx.store.insert_block(&stored_block)?;
                    None
                }
            };
            // The receipt is written before fanout below, so no subscriber or peer sees the
            // block without it.
            if let Some(input) = render_input.take() {
                stored_receipt = receipt_after_landing(ctx, input, &block_cid, record).await;
            }
            if !stored_receipt.receipt_bytes.is_empty() {
                ctx.store.insert_receipt_once(&stored_receipt)?;
            }
        }
    }

    // Channel membership for bridge-sink dispatch. Step 3b resolved the row
    // BEFORE `apply_effect`; a control-plane block has just changed
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
        && let Some(id) = stored_block.channel_id.as_deref()
    {
        // Archived rows included: a channel-archive has just set
        // `archived_at`, and its own block must still be delivered under the
        // channel's policy rather than to everyone because the live lookup
        // stopped finding it.
        match ctx.store.get_channel_by_id_including_archived(id) {
            Ok(row) => resolved_channel = row,
            Err(e) => {
                tracing::warn!(channel_id = id, error = %e, "channel lookup failed at fanout; denying");
                lookup_failed = true;
            }
        }
    }
    let mut policy = if lookup_failed {
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
    // A removed member still receives its own removal: on an encrypted channel
    // that block carries the commit telling its client the group is gone.
    if kind == BlockKind::MemberRemove
        && let (Some(policy), Some(target)) = (
            policy.as_mut(),
            manifest.metadata.get("member_did").and_then(|v| v.as_str()),
        )
    {
        policy
            .member_dids
            .push(crate::effect::canonical_did_string(target));
    }

    // A subscription made by slug before this channel existed waits under
    // that slug; from now on it follows the channel's id, starting with this
    // very block.
    if kind == BlockKind::ChannelCreate
        && let Some(slug) = channel_slug_of(kind, &manifest)
    {
        ctx.fanout.bind_pending_channel(slug, &block_cid).await;
    }

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

    crate::metrics::block_ingested(&source);
    Ok(block_cid)
}

/// The refusal a block gets when its role no longer held at the seq it was
/// to be given: the one the write gate would have returned.
fn refused_at_landing(refusal: Option<IngestError>, kind: &str) -> IngestError {
    tracing::info!(
        kind,
        "write refused at landing: the signer's role was taken away first"
    );
    refusal.unwrap_or_else(|| IngestError::Other(anyhow::anyhow!("refused at landing")))
}

#[cfg(test)]
thread_local! {
    /// Runs once, between the write gate and the landing transaction, so a
    /// test can sequence another block in exactly that window.
    static BEFORE_LANDING: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_before_landing_hook() {
    if let Some(hook) = BEFORE_LANDING.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

/// The metadata key under which a block names its channel by id: the CID of
/// the channel's channel-create block, in canonical text.
pub const CHANNEL_ID_KEY: &str = "channel_id";

/// A block's channel: the name its metadata gave, and the id that name
/// resolves to. What [`channel_id_of`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockChannel {
    /// The channel's id — the CID of its channel-create block (JEP-0005
    /// rule 1). For a channel-create, the block's own CID; otherwise the id
    /// of the channel row the metadata names, archived or not. `None` when
    /// the name resolves to no channel this server holds.
    pub id: Option<String>,
    /// The name as the block carried it — the slug, or the `channel_id` text
    /// — for errors and logs.
    pub named: String,
}

/// The channel a block belongs to — the ONE rule shared by the write gate,
/// the persisted `blocks.channel_id` column, fanout and the effect layer.
/// `None` when the block names no channel at all.
///
/// - A `channel-create` is its channel: the id is `block_cid`, its own CID.
/// - Any other kind names the channel it acts on by metadata `channel_id`
///   (the canonical CID text) when present, else by metadata `channel` (the
///   slug), which is looked up among this server's channels.
/// - A block carrying both must have them agree: a `channel` slug naming
///   any other channel (or none) leaves the id unresolved, so the block is
///   refused as naming an unknown channel. Otherwise a reader going by the
///   slug would file the block under a channel it was never gated against.
///
/// Archived channels resolve too, so the caller can tell "retired" from "no
/// such channel".
pub fn channel_id_of(
    store: &SqliteStore,
    kind: BlockKind,
    manifest: &jig_core::BlockManifest,
    block_cid: &str,
) -> crate::persist::Result<Option<BlockChannel>> {
    if kind == BlockKind::ChannelCreate {
        return Ok(Some(BlockChannel {
            id: Some(block_cid.to_string()),
            named: channel_slug_of(kind, manifest)
                .unwrap_or(block_cid)
                .to_string(),
        }));
    }
    if let Some(id) = manifest
        .metadata
        .get(CHANNEL_ID_KEY)
        .and_then(|v| v.as_str())
    {
        let mut resolved = store
            .get_channel_by_id_including_archived(id)?
            .map(|c| c.id);
        if let Some(slug) = channel_slug_of(kind, manifest)
            && resolved.is_some()
            && store
                .get_channel_by_slug_including_archived(slug)?
                .map(|c| c.id)
                != resolved
        {
            resolved = None;
        }
        return Ok(Some(BlockChannel {
            id: resolved,
            named: id.to_string(),
        }));
    }
    if let Some(slug) = channel_slug_of(kind, manifest) {
        return Ok(Some(BlockChannel {
            id: store
                .get_channel_by_slug_including_archived(slug)?
                .map(|c| c.id),
            named: slug.to_string(),
        }));
    }
    Ok(None)
}

/// The slug a block's manifest metadata names, if any. Ingest keys channels
/// by [`channel_id_of`]; this is for callers that only have the manifest (a
/// client deciding how to decrypt, a metrics label) and for the
/// slug-uniqueness check on channel-create.
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
/// Whether this is the server's own write into its manifest log, which then
/// skips the kind whitelist. Refuses everything else under the reserved
/// slugs, and a `server-manifest` anywhere else or one that does not decode:
/// only the server's DID writes its log, and only its channel-create and
/// `server-manifest` blocks.
fn manifest_log_write(
    ctx: &IngestContext,
    kind: BlockKind,
    manifest: &jig_core::BlockManifest,
    sender: &jig_core::did::Did,
) -> Result<bool, IngestError> {
    use crate::server_manifest::{LOG_SLUG, METADATA_KEY, RESERVED_PREFIX, ServerManifest};
    let slug = channel_slug_of(kind, manifest);
    // Case-insensitive, so `#JIG/manifest` is reserved too.
    let reserved = slug.is_some_and(|s| s.to_ascii_lowercase().starts_with(RESERVED_PREFIX));
    if !reserved && kind != BlockKind::ServerManifest {
        return Ok(false);
    }
    let own = sender.to_did_jig_string() == ctx.server_did.to_did_jig_string();
    // Who may create a channel under `#jig/` is the slug grammar's rule
    // (`check_new_slug`); here only the log's own create skips the kind
    // whitelist.
    if kind == BlockKind::ChannelCreate {
        return Ok(own && slug == Some(LOG_SLUG));
    }
    let refuse = |reason: &str| {
        Err(IngestError::ManifestLog {
            reason: reason.to_string(),
        })
    };
    if !own {
        return refuse("only this server writes its manifest log and its reserved channels");
    }
    if slug != Some(LOG_SLUG) {
        return refuse(
            "a server-manifest goes only into the manifest log, which is the only reserved channel",
        );
    }
    match kind {
        BlockKind::ServerManifest => {
            use base64::Engine as _;
            let decoded = manifest
                .metadata
                .get(METADATA_KEY)
                .and_then(|v| v.as_str())
                .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok());
            match decoded.map(|bytes: Vec<u8>| ServerManifest::decode(&bytes)) {
                Some(Ok(_)) => Ok(true),
                Some(Err(e)) => refuse(&format!("the server-manifest does not decode: {e}")),
                None => refuse("a server-manifest carries its document"),
            }
        }
        _ => refuse("the manifest log takes only server-manifest blocks"),
    }
}

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
/// A federated `text-render` is NOT exempt either: with no channel row there
/// is no membership or ownership to gate it against, so it used to be stored
/// as an orphan. A channel reaches a peer through its relayed `channel-create`,
/// which gives the peer a row first; anything else fails closed. The source no
/// longer changes the answer.
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
fn requires_existing_channel(kind: BlockKind, _source: &IngestSource) -> bool {
    matches!(
        kind,
        BlockKind::TextRender
            | BlockKind::MemberAdd
            | BlockKind::MemberRemove
            | BlockKind::ChannelPromote
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

/// Check a new channel's slug ([`jig_core::slug::classify_slug`]) and that
/// its creator may create that class:
/// - `User`: anyone;
/// - `Dm`: anyone here; the DM rule in [`crate::mls_gate`] then limits it to
///   one of the pair that derives the slug;
/// - `Email`: only the email bridge (`IngestSource::Bridge`), so nobody can
///   take a DID pair's mail-thread slug before the bridge does. A relayed
///   create (`IngestSource::FederatedPeer`) is refused on purpose: bridge
///   threads are local-only. The bridge creates them restricted
///   (`bridges/email/src/channel.rs`, `ensure_thread_channel`), and v0.2
///   federates only open, unencrypted channels (`DeliveryPolicy::federates`),
///   so no peer legitimately relays one. A future peer-policy field naming a
///   peer's bridge DIDs could relax this;
/// - `Server`: only this server's own DID.
pub fn check_create_slug(
    slug: &str,
    creator: &str,
    server_did: &str,
    source: &IngestSource,
) -> Result<jig_core::slug::SlugClass, IngestError> {
    use jig_core::slug::SlugClass;
    let refuse = |reason: String| IngestError::InvalidSlug {
        slug: slug.to_string(),
        reason,
    };
    let class = jig_core::slug::classify_slug(slug).map_err(|e| refuse(e.to_string()))?;
    match class {
        SlugClass::Email if !matches!(source, IngestSource::Bridge) => Err(refuse(format!(
            "`{}` is reserved for the email bridge's mail threads",
            jig_core::slug::EMAIL_PREFIX
        ))),
        SlugClass::Server if creator != server_did => Err(refuse(format!(
            "`{}` is reserved for this server's own channels",
            jig_core::slug::JIG_PREFIX
        ))),
        class => Ok(class),
    }
}

/// The metadata key a `channel-create` names its sequencer under.
pub const SEQUENCER_KEY: &str = "sequencer";
/// The metadata key a `channel-create` lists its co-owners under.
pub const CO_OWNERS_KEY: &str = "co_owners";

/// A `channel-create`'s terms beyond slug, visibility and suite, checked:
/// the sequencer (this server's DID when absent) and the co-owners, both in
/// canonical text. The co-owners are deduplicated and never include the
/// creator, who is the root owner already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelTerms {
    pub sequencer: String,
    pub co_owners: Vec<String>,
}

/// Read and check a `channel-create`'s terms (JEP-0005 rules 5 and 6).
///
/// - `sequencer`, when present, is a `did:jig` DID and MUST be this server:
///   a server creates only channels it sequences. Absent, the channel is
///   local and this server sequences it, which keeps clients from before
///   terms working.
/// - `co_owners`, when present, is an array of `did:jig` DIDs.
pub fn channel_terms(
    manifest: &jig_core::BlockManifest,
    server_did: &str,
) -> Result<ChannelTerms, IngestError> {
    let invalid = |field: &str, detail: String| IngestError::InvalidTerms {
        field: field.to_string(),
        detail,
    };
    let did = |field: &str, raw: &serde_json::Value| -> Result<String, IngestError> {
        let text = raw
            .as_str()
            .ok_or_else(|| invalid(field, format!("`{raw}` is not a DID string")))?;
        let parsed = Did::from_did_jig_string(text)
            .map_err(|e| invalid(field, format!("`{text}` is not a did:jig DID: {e}")))?;
        Ok(crate::effect::canonical_did_string(
            &parsed.to_did_jig_string(),
        ))
    };
    let sequencer = match manifest.metadata.get(SEQUENCER_KEY) {
        None => server_did.to_string(),
        Some(raw) => did(SEQUENCER_KEY, raw)?,
    };
    if sequencer != server_did {
        return Err(IngestError::NotSequencer {
            sequencer,
            server: server_did.to_string(),
        });
    }
    let creator = manifest
        .authors
        .first()
        .map(|a| crate::effect::canonical_did_string(&a.did.to_string()))
        .unwrap_or_default();
    let mut co_owners: Vec<String> = Vec::new();
    match manifest.metadata.get(CO_OWNERS_KEY) {
        None => {}
        Some(serde_json::Value::Array(list)) => {
            for raw in list {
                let co_owner = did(CO_OWNERS_KEY, raw)?;
                if co_owner != creator && !co_owners.contains(&co_owner) {
                    co_owners.push(co_owner);
                }
            }
        }
        Some(other) => {
            return Err(invalid(
                CO_OWNERS_KEY,
                format!("`{other}` is not an array of DIDs"),
            ));
        }
    }
    Ok(ChannelTerms {
        sequencer,
        co_owners,
    })
}

/// The membership change a commit-carrying block makes — what
/// `apply_effect` would do for it, as data, so it can share the commit's
/// transaction.
fn membership_change(
    kind: BlockKind,
    manifest: &jig_core::BlockManifest,
    channel: Option<&crate::persist::StoredChannel>,
    block_cid: &str,
) -> crate::persist::MembershipChange {
    use crate::persist::{MembershipChange, StoredMembership};
    let (Some(channel), Some(member)) = (
        channel,
        manifest.metadata.get("member_did").and_then(|v| v.as_str()),
    ) else {
        return MembershipChange::None;
    };
    let member_did = crate::effect::canonical_did_string(member);
    match kind {
        BlockKind::MemberAdd => MembershipChange::Upsert(StoredMembership {
            channel_id: channel.id.clone(),
            member_did,
            role: "member".to_string(),
            joined_at: chrono::Utc::now().timestamp(),
            source_block_cid: block_cid.to_string(),
        }),
        BlockKind::MemberRemove => MembershipChange::Remove {
            channel_id: channel.id.clone(),
            member_did,
        },
        _ => MembershipChange::None,
    }
}

/// Map a suite-gate refusal onto the typed ingest error every surface
/// classifies.
/// The ingest error a suite-gate refusal answers with. Public so the
/// suite conformance vectors check the same codes live traffic gets.
pub fn suite_refusal(refusal: crate::mls_gate::SuiteRefusal, slug: &str) -> IngestError {
    use crate::mls_gate::SuiteRefusal;
    match refusal {
        SuiteRefusal::UnknownSuite(suite) => IngestError::UnknownSuite { suite },
        SuiteRefusal::Mismatch {
            slug,
            channel,
            block,
        } => IngestError::SuiteMismatch {
            slug,
            channel,
            block,
        },
        SuiteRefusal::Plaintext { slug, suite } => IngestError::SuiteMismatch {
            slug,
            channel: suite.to_string(),
            block: "plaintext body".to_string(),
        },
        SuiteRefusal::Missing { field } => IngestError::MissingMetadata {
            kind: "encrypted-channel block".to_string(),
            field: field.to_string(),
        },
        SuiteRefusal::Mls(jig_mls::MlsError::StaleEpoch { current, got }) => {
            IngestError::StaleEpoch {
                slug: slug.to_string(),
                current,
                got,
            }
        }
        SuiteRefusal::Mls(e) => IngestError::MlsRejected {
            detail: e.to_string(),
        },
        SuiteRefusal::RestrictedNeedsMls { slug } => IngestError::RestrictedRequiresMls { slug },
        SuiteRefusal::PlaintextRestricted { slug } => {
            IngestError::PlaintextRestrictedFrozen { slug }
        }
    }
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

/// The manifest's DID fields that this pipeline reads, by the name an error
/// reports them under: `member_did` (member-add), `member` (role-assign and
/// role-unassign) and `ns_did`.
const MANIFEST_DID_FIELDS: &[&str] = &["member_did", crate::roles::MEMBER_KEY, "ns_did"];

/// Refuse a manifest carrying a key-derived DID in any spelling but the key's
/// own. Legacy, non-key-derived DIDs (`did:jig:alice`) are opaque labels and
/// are left to the steps that read them.
fn check_manifest_dids(manifest: &jig_core::BlockManifest) -> Result<(), IngestError> {
    let respelled = |did: &str| {
        matches!(
            Did::from_str_unchecked(did).as_bytes(),
            Err(jig_core::did::DidError::NotLowercase)
        )
    };
    if let Some(author) = manifest.authors.iter().find(|a| respelled(&a.did)) {
        return Err(IngestError::NonCanonicalDid {
            field: format!("authors[].did `{}`", author.did),
        });
    }
    for field in MANIFEST_DID_FIELDS {
        if let Some(did) = manifest.metadata.get(*field).and_then(|v| v.as_str())
            && respelled(did)
        {
            return Err(IngestError::NonCanonicalDid {
                field: (*field).to_string(),
            });
        }
    }
    // Signed too, and stored as the tie-break between equal clocks.
    if let Some(hlc) = &manifest.hlc_ts
        && respelled(hlc.server_did.as_str())
    {
        return Err(IngestError::NonCanonicalDid {
            field: "hlc_ts.server_did".to_string(),
        });
    }
    Ok(())
}

/// Verify the sender's ed25519 signature over the bundle's canonical bytes.
///
/// The signer is the first author in the manifest. If the DID is not in
/// canonical `did:jig:z<base32>` form (e.g. a legacy test DID), decoding
/// fails and we return `InvalidSignature` — no opaque-label fallback,
/// because the ingest pipeline must never accept an unverifiable signature.
/// Verify the author's signature and return the author's DID. Its spelling
/// is canonical: [`check_manifest_dids`] refused any other.
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

/// The text-render input for a block, checked before the block lands: the body is required, and
/// so is an executor.
///
/// Only `body_raw` reaches `render_hash`; the rest is passed so the guest has the block's context.
/// The ingest clock and the channel CID in the invocation come from the block's ingest record, at
/// render time ([`render_after_landing`]).
fn text_render_input(
    ctx: &IngestContext,
    manifest: &jig_core::BlockManifest,
    kind_str: &str,
) -> Result<text_block::Input, IngestError> {
    if ctx.executor.is_none() {
        return Err(IngestError::NoExecutor {
            kind: kind_str.to_string(),
        });
    }
    crate::executor::text_input(manifest).ok_or_else(|| IngestError::MissingMetadata {
        kind: kind_str.to_string(),
        field: "body".to_string(),
    })
}

/// Render a landed `text-render` block and build its signed v0.3 receipt.
///
/// The `jig:block` invocation names the block's ingest record: its sequence, its clock and its
/// channel. A client re-executing the block rebuilds the same invocation from the same record, so
/// the receipt's invocation hash is one it can check. That record exists only once the block has
/// landed, which is why rendering happens after landing and not before (JEP-0006).
///
/// A block with no record here (a relayed post for a channel another server sequences) gets an
/// `accepted` receipt: without the record there is no invocation a client could rebuild.
///
/// Every run outcome gets an `exec` receipt, including a guest error, a trap and an incomplete
/// run; only a successful render has a `render_hash`.
async fn render_after_landing(
    ctx: &IngestContext,
    input: text_block::Input,
    block_cid: &str,
    record: Option<crate::ingest_record::IngestRecord>,
) -> Result<StoredReceipt, IngestError> {
    let record = match record {
        Some(record) => Some(record),
        None => ctx.store.get_ingest_record(block_cid)?,
    };
    let Some(record) = record else {
        let bytes = crate::receipts::accepted(block_cid, &ctx.server_key)
            .map_err(|e| anyhow::anyhow!("signing the accepted receipt: {e}"))?;
        return Ok(stored_receipt(ctx, block_cid, bytes, None));
    };
    let executor = ctx
        .executor
        .as_ref()
        .ok_or_else(|| IngestError::NoExecutor {
            kind: BlockKind::TextRender.as_str().to_string(),
        })?;

    let invocation = crate::executor::text_render_invocation(&input, block_cid, &record);

    let run = run_text_render(executor, invocation).await?;

    let render_hash = run.text_output().ok().map(|o| o.render_hash);
    let receipt = run.receipt(
        crate::receipts::block_cid(block_cid)
            .map_err(|e| anyhow::anyhow!("block CID for the receipt: {e}"))?,
        crate::receipts::executor(&ctx.server_key),
        crate::receipts::now_ms(),
    );
    let bytes = crate::receipts::sign(receipt, &ctx.server_key)
        .map_err(|e| anyhow::anyhow!("signing the exec receipt: {e}"))?;
    Ok(stored_receipt(ctx, block_cid, bytes, render_hash))
}

/// The receipt of a landed `text-render` block, whatever happens while rendering it.
///
/// Once the block and its record have landed, ingest must not report it as refused: it is in the
/// channel's chain and history serves it. So a failure here (the render task dying, a store
/// error reading the record, a signing error) is logged and the block gets an `accepted` receipt
/// instead of an `exec` one. If even that cannot be signed, the receipt is left unwritten: readers
/// see the block as pending, and the boot backfill tries again.
async fn receipt_after_landing(
    ctx: &IngestContext,
    input: text_block::Input,
    block_cid: &str,
    record: Option<crate::ingest_record::IngestRecord>,
) -> StoredReceipt {
    #[cfg(test)]
    let rendered = if FAIL_AFTER_LANDING.with(|f| f.replace(false)) {
        Err(IngestError::RenderFailed {
            kind: "text-render".into(),
            detail: "injected by a test".into(),
        })
    } else {
        render_after_landing(ctx, input, block_cid, record).await
    };
    #[cfg(not(test))]
    let rendered = render_after_landing(ctx, input, block_cid, record).await;
    match rendered {
        Ok(receipt) => receipt,
        Err(e) => {
            tracing::warn!(block_cid, error = %e, "rendering a landed block failed; writing an accepted receipt");
            fallback_receipt(ctx, block_cid)
        }
    }
}

/// An `accepted` receipt for a landed block that could not be rendered. Empty bytes if it cannot
/// be signed; [`SqliteStore::insert_receipt_once`] callers skip those.
fn fallback_receipt(ctx: &IngestContext, block_cid: &str) -> StoredReceipt {
    match crate::receipts::accepted(block_cid, &ctx.server_key) {
        Ok(bytes) => stored_receipt(ctx, block_cid, bytes, None),
        Err(e) => {
            tracing::error!(block_cid, error = %e, "signing an accepted receipt failed; the block stays pending");
            stored_receipt(ctx, block_cid, Vec::new(), None)
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Makes the next render after landing fail, so a test can check ingest still reports the
    /// landed block as accepted.
    static FAIL_AFTER_LANDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run text-render once, off the async worker.
///
/// `render` parks on a condvar for a concurrency slot and then runs the guest on the same thread.
/// Execution is bounded by the epoch deadline; the slot wait is not, so running it inline could
/// park enough workers to stall the tasks that would free slots.
async fn run_text_render(
    executor: &Arc<crate::executor::BlockExecutor>,
    invocation: jig_runtime::component::Invocation,
) -> Result<crate::executor::ExecRun, IngestError> {
    let executor = Arc::clone(executor);
    let kind = BlockKind::TextRender.as_str().to_string();
    tokio::task::spawn_blocking(move || executor.render(&invocation))
        .await
        // A join error points at the host (a panic, a pool shut down), not the block.
        .map_err(|e| IngestError::RenderFailed {
            kind: kind.clone(),
            detail: format!("render task did not complete: {e}"),
        })?
        .map_err(|e| IngestError::RenderFailed {
            kind,
            detail: e.to_string(),
        })
}

/// Refuse, before it lands, a `text-render` block whose render runs out of fuel, stack or time,
/// or faults the host.
///
/// An `incomplete` run asserts nothing about the block (JEP-0006), and nothing requires storing
/// it. Storing it would let one post that exhausts the limits be fanned out and, in step 7,
/// re-executed by every recipient. The receipt's run needs the block's ingest record, which
/// exists only after landing, and a landed block cannot be unlanded (its record is in the
/// channel's hash chain). So this check runs first, on the invocation without the record
/// (sequence 0, the block's own clock); the receipt's run follows after landing.
///
/// Fuel and stack use do not depend on the record's values for a renderer that does not branch on
/// them, which includes text-block. A deadline can still pass on the second run under load; that
/// block lands with an `incomplete` receipt, which is never compared.
async fn check_text_render(
    ctx: &IngestContext,
    input: &text_block::Input,
    block_cid: &str,
) -> Result<(), IngestError> {
    let executor = ctx
        .executor
        .as_ref()
        .ok_or_else(|| IngestError::NoExecutor {
            kind: BlockKind::TextRender.as_str().to_string(),
        })?;
    let run = run_text_render(
        executor,
        crate::executor::text_invocation(input, block_cid.to_string(), 0),
    )
    .await?;
    if let jig_runtime::component::RunOutcome::Incomplete(reason) = &run.outcome {
        return Err(IngestError::RenderFailed {
            kind: BlockKind::TextRender.as_str().to_string(),
            detail: format!("the render is incomplete: {}", reason.as_str()),
        });
    }
    Ok(())
}

fn stored_receipt(
    ctx: &IngestContext,
    block_cid: &str,
    receipt_bytes: Vec<u8>,
    render_hash: Option<String>,
) -> StoredReceipt {
    StoredReceipt {
        cid: format!("r_{}", &block_cid[..16.min(block_cid.len())]),
        block_cid: block_cid.to_string(),
        server_id: ctx.server_did.to_string(),
        receipt_bytes,
        render_hash,
        produced_at: chrono::Utc::now().timestamp(),
    }
}

/// Write the receipt of every `text-render` block that landed without one: the server stopped
/// between landing a block and writing its receipt. Run at boot, before serving.
///
/// Rendering is deterministic, so a backfilled receipt states what the straight-through one would
/// have. Writing is idempotent, so running this twice, or alongside ingest, stores one receipt per
/// block. Returns how many receipts it wrote.
pub async fn backfill_render_receipts(ctx: &IngestContext) -> Result<usize, IngestError> {
    let kind = BlockKind::TextRender.as_str();
    let mut written = 0;
    let mut fell_back = 0;
    for block in ctx
        .store
        .blocks_missing_receipt(kind, &ctx.server_did.to_string())?
    {
        // One block that cannot be rendered (a damaged bundle, a missing body) gets an
        // `accepted` receipt and is logged, so it neither stops the blocks after it nor comes
        // back on every boot.
        let receipt = match backfill_input(ctx, &block, kind) {
            Ok(input) => match render_after_landing(ctx, input, &block.cid, None).await {
                Ok(receipt) => receipt,
                Err(e) => {
                    tracing::warn!(block_cid = %block.cid, error = %e, "backfill render failed");
                    fell_back += 1;
                    fallback_receipt(ctx, &block.cid)
                }
            },
            Err(e) => {
                tracing::warn!(block_cid = %block.cid, error = %e, "stored block cannot be rendered");
                fell_back += 1;
                fallback_receipt(ctx, &block.cid)
            }
        };
        if !receipt.receipt_bytes.is_empty() && ctx.store.insert_receipt_once(&receipt)? {
            written += 1;
        }
    }
    if fell_back > 0 {
        tracing::warn!(
            fell_back,
            "backfill wrote accepted receipts for blocks it could not render"
        );
    }
    Ok(written)
}

fn backfill_input(
    ctx: &IngestContext,
    block: &StoredBlock,
    kind: &str,
) -> Result<text_block::Input, IngestError> {
    let (manifest_bytes, _code): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&block.bundle_bytes)
            .map_err(|e| IngestError::BundleMalformed(format!("stored bundle: {e}")))?;
    text_render_input(ctx, &parse_manifest(&manifest_bytes)?, kind)
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

    /// Every key-derived DID a manifest carries, signed, is in its one
    /// spelling: a role-assign's `member` and the clock's `server_did` too.
    #[test]
    fn a_recased_member_or_clock_server_did_is_refused() {
        let key = random_signing_key();
        let did = Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
        let recased = did
            .to_did_jig_string()
            .to_uppercase()
            .replacen("DID:JIG:Z", "did:jig:z", 1);
        let manifest = || {
            BlockManifest::builder()
                .version(Version::new(0, 1, 0))
                .author(Author {
                    did: did.clone(),
                    public_key: None,
                    roles: vec![],
                })
                .build()
                .unwrap()
                .with_kind(BlockKind::RoleAssign)
        };
        let mut role = manifest();
        role.metadata
            .insert(crate::roles::MEMBER_KEY.into(), serde_json::json!(recased));
        assert!(matches!(
            check_manifest_dids(&role),
            Err(IngestError::NonCanonicalDid { ref field }) if field == "member"
        ));

        let mut clock = manifest();
        clock.hlc_ts = Some(jig_core::HlcTimestamp {
            wall_ms: 1,
            logical: 0,
            server_did: Did::from_str_unchecked(recased.clone()),
        });
        assert!(matches!(
            check_manifest_dids(&clock),
            Err(IngestError::NonCanonicalDid { ref field }) if field == "hlc_ts.server_did"
        ));

        // Canonical, and legacy labels, pass.
        let mut fine = manifest();
        fine.metadata.insert(
            crate::roles::MEMBER_KEY.into(),
            serde_json::json!(did.to_did_jig_string()),
        );
        fine.hlc_ts = Some(jig_core::HlcTimestamp {
            wall_ms: 1,
            logical: 0,
            server_did: Did::from_str_unchecked("did:jig:server-test"),
        });
        assert!(check_manifest_dids(&fine).is_ok());
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
        let id = crate::ingest_record::label_cid(&format!("seed {slug}"));
        ctx.store
            .upsert_channel(&crate::persist::StoredChannel {
                id: id.clone(),
                slug: slug.to_string(),
                visibility: "open".into(),
                created_at: 0,
                owner_did: owner_did.into(),
                suite: "none".to_string(),
                sequencer_did: String::new(),
                co_owners: Vec::new(),
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
        seed_channel(&ctx, "#hello");
        let sender_key = random_signing_key();
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&sender_key, BlockKind::TextRender, "#hello");

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

    fn exec_receipt(
        ctx: &IngestContext,
        block_cid: &str,
    ) -> jig_core::block_receipt::SignedReceipt {
        let stored = ctx
            .store
            .get_receipts_for_block(block_cid)
            .unwrap()
            .remove(0);
        match crate::receipts::read(&stored.receipt_bytes).expect("the receipt verifies") {
            crate::receipts::ReadReceipt::V03(r) => r,
            other => panic!("a new receipt is v0.3, got {other:?}"),
        }
    }

    async fn ingest_text(ctx: &IngestContext, body: &str) -> String {
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &random_signing_key(),
            BlockKind::TextRender,
            &[("channel", "#hello"), ("body", body)],
        );
        do_ingest(ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap()
    }

    /// The `exec` receipt is signed by this server and names the invocation a client rebuilds
    /// from the block's ingest record: its seq, clock and channel.
    #[tokio::test]
    async fn a_text_render_gets_an_exec_receipt_for_the_invocation_its_record_names() {
        use jig_core::block_receipt::Body;
        let ctx = test_ctx();
        seed_channel(&ctx, "#hello");
        let cid = ingest_text(&ctx, TEST_BODY).await;

        let signed = exec_receipt(&ctx, &cid);
        assert_eq!(
            signed.receipt.executor,
            crate::receipts::executor(&ctx.server_key)
        );
        let Body::Exec(exec) = &signed.receipt.body else {
            panic!("a rendered block gets an exec receipt");
        };
        assert!(matches!(
            exec.outcome,
            jig_core::block_receipt::Outcome::Ok { .. }
        ));

        let record = ctx
            .store
            .get_ingest_record(&cid)
            .unwrap()
            .expect("sequenced");
        let block = ctx.store.get_block(&cid).unwrap().unwrap();
        let (manifest_bytes, _): (Vec<u8>, Vec<u8>) =
            serde_json::from_slice(&block.bundle_bytes).unwrap();
        let input = text_render_input(
            &ctx,
            &parse_manifest(&manifest_bytes).unwrap(),
            "text-render",
        )
        .unwrap();
        let invocation = crate::executor::text_render_invocation(&input, &cid, &record);
        assert_eq!(
            exec.invocation_hash,
            jig_runtime::component::hash_bytes(&jig_runtime::component::invocation_hash(
                &invocation
            )),
            "a client rebuilding the invocation from the record must get the same hash"
        );
    }

    /// Without an ingest record there is no invocation a client could rebuild, so the block is
    /// stored with an `accepted` receipt and no render_hash.
    #[tokio::test]
    async fn a_text_render_with_no_ingest_record_gets_an_accepted_receipt() {
        let ctx = test_ctx();
        let (mb, cb, sig) = build_bundle_parts(&random_signing_key(), BlockKind::TextRender);
        let cid = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap();
        assert!(ctx.store.get_ingest_record(&cid).unwrap().is_none());
        let stored = ctx.store.get_receipts_for_block(&cid).unwrap().remove(0);
        assert_eq!(stored.render_hash, None);
        assert_eq!(
            exec_receipt(&ctx, &cid).receipt.body,
            jig_core::block_receipt::Body::Accepted
        );
    }

    /// A render that runs out of fuel is refused before the block lands: nothing is stored,
    /// sequenced or fanned out.
    #[tokio::test]
    async fn a_text_render_that_exhausts_its_fuel_is_refused_before_landing() {
        let mut ctx = test_ctx();
        let mut config = jig_runtime::RuntimeConfig::default();
        config.limits.fuel_max = 100; // far below what a render costs
        ctx.executor = Some(Arc::new(
            crate::executor::BlockExecutor::for_tests(config).unwrap(),
        ));
        seed_channel(&ctx, "#hello");
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &random_signing_key(),
            BlockKind::TextRender,
            &[("channel", "#hello"), ("body", "too expensive")],
        );
        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap_err();
        assert!(
            matches!(&err, IngestError::RenderFailed { detail, .. } if detail.contains("fuel-exhausted")),
            "{err:?}"
        );
        assert!(
            ctx.store
                .list_blocks_by_channel("#hello", 10, None)
                .unwrap()
                .is_empty(),
            "the refused block must not have landed"
        );
    }

    /// A render that fails after the block has landed does not make ingest report the block as
    /// refused: it is in the chain. It gets an `accepted` receipt and is delivered.
    #[tokio::test]
    async fn a_render_failure_after_landing_still_accepts_and_delivers_the_block() {
        let ctx = test_ctx();
        let channel_id = seed_channel(&ctx, "#hello");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ctx.fanout
            .subscribe_local(
                crate::fanout::SubscriptionScope::Channel(channel_id),
                crate::fanout::SubscriberIdentity::Unchecked,
                tx,
            )
            .await;
        super::FAIL_AFTER_LANDING.with(|f| f.set(true));
        let cid = ingest_text(&ctx, "lands, then the render fails").await;

        assert!(ctx.store.get_ingest_record(&cid).unwrap().is_some());
        assert_eq!(
            exec_receipt(&ctx, &cid).receipt.body,
            jig_core::block_receipt::Body::Accepted
        );
        assert!(rx.try_recv().is_ok(), "the landed block must be delivered");
    }

    /// One stored block the backfill cannot render gets an `accepted` receipt; it does not stop
    /// the blocks after it.
    #[tokio::test]
    async fn the_backfill_skips_past_a_block_it_cannot_render() {
        let ctx = test_ctx();
        seed_channel(&ctx, "#hello");
        let bad = ingest_text(&ctx, "first").await;
        let good = ingest_text(&ctx, "second").await;
        ctx.store.delete_receipts_for_block(&bad).unwrap();
        ctx.store.delete_receipts_for_block(&good).unwrap();
        ctx.store.corrupt_bundle_for_test(&bad).unwrap();

        assert_eq!(backfill_render_receipts(&ctx).await.unwrap(), 2);
        assert_eq!(
            exec_receipt(&ctx, &bad).receipt.body,
            jig_core::block_receipt::Body::Accepted
        );
        assert!(matches!(
            exec_receipt(&ctx, &good).receipt.body,
            jig_core::block_receipt::Body::Exec(_)
        ));
    }

    /// The server stops after landing a block and before writing its receipt. At the next boot
    /// the backfill writes the receipt the straight-through path would have, and only once.
    #[tokio::test]
    async fn the_boot_backfill_writes_the_receipt_a_crash_skipped() {
        let ctx = test_ctx();
        seed_channel(&ctx, "#hello");
        let cid = ingest_text(&ctx, "written before the crash").await;
        let straight = exec_receipt(&ctx, &cid);
        let render_hash = ctx.store.get_receipts_for_block(&cid).unwrap()[0]
            .render_hash
            .clone();

        // The crash: the block and its record landed, the receipt did not.
        ctx.store.delete_receipts_for_block(&cid).unwrap();
        assert!(ctx.store.get_receipts_for_block(&cid).unwrap().is_empty());

        assert_eq!(backfill_render_receipts(&ctx).await.unwrap(), 1);
        let backfilled = exec_receipt(&ctx, &cid);
        assert_eq!(backfilled.receipt.body, straight.receipt.body);
        assert_eq!(
            ctx.store.get_receipts_for_block(&cid).unwrap()[0].render_hash,
            render_hash
        );

        // Idempotent: nothing left to write, and the receipt is not duplicated.
        assert_eq!(backfill_render_receipts(&ctx).await.unwrap(), 0);
        assert_eq!(ctx.store.get_receipts_for_block(&cid).unwrap().len(), 1);
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
                // `mls` is a content suite v0.2 carries, so it passes the
                // manifest gate; with no channel to check it against, the
                // suite gate refuses it rather than carrying it on trust.
                IngestError::SuiteMismatch { .. } => assert!(!expect_schema),
                other => panic!("expected a gate refusal, got {other:?}"),
            }
        }
    }

    // ---- Encrypted channels ------------------------------------------------

    /// Sign a block with arbitrary metadata and suite, as a client would.
    fn signed_parts(
        key: &SigningKey,
        kind: BlockKind,
        suite: jig_core::EncryptionSuite,
        meta: serde_json::Value,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // A fresh HLC per block, so two blocks with the same payload (a
        // replayed commit) are different blocks rather than one duplicate.
        signed_parts_at(key, kind, suite, meta, rand::random::<u32>() as u64)
    }

    /// [`signed_parts`] with the author's clock at `wall_ms`.
    fn signed_parts_at(
        key: &SigningKey,
        kind: BlockKind,
        suite: jig_core::EncryptionSuite,
        meta: serde_json::Value,
        wall_ms: u64,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let did = Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
        let mut builder = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did,
                public_key: None,
                roles: vec![],
            });
        if suite != jig_core::EncryptionSuite::Unencrypted {
            builder = builder.privacy(jig_core::Privacy {
                encryption: suite,
                recipients: vec![],
                metadata_visibility: Default::default(),
            });
        }
        let mut manifest = builder.build().unwrap().with_kind(kind);
        if let serde_json::Value::Object(map) = meta {
            manifest.metadata.extend(map);
        }
        manifest.hlc_ts = Some(jig_core::HlcTimestamp {
            wall_ms,
            logical: 0,
            server_did: Did::from_str_unchecked("did:jig:client"),
        });
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let code_bytes: Vec<u8> = vec![];
        let canonical = serde_json::to_vec(&(&manifest_bytes, &code_bytes)).unwrap();
        let sig = key.sign(&canonical).to_bytes().to_vec();
        (manifest_bytes, code_bytes, sig)
    }

    struct Person {
        key: SigningKey,
        did: String,
        mls: jig_mls::member::Member,
    }

    fn person() -> Person {
        let key = random_signing_key();
        let did = Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
        let mls = jig_mls::member::Member::new(&key.to_bytes(), &did).unwrap();
        Person {
            key,
            did: did.to_did_jig_string(),
            mls,
        }
    }

    async fn submit(
        ctx: &IngestContext,
        who: &Person,
        kind: BlockKind,
        suite: jig_core::EncryptionSuite,
        meta: serde_json::Value,
    ) -> Result<String, IngestError> {
        let (mb, cb, sig) = signed_parts(&who.key, kind, suite, meta);
        do_ingest(ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 }).await
    }

    /// A block further ahead of the server's clock than the advertised bound
    /// is refused, and the server's clock does not move to it; a block within
    /// the bound, or from any time in the past, is taken.
    #[tokio::test]
    async fn a_block_from_too_far_in_the_future_is_refused() {
        let ctx = all_channel_kinds();
        let who = person();
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let bound = crate::handshake::DEFAULT_FUTURE_SKEW_MS;
        let create = |slug: &str, wall_ms: u64| {
            signed_parts_at(
                &who.key,
                BlockKind::ChannelCreate,
                jig_core::EncryptionSuite::Unencrypted,
                serde_json::json!({"slug": slug, "visibility": "open"}),
                wall_ms,
            )
        };

        let (mb, cb, sig) = create("#ahead", now + 2 * bound);
        match do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 }).await {
            Err(IngestError::ClockSkew {
                ahead_ms, bound_ms, ..
            }) => {
                assert!(ahead_ms > bound);
                assert_eq!(bound_ms, bound);
            }
            other => panic!("expected CLOCK_SKEW, got {other:?}"),
        }
        assert!(
            ctx.hlc_clock.tick(now).wall_ms < now + bound,
            "the server's clock must not adopt a refused block's time"
        );

        for (slug, wall_ms) in [("#near", now + bound / 2), ("#old", 1)] {
            let (mb, cb, sig) = create(slug, wall_ms);
            do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
                .await
                .unwrap_or_else(|e| panic!("{slug}: {e}"));
        }
    }

    fn b64(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn all_channel_kinds() -> IngestContext {
        test_ctx_allowing(&[
            "text-render",
            "channel-create",
            "member-add",
            "member-remove",
        ])
    }

    /// Create `#sealed` owned by `owner` and return its MLS group id.
    async fn create_sealed(ctx: &IngestContext, owner: &Person) -> Vec<u8> {
        let created = owner.mls.create_group().unwrap();
        submit(
            ctx,
            owner,
            BlockKind::ChannelCreate,
            jig_core::EncryptionSuite::Unencrypted,
            serde_json::json!({"slug": "#sealed", "visibility": "restricted", "suite": "mls",
                "mls_group_info": b64(&created.group_info),
                "mls_ratchet_tree": b64(&created.ratchet_tree)}),
        )
        .await
        .unwrap();
        created.group_id
    }

    /// Every block of a channel this server holds gets the next record of
    /// one chain, signed by the server: the channel-create at 0, then a
    /// commit carried through the MLS transaction, in arrival order.
    #[tokio::test]
    async fn a_channels_blocks_form_one_signed_chain() {
        let ctx = all_channel_kinds();
        let owner = person();
        let gid = create_sealed(&ctx, &owner).await;
        let bob = person();
        add_to_sealed(&ctx, &owner, &bob, &gid).await;

        let chain = ctx.store.list_ingest_records("#sealed", 0, 50).unwrap();
        assert_eq!(chain.len(), 2, "{chain:?}");
        let server = ctx.server_did.to_did_jig_string();
        for record in &chain {
            record.verify(&server).unwrap();
        }
        assert!(chain[0].is_genesis());
        assert_eq!(
            chain[0].block_cid, chain[0].channel_id,
            "the chain is named by its creation"
        );
        assert!(
            chain[1].follows(&chain[0]),
            "the commit's record is carried in its transaction"
        );
        assert!(
            (chain[1].ingest_wall_ms, chain[1].ingest_logical)
                > (chain[0].ingest_wall_ms, chain[0].ingest_logical),
            "the sequencer's clock moves forward along the chain"
        );
    }

    async fn add_to_sealed(
        ctx: &IngestContext,
        owner: &Person,
        who: &Person,
        gid: &[u8],
    ) -> jig_mls::member::Commit {
        let kp = who.mls.key_packages(1, false).unwrap().remove(0);
        let c = owner.mls.add(gid, &kp, &who.did).unwrap();
        submit(
            ctx,
            owner,
            BlockKind::MemberAdd,
            jig_core::EncryptionSuite::Unencrypted,
            serde_json::json!({"channel": "#sealed", "member_did": who.did,
                "mls_commit": b64(&c.commit), "mls_welcome": b64(c.welcome.as_ref().unwrap()),
                "mls_group_info": b64(c.group_info.as_ref().unwrap()), "mls_epoch": c.epoch}),
        )
        .await
        .unwrap();
        owner.mls.confirm(gid).unwrap();
        who.mls.join_welcome(c.welcome.as_ref().unwrap()).unwrap();
        c
    }

    #[tokio::test]
    async fn an_encrypted_channel_stores_ciphertext_and_never_executes_it() {
        let ctx = all_channel_kinds();
        let alice = person();
        let bob = person();
        let gid = create_sealed(&ctx, &alice).await;
        let chan = ctx.store.get_channel_by_slug("#sealed").unwrap().unwrap();
        assert_eq!(chan.suite, "mls");
        assert_eq!(
            ctx.store.get_mls_group("#sealed").unwrap().unwrap().epoch,
            0
        );

        add_to_sealed(&ctx, &alice, &bob, &gid).await;
        assert!(ctx.store.is_member("#sealed", &bob.did).unwrap());
        assert_eq!(
            ctx.store.get_mls_group("#sealed").unwrap().unwrap().epoch,
            1
        );

        let (msg, _) = alice.mls.encrypt(&gid, b"the plan").unwrap();
        let cid = submit(
            &ctx,
            &alice,
            BlockKind::TextRender,
            jig_core::EncryptionSuite::Mls,
            serde_json::json!({"channel": "#sealed", "mls_message": b64(&msg)}),
        )
        .await
        .unwrap();
        let stored = ctx.store.get_block(&cid).unwrap().unwrap();
        assert!(
            !String::from_utf8_lossy(&stored.bundle_bytes).contains("the plan"),
            "the server stores no plaintext"
        );
        let receipt = ctx.store.get_receipts_for_block(&cid).unwrap().remove(0);
        assert_eq!(receipt.render_hash, None, "nothing was executed");
        let crate::receipts::ReadReceipt::V03(read) =
            crate::receipts::read(&receipt.receipt_bytes).expect("the sealed receipt verifies")
        else {
            panic!("a new receipt is v0.3");
        };
        assert_eq!(read.receipt.body, jig_core::block_receipt::Body::Sealed);
        // Bob reads what the server cannot.
        let (_, bundle_msg) = (stored, msg);
        assert_eq!(
            bob.mls.decrypt(&gid, &bundle_msg).unwrap().plaintext,
            b"the plan"
        );

        let plaintext = submit(
            &ctx,
            &alice,
            BlockKind::TextRender,
            jig_core::EncryptionSuite::Unencrypted,
            serde_json::json!({"channel": "#sealed", "body": "in the clear"}),
        )
        .await;
        assert!(
            matches!(plaintext, Err(IngestError::SuiteMismatch { .. })),
            "{plaintext:?}"
        );
    }

    #[tokio::test]
    async fn a_commit_built_on_a_passed_epoch_is_stale() {
        let ctx = all_channel_kinds();
        let alice = person();
        let bob = person();
        let carol = person();
        let gid = create_sealed(&ctx, &alice).await;
        let kp = bob.mls.key_packages(1, false).unwrap().remove(0);
        let c = alice.mls.add(&gid, &kp, &bob.did).unwrap();
        let meta = serde_json::json!({"channel": "#sealed", "member_did": bob.did,
            "mls_commit": b64(&c.commit), "mls_welcome": b64(c.welcome.as_ref().unwrap())});
        submit(
            &ctx,
            &alice,
            BlockKind::MemberAdd,
            jig_core::EncryptionSuite::Unencrypted,
            meta.clone(),
        )
        .await
        .unwrap();
        let replay = submit(
            &ctx,
            &alice,
            BlockKind::MemberAdd,
            jig_core::EncryptionSuite::Unencrypted,
            meta,
        )
        .await;
        assert!(
            matches!(
                replay,
                Err(IngestError::StaleEpoch {
                    current: 1,
                    got: 0,
                    ..
                })
            ),
            "{replay:?}"
        );
        // An add that names someone other than whom the commit adds.
        alice.mls.confirm(&gid).unwrap();
        let kp = carol.mls.key_packages(1, false).unwrap().remove(0);
        let c = alice.mls.add(&gid, &kp, &carol.did).unwrap();
        let lie = submit(
            &ctx,
            &alice,
            BlockKind::MemberAdd,
            jig_core::EncryptionSuite::Unencrypted,
            serde_json::json!({"channel": "#sealed", "member_did": bob.did,
                "mls_commit": b64(&c.commit), "mls_welcome": b64(c.welcome.as_ref().unwrap())}),
        )
        .await;
        assert!(
            matches!(lie, Err(IngestError::MlsRejected { .. })),
            "{lie:?}"
        );
        assert!(!ctx.store.is_member("#sealed", &carol.did).unwrap());
    }

    #[tokio::test]
    async fn leaving_drops_membership_and_a_member_commits_the_removal() {
        let ctx = all_channel_kinds();
        let alice = person();
        let bob = person();
        let carol = person();
        let gid = create_sealed(&ctx, &alice).await;
        add_to_sealed(&ctx, &alice, &bob, &gid).await;
        let carol_added = add_to_sealed(&ctx, &alice, &carol, &gid).await;
        // Bob catches up on Carol's add, as his client would from history.
        bob.mls.apply_commit(&gid, &carol_added.commit).unwrap();
        assert_eq!(
            ctx.store.get_mls_group("#sealed").unwrap().unwrap().epoch,
            2
        );

        // Carol leaves: no commit, membership gone at once.
        submit(
            &ctx,
            &carol,
            BlockKind::MemberRemove,
            jig_core::EncryptionSuite::Unencrypted,
            serde_json::json!({"channel": "#sealed", "member_did": carol.did}),
        )
        .await
        .unwrap();
        assert!(!ctx.store.is_member("#sealed", &carol.did).unwrap());

        // Bob — not the owner — commits her leaf out.
        let c = bob.mls.remove(&gid, &carol.did).unwrap();
        submit(
            &ctx,
            &bob,
            BlockKind::MemberRemove,
            jig_core::EncryptionSuite::Unencrypted,
            serde_json::json!({"channel": "#sealed", "member_did": carol.did,
                "mls_commit": b64(&c.commit)}),
        )
        .await
        .unwrap();
        assert_eq!(
            ctx.store.get_mls_group("#sealed").unwrap().unwrap().epoch,
            3
        );

        // But Bob may not kick a current member, and the owner may not leave.
        bob.mls.confirm(&gid).unwrap();
        let c = bob.mls.remove(&gid, &alice.did).unwrap();
        let kick = submit(
            &ctx,
            &bob,
            BlockKind::MemberRemove,
            jig_core::EncryptionSuite::Unencrypted,
            serde_json::json!({"channel": "#sealed", "member_did": alice.did,
                "mls_commit": b64(&c.commit)}),
        )
        .await;
        assert!(
            matches!(kick, Err(IngestError::NotChannelOwner { .. })),
            "{kick:?}"
        );
        let leave = submit(
            &ctx,
            &alice,
            BlockKind::MemberRemove,
            jig_core::EncryptionSuite::Unencrypted,
            serde_json::json!({"channel": "#sealed", "member_did": alice.did}),
        )
        .await;
        assert!(
            matches!(leave, Err(IngestError::OwnerCannotLeave { .. })),
            "{leave:?}"
        );
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

    /// A channel-create is its own channel: its `channel_id` is its own CID,
    /// the id the channel row carries (JEP-0005 rule 1).
    #[tokio::test]
    async fn a_channel_create_is_stored_under_its_own_cid() {
        let ctx = test_ctx_allowing(&["channel-create"]);
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &random_signing_key(),
            BlockKind::ChannelCreate,
            &[("slug", "#first"), ("visibility", "open")],
        );
        let cid = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap();
        let stored = ctx.store.get_block(&cid).unwrap().unwrap();
        assert_eq!(stored.channel_id.as_deref(), Some(cid.as_str()));
        assert_eq!(
            ctx.store.get_channel_by_slug("#first").unwrap().unwrap().id,
            cid
        );
    }

    /// A subscription made by slug before the channel exists follows the
    /// channel once it is created: it receives the creation block and what
    /// is posted after it, both keyed by the channel's CID.
    #[tokio::test]
    async fn a_subscription_waiting_on_a_slug_follows_the_channel_once_created() {
        let ctx = test_ctx_allowing(&["channel-create", "text-render"]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ctx.fanout
            .subscribe_local(
                crate::fanout::SubscriptionScope::Channel("#later".to_string()),
                crate::fanout::SubscriberIdentity::Unchecked,
                tx,
            )
            .await;
        let owner = random_signing_key();
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &owner,
            BlockKind::ChannelCreate,
            &[("slug", "#later"), ("visibility", "open")],
        );
        let channel_cid = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap();
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&owner, BlockKind::TextRender, "#later");
        do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap();
        for kind in ["channel-create", "text-render"] {
            let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
                .await
                .expect("the waiting subscription should receive")
                .expect("a delivery");
            assert_eq!(got.0.block_kind, kind);
            assert_eq!(got.0.channel_id.as_deref(), Some(channel_cid.as_str()));
        }
    }

    /// A block may name its channel by `channel_id`, the CID of the
    /// channel-create, and lands under that CID.
    #[tokio::test]
    async fn a_block_naming_channel_id_lands_under_that_cid() {
        let ctx = test_ctx();
        let channel_id = seed_channel(&ctx, "#hello");
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &random_signing_key(),
            BlockKind::TextRender,
            &[("channel_id", channel_id.as_str()), ("body", TEST_BODY)],
        );
        let cid = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap();
        let stored = ctx.store.get_block(&cid).unwrap().unwrap();
        assert_eq!(stored.channel_id.as_deref(), Some(channel_id.as_str()));
        assert_eq!(
            ctx.store
                .list_blocks_by_channel("#hello", 10, None)
                .unwrap()
                .len(),
            1
        );
    }

    /// A `channel_id` that names no channel here is refused exactly as an
    /// unknown slug is, and leaves nothing behind.
    #[tokio::test]
    async fn a_block_naming_an_unknown_channel_id_is_refused_like_an_unknown_slug() {
        let ctx = test_ctx_allowing(&["text-render", "member-add"]);
        // The slug of a real channel is not its id.
        seed_channel(&ctx, "#hello");
        for (kind, named) in [
            (BlockKind::TextRender, "bafyNoSuchChannel"),
            (BlockKind::TextRender, "#hello"),
            (BlockKind::MemberAdd, "bafyNoSuchChannel"),
        ] {
            let (mb, cb, sig) = build_bundle_parts_with_meta(
                &random_signing_key(),
                kind,
                &[
                    ("channel_id", named),
                    ("body", TEST_BODY),
                    ("member_did", "did:jig:zX"),
                ],
            );
            let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
                .await
                .unwrap_err();
            assert!(
                matches!(&err, IngestError::UnknownChannel { slug } if slug == named),
                "{kind:?} naming {named}: expected UnknownChannel, got {err:?}"
            );
        }
        assert!(
            ctx.store
                .list_blocks_by_channel("#hello", 10, None)
                .unwrap()
                .is_empty()
        );
    }

    /// `channel_id` and `channel` must name the same channel; a pair that
    /// disagrees is refused as naming an unknown channel. A pair that agrees
    /// lands under the id.
    #[tokio::test]
    async fn a_channel_id_and_slug_that_disagree_are_refused() {
        let ctx = test_ctx();
        let hello = seed_channel(&ctx, "#hello");
        seed_channel(&ctx, "#other");
        for slug in ["#other", "#nowhere"] {
            let (mb, cb, sig) = build_bundle_parts_with_meta(
                &random_signing_key(),
                BlockKind::TextRender,
                &[
                    ("channel_id", hello.as_str()),
                    ("channel", slug),
                    ("body", TEST_BODY),
                ],
            );
            let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
                .await
                .unwrap_err();
            assert!(
                matches!(&err, IngestError::UnknownChannel { slug } if *slug == hello),
                "channel {slug}: expected UnknownChannel, got {err:?}"
            );
        }
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &random_signing_key(),
            BlockKind::TextRender,
            &[
                ("channel_id", hello.as_str()),
                ("channel", "#hello"),
                ("body", TEST_BODY),
            ],
        );
        let cid = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap();
        assert_eq!(
            ctx.store.get_block(&cid).unwrap().unwrap().channel_id,
            Some(hello)
        );
    }

    /// An archived channel named by its id refuses like one named by slug.
    #[tokio::test]
    async fn an_archived_channel_named_by_id_refuses() {
        let ctx = test_ctx();
        let channel_id = seed_channel(&ctx, "#retired");
        assert!(ctx.store.archive_channel_by_id(&channel_id, 1).unwrap());
        let (mb, cb, sig) = build_bundle_parts_with_meta(
            &random_signing_key(),
            BlockKind::TextRender,
            &[("channel_id", channel_id.as_str()), ("body", TEST_BODY)],
        );
        let err = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap_err();
        assert!(
            matches!(err, IngestError::ChannelArchived { .. }),
            "expected ChannelArchived, got {err:?}"
        );
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
    async fn federated_text_render_to_unknown_channel_is_refused() {
        // Fail closed: a relayed post for a channel this server has no row
        // for has no membership or ownership to be gated against, so it used
        // to be stored as an orphan. Channels federate by their
        // channel-create, which gives the receiving server a row first.
        let ctx = test_ctx();
        let sender_key = random_signing_key();
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&sender_key, BlockKind::TextRender, "#remote-only");

        let err = do_ingest(
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
        .unwrap_err();
        assert!(
            matches!(&err, IngestError::UnknownChannel { slug } if slug == "#remote-only"),
            "expected UnknownChannel, got {err:?}"
        );
        assert!(
            ctx.store
                .list_blocks_by_channel("#remote-only", 10, None)
                .unwrap()
                .is_empty(),
            "a refused relayed post must leave nothing behind"
        );
    }

    #[tokio::test]
    async fn a_peers_control_block_for_an_unknown_channel_is_refused() {
        // A member-add for a channel this server has no row for has no owner
        // to be authorized against. It must not ride the text-render
        // exemption past the write gate.
        let ctx = test_ctx_allowing(&["member-add"]);
        let sender_key = random_signing_key();
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&sender_key, BlockKind::MemberAdd, "#remote-only");

        let err = do_ingest(
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
        .unwrap_err();
        assert!(
            matches!(&err, IngestError::UnknownChannel { slug } if slug == "#remote-only"),
            "expected UnknownChannel, got {err:?}"
        );
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
        // A block naming its channel only by slug is stored under the
        // channel's CID, never the slug (JEP-0005 rule 1).
        let ctx = test_ctx(); // allows "text-render"
        let channel_id = seed_channel(&ctx, "#hello");
        let sender_key = random_signing_key();
        let (mb, cb, sig) =
            build_bundle_parts_with_channel(&sender_key, BlockKind::TextRender, "#hello");
        let cid = do_ingest(&ctx, mb, cb, sig, IngestSource::LocalClient { conn_id: 1 })
            .await
            .unwrap();
        let stored = ctx.store.get_block(&cid).unwrap().unwrap();
        assert_eq!(stored.channel_id.as_deref(), Some(channel_id.as_str()));
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
        let channel_cid = crate::ingest_record::label_cid("dm x");
        ctx.store
            .upsert_channel(&StoredChannel {
                id: channel_cid.clone(),
                slug: "#dm/x".into(),
                // Bridges carry plaintext, which only an open channel takes (D25).
                visibility: "open".into(),
                created_at: 0,
                owner_did: bob_did.clone(),
                suite: "none".to_string(),
                sequencer_did: String::new(),
                co_owners: Vec::new(),
            })
            .unwrap();
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
        assert_eq!(got.0.channel_id.as_deref(), Some(channel_cid.as_str()));
        assert_eq!(got.0.sender_did, bob_did);
    }

    #[tokio::test]
    async fn bridge_sink_resolves_slug_to_channel_cid_for_members() {
        // Regression: memberships are keyed by the channel's CID, not its slug.
        // The prior dispatch used `list_members(slug)` which returns nothing when
        // `channel.id != channel.slug` (the realistic shape from channel-create).
        // This test stores channel.id = a CID and channel.slug = "#dm/z"
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
        let channel_cid = crate::ingest_record::label_cid("dm z");
        ctx.store
            .upsert_channel(&StoredChannel {
                id: channel_cid.clone(),
                slug: "#dm/z".into(),
                // Bridges carry plaintext, which only an open channel takes (D25).
                visibility: "open".into(),
                created_at: 0,
                owner_did: bob_did.clone(),
                suite: "none".to_string(),
                sequencer_did: String::new(),
                co_owners: Vec::new(),
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
        assert_eq!(got.0.channel_id.as_deref(), Some(channel_cid.as_str()));
        assert_eq!(got.0.sender_did, bob_did);
    }

    #[tokio::test]
    async fn ingest_bridge_source_broadcasts_like_local() {
        // A block ingested with IngestSource::Bridge should reach a local
        // channel subscriber (full broadcast), same as LocalClient.
        let ctx = test_ctx();
        let channel_id = seed_channel(&ctx, "#dm/y");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ctx.fanout
            .subscribe_local(
                crate::fanout::SubscriptionScope::Channel(channel_id.clone()),
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
        assert_eq!(got.0.channel_id.as_deref(), Some(channel_id.as_str()));
    }

    // ---- Channel terms and roles (JEP-0005 rules 5-7b) -------------------

    fn roles_ctx() -> IngestContext {
        test_ctx_allowing(&[
            "text-render",
            "channel-create",
            "member-add",
            "member-remove",
            "channel-archive",
            "role-assign",
            "role-unassign",
        ])
    }

    async fn plain(
        ctx: &IngestContext,
        who: &Person,
        kind: BlockKind,
        meta: serde_json::Value,
    ) -> Result<String, IngestError> {
        submit(ctx, who, kind, jig_core::EncryptionSuite::Unencrypted, meta).await
    }

    fn seq_of(ctx: &IngestContext, cid: &str) -> u64 {
        ctx.store.get_ingest_record(cid).unwrap().unwrap().seq
    }

    /// Rule 5: this server creates only the channels it sequences. A create
    /// naming another sequencer is refused and leaves nothing behind; one
    /// naming none is local, stored with this server's DID.
    #[tokio::test]
    async fn a_channel_create_naming_another_sequencer_is_refused() {
        let ctx = roles_ctx();
        let owner = person();
        let elsewhere = did_of(&random_signing_key());
        let refused = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#theirs", "sequencer": elsewhere}),
        )
        .await;
        match refused {
            Err(IngestError::NotSequencer { sequencer, server }) => {
                assert_eq!(sequencer, elsewhere);
                assert_eq!(server, ctx.server_did.to_did_jig_string());
            }
            other => panic!("expected NotSequencer, got {other:?}"),
        }
        assert!(ctx.store.get_channel_by_slug("#theirs").unwrap().is_none());

        let not_a_did = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#bad", "sequencer": "server.example"}),
        )
        .await;
        assert!(
            matches!(not_a_did, Err(IngestError::InvalidTerms { ref field, .. }) if field == "sequencer"),
            "got {not_a_did:?}"
        );
    }

    #[tokio::test]
    async fn a_channel_create_without_a_sequencer_is_this_servers() {
        let ctx = roles_ctx();
        let owner = person();
        let cid = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#mine"}),
        )
        .await
        .unwrap();
        let row = ctx.store.get_channel_by_id(&cid).unwrap().unwrap();
        assert_eq!(row.sequencer_did, ctx.server_did.to_did_jig_string());
        assert!(row.co_owners.is_empty());

        // Naming this server explicitly is the same channel shape, and the
        // co-owners are kept once each and without the creator.
        let co = person();
        let cid = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#ours",
                "sequencer": ctx.server_did.to_did_jig_string(),
                "co_owners": [co.did, co.did, owner.did]}),
        )
        .await
        .unwrap();
        // A DID in signed terms is in its one canonical spelling: another
        // spelling of the same key is refused, not read as it.
        let recased = co.did.to_uppercase().replacen("DID:JIG:Z", "did:jig:z", 1);
        let bad = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#recased", "co_owners": [recased]}),
        )
        .await;
        assert!(
            matches!(bad, Err(IngestError::InvalidTerms { ref field, .. }) if field == "co_owners"),
            "{bad:?}"
        );
        let row = ctx.store.get_channel_by_id(&cid).unwrap().unwrap();
        assert_eq!(row.sequencer_did, ctx.server_did.to_did_jig_string());
        assert_eq!(row.co_owners, vec![co.did.clone()]);

        let bad = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#worse", "co_owners": "did:jig:zNotAList"}),
        )
        .await;
        assert!(
            matches!(bad, Err(IngestError::InvalidTerms { ref field, .. }) if field == "co_owners"),
            "got {bad:?}"
        );
    }

    /// A carried channel with the same slug (inserted directly: carried
    /// channels arrive by contract in a later slice) does not take the slug
    /// from this server, and slug-named blocks land in the local one.
    #[tokio::test]
    async fn a_carried_channel_does_not_shadow_a_local_slug() {
        let ctx = roles_ctx();
        ctx.store
            .adopt_local_sequencer(&ctx.server_did.to_did_jig_string())
            .unwrap();
        ctx.store
            .upsert_channel(&crate::persist::StoredChannel {
                id: "bafy_carried".to_string(),
                slug: "#shared".to_string(),
                visibility: "open".to_string(),
                created_at: 0,
                owner_did: "did:jig:zFarOwner".to_string(),
                suite: "none".to_string(),
                sequencer_did: did_of(&random_signing_key()),
                co_owners: Vec::new(),
            })
            .unwrap();
        let owner = person();
        let local = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#shared"}),
        )
        .await
        .expect("the slug is free among this server's channels");
        let post = plain(
            &ctx,
            &owner,
            BlockKind::TextRender,
            serde_json::json!({"channel": "#shared", "body": "hi"}),
        )
        .await
        .unwrap();
        let stored = ctx.store.get_block(&post).unwrap().unwrap();
        assert_eq!(stored.channel_id.as_deref(), Some(local.as_str()));
    }

    /// Rule 7b: an admin holds `membership` but not the owner role. Its
    /// member-add passes; its role-assign is refused; the owner's passes.
    #[tokio::test]
    async fn an_admin_adds_members_but_only_an_owner_assigns_roles() {
        let ctx = roles_ctx();
        let owner = person();
        let admin = person();
        let chan = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#team"}),
        )
        .await
        .unwrap();

        let before = plain(
            &ctx,
            &admin,
            BlockKind::MemberAdd,
            serde_json::json!({"channel_id": chan, "member_did": "did:jig:zFriend"}),
        )
        .await;
        assert!(
            matches!(before, Err(IngestError::NotChannelOwner { .. })),
            "not an admin yet: {before:?}"
        );

        plain(
            &ctx,
            &owner,
            BlockKind::RoleAssign,
            serde_json::json!({"channel_id": chan, "role": "admin", "member": admin.did}),
        )
        .await
        .expect("an owner assigns roles");

        plain(
            &ctx,
            &admin,
            BlockKind::MemberAdd,
            serde_json::json!({"channel_id": chan, "member_did": "did:jig:zFriend"}),
        )
        .await
        .expect("an admin holds the membership right");
        assert!(ctx.store.is_member_by_id(&chan, "did:jig:zFriend").unwrap());

        let promote = plain(
            &ctx,
            &admin,
            BlockKind::RoleAssign,
            serde_json::json!({"channel_id": chan, "role": "admin", "member": "did:jig:zFriend"}),
        )
        .await;
        match promote {
            Err(IngestError::MissingRight { right, sender, .. }) => {
                assert_eq!(right, "owner");
                assert_eq!(sender, admin.did);
            }
            other => panic!("an admin cannot make an admin; got {other:?}"),
        }
        let archive = plain(
            &ctx,
            &admin,
            BlockKind::ChannelArchive,
            serde_json::json!({"channel_id": chan}),
        )
        .await;
        assert!(
            matches!(archive, Err(IngestError::NotChannelOwner { .. })),
            "archive stays owner-only: {archive:?}"
        );
    }

    /// Rights are read as of the block's position in the chain, by record
    /// `seq`: a block the admin signed while it was one stays valid after
    /// the role is taken away, and its next membership block is refused.
    #[tokio::test]
    async fn rights_are_read_at_the_blocks_position_in_the_chain() {
        let ctx = roles_ctx();
        let owner = person();
        let admin = person();
        let chan = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#team"}),
        )
        .await
        .unwrap();
        let assign = plain(
            &ctx,
            &owner,
            BlockKind::RoleAssign,
            serde_json::json!({"channel_id": chan, "role": "admin", "member": admin.did}),
        )
        .await
        .unwrap();
        let added = plain(
            &ctx,
            &admin,
            BlockKind::MemberAdd,
            serde_json::json!({"channel_id": chan, "member_did": "did:jig:zEarly"}),
        )
        .await
        .unwrap();
        let unassign = plain(
            &ctx,
            &owner,
            BlockKind::RoleUnassign,
            serde_json::json!({"channel_id": chan, "role": "admin", "member": admin.did}),
        )
        .await
        .unwrap();
        let (s_assign, s_added, s_unassign) = (
            seq_of(&ctx, &assign),
            seq_of(&ctx, &added),
            seq_of(&ctx, &unassign),
        );
        assert!(s_assign < s_added && s_added < s_unassign);

        use crate::roles::{Rights, rights_at};
        let at = |seq| rights_at(&ctx.store, &chan, &admin.did, seq).unwrap();
        assert_eq!(at(s_assign), Rights::NONE, "a block does not see itself");
        assert_eq!(
            at(s_added),
            Rights::ADMIN,
            "the admin's add was signed in role"
        );
        assert_eq!(at(s_unassign), Rights::ADMIN);
        assert_eq!(at(s_unassign + 1), Rights::NONE);
        assert_eq!(
            rights_at(&ctx.store, &chan, &owner.did, 0).unwrap(),
            Rights::OWNER,
            "the creator is owner from the start"
        );
        assert!(
            ctx.store.is_member_by_id(&chan, "did:jig:zEarly").unwrap(),
            "the earlier add stands"
        );

        let late = plain(
            &ctx,
            &admin,
            BlockKind::MemberAdd,
            serde_json::json!({"channel_id": chan, "member_did": "did:jig:zLate"}),
        )
        .await;
        assert!(
            matches!(late, Err(IngestError::NotChannelOwner { .. })),
            "after the unassign, the same DID's next membership block is refused: {late:?}"
        );
        assert!(!ctx.store.is_member_by_id(&chan, "did:jig:zLate").unwrap());
    }

    /// The creator and a co-owner the channel-create listed are root owners:
    /// no role block can name them, and the co-owner holds every right.
    #[tokio::test]
    async fn the_creator_and_a_co_owner_cannot_be_unassigned() {
        let ctx = roles_ctx();
        let owner = person();
        let co = person();
        let chan = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#team", "co_owners": [co.did]}),
        )
        .await
        .unwrap();
        for (signer, target) in [(&owner, &co), (&co, &owner), (&owner, &owner)] {
            let r = plain(
                &ctx,
                signer,
                BlockKind::RoleUnassign,
                serde_json::json!({"channel_id": chan, "role": "admin", "member": target.did}),
            )
            .await;
            match r {
                Err(IngestError::RootOwnerRole { member, .. }) => assert_eq!(member, target.did),
                other => panic!("a root owner's role is fixed; got {other:?}"),
            }
        }
        // The co-owner holds the owner role from the terms alone.
        let admin = person();
        plain(
            &ctx,
            &co,
            BlockKind::RoleAssign,
            serde_json::json!({"channel_id": chan, "role": "admin", "member": admin.did}),
        )
        .await
        .expect("a co-owner assigns roles");
        let leave = plain(
            &ctx,
            &co,
            BlockKind::MemberRemove,
            serde_json::json!({"channel_id": chan, "member_did": co.did}),
        )
        .await;
        assert!(
            matches!(leave, Err(IngestError::OwnerCannotLeave { .. })),
            "got {leave:?}"
        );
        let unknown = plain(
            &ctx,
            &owner,
            BlockKind::RoleAssign,
            serde_json::json!({"channel_id": chan, "role": "owner", "member": admin.did}),
        )
        .await;
        assert!(
            matches!(unknown, Err(IngestError::UnknownRole { .. })),
            "got {unknown:?}"
        );
    }

    /// A role block on an encrypted channel is plaintext control plane and
    /// needs no MLS payload.
    #[tokio::test]
    async fn a_role_block_on_an_encrypted_channel_needs_no_commit() {
        let ctx = roles_ctx();
        let owner = person();
        create_sealed(&ctx, &owner).await;
        let admin = person();
        plain(
            &ctx,
            &owner,
            BlockKind::RoleAssign,
            serde_json::json!({"channel": "#sealed", "role": "admin", "member": admin.did}),
        )
        .await
        .expect("role-assign on an mls channel");
    }

    /// Sequence the owner's `role-unassign` of `admin` between the next
    /// block's write gate and its landing. Says whether it ran.
    fn unassign_before_landing(
        ctx: &IngestContext,
        owner: &Person,
        admin: &Person,
        chan: &str,
    ) -> std::rc::Rc<std::cell::Cell<bool>> {
        let (mb, cb, sig) = signed_parts(
            &owner.key,
            BlockKind::RoleUnassign,
            jig_core::EncryptionSuite::Unencrypted,
            serde_json::json!({"channel_id": chan, "role": "admin", "member": admin.did}),
        );
        let unassign = StoredBlock {
            cid: crate::ingest_record::label_cid("unassign in the window"),
            channel_id: Some(chan.to_string()),
            block_kind: "role-unassign".to_string(),
            sender_did: owner.did.clone(),
            sender_sig: sig,
            bundle_bytes: serde_json::to_vec(&(&mb, &cb)).unwrap(),
            is_synthetic: true,
            hlc_wall_ms: 0,
            hlc_logical: 0,
            hlc_origin: String::new(),
            posted_at: 0,
            origin_server: String::new(),
            federated_from: None,
        };
        let store = ctx.store.clone();
        let key = ctx.server_key.clone();
        let channel_id = chan.to_string();
        let ran = std::rc::Rc::new(std::cell::Cell::new(false));
        let ran_in_hook = ran.clone();
        super::BEFORE_LANDING.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                ran_in_hook.set(true);
                store
                    .insert_block_sequenced(
                        &unassign,
                        &crate::ingest_record::RecordSigner {
                            channel_id,
                            key: &key,
                            ingest_wall_ms: 0,
                            ingest_logical: 0,
                        },
                    )
                    .unwrap();
            }));
        });
        ran
    }

    /// The rights check is atomic with sequencing (JEP-0005 rule 7b): an
    /// admin's member-add passes the write gate, then a role-unassign for
    /// that admin is sequenced before the add lands. The landing transaction
    /// folds the chain up to the seq the add would get, finds the role gone,
    /// and refuses it with the gate's own error. Nothing of it is written.
    #[tokio::test]
    async fn a_role_taken_away_before_landing_refuses_the_block() {
        let ctx = roles_ctx();
        let owner = person();
        let admin = person();
        let chan = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#team"}),
        )
        .await
        .unwrap();
        plain(
            &ctx,
            &owner,
            BlockKind::RoleAssign,
            serde_json::json!({"channel_id": chan, "role": "admin", "member": admin.did}),
        )
        .await
        .unwrap();

        // The interleaving: between the gate and the landing, the owner's
        // role-unassign is sequenced.
        let ran = unassign_before_landing(&ctx, &owner, &admin, &chan);

        let add = plain(
            &ctx,
            &admin,
            BlockKind::MemberAdd,
            serde_json::json!({"channel_id": chan, "member_did": "did:jig:zRacer"}),
        )
        .await;
        assert!(ran.get(), "the add passed the write gate's early check");
        match add {
            Err(IngestError::NotChannelOwner { kind, sender, .. }) => {
                assert_eq!(kind, "member-add");
                assert_eq!(sender, admin.did);
            }
            other => panic!("the add must be refused at landing; got {other:?}"),
        }
        assert!(!ctx.store.is_member_by_id(&chan, "did:jig:zRacer").unwrap());
        let chain = ctx.store.list_ingest_records_by_id(&chan, 0, 50).unwrap();
        assert_eq!(
            chain.last().map(|r| r.block_cid.as_str()),
            Some(crate::ingest_record::label_cid("unassign in the window").as_str()),
            "the refused add got no record and the chain has no gap"
        );
        assert_eq!(chain.len(), 3);

        // An owner's add needs no role and is not guarded.
        plain(
            &ctx,
            &owner,
            BlockKind::MemberAdd,
            serde_json::json!({"channel_id": chan, "member_did": "did:jig:zRacer"}),
        )
        .await
        .unwrap();
        assert!(ctx.store.is_member_by_id(&chan, "did:jig:zRacer").unwrap());
    }

    /// A role that still holds at landing lets the guarded block through,
    /// with its effect applied in the same transaction.
    #[tokio::test]
    async fn a_guarded_member_remove_by_an_admin_lands_with_its_effect() {
        let ctx = roles_ctx();
        let owner = person();
        let admin = person();
        let chan = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#team"}),
        )
        .await
        .unwrap();
        plain(
            &ctx,
            &owner,
            BlockKind::MemberAdd,
            serde_json::json!({"channel_id": chan, "member_did": "did:jig:zGone"}),
        )
        .await
        .unwrap();
        plain(
            &ctx,
            &owner,
            BlockKind::RoleAssign,
            serde_json::json!({"channel_id": chan, "role": "admin", "member": admin.did}),
        )
        .await
        .unwrap();
        let rm = plain(
            &ctx,
            &admin,
            BlockKind::MemberRemove,
            serde_json::json!({"channel_id": chan, "member_did": "did:jig:zGone"}),
        )
        .await
        .unwrap();
        assert!(!ctx.store.is_member_by_id(&chan, "did:jig:zGone").unwrap());
        assert!(ctx.store.get_ingest_record(&rm).unwrap().is_some());
        assert!(!ctx.store.get_receipts_for_block(&rm).unwrap().is_empty());
    }

    /// Co-owners are members, with role `owner`, like the creator.
    #[tokio::test]
    async fn a_co_owner_is_a_member_from_the_creation_block() {
        let ctx = roles_ctx();
        let owner = person();
        let co = person();
        let chan = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#team", "co_owners": [co.did]}),
        )
        .await
        .unwrap();
        let members = ctx.store.list_members(&chan).unwrap();
        for did in [&owner.did, &co.did] {
            let m = members
                .iter()
                .find(|m| &m.member_did == did)
                .unwrap_or_else(|| panic!("{did} must be a member"));
            assert_eq!(m.role, "owner");
        }
    }

    // ---- Slug grammar (jig_core::slug) ------------------------------------

    async fn create_from(
        ctx: &IngestContext,
        key: &SigningKey,
        slug: &str,
        source: IngestSource,
    ) -> Result<String, IngestError> {
        let (mb, cb, sig) = signed_parts(
            key,
            BlockKind::ChannelCreate,
            jig_core::EncryptionSuite::Unencrypted,
            serde_json::json!({"slug": slug, "visibility": "open"}),
        );
        do_ingest(ctx, mb, cb, sig, source).await
    }

    fn local() -> IngestSource {
        IngestSource::LocalClient { conn_id: 1 }
    }

    fn invalid_slug(r: &Result<String, IngestError>) -> bool {
        matches!(r, Err(IngestError::InvalidSlug { .. }))
    }

    #[tokio::test]
    async fn a_create_outside_the_slug_grammar_is_refused_never_lowercased() {
        let ctx = roles_ctx();
        let who = random_signing_key();
        let max = format!("#{}", "a".repeat(64));
        for slug in ["#general", "#dev-ops", "#a", max.as_str()] {
            create_from(&ctx, &who, slug, local())
                .await
                .unwrap_or_else(|e| panic!("{slug}: {e}"));
        }
        let too_long = format!("#{}", "a".repeat(65));
        for slug in [
            "#General",
            "#café",
            "＃x",
            "#a\u{200d}b",
            "#a b",
            too_long.as_str(),
            "#",
            "#-lead",
            "#team/ops",
        ] {
            let r = create_from(&ctx, &who, slug, local()).await;
            assert!(invalid_slug(&r), "{slug:?}: {r:?}");
        }
        assert!(
            ctx.store.get_channel_by_slug("#general").unwrap().is_some()
                && ctx.store.get_channel_by_slug("#General").unwrap().is_none(),
            "a refused slug is not created under a lowercased spelling"
        );
    }

    /// `#email/` threads are the email bridge's: only a bridge-sourced create
    /// is taken. Not from a client, which could otherwise squat a DID pair's
    /// thread before the bridge; not from a peer either, since bridge threads
    /// are local-only (restricted, so they never federate).
    #[tokio::test]
    async fn an_email_thread_is_created_only_through_the_bridge() {
        let ctx = roles_ctx();
        let who = random_signing_key();
        let thread = "#email/0011223344556677";
        let r = create_from(&ctx, &who, thread, local()).await;
        assert!(invalid_slug(&r), "client: {r:?}");
        let r = create_from(&ctx, &who, thread, IngestSource::AdminEndpoint).await;
        assert!(invalid_slug(&r), "admin endpoint: {r:?}");
        let peer = IngestSource::FederatedPeer {
            peer_did: Did::from_ed25519_pubkey(random_signing_key().verifying_key().as_bytes()),
            peer_url: "wss://peer.invalid".to_string(),
        };
        let r = create_from(&ctx, &who, thread, peer).await;
        assert!(invalid_slug(&r), "peer: {r:?}");
        assert!(ctx.store.get_channel_by_slug(thread).unwrap().is_none());

        create_from(&ctx, &who, thread, IngestSource::Bridge)
            .await
            .expect("the bridge creates its thread");
        for bad in ["#EMAIL/0011223344556677", "#email/xyz"] {
            let r = create_from(&ctx, &who, bad, IngestSource::Bridge).await;
            assert!(invalid_slug(&r), "{bad}: {r:?}");
        }
    }

    #[tokio::test]
    async fn a_jig_slug_is_the_servers_alone() {
        let ctx = roles_ctx();
        let user = random_signing_key();
        for slug in ["#jig/manifest", "#JIG/manifest", "#Jig/manifest"] {
            let r = create_from(&ctx, &user, slug, local()).await;
            assert!(invalid_slug(&r), "{slug}: {r:?}");
        }
        let server_key = ctx.server_key.clone();
        let r = create_from(&ctx, &server_key, "#JIG/manifest", local()).await;
        assert!(
            invalid_slug(&r),
            "not canonical, even for the server: {r:?}"
        );
        create_from(&ctx, &server_key, "#jig/manifest", local())
            .await
            .expect("the server creates its own #jig/ channel");
    }

    #[tokio::test]
    async fn a_dm_slug_is_created_only_through_the_dm_rule() {
        let ctx = roles_ctx();
        let alice = person();
        let bob = person();
        let r = create_from(&ctx, &alice.key, "#dm/xyz", local()).await;
        assert!(invalid_slug(&r), "{r:?}");
        let r = create_from(&ctx, &alice.key, "#Dm/0011223344556677", local()).await;
        assert!(invalid_slug(&r), "{r:?}");

        // A well-formed DM slug still answers to the DM rule: an open,
        // plaintext create of it is refused there.
        let slug = jig_core::dm::dm_slug(&alice.did, &bob.did);
        let r = create_from(&ctx, &alice.key, &slug, local()).await;
        assert!(
            matches!(
                r,
                Err(IngestError::MissingMetadata { .. }) | Err(IngestError::MlsRejected { .. })
            ),
            "{r:?}"
        );

        let created = alice.mls.create_group().unwrap();
        submit(
            &ctx,
            &alice,
            BlockKind::ChannelCreate,
            jig_core::EncryptionSuite::Unencrypted,
            serde_json::json!({"slug": slug, "visibility": "restricted", "suite": "mls",
                "dm_peer": bob.did,
                "mls_group_info": b64(&created.group_info),
                "mls_ratchet_tree": b64(&created.ratchet_tree)}),
        )
        .await
        .expect("one of the pair creates their DM");
    }

    /// The grammar is for new channels. A row from before it keeps its slug
    /// and stays reachable by exact match.
    #[tokio::test]
    async fn a_grandfathered_slug_stays_readable_and_writable() {
        let ctx = roles_ctx();
        let id = seed_channel(&ctx, "#Old");
        assert_eq!(
            ctx.store.get_channel_by_slug("#Old").unwrap().map(|c| c.id),
            Some(id.clone())
        );
        assert!(ctx.store.get_channel_by_slug("#old").unwrap().is_none());
        let who = person();
        let post = plain(
            &ctx,
            &who,
            BlockKind::TextRender,
            serde_json::json!({"channel": "#Old", "body": "still here"}),
        )
        .await
        .unwrap();
        assert_eq!(
            ctx.store.get_block(&post).unwrap().unwrap().channel_id,
            Some(id.clone())
        );
        assert_eq!(
            ctx.store
                .list_blocks_by_channel_id(&id, 10, None)
                .unwrap()
                .len(),
            1
        );
    }

    // ---- The share flow's blocks (JEP-0005 rules 7-11) --------------------

    /// A share needs the `share` right at its position in the chain, and only
    /// the channel's sequencer, this server, records what came of it.
    #[tokio::test]
    async fn a_share_needs_the_right_and_only_the_sequencer_records_the_contract() {
        use base64::Engine as _;
        use jig_core::contract::{ContractAccept, ContractOffer, Grant, ManifestRef};
        let ctx = test_ctx_allowing(&[
            "channel-create",
            "role-assign",
            "channel-share",
            "channel-unshare",
            "contract-accept",
        ]);
        let owner = person();
        let admin = person();
        let follower = random_signing_key();
        let follower_did = did_of(&follower);
        let chan = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#shared"}),
        )
        .await
        .unwrap();
        let share = serde_json::json!({"channel_id": chan, "to": follower_did, "grant": "write"});

        let before = plain(&ctx, &admin, BlockKind::ChannelShare, share.clone()).await;
        assert!(
            matches!(before, Err(IngestError::MissingRight { ref right, .. }) if right == "share"),
            "no role yet: {before:?}"
        );
        plain(
            &ctx,
            &owner,
            BlockKind::RoleAssign,
            serde_json::json!({"channel_id": chan, "role": "admin", "member": admin.did}),
        )
        .await
        .unwrap();
        plain(&ctx, &admin, BlockKind::ChannelShare, share)
            .await
            .expect("an admin holds the share right");
        let unnamed = plain(
            &ctx,
            &admin,
            BlockKind::ChannelUnshare,
            serde_json::json!({"channel_id": chan}),
        )
        .await;
        assert!(
            matches!(unnamed, Err(IngestError::BadContractBlock { .. })),
            "an unshare names its server: {unnamed:?}"
        );

        // The record of the follower's accept, signed by this server.
        let channel_id = chan.parse::<cid::Cid>().unwrap();
        let offer = ContractOffer::sign(
            &ctx.server_key,
            &follower_did,
            channel_id,
            Grant::Write,
            vec![],
            vec![],
            ManifestRef {
                cid: channel_id,
                seq: 1,
            },
            vec![],
        );
        let accept = ContractAccept::sign(
            &follower,
            &offer,
            ManifestRef {
                cid: channel_id,
                seq: 2,
            },
            vec![],
            vec![],
        );
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let record = serde_json::json!({
            "channel_id": chan,
            "to": follower_did,
            "offer": b64(&offer.envelope),
            "accept": b64(&accept.envelope),
        });
        let by_owner = plain(&ctx, &owner, BlockKind::ContractAccept, record.clone()).await;
        assert!(
            matches!(by_owner, Err(IngestError::SequencerOnly { .. })),
            "the channel's owner is not its sequencer: {by_owner:?}"
        );
        let (mb, cb, sig) = signed_parts(
            &ctx.server_key,
            BlockKind::ContractAccept,
            jig_core::EncryptionSuite::Unencrypted,
            record,
        );
        do_ingest(&ctx, mb, cb, sig, IngestSource::AdminEndpoint)
            .await
            .expect("the sequencer records the accept");
    }

    /// The share right is guarded at landing like `membership`: an admin
    /// unassigned between the gate and the landing shares nothing.
    #[tokio::test]
    async fn a_share_right_taken_away_before_landing_refuses_the_share() {
        let ctx = test_ctx_allowing(&[
            "channel-create",
            "role-assign",
            "role-unassign",
            "channel-share",
        ]);
        let owner = person();
        let admin = person();
        let chan = plain(
            &ctx,
            &owner,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#team"}),
        )
        .await
        .unwrap();
        plain(
            &ctx,
            &owner,
            BlockKind::RoleAssign,
            serde_json::json!({"channel_id": chan, "role": "admin", "member": admin.did}),
        )
        .await
        .unwrap();
        let ran = unassign_before_landing(&ctx, &owner, &admin, &chan);
        let to = did_of(&random_signing_key());
        let share = plain(
            &ctx,
            &admin,
            BlockKind::ChannelShare,
            serde_json::json!({"channel_id": chan, "to": to, "grant": "read"}),
        )
        .await;
        assert!(ran.get(), "the share passed the write gate's early check");
        assert!(
            matches!(share, Err(IngestError::MissingRight { ref right, .. }) if right == "share"),
            "the share must be refused at landing; got {share:?}"
        );
        let chain = ctx.store.list_ingest_records_by_id(&chan, 0, 50).unwrap();
        assert_eq!(chain.len(), 3, "create, assign, and the unassign: no share");
    }

    /// What a share discloses (JEP-0005 Security Considerations, PV-05). On a
    /// restricted MLS channel the server reads a share's `{to, grant}`, which
    /// it needs to make the offer, and nothing of the content around it: an
    /// application message on the same channel stays ciphertext to it. A
    /// share cannot be sent encrypted instead, since the server must read it.
    #[tokio::test]
    async fn a_share_on_an_encrypted_channel_discloses_its_target_and_grant_only() {
        let ctx = test_ctx_allowing(&[
            "channel-create",
            "member-add",
            "text-render",
            "channel-share",
        ]);
        let owner = person();
        let bob = person();
        let gid = create_sealed(&ctx, &owner).await;
        add_to_sealed(&ctx, &owner, &bob, &gid).await;
        let to = did_of(&random_signing_key());

        let share = plain(
            &ctx,
            &owner,
            BlockKind::ChannelShare,
            serde_json::json!({"channel": "#sealed", "to": to, "grant": "write"}),
        )
        .await
        .expect("a share is a plaintext control block on an mls channel");
        let stored = ctx.store.get_block(&share).unwrap().unwrap();
        let (manifest_bytes, _): (Vec<u8>, Vec<u8>) =
            serde_json::from_slice(&stored.bundle_bytes).unwrap();
        let manifest: BlockManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(
            crate::contracts::share_request(BlockKind::ChannelShare, &manifest).unwrap(),
            crate::contracts::ShareRequest {
                to: to.clone(),
                grant: Some(jig_core::contract::Grant::Write),
            },
            "the server reads the target and the grant"
        );
        let mut keys: Vec<_> = manifest.metadata.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["channel", "grant", "to"], "and nothing else");

        let (msg, _) = owner.mls.encrypt(&gid, b"the plan").unwrap();
        let post = submit(
            &ctx,
            &owner,
            BlockKind::TextRender,
            jig_core::EncryptionSuite::Mls,
            serde_json::json!({"channel": "#sealed", "mls_message": b64(&msg)}),
        )
        .await
        .unwrap();
        let stored = ctx.store.get_block(&post).unwrap().unwrap();
        assert!(
            !String::from_utf8_lossy(&stored.bundle_bytes).contains("the plan"),
            "the content around it stays ciphertext"
        );

        let (sealed_share, _) = owner.mls.encrypt(&gid, b"{}").unwrap();
        let hidden = submit(
            &ctx,
            &owner,
            BlockKind::ChannelShare,
            jig_core::EncryptionSuite::Mls,
            serde_json::json!({"channel": "#sealed", "to": to, "grant": "read",
                "mls_message": b64(&sealed_share)}),
        )
        .await;
        assert!(
            matches!(hidden, Err(IngestError::SuiteMismatch { .. })),
            "a share the server cannot read is refused: {hidden:?}"
        );
    }

    /// The server's share watcher (`Fanout::watch_kinds`) sees the share
    /// kinds and nothing else: a restricted MLS channel's membership blocks
    /// and application messages never reach it.
    #[tokio::test]
    async fn the_share_watcher_sees_shares_and_never_a_channels_content() {
        let ctx = test_ctx_allowing(&[
            "channel-create",
            "member-add",
            "text-render",
            "channel-share",
        ]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ctx.fanout
            .watch_kinds(&[BlockKind::ChannelShare, BlockKind::ChannelUnshare], tx);
        let owner = person();
        let bob = person();
        let gid = create_sealed(&ctx, &owner).await;
        add_to_sealed(&ctx, &owner, &bob, &gid).await;
        let (msg, _) = owner.mls.encrypt(&gid, b"the plan").unwrap();
        submit(
            &ctx,
            &owner,
            BlockKind::TextRender,
            jig_core::EncryptionSuite::Mls,
            serde_json::json!({"channel": "#sealed", "mls_message": b64(&msg)}),
        )
        .await
        .unwrap();
        let share = plain(
            &ctx,
            &owner,
            BlockKind::ChannelShare,
            serde_json::json!({"channel": "#sealed", "to": did_of(&random_signing_key()), "grant": "read"}),
        )
        .await
        .unwrap();

        let mut seen = Vec::new();
        while let Ok((block, _)) = rx.try_recv() {
            seen.push((block.cid, block.block_kind));
        }
        assert_eq!(seen, [(share, "channel-share".to_string())]);
    }
}
