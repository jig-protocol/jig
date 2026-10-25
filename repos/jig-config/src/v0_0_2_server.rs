//! v0.0.2 `jig-server` configuration: the sections the pipeline `AppState`
//! reads. jig-server's `ServerConfig` carries each of these as a field of the
//! one `--config` file and hands them over as a [`JigServerConfig`].
//!
//! ## Sections
//! - `[server]`     — bind address, server DID keyfile, allowed block kinds
//! - `[identity]`   — TOFU vs nameserver mode + trusted nameservers
//! - `[federation]` — peers, TLS toggle, the published peer policy
//! - `[debug]`      — antipattern-flag-gated REST endpoints + nameserver enumeration
//! - `[nameserver]` — alias suffixes this node serves (nameserver mode)
//!
//! Every section carries a container-level `#[serde(default)]`, so a config
//! file may omit a section entirely or set only the keys it cares about; the
//! rest come from that section's `impl Default`. Every section also denies
//! unknown fields: a misspelled key is a parse error, not a silent default.
//!
//! All antipattern flags follow the project convention (`dangerously_`,
//! `naively_`, `unsafe_`, `debug_`-prefixed) and are listed by
//! [`JigServerConfig::unsafe_options_active`] for advertisement in
//! `GET /.well-known/jig`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct JigServerConfig {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub identity: IdentitySection,
    #[serde(default)]
    pub federation: FederationSection,
    #[serde(default)]
    pub debug: DebugSection,
    #[serde(default)]
    pub bridges: BridgesSection,
    #[serde(default)]
    pub nameserver: NameserverSection,
    #[serde(default)]
    pub auth: AuthSection,
    #[serde(default)]
    pub keys: KeysSection,
    #[serde(default)]
    pub limits: LimitsSection,
}

/// `[limits]`: the most bytes one HTTP request body or one WebSocket message
/// may carry. The WebSocket limits hold on every connection this server
/// accepts and on the ones it dials to its federation peers.
///
/// Unset, each is the smallest limit that still carries every block a server
/// accepts: one `jig_core::bundle::MAX_BUNDLE_BYTES` bundle in base64 plus its
/// envelope (`jig_core::bundle::MAX_ENVELOPE_BYTES`, 2 162 688 bytes). The
/// server refuses to boot with a smaller value, which would turn valid blocks
/// away, or with a frame limit above the message limit.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsSection {
    /// Largest HTTP request body, in bytes. A body over it is refused with
    /// `413 Payload Too Large` before it is parsed.
    pub max_request_body_bytes: Option<usize>,
    /// Largest WebSocket message, in bytes, after its frames are joined. A
    /// connection that sends a bigger one is closed.
    pub max_ws_message_bytes: Option<usize>,
    /// Largest single WebSocket frame, in bytes. A connection that sends a
    /// bigger one is closed.
    pub max_ws_frame_bytes: Option<usize>,
}

/// `[keys]`: how this server opens its own signing key, a `.jigkey`.
///
/// A server boots unattended: it never prompts and never uses an OS keychain.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeysSection {
    /// The slot to open the key with, and to seal a new key with:
    /// `credential:PATH` (a systemd credential, `LoadCredentialEncrypted=`),
    /// `env:NAME`, or `passphrase` (read from `JIG_KEY_PASSPHRASE`).
    /// `JIG_KEY_UNLOCK` and `JIG_KEY_PASSPHRASE` are tried too.
    pub unlock: Option<String>,
    /// `sealed` (the default) or `plaintext`, an antipattern: a raw 32-byte
    /// key in clear, warned about on every boot. Deliberately not listed in
    /// `unsafe_options_active`, which `/.well-known/jig` publishes: it would
    /// mark this server as a soft target, and no client can verify it.
    pub storage: KeyStorage,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStorage {
    #[default]
    Sealed,
    Plaintext,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
// Container-level (not per-field) default: a partially-written section must
// keep the documented defaults for the keys the operator omitted, rather than
// failing to parse. Container-level reuses the hand-written `impl Default`
// below, which per-field `#[serde(default)]` cannot do.
#[serde(default, deny_unknown_fields)]
pub struct ServerSection {
    pub listen: String,
    pub server_did_keyfile: String,
    pub allowed_block_kinds: Vec<String>,
    /// How far ahead of this server's clock a block's `hlc_ts` may run, in
    /// milliseconds (JEP-0002 rule 13). Ingest refuses anything further with
    /// `CLOCK_SKEW`, and the welcome signs the value. The protocol bounds it
    /// to 30 000–900 000 (`jig_pipeline::handshake`); the server refuses to
    /// boot outside that range.
    pub max_future_skew_ms: u64,
}

/// The default `[server] max_future_skew_ms`: five minutes.
pub const DEFAULT_MAX_FUTURE_SKEW_MS: u64 = 300_000;

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7117".to_string(),
            server_did_keyfile: "~/.jig/server/server.key".to_string(),
            // Core v0.0.2 block kinds. text-render is the chat-message kind;
            // channel-create + member-add + channel-archive are required by
            // F4's `jig channel create/join/delete` flow and are core (not
            // opt-in) for v0.0.2 because there's no other way to bootstrap or
            // retire a channel until v0.0.3+ ships Wasm-executed channel ops.
            // channel-archive is owner-gated server-side, so allowing it by
            // default does not widen who can change what. member-remove (kick
            // and leave) and channel-promote (opening a restricted channel or
            // DM up) are v0.2 channel dynamics, gated the same way.
            // role-assign and role-unassign (JEP-0005 rule 7b) are owner-only.
            // channel-share and channel-unshare need the `share` right, and
            // only the channel's sequencer writes the contract-* records of
            // what came of a share (JEP-0005 rules 7-11).
            allowed_block_kinds: vec![
                "text-render".to_string(),
                "channel-create".to_string(),
                "member-add".to_string(),
                "member-remove".to_string(),
                "channel-promote".to_string(),
                "channel-archive".to_string(),
                "role-assign".to_string(),
                "role-unassign".to_string(),
                "channel-share".to_string(),
                "channel-unshare".to_string(),
                "contract-accept".to_string(),
                "contract-refuse".to_string(),
                "contract-end".to_string(),
            ],
            max_future_skew_ms: DEFAULT_MAX_FUTURE_SKEW_MS,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityMode {
    Tofu,
    Nameserver,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
// Must stay container-level: `IdentityMode` deliberately has no `Default`
// (neither variant is a safe automatic pick), so per-field `#[serde(default)]`
// on `mode` would not compile. The container form takes `mode` from the
// hand-written `impl Default` below instead.
#[serde(default, deny_unknown_fields)]
pub struct IdentitySection {
    pub mode: IdentityMode,
    pub trusted_nameservers: Vec<String>,
    pub cache_ttl_seconds: u64,
    pub naively_allow_unknown_handles_fallback: bool,
    /// Who speaks for each alias suffix, keyed by suffix (JEP-0004 rule 3,
    /// `config` root). In nameserver mode an alias whose suffix has no entry
    /// here is refused when it is looked up; there is no discovery on the
    /// server side.
    pub delegations: BTreeMap<String, NameDelegation>,
    /// Ask `http://` nameservers under `[identity.delegations]`. Off, a
    /// nameserver is reached only over TLS one of its suffix's authorities
    /// vouches for (its DID's binding for the certificate). For loopback or
    /// local testing only: over plaintext anyone on the path sees which
    /// aliases are looked up and can hide answers, though not forge them.
    /// Listed in `unsafe_options_active`.
    pub dangerously_allow_plaintext_nameservers: bool,
    /// Suffixes under which every alias is refused, before any delegation,
    /// including the built-in `jig` one, which a refused `jig` never gets.
    /// Compared case-insensitively. A suffix may not be both here and in
    /// `[identity.delegations]`. Logged at boot, not advertised.
    pub refused_suffixes: Vec<String>,
}

impl IdentitySection {
    /// `refused_suffixes`, lowercased, as aliases are.
    pub fn refused(&self) -> std::collections::BTreeSet<String> {
        self.refused_suffixes
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect()
    }

    /// Refuse a suffix that is both delegated and refused: which one the
    /// operator meant cannot be guessed.
    pub fn validate(&self) -> Result<(), String> {
        let refused = self.refused();
        match self
            .delegations
            .keys()
            .map(|s| s.to_ascii_lowercase())
            .find(|s| refused.contains(s))
        {
            Some(suffix) => Err(format!(
                "`{suffix}` is both in [identity.delegations] and in [identity] \
                 refused_suffixes; remove it from one"
            )),
            None => Ok(()),
        }
    }
}

/// One suffix's entry in `[identity.delegations]`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
// A misspelt key must not leave a suffix with no authorities: refuse it.
#[serde(deny_unknown_fields)]
pub struct NameDelegation {
    /// The DIDs whose attestations count for this suffix.
    pub authorities: Vec<String>,
    /// The nameserver URLs to ask. Every one is asked; which DID signed an
    /// answer, not which URL served it, decides whether it counts.
    pub nameservers: Vec<String>,
}

impl Default for IdentitySection {
    fn default() -> Self {
        Self {
            mode: IdentityMode::Tofu,
            trusted_nameservers: vec![],
            cache_ttl_seconds: 300,
            naively_allow_unknown_handles_fallback: false,
            delegations: BTreeMap::new(),
            dangerously_allow_plaintext_nameservers: false,
            refused_suffixes: Vec::new(),
        }
    }
}

/// Authentication policy for this server.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
// Container-level default, matching `ServerSection` and `IdentitySection`: a
// partially-written `[auth]` block must keep the documented defaults for keys
// the operator omitted. Per-field `#[serde(default)]` would give
// `require_authenticated_reads` the *type* default of `false` — silently
// turning authentication off for anyone who set only the window. Verified: with
// per-field defaults, `a_partial_auth_section_keeps_the_safe_default` fails.
//
// `deny_unknown_fields`, like every section: a misspelled sub-table
// (`[auth.admision]`) must not silently leave the permissive defaults in place.
#[serde(default, deny_unknown_fields)]
pub struct AuthSection {
    /// Require a valid proof of possession on read requests.
    ///
    /// Defaults to **true**. A server that boots without an `[auth]` block must
    /// be safe on a public address, because the `curl | sh` install flow puts it
    /// on one. Setting this false restores the pre-authentication behaviour
    /// where any caller reads any channel, and exists only to migrate an
    /// existing deployment.
    pub require_authenticated_reads: bool,

    /// Half-width of the request acceptance window, in milliseconds. A request
    /// is fresh if its timestamp is within this of the server's clock in either
    /// direction. Wider tolerates more clock skew and costs proportionally more
    /// memory.
    pub replay_window_ms: u64,

    /// Hard cap on retained nonces.
    ///
    /// Size this above the expected `rate x window` product. The guard refuses
    /// new requests rather than evicting a nonce that is still inside the
    /// window — evicting one would turn a replay into a cache miss, and a miss
    /// is an accept. So an undersized cap degrades to refusing legitimate
    /// traffic, which is the safe direction but still a denial of service.
    pub replay_capacity: usize,

    /// Gate 2: whom this server will deal with at all. See [`AdmissionSection`].
    pub admission: AdmissionSection,

    /// How fast one identity, or one address, may use this server. See
    /// [`RateLimitSection`].
    pub rate_limit: RateLimitSection,
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            require_authenticated_reads: true,
            replay_window_ms: 30_000,
            replay_capacity: 100_000,
            admission: AdmissionSection::default(),
            rate_limit: RateLimitSection::default(),
        }
    }
}

/// `[auth.rate_limit]` — token buckets in front of the gates. On by default:
/// without them one identity can spend the replay guard's capacity, and so
/// refuse everyone, and one address can sign requests under as many throwaway
/// identities as it likes.
///
/// Each bucket holds up to `*_burst` requests and refills at `*_per_second`.
/// A rate of 0 turns that limit off.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitSection {
    /// Per verified DID: authenticated reads, subscriptions, and every write
    /// it authors, whichever surface (REST, WebSocket, federation, bridge)
    /// carried it.
    pub per_did_burst: u32,
    pub per_did_per_second: u32,
    /// Per remote address: every HTTP request and every WebSocket frame,
    /// signed or not. Behind a reverse proxy every request comes from the
    /// proxy's address, so raise this or turn it off there.
    pub per_ip_burst: u32,
    pub per_ip_per_second: u32,
    /// Nonces one DID may hold in the replay guard at once. Keeps one
    /// identity from filling the guard's shared `replay_capacity`.
    pub replay_per_did: usize,
    /// Most identities or addresses tracked at once. When full, an idle
    /// bucket is forgotten to make room; with none idle, a newcomer is
    /// refused rather than an old bucket reset.
    pub max_tracked: usize,
}

impl Default for RateLimitSection {
    fn default() -> Self {
        Self {
            per_did_burst: 300,
            per_did_per_second: 50,
            per_ip_burst: 600,
            per_ip_per_second: 100,
            replay_per_did: 2_000,
            max_tracked: 100_000,
        }
    }
}

/// `[auth.admission]` — the operator's policy for who is admitted, evaluated
/// after a caller has proved possession of their key and before anything is
/// authorized. Refusing here narrows access, so nothing in this section is a
/// `dangerously_` carve-out; the default admits everyone.
///
/// Reputation is ruleset-scoped, never a scalar: a floor names the ruleset it
/// applies to, and a DID with no score under that ruleset is *unknown* for
/// it — decided by `unknown_dids`, never by comparing an absent score against
/// `minimum`.
// `deny_unknown_fields`, like every section, and it matters most here: a
// misspelled key in a section whose whole job is to NARROW access would
// silently leave the permissive default in place. A members-only server whose
// operator wrote `unknown_did` (singular) must not boot as an open one.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdmissionSection {
    /// What to do with a DID this server has no relevant record for.
    /// `"admit"` (the default), `"refuse"`, or `"proof-of-work"`. `"refuse"`
    /// with a set of `records` is a members-only server. `"proof-of-work"`
    /// admits a new DID once it has done the work this server asks
    /// (`POST /api/v1/admission`, JEP-0008's `admit` puzzle); blocks relayed
    /// by a peer or submitted by a bridge are not asked for it.
    pub unknown_dids: UnknownDidsPolicy,
    /// Legacy: leading zero bits of work, 1 to 28; `0` (the default) is
    /// unset. Kept for one release; it means `min_effort = 2^pow_bits`. Set
    /// this or `min_effort`, not both.
    pub pow_bits: u8,
    /// The least effort (expected digests) a new DID owes under
    /// `"proof-of-work"`, whatever the load (JEP-0008 rule 19). `0` asks no
    /// work while the server is idle (rule 17). Unset: `2^20`, under a second
    /// on a laptop.
    pub min_effort: Option<u64>,
    /// The most effort the controller asks, at most `2^28`.
    pub max_effort: u64,
    /// The controller (rule 17): after a window in which more than
    /// `controller_target` distinct unknown DIDs arrived, the effort asked
    /// above `min_effort` doubles, starting from `controller_start_effort`;
    /// after a window with at most half that many, it halves, and below the
    /// start it drops to zero.
    pub controller_window_secs: u64,
    pub controller_target: u32,
    pub controller_start_effort: u64,
    /// DIDs this server refuses outright, whatever their scores.
    pub banned_dids: Vec<String>,
    /// Reputation floors, evaluated in the order written.
    pub floors: Vec<AdmissionFloor>,
    /// Reputation this operator wrote down by hand — the server's whole view
    /// until a ledger exists.
    pub records: Vec<ReputationRecord>,
}

impl Default for AdmissionSection {
    fn default() -> Self {
        Self {
            unknown_dids: UnknownDidsPolicy::default(),
            pow_bits: 0,
            min_effort: None,
            max_effort: 1 << 24,
            controller_window_secs: 60,
            controller_target: 100,
            controller_start_effort: 1 << 16,
            banned_dids: Vec::new(),
            floors: Vec::new(),
            records: Vec::new(),
        }
    }
}

/// The explicit choice for an unknown DID. Not a bool: "admit" and "refuse"
/// are both decisions, and neither is a type default that could be reached by
/// omission.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UnknownDidsPolicy {
    #[default]
    Admit,
    Refuse,
    #[serde(rename = "proof-of-work")]
    ProofOfWork,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionFloor {
    pub ruleset_key: String,
    pub minimum: i64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationRecord {
    pub did: String,
    pub ruleset_key: String,
    pub score: i64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FederationSection {
    pub peers: Vec<FederationPeer>,
    pub dangerously_disable_federation_tls: bool,
    /// Antipattern flag: permit `ws://` (plaintext) peer URLs. Without it, a
    /// `ws://` peer is a boot error and is never dialed. The peer's DID is
    /// still checked by the signed welcome, but nothing after the welcome is
    /// protected on a plaintext link. Surfaces in `unsafe_options_active`.
    pub dangerously_allow_plaintext_federation: bool,
    /// The quota for every peer without its own `quota`, published in the
    /// server manifest (JEP-0005 rule 16). Defaults to
    /// [`DEFAULT_PEER_BLOCKS_PER_MIN`] blocks and [`DEFAULT_PEER_BYTES_PER_MIN`]
    /// bytes a minute.
    pub default_peer_quota: PeerQuotaConfig,
    /// The name suffixes this server attests, published in the server
    /// manifest.
    pub attested_suffixes: Vec<AttestedSuffixConfig>,
    /// How often a follower may ask this server for one channel's records
    /// (`records-from`). Defaults to a burst of [`DEFAULT_RECORDS_FROM_BURST`]
    /// and [`DEFAULT_RECORDS_FROM_PER_MIN`] a minute.
    pub records_from: RecordsFromLimit,
}

/// Blocks a peer may relay to this server per minute, unless it has its own
/// `quota`.
pub const DEFAULT_PEER_BLOCKS_PER_MIN: u64 = 600;
/// Bytes a peer may relay to this server per minute, unless it has its own
/// `quota`: 8 MiB.
pub const DEFAULT_PEER_BYTES_PER_MIN: u64 = 8 * 1024 * 1024;

/// `records-from` requests one peer may make for one channel back to back.
pub const DEFAULT_RECORDS_FROM_BURST: u32 = 8;
/// `records-from` requests one peer may make for one channel per minute, once
/// its burst is spent. A follower polls each channel 6 times a minute, and
/// catching up at the default peer quota takes about 10 full frames a minute.
pub const DEFAULT_RECORDS_FROM_PER_MIN: u32 = 20;

impl Default for FederationSection {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            dangerously_disable_federation_tls: false,
            dangerously_allow_plaintext_federation: false,
            default_peer_quota: PeerQuotaConfig {
                blocks_per_min: DEFAULT_PEER_BLOCKS_PER_MIN,
                bytes_per_min: DEFAULT_PEER_BYTES_PER_MIN,
            },
            attested_suffixes: Vec::new(),
            records_from: RecordsFromLimit {
                burst: DEFAULT_RECORDS_FROM_BURST,
                per_min: DEFAULT_RECORDS_FROM_PER_MIN,
            },
        }
    }
}

/// A server this one federates with. Listing it is what makes it trusted:
/// this server dials `url` and refuses a welcome signed by any DID but
/// `expected_did`, and only a DID listed here may subscribe to this server's
/// federation stream.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationPeer {
    pub url: String,
    pub expected_did: String,
    #[serde(default)]
    pub alias: Option<String>,
    /// List `expected_did` in the server manifest's `peers`. Off by default:
    /// who a server federates with is the operator's to disclose.
    #[serde(default)]
    pub publish: bool,
    /// This peer's own quota, in place of `default_peer_quota`. Published
    /// only when `publish` is set: a quota names its peer.
    #[serde(default)]
    pub quota: Option<PeerQuotaConfig>,
    /// What this server does with a channel this peer offers it (JEP-0005
    /// rule 8): hold the offer for the operator (the default), or accept it.
    /// An offer this server cannot honour is refused either way.
    #[serde(default)]
    pub offers: OfferPolicy,
}

/// What a server does with a contract offer from one peer.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OfferPolicy {
    /// Keep the offer until the operator accepts or refuses it.
    #[default]
    Hold,
    /// Accept every offer this server can honour.
    Accept,
}

/// How much one peer may relay to this server.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerQuotaConfig {
    pub blocks_per_min: u64,
    pub bytes_per_min: u64,
}

/// How often one peer may ask this server for one channel's records: a token
/// bucket per peer and channel, holding `burst` requests and refilled at
/// `per_min` a minute. A request past it is refused with the time to retry.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordsFromLimit {
    pub burst: u32,
    pub per_min: u32,
}

/// A name suffix this server attests (JEP-0004).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedSuffixConfig {
    pub suffix: String,
    /// What the attestation rests on. Only `"dns"` for now.
    pub root: String,
}

impl FederationSection {
    /// Refuse a peer policy the server manifest could not publish, or should
    /// not.
    pub fn validate(&self) -> Result<(), String> {
        let check_quota = |q: &PeerQuotaConfig, at: &str| {
            // Zero would publish "send nothing", which no peer can honour
            // while federating.
            if q.blocks_per_min == 0 || q.bytes_per_min == 0 {
                return Err(format!(
                    "[federation] {at}: blocks_per_min and bytes_per_min must both be at least 1"
                ));
            }
            Ok(())
        };
        check_quota(&self.default_peer_quota, "default_peer_quota")?;
        if self.records_from.burst == 0 || self.records_from.per_min == 0 {
            // Zero would refuse every follower, the first request included.
            return Err(
                "[federation] records_from: burst and per_min must both be at least 1".to_string(),
            );
        }
        let mut quotas: BTreeMap<&str, Option<PeerQuotaConfig>> = BTreeMap::new();
        for (i, peer) in self.peers.iter().enumerate() {
            if let Some(q) = &peer.quota {
                check_quota(q, &format!("peers[{i}].quota"))?;
            }
            if let Some(earlier) = quotas.insert(&peer.expected_did, peer.quota)
                && earlier != peer.quota
            {
                return Err(format!(
                    "[federation] peers[{i}]: {} is listed more than once with different quotas",
                    peer.expected_did
                ));
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for (i, entry) in self.attested_suffixes.iter().enumerate() {
            let at = format!("[federation] attested_suffixes[{i}]");
            match entry.root.as_str() {
                "dns" => {}
                "contract" => {
                    return Err(format!(
                        "{at}: contract-rooted suffixes are v0.3; only root = \"dns\" is \
                         supported"
                    ));
                }
                "config" => {
                    return Err(format!(
                        "{at}: a config-rooted suffix is never published (JEP-0004 rule 7); \
                         only root = \"dns\" belongs here"
                    ));
                }
                other => {
                    return Err(format!(
                        "{at}: unknown root `{other}`; only \"dns\" is supported"
                    ));
                }
            }
            let suffix = entry.suffix.to_lowercase();
            // JEP-0004 rules 1 and 4: a dotted name of `[a-z0-9-]` labels that
            // neither start nor end with a hyphen, and
            // more than one, since a single label has no DNS name to root it.
            let labels_ok = suffix.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
            if suffix.split('.').count() < 2 || !labels_ok {
                return Err(format!(
                    "{at}: `{}` is not a multi-label DNS suffix of `[a-z0-9-]` labels (e.g. `names.example.org`)",
                    entry.suffix
                ));
            }
            if !seen.insert(suffix) {
                return Err(format!("{at}: `{}` is listed more than once", entry.suffix));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct DebugSection {
    pub list_handles: bool,
}

/// Server-side bridge policy. Read at startup; gates whether
/// [`JigServerConfig::bridge_permitted`] returns true for each bridge name.
///
/// Defaults to deny-all: no bridges loaded unless explicitly allowlisted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BridgesSection {
    /// Allowlist: if non-empty, only these bridges may load. If empty, all
    /// bridges with `per_bridge.<name>.enabled = true` (and not in deny_list)
    /// may load. Empty + nothing in deny_list = deny-by-default (no bridges).
    #[serde(default)]
    pub allow_list: Vec<String>,

    /// Denylist: bridges in this list may not load regardless of allow_list.
    /// Special value `"*"` blocks all bridges (useful for high-sec lockdown).
    #[serde(default)]
    pub deny_list: Vec<String>,

    /// Per-bridge configuration. Keyed by bridge name (matches
    /// `Bridge::name()`).
    #[serde(default)]
    pub per_bridge: BTreeMap<String, BridgeSection>,
}

/// Per-bridge policy + configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BridgeSection {
    /// Kill-switch independent of allow_list / deny_list. A bridge with
    /// `enabled = false` does NOT load even if it's in allow_list.
    #[serde(default)]
    pub enabled: bool,

    /// Max submissions per minute. Enforcement scaffolded in alpha.1a;
    /// actual rate-counting lands in alpha.email.
    #[serde(default)]
    pub rate_limit_per_minute: Option<u32>,

    /// Max submissions per day. Same scaffold-now-enforce-later treatment.
    #[serde(default)]
    pub rate_limit_per_day: Option<u32>,

    /// If non-empty, bridge submissions are restricted to these channel
    /// slugs. Empty = no channel restriction.
    #[serde(default)]
    pub allow_channels: Vec<String>,

    /// Bridge-specific opaque config table. Server passes this through to
    /// `BridgeContext::config` without inspection.
    #[serde(default)]
    pub config: toml::Table,
}

/// Nameserver-mode settings. Only meaningful when this process runs as a
/// jig-nameserver; a plain chat server parses and ignores the section.
///
/// `alias_suffixes` has no default: a nameserver must name the suffixes it
/// serves. [`NameserverSection::validate`] enforces that, and jig-nameserver
/// calls it at load; jig-server never does, so a chat server's config needs no
/// `[nameserver]` table.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NameserverSection {
    /// The removed single-suffix key. Parsed only so `validate` can name its
    /// replacement instead of failing on an unknown field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias_suffix: Option<String>,
    /// The suffixes this nameserver serves, the part after the `@` in
    /// `dj@names.example.org`. Each one is stored without the `@`.
    pub alias_suffixes: Vec<SuffixConfig>,
}

/// Whether a suffix accepts new registrations. A closed suffix still resolves,
/// renews and rotates the names it already holds.
///
/// Non-exhaustive so a later mode (an operator approval queue) is an added
/// variant, not a config break.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Registration {
    #[default]
    Open,
    Closed,
}

/// One DID and the exact aliases it may register on a suffix, closed or not,
/// regardless of the minimum length and the reserved names. Removing an entry
/// does not affect a name already registered.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    pub did: String,
    pub aliases: Vec<String>,
}

/// One served suffix and its registration policy.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuffixConfig {
    pub suffix: String,
    #[serde(default)]
    pub registration: Registration,
    /// Required to serve a single-label suffix such as `jig`. Clients trust a
    /// single-label suffix only through their own config, so its names verify
    /// only for clients whose config names this nameserver's DID.
    #[serde(default)]
    pub single_label_authority: bool,
    /// Shortest alias accepted, counted on the lowercased alias as typed.
    #[serde(default = "default_min_alias_len")]
    pub min_alias_len: usize,
    /// Refused when the normalized alias equals one of these.
    #[serde(default = "default_reserved")]
    pub reserved: Vec<String>,
    /// Refused when the normalized alias contains one of these.
    #[serde(default = "default_reserved_contains")]
    pub reserved_contains: Vec<String>,
    /// Refused when the normalized alias starts or ends with one of these.
    #[serde(default = "default_reserved_affixes")]
    pub reserved_affixes: Vec<String>,
    #[serde(default)]
    pub registration_allow: Vec<AllowEntry>,
    /// The proof-of-work register, renew and rotate carry (JEP-0008).
    #[serde(default)]
    pub pow: PowPolicy,
    /// The cap on stranger registrations (JEP-0008 rules 17 and 21–24).
    #[serde(default)]
    pub pool: PoolPolicy,
}

/// `[v0_0_2.nameserver.alias_suffixes.pool]`: how many registrations by DIDs
/// the allowlist does not name are admitted, however much work they bring
/// (R1 decision 2), and how effort follows the demand.
///
/// On by default at [`PoolPolicy::recommended`], the opening value for `@jig`:
/// `jig` waits out `503 REGISTRATION_BUSY` and retries (R1 slice 2).
/// [`PoolPolicy::off`] admits every stranger.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PoolPolicy {
    pub enabled: bool,
    /// Stranger registrations admitted per hour.
    pub strangers_per_hour: u32,
    /// How many may be admitted at once after a quiet spell.
    pub burst: u32,
    /// How the suggested effort follows the queue. Only `doubling`.
    pub controller: Controller,
    /// One controller window.
    pub controller_window_secs: u64,
    /// Requests held for a token, highest effort first.
    pub queue_len: usize,
    /// The longest a held request waits before `503 REGISTRATION_BUSY`.
    pub queue_wait_secs: u64,
}

/// How the suggested effort adapts (JEP-0008 rule 17).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Controller {
    /// Double after a window with the queue full; halve after a window with
    /// it empty throughout.
    #[default]
    Doubling,
}

impl Default for PoolPolicy {
    fn default() -> Self {
        Self::recommended()
    }
}

impl PoolPolicy {
    /// R1 decision 2: 60 an hour with a burst of 10 for `@jig`'s first week.
    pub fn recommended() -> Self {
        Self {
            enabled: true,
            strangers_per_hour: 60,
            burst: 10,
            controller: Controller::Doubling,
            controller_window_secs: 300,
            queue_len: 20,
            queue_wait_secs: 10,
        }
    }

    /// No pool: every stranger with valid work is admitted, with
    /// [`PoolPolicy::recommended`]'s other values.
    pub fn off() -> Self {
        Self {
            enabled: false,
            ..Self::recommended()
        }
    }
}

/// `[v0_0_2.nameserver.alias_suffixes.pow]`: how much work a suffix asks for
/// (JEP-0008 rules 16–31). Each challenge promises an effort, signed, and the
/// proof is checked against that promise.
///
/// The default is [`PowPolicy::recommended`]: the CLI solves (R1 slice 2).
/// `min_effort = 0` turns it off.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PowPolicy {
    /// The puzzle algorithm (rule 8). Only `1`, BLAKE3, is registered.
    pub alg: u8,
    /// The effort an ordinary registration pays before the length multiplier;
    /// the floor for strangers (rule 19). `0` asks no work of anyone on this
    /// suffix.
    pub min_effort: u64,
    /// The most a registration is asked for. It must fit `max_solve_secs` on
    /// the slowest client this suffix means to serve.
    pub max_effort: u64,
    /// What `max_effort` must be solvable in.
    pub max_solve_secs: u64,
    /// Aliases shorter than this pay the length multiplier.
    pub short_name_len: usize,
    /// Effort × `short_name_factor`^(`short_name_len` − length).
    pub short_name_factor: u64,
    /// What renew and rotate by the holder pay (rule 31). `0` asks none.
    pub renew_effort: u64,
    /// How long a penalty point lasts; each repeat offence before it lapses
    /// doubles it (rule 27).
    pub penalty_decay_secs: u64,
}

impl Default for PowPolicy {
    fn default() -> Self {
        Self::recommended()
    }
}

impl PowPolicy {
    /// The R1 plan's values: 2^20 to register, ×4 per letter under 5, at most
    /// 2^24 (about 3 s on one server core); 1 to renew or rotate.
    pub fn recommended() -> Self {
        Self {
            alg: 1,
            min_effort: 1 << 20,
            max_effort: 1 << 24,
            max_solve_secs: 10,
            short_name_len: 5,
            short_name_factor: 4,
            renew_effort: 1,
            penalty_decay_secs: 600,
        }
    }

    /// No work is asked on this suffix, with [`PowPolicy::recommended`]'s
    /// other values.
    pub fn off() -> Self {
        Self {
            min_effort: 0,
            renew_effort: 0,
            ..Self::recommended()
        }
    }
}

fn default_min_alias_len() -> usize {
    3
}

fn strings(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| x.to_string()).collect()
}

fn default_reserved() -> Vec<String> {
    strings(&[
        "admin",
        "root",
        "support",
        "help",
        "security",
        "abuse",
        "official",
        "jig",
        "foundation",
        "team",
        "staff",
        "mod",
        "moderator",
        "system",
        "postmaster",
        "noreply",
    ])
}

fn default_reserved_contains() -> Vec<String> {
    strings(&["official", "support", "jig"])
}

fn default_reserved_affixes() -> Vec<String> {
    strings(&["admin", "staff"])
}

impl SuffixConfig {
    /// A suffix with the default policy.
    pub fn new(suffix: &str) -> Self {
        Self {
            suffix: suffix.to_string(),
            registration: Registration::default(),
            single_label_authority: false,
            min_alias_len: default_min_alias_len(),
            reserved: default_reserved(),
            reserved_contains: default_reserved_contains(),
            reserved_affixes: default_reserved_affixes(),
            registration_allow: Vec::new(),
            pow: PowPolicy::default(),
            pool: PoolPolicy::default(),
        }
    }

    /// `jig`, as opposed to `names.example.org`.
    pub fn is_single_label(&self) -> bool {
        !self.suffix.contains('.')
    }

    fn validate(&self) -> Result<(), String> {
        let s = &self.suffix;
        if s.is_empty() {
            return Err("a nameserver.alias_suffixes entry has an empty suffix".to_string());
        }
        if s.contains('@') {
            return Err(format!(
                "nameserver suffix must not contain '@'; it is the suffix alone \
                 (e.g. `names.example.org`), not a full alias; got `{s}`"
            ));
        }
        if s.chars().any(|c| c.is_uppercase()) {
            return Err(format!("nameserver suffix must be lowercase; got `{s}`"));
        }
        if s.chars().any(char::is_whitespace) {
            return Err(format!(
                "nameserver suffix must not contain whitespace; got `{s}`"
            ));
        }
        if self.is_single_label() && !self.single_label_authority {
            return Err(format!(
                "suffix `{s}` is a single label. Clients trust a single-label suffix only \
                 through their own config, so names registered here verify only for clients \
                 whose config names this nameserver's DID. Set `single_label_authority = true` \
                 on this suffix if that is intended."
            ));
        }
        if self.min_alias_len == 0 {
            return Err(format!("suffix `{s}`: min_alias_len must be at least 1"));
        }
        for list in [
            &self.reserved,
            &self.reserved_contains,
            &self.reserved_affixes,
        ] {
            if let Some(bad) = list.iter().find(|w| {
                w.is_empty()
                    || w.chars()
                        .any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit())
            }) {
                return Err(format!(
                    "suffix `{s}`: reserved entry `{bad}` must be non-empty lowercase letters \
                     and digits"
                ));
            }
        }
        Ok(())
    }
}

impl NameserverSection {
    /// Reject a nameserver config that would serve no suffix, or suffixes that
    /// would produce unresolvable aliases. Aliases are compared byte-wise
    /// downstream, so a suffix that differs only in case or padding silently
    /// fails to resolve; catch it at boot instead.
    pub fn validate(&self) -> Result<(), String> {
        if self.alias_suffix.is_some() {
            return Err(
                "nameserver.alias_suffix was replaced by nameserver.alias_suffixes, a list of \
                 tables: [[nameserver.alias_suffixes]] with suffix = \"...\". There is no \
                 default suffix."
                    .to_string(),
            );
        }
        if self.alias_suffixes.is_empty() {
            return Err(
                "nameserver.alias_suffixes is required: name each suffix this nameserver \
                 serves, e.g. [[nameserver.alias_suffixes]] with suffix = \"names.example.org\". \
                 There is no default suffix."
                    .to_string(),
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for entry in &self.alias_suffixes {
            entry.validate()?;
            if !seen.insert(entry.suffix.as_str()) {
                return Err(format!(
                    "suffix `{}` is listed twice in nameserver.alias_suffixes",
                    entry.suffix
                ));
            }
        }
        Ok(())
    }
}

impl JigServerConfig {
    /// List of active antipattern flags. Returned by `GET /.well-known/jig`
    /// so federated peers can detect a misconfigured node. A block's clock is
    /// bounded by `[server] max_future_skew_ms`, so there is no unbounded
    /// clock-skew flag any more.
    pub fn unsafe_options_active(&self) -> Vec<String> {
        let mut active = Vec::new();
        if self.federation.dangerously_disable_federation_tls {
            active.push("federation.dangerously_disable_federation_tls".to_string());
        }
        if self.federation.dangerously_allow_plaintext_federation {
            active.push("federation.dangerously_allow_plaintext_federation".to_string());
        }
        if self.identity.naively_allow_unknown_handles_fallback {
            active.push("identity.naively_allow_unknown_handles_fallback".to_string());
        }
        if self.identity.dangerously_allow_plaintext_nameservers {
            active.push("identity.dangerously_allow_plaintext_nameservers".to_string());
        }
        if self.debug.list_handles {
            active.push("debug.list_handles".to_string());
        }
        // Switching authentication off also switches authorization off on
        // every surface: with no verified caller there is nobody to
        // authorize, so restricted channels read as open. Advertise it.
        if !self.auth.require_authenticated_reads {
            active.push("auth.require_authenticated_reads=false".to_string());
        }
        // v0.0.3 (alpha.email): only the SQLite BridgeStorage backend ships;
        // the abstraction is unproven against Postgres/CockroachDB. Advertise
        // the limitation whenever any bridge would load, so federated peers +
        // operators can see it via /.well-known/jig.
        if self
            .bridges
            .per_bridge
            .keys()
            .any(|n| self.bridge_permitted(n))
        {
            active.push("naively_single_backend_bridge_storage".to_string());
        }
        active
    }

    /// Returns true if the bridge may load per current policy. Combines
    /// `allow_list`, `deny_list`, and per-bridge `enabled` checks.
    ///
    /// Decision order:
    /// 1. If bridge is in `deny_list` (or deny_list contains `"*"`) → false
    /// 2. If `allow_list` is non-empty AND bridge is not in it → false
    /// 3. If bridge has no `per_bridge` entry OR entry has `enabled = false` → false
    /// 4. Otherwise → true
    pub fn bridge_permitted(&self, name: &str) -> bool {
        // Step 1: deny_list check
        if self.bridges.deny_list.iter().any(|d| d == "*" || d == name) {
            return false;
        }
        // Step 2: allow_list gate
        if !self.bridges.allow_list.is_empty() && !self.bridges.allow_list.iter().any(|a| a == name)
        {
            return false;
        }
        // Step 3: per-bridge enabled check (also acts as deny-by-default
        // for bridges with no per_bridge entry at all)
        matches!(self.bridges.per_bridge.get(name), Some(b) if b.enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default must be the safe one. A server booting without an `[auth]`
    /// block should require authentication, not skip it — the whole point of
    /// this work is that a fresh install is safe on a public address.
    #[test]
    fn auth_defaults_to_requiring_authentication() {
        let auth = AuthSection::default();
        assert!(
            auth.require_authenticated_reads,
            "a default server must require authenticated reads"
        );
        assert_eq!(auth.replay_window_ms, 30_000);
        assert_eq!(auth.replay_capacity, 100_000);
    }

    /// A config file with NO `[auth]` section at all must still authenticate.
    /// This is the case a real fresh install hits.
    #[test]
    fn a_config_without_an_auth_section_still_requires_authentication() {
        let cfg: JigServerConfig =
            toml::from_str("[server]\nlisten = \"127.0.0.1:7117\"\n").expect("parses");
        assert!(
            cfg.auth.require_authenticated_reads,
            "an absent [auth] section must not disable authentication"
        );
    }

    #[test]
    fn a_missing_admission_section_admits_everyone() {
        let cfg: JigServerConfig = toml::from_str("[auth]\n").expect("parses");
        assert_eq!(cfg.auth.admission, AdmissionSection::default());
        assert_eq!(cfg.auth.admission.unknown_dids, UnknownDidsPolicy::Admit);
        assert!(cfg.auth.admission.floors.is_empty());
        assert!(cfg.auth.admission.banned_dids.is_empty());
    }

    #[test]
    fn a_full_admission_section_parses() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [auth.admission]
            unknown_dids = "refuse"
            banned_dids = ["did:jig:zBad"]

            [[auth.admission.floors]]
            ruleset_key = "jig.highsec.v1"
            minimum = 0

            [[auth.admission.records]]
            did = "did:jig:zGood"
            ruleset_key = "jig.highsec.v1"
            score = 5
            "#,
        )
        .expect("parses");
        let a = &cfg.auth.admission;
        assert_eq!(a.unknown_dids, UnknownDidsPolicy::Refuse);
        assert_eq!(a.banned_dids, vec!["did:jig:zBad".to_string()]);
        assert_eq!(a.floors[0].ruleset_key, "jig.highsec.v1");
        assert_eq!(a.floors[0].minimum, 0);
        assert_eq!(a.records[0].did, "did:jig:zGood");
        assert_eq!(a.records[0].score, 5);
    }

    /// A partial admission section keeps the admit-everyone defaults for what
    /// it omits, and `[auth.admission]` on its own does not disturb `[auth]`'s
    /// own safe defaults.
    #[test]
    fn a_partial_admission_section_keeps_the_defaults() {
        let cfg: JigServerConfig =
            toml::from_str("[auth.admission]\nbanned_dids = [\"did:jig:zBad\"]\n").expect("parses");
        assert_eq!(cfg.auth.admission.unknown_dids, UnknownDidsPolicy::Admit);
        assert!(cfg.auth.require_authenticated_reads);
    }

    /// A misspelled key in a section that narrows access must be an error,
    /// not a silently permissive server.
    #[test]
    fn a_misspelled_admission_key_is_an_error() {
        for bad in [
            "[auth.admision]\nunknown_dids = \"refuse\"\n",
            "[auth]\nrequire_authenticated_read = false\n",
            "[auth.admission]\nunknown_did = \"refuse\"\n",
            "[auth.admission]\nbanned_did = [\"did:jig:zx\"]\n",
            "[[auth.admission.floors]]\nruleset = \"r\"\nminimum = 0\n",
            "[[auth.admission.records]]\ndid = \"did:jig:zx\"\nruleset_key = \"r\"\nscores = 1\n",
        ] {
            assert!(
                toml::from_str::<JigServerConfig>(bad).is_err(),
                "must not parse: {bad}"
            );
        }
    }

    #[test]
    fn unknown_dids_accepts_only_the_two_choices() {
        assert!(
            toml::from_str::<JigServerConfig>("[auth.admission]\nunknown_dids = \"maybe\"\n")
                .is_err()
        );
    }

    /// A PARTIAL `[auth]` section must keep the safe default for keys the
    /// operator did not mention. Setting only the window must not silently
    /// switch authentication off — which is exactly what per-field
    /// `#[serde(default)]` would do, since the bool's type default is false.
    #[test]
    fn a_partial_auth_section_keeps_the_safe_default() {
        let cfg: JigServerConfig =
            toml::from_str("[auth]\nreplay_window_ms = 5000\n").expect("parses");
        assert!(
            cfg.auth.require_authenticated_reads,
            "omitting require_authenticated_reads must leave it true"
        );
        assert_eq!(cfg.auth.replay_window_ms, 5_000);
        assert_eq!(cfg.auth.replay_capacity, 100_000);
    }

    /// The escape hatch works when asked for explicitly, and only then.
    #[test]
    fn authentication_can_be_disabled_explicitly() {
        let cfg: JigServerConfig =
            toml::from_str("[auth]\nrequire_authenticated_reads = false\n").expect("parses");
        assert!(!cfg.auth.require_authenticated_reads);
    }

    #[test]
    fn default_config_round_trips_through_toml() {
        let cfg = JigServerConfig::default();
        let toml_str = toml::to_string(&cfg).unwrap();
        let parsed: JigServerConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn default_identity_mode_is_tofu() {
        let cfg = JigServerConfig::default();
        assert_eq!(cfg.identity.mode, IdentityMode::Tofu);
        assert!(cfg.identity.trusted_nameservers.is_empty());
    }

    #[test]
    fn default_listen_is_loopback_for_safety() {
        let cfg = JigServerConfig::default();
        assert_eq!(cfg.server.listen, "127.0.0.1:7117");
    }

    #[test]
    fn default_allowed_block_kinds_includes_core_v0_0_2_kinds() {
        // v0.0.2 needs text-render (chat messages), channel-create,
        // member-add, and channel-archive (channel ops) in the default allow
        // list — the hello-world flow can't run without them, and without
        // channel-archive a stray channel can never be removed. Operators should
        // explicitly remove kinds to restrict; v0.0.2 doesn't ship a
        // narrower default.
        let cfg = JigServerConfig::default();
        for required in [
            "text-render",
            "channel-create",
            "member-add",
            "member-remove",
            "channel-promote",
            "channel-archive",
            "role-assign",
            "role-unassign",
            "channel-share",
            "channel-unshare",
            "contract-accept",
            "contract-refuse",
            "contract-end",
        ] {
            assert!(
                cfg.server.allowed_block_kinds.iter().any(|k| k == required),
                "default allowed_block_kinds must include `{required}`; got {:?}",
                cfg.server.allowed_block_kinds
            );
        }
    }

    #[test]
    fn antipattern_flags_default_off() {
        let cfg = JigServerConfig::default();
        assert!(!cfg.federation.dangerously_disable_federation_tls);
        assert!(!cfg.federation.dangerously_allow_plaintext_federation);
        assert!(!cfg.identity.naively_allow_unknown_handles_fallback);
        assert!(!cfg.debug.list_handles);
    }

    #[test]
    fn a_default_install_advertises_no_unsafe_option() {
        let cfg = JigServerConfig::default();
        assert_eq!(cfg.unsafe_options_active(), Vec::<String>::new());
    }

    #[test]
    fn keys_default_to_sealed_and_parse_when_set() {
        let omitted: JigServerConfig = toml::from_str("").unwrap();
        assert_eq!(omitted.keys, KeysSection::default());
        assert_eq!(omitted.keys.storage, KeyStorage::Sealed);
        let set: JigServerConfig = toml::from_str(
            "[keys]\nunlock = \"credential:/run/credentials/jig-server.service/key\"\n",
        )
        .unwrap();
        assert_eq!(
            set.keys.unlock.as_deref(),
            Some("credential:/run/credentials/jig-server.service/key")
        );
        let plain: JigServerConfig = toml::from_str("[keys]\nstorage = \"plaintext\"\n").unwrap();
        assert_eq!(plain.keys.storage, KeyStorage::Plaintext);
        assert!(toml::from_str::<JigServerConfig>("[keys]\nunlok = \"env:X\"\n").is_err());
    }

    #[test]
    fn the_skew_bound_defaults_when_omitted_and_parses_when_set() {
        let omitted: JigServerConfig =
            toml::from_str("[server]\nlisten = \"0.0.0.0:443\"\n").unwrap();
        assert_eq!(
            omitted.server.max_future_skew_ms,
            DEFAULT_MAX_FUTURE_SKEW_MS
        );
        let set: JigServerConfig =
            toml::from_str("[server]\nmax_future_skew_ms = 60000\n").unwrap();
        assert_eq!(set.server.max_future_skew_ms, 60_000);
    }

    #[test]
    fn unsafe_options_active_lists_enabled_antipatterns() {
        let mut cfg = JigServerConfig::default();
        cfg.federation.dangerously_disable_federation_tls = true;
        cfg.federation.dangerously_allow_plaintext_federation = true;
        cfg.identity.naively_allow_unknown_handles_fallback = true;
        cfg.identity.dangerously_allow_plaintext_nameservers = true;
        cfg.debug.list_handles = true;
        cfg.auth.require_authenticated_reads = false;
        cfg.keys.storage = KeyStorage::Plaintext;
        let active = cfg.unsafe_options_active();
        // Not published: it would point attackers at soft targets, and clients
        // cannot verify an operator's word about it anyway. It warns at boot.
        assert!(!active.iter().any(|o| o.starts_with("keys.")));
        assert!(active.contains(&"auth.require_authenticated_reads=false".to_string()));
        assert!(active.contains(&"federation.dangerously_disable_federation_tls".to_string()));
        assert!(active.contains(&"federation.dangerously_allow_plaintext_federation".to_string()));
        assert!(active.contains(&"identity.naively_allow_unknown_handles_fallback".to_string()));
        assert!(active.contains(&"identity.dangerously_allow_plaintext_nameservers".to_string()));
        assert!(active.contains(&"debug.list_handles".to_string()));
        assert!(!active.contains(&"naively_unbounded_clock_skew".to_string()));
    }

    #[test]
    fn federation_peer_parses_from_toml() {
        let toml_input = r#"
            [server]
            listen = "0.0.0.0:443"
            server_did_keyfile = "/etc/jig/server.key"
            allowed_block_kinds = ["text-render"]

            [identity]
            mode = "nameserver"
            trusted_nameservers = ["https://ns.jig.onl"]
            cache_ttl_seconds = 600
            naively_allow_unknown_handles_fallback = false

            [federation]
            dangerously_disable_federation_tls = false

            [[federation.peers]]
            url = "wss://deji.jig.onl"
            expected_did = "did:jig:zABC"
            alias = "deji.jig"

            [debug]
            list_handles = false
        "#;
        let cfg: JigServerConfig = toml::from_str(toml_input).unwrap();
        assert_eq!(cfg.server.listen, "0.0.0.0:443");
        assert_eq!(cfg.identity.mode, IdentityMode::Nameserver);
        assert_eq!(cfg.identity.trusted_nameservers, vec!["https://ns.jig.onl"]);
        assert_eq!(cfg.federation.peers.len(), 1);
        assert_eq!(cfg.federation.peers[0].alias.as_deref(), Some("deji.jig"));
        assert!(!cfg.debug.list_handles);
    }

    // --- [federation] peer policy ----------------------------------------

    fn federation(doc: &str) -> Result<FederationSection, String> {
        let cfg: JigServerConfig = toml::from_str(doc).map_err(|e| e.to_string())?;
        cfg.federation.validate()?;
        Ok(cfg.federation)
    }

    #[test]
    fn the_peer_policy_defaults_publish_nothing_but_the_default_quota() {
        let f = federation(
            r#"
            [[federation.peers]]
            url = "wss://peer.example.org"
            expected_did = "did:jig:zPeer"
            "#,
        )
        .unwrap();
        assert!(!f.peers[0].publish);
        assert_eq!(f.peers[0].quota, None);
        assert_eq!(
            f.default_peer_quota,
            PeerQuotaConfig {
                blocks_per_min: 600,
                bytes_per_min: 8 * 1024 * 1024,
            }
        );
        assert!(f.attested_suffixes.is_empty());
        JigServerConfig::default().federation.validate().unwrap();
    }

    #[test]
    fn a_full_peer_policy_parses() {
        let f = federation(
            r#"
            [federation.default_peer_quota]
            blocks_per_min = 100
            bytes_per_min = 1000

            [[federation.peers]]
            url = "wss://peer.example.org"
            expected_did = "did:jig:zPeer"
            publish = true
            quota = { blocks_per_min = 5, bytes_per_min = 50 }

            [[federation.attested_suffixes]]
            suffix = "Names.Example.org"
            root = "dns"
            "#,
        )
        .unwrap();
        assert!(f.peers[0].publish);
        assert_eq!(
            f.peers[0].quota,
            Some(PeerQuotaConfig {
                blocks_per_min: 5,
                bytes_per_min: 50,
            })
        );
        assert_eq!(f.default_peer_quota.blocks_per_min, 100);
        assert_eq!(f.attested_suffixes[0].suffix, "Names.Example.org");
    }

    #[test]
    fn a_bad_peer_policy_is_refused() {
        let peer = |did: &str, quota: &str| {
            format!(
                "[[federation.peers]]\nurl = \"wss://peer.example.org\"\n\
                 expected_did = \"{did}\"\n{quota}\n"
            )
        };
        let suffix = |s: &str, root: &str| {
            format!("[[federation.attested_suffixes]]\nsuffix = \"{s}\"\nroot = \"{root}\"\n")
        };
        for (doc, why) in [
            (suffix("names.example.org", "contract"), "v0.3"),
            (suffix("names.example.org", "config"), "never published"),
            (suffix("names.example.org", "ens"), "unknown root"),
            (suffix("jig", "dns"), "multi-label"),
            (suffix("example.", "dns"), "multi-label"),
            (suffix("ex ample.org", "dns"), "multi-label"),
            (suffix("ex_ample.org", "dns"), "multi-label"),
            (suffix("-ex.org", "dns"), "multi-label"),
            (suffix("ex-.org", "dns"), "multi-label"),
            (
                suffix("names.example.org", "dns") + &suffix("NAMES.example.org", "dns"),
                "more than once",
            ),
            (
                "[federation.default_peer_quota]\nblocks_per_min = 0\nbytes_per_min = 1\n"
                    .to_string(),
                "at least 1",
            ),
            (
                "[federation.records_from]\nburst = 0\nper_min = 20\n".to_string(),
                "records_from",
            ),
            (
                "[federation.records_from]\nburst = 8\nper_min = 0\n".to_string(),
                "records_from",
            ),
            (
                peer(
                    "did:jig:zPeer",
                    "quota = { blocks_per_min = 1, bytes_per_min = 0 }",
                ),
                "at least 1",
            ),
            (
                peer(
                    "did:jig:zPeer",
                    "quota = { blocks_per_min = 1, bytes_per_min = 1 }",
                ) + &peer(
                    "did:jig:zPeer",
                    "quota = { blocks_per_min = 2, bytes_per_min = 1 }",
                ),
                "different quotas",
            ),
            (
                peer(
                    "did:jig:zPeer",
                    "quota = { blocks_per_min = 1, bytes_per_min = 1 }",
                ) + &peer("did:jig:zPeer", ""),
                "different quotas",
            ),
        ] {
            let err = federation(&doc).expect_err(&doc);
            assert!(err.contains(why), "{doc}: {err}");
        }
        // The same DID twice with the same quota is one peer.
        let same = "quota = { blocks_per_min = 1, bytes_per_min = 1 }";
        federation(&(peer("did:jig:zPeer", same) + &peer("did:jig:zPeer", same))).unwrap();
    }

    #[test]
    fn missing_sections_use_defaults() {
        // Minimal config — only [server] required-shape fields specified
        let toml_input = r#"
            [server]
            listen = "127.0.0.1:7117"
            server_did_keyfile = "/tmp/key"
            allowed_block_kinds = ["text-render"]
        "#;
        let cfg: JigServerConfig = toml::from_str(toml_input).unwrap();
        assert_eq!(cfg.identity.mode, IdentityMode::Tofu);
        assert!(cfg.federation.peers.is_empty());
        assert!(!cfg.debug.list_handles);
    }

    // --- partial-section defaults -------------------------------------
    // Operators routinely write a config that names a section but only sets
    // the one key they care about. Without container-level serde defaults
    // that is a hard parse error, which is why neither install.sh's config
    // nor `--init-config`'s template produced a bootable server.

    #[test]
    fn partial_server_section_keeps_sibling_defaults() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [server]
            listen = "0.0.0.0:9999"
        "#,
        )
        .expect("partial [server] must deserialize");
        let d = ServerSection::default();
        assert_eq!(cfg.server.listen, "0.0.0.0:9999");
        assert_eq!(cfg.server.server_did_keyfile, d.server_did_keyfile);
        assert_eq!(cfg.server.allowed_block_kinds, d.allowed_block_kinds);
    }

    #[test]
    fn partial_identity_section_keeps_sibling_defaults() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [identity]
            cache_ttl_seconds = 60
        "#,
        )
        .expect("partial [identity] must deserialize");
        assert_eq!(cfg.identity.cache_ttl_seconds, 60);
        assert_eq!(cfg.identity.mode, IdentityMode::Tofu);
        assert!(cfg.identity.trusted_nameservers.is_empty());
        assert!(!cfg.identity.naively_allow_unknown_handles_fallback);
    }

    #[test]
    fn identity_delegations_parse_keyed_by_suffix() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [identity]
            mode = "nameserver"

            [identity.delegations."gigue.jig"]
            authorities = ["did:jig:zA", "did:jig:zB"]
            nameservers = ["https://ns1.example", "https://ns2.example"]
        "#,
        )
        .expect("[identity.delegations] must deserialize");
        let d = &cfg.identity.delegations["gigue.jig"];
        assert_eq!(d.authorities, vec!["did:jig:zA", "did:jig:zB"]);
        assert_eq!(
            d.nameservers,
            vec!["https://ns1.example", "https://ns2.example"]
        );
        assert_eq!(cfg.identity.delegations.len(), 1);
        assert!(IdentitySection::default().delegations.is_empty());
    }

    #[test]
    fn a_suffix_both_delegated_and_refused_is_a_config_error() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [identity]
            refused_suffixes = ["example.org"]

            [identity.delegations."Example.ORG"]
            authorities = ["did:jig:zA"]
            nameservers = ["https://ns.example"]
        "#,
        )
        .unwrap();
        let err = cfg.identity.validate().unwrap_err();
        assert!(err.contains("`example.org`"), "{err}");

        let refused_only: JigServerConfig =
            toml::from_str("[identity]\nrefused_suffixes = [\"JIG\"]\n").unwrap();
        refused_only.identity.validate().unwrap();
        assert!(refused_only.identity.refused().contains("jig"));
        assert!(IdentitySection::default().refused_suffixes.is_empty());
    }

    #[test]
    fn a_delegation_with_a_misspelt_or_missing_key_is_refused() {
        for body in [
            "authorites = [\"did:jig:zA\"]\nnameservers = []",
            "nameservers = [\"https://ns.example\"]",
        ] {
            let toml_input = format!("[identity.delegations.\"gigue.jig\"]\n{body}\n");
            assert!(
                toml::from_str::<JigServerConfig>(&toml_input).is_err(),
                "must refuse: {body}"
            );
        }
    }

    #[test]
    fn partial_debug_section_keeps_sibling_defaults() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [debug]
            list_handles = true
        "#,
        )
        .expect("partial [debug] must deserialize");
        assert!(cfg.debug.list_handles);
    }

    /// Every section denies unknown keys: a typo is a parse error naming the
    /// key, never a silent default.
    #[test]
    fn unknown_keys_are_rejected_in_every_section() {
        for (section, key) in [
            ("server", "lisen"),
            ("identity", "mod"),
            ("federation", "peer"),
            ("debug", "admin_endpoints"),
            ("bridges", "allowlist"),
            ("nameserver", "suffix"),
            ("auth", "require_authenticated_read"),
            ("auth.rate_limit", "per_did"),
            ("auth.admission", "unknown_did"),
        ] {
            let toml_str = format!("[{section}]\n{key} = true\n");
            let err = toml::from_str::<JigServerConfig>(&toml_str)
                .expect_err(&format!("[{section}] {key} must be rejected"));
            assert!(
                err.to_string().contains(key),
                "the error must name `{key}`, got: {err}"
            );
        }
        let err = toml::from_str::<JigServerConfig>("[bridges.per_bridge.email]\nenabeld = true\n")
            .expect_err("a misspelled per-bridge key must be rejected");
        assert!(err.to_string().contains("enabeld"), "got: {err}");
        assert!(toml::from_str::<JigServerConfig>("[sever]\n").is_err());
    }

    #[test]
    fn partial_federation_section_keeps_sibling_defaults() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [federation]
            dangerously_disable_federation_tls = true
        "#,
        )
        .expect("partial [federation] must deserialize");
        assert!(cfg.federation.dangerously_disable_federation_tls);
        assert!(cfg.federation.peers.is_empty());
        assert!(!cfg.federation.dangerously_allow_plaintext_federation);
    }

    #[test]
    fn plaintext_federation_flag_parses_and_surfaces() {
        let mut cfg = JigServerConfig::default();
        assert!(
            !cfg.unsafe_options_active()
                .contains(&"federation.dangerously_allow_plaintext_federation".to_string()),
            "flag must not appear in active list when disabled"
        );
        cfg = toml::from_str(
            r#"
            [federation]
            dangerously_allow_plaintext_federation = true
        "#,
        )
        .expect("flag must deserialize");
        assert!(cfg.federation.dangerously_allow_plaintext_federation);
        assert!(
            cfg.unsafe_options_active()
                .contains(&"federation.dangerously_allow_plaintext_federation".to_string()),
            "flag must appear in active list when enabled"
        );
    }

    #[test]
    fn empty_config_file_equals_full_default() {
        let cfg: JigServerConfig = toml::from_str("").expect("empty config must deserialize");
        assert_eq!(cfg, JigServerConfig::default());
    }

    // --- [nameserver] --------------------------------------------------

    fn ns(doc: &str) -> Result<NameserverSection, String> {
        let cfg: JigServerConfig = toml::from_str(doc).map_err(|e| e.to_string())?;
        cfg.nameserver.validate()?;
        Ok(cfg.nameserver)
    }

    #[test]
    fn nameserver_has_no_default_suffix() {
        assert!(
            JigServerConfig::default()
                .nameserver
                .alias_suffixes
                .is_empty()
        );
        let err = JigServerConfig::default()
            .nameserver
            .validate()
            .expect_err("a nameserver with no suffix must not start");
        assert!(err.contains("alias_suffixes is required"), "{err}");
    }

    #[test]
    fn a_chat_server_config_needs_no_nameserver_table() {
        // jig-server parses the section but never validates it.
        let cfg: JigServerConfig = toml::from_str("[server]\n").unwrap();
        assert_eq!(cfg.nameserver, NameserverSection::default());
    }

    #[test]
    fn the_old_single_suffix_key_names_its_replacement() {
        let err = ns("[nameserver]\nalias_suffix = \"dj.jig\"\n").expect_err("old key");
        assert!(
            err.contains("replaced by nameserver.alias_suffixes"),
            "{err}"
        );
    }

    #[test]
    fn a_suffix_entry_round_trips_with_the_default_policy() {
        let section = ns(r#"
            [[nameserver.alias_suffixes]]
            suffix = "names.example.org"
        "#)
        .unwrap();
        assert_eq!(
            section.alias_suffixes,
            vec![SuffixConfig::new("names.example.org")]
        );
        let entry = &section.alias_suffixes[0];
        assert_eq!(entry.registration, Registration::Open);
        assert_eq!(entry.min_alias_len, 3);
        assert!(entry.reserved.contains(&"postmaster".to_string()));
        assert_eq!(entry.reserved_contains, ["official", "support", "jig"]);
        assert_eq!(entry.reserved_affixes, ["admin", "staff"]);

        let cfg = JigServerConfig {
            nameserver: section,
            ..Default::default()
        };
        let reparsed: JigServerConfig = toml::from_str(&toml::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(reparsed, cfg);
    }

    #[test]
    fn a_full_suffix_entry_parses() {
        let section = ns(r#"
            [[nameserver.alias_suffixes]]
            suffix = "names.example.org"
            registration = "closed"
            min_alias_len = 2
            reserved = ["boss"]
            reserved_contains = []
            reserved_affixes = ["ops"]

            [[nameserver.alias_suffixes.registration_allow]]
            did = "did:jig:zexample"
            aliases = ["dj", "ana"]

            [[nameserver.alias_suffixes]]
            suffix = "other.example.org"
        "#)
        .unwrap();
        let first = &section.alias_suffixes[0];
        assert_eq!(first.registration, Registration::Closed);
        assert_eq!(first.min_alias_len, 2);
        assert_eq!(first.reserved, ["boss"]);
        assert!(first.reserved_contains.is_empty());
        assert_eq!(first.registration_allow[0].aliases, ["dj", "ana"]);
        assert_eq!(section.alias_suffixes[1].registration, Registration::Open);
    }

    #[test]
    fn an_unknown_registration_mode_is_a_parse_error() {
        let err = ns(r#"
            [[nameserver.alias_suffixes]]
            suffix = "names.example.org"
            registration = "moderated"
        "#)
        .expect_err("not built yet");
        assert!(err.contains("moderated"), "{err}");
    }

    #[test]
    fn a_single_label_suffix_needs_the_acknowledgement() {
        let err = ns("[[nameserver.alias_suffixes]]\nsuffix = \"jig\"\n").expect_err("no ack");
        assert!(err.contains("single_label_authority"), "{err}");
        assert!(
            err.contains("only for clients"),
            "the error must say why: {err}"
        );

        ns("[[nameserver.alias_suffixes]]\nsuffix = \"jig\"\nsingle_label_authority = true\n")
            .expect("acknowledged");
    }

    #[test]
    fn nameserver_validate_rejects_the_malformed_suffixes() {
        let cases = [
            ("", "empty"),
            ("alice@dj.example", "'@'"),
            ("DJ.example", "lowercase"),
            ("dj .example", "whitespace"),
        ];
        let mut messages = Vec::new();
        for (suffix, expected_fragment) in cases {
            let section = NameserverSection {
                alias_suffix: None,
                alias_suffixes: vec![SuffixConfig::new(suffix)],
            };
            let err = section
                .validate()
                .expect_err("malformed suffix must be rejected");
            assert!(
                err.contains(expected_fragment),
                "message for {suffix:?} should mention {expected_fragment}; got {err}"
            );
            messages.push(err);
        }
        // Each malformed shape gets its own message so an operator can tell
        // which rule they tripped from the log line alone.
        let distinct: std::collections::BTreeSet<&String> = messages.iter().collect();
        assert_eq!(distinct.len(), messages.len(), "messages: {messages:?}");
    }

    #[test]
    fn nameserver_validate_rejects_bad_policy() {
        let dup = NameserverSection {
            alias_suffix: None,
            alias_suffixes: vec![
                SuffixConfig::new("a.example"),
                SuffixConfig::new("a.example"),
            ],
        };
        assert!(dup.validate().unwrap_err().contains("listed twice"));

        let mut zero = SuffixConfig::new("a.example");
        zero.min_alias_len = 0;
        let section = NameserverSection {
            alias_suffix: None,
            alias_suffixes: vec![zero],
        };
        assert!(section.validate().unwrap_err().contains("min_alias_len"));

        let mut upper = SuffixConfig::new("a.example");
        upper.reserved_contains = vec!["Admin".to_string()];
        let section = NameserverSection {
            alias_suffix: None,
            alias_suffixes: vec![upper],
        };
        assert!(section.validate().unwrap_err().contains("reserved entry"));
    }

    #[test]
    fn bridges_section_default_is_empty_allowlist() {
        let cfg = JigServerConfig::default();
        assert!(cfg.bridges.allow_list.is_empty());
        assert!(cfg.bridges.deny_list.is_empty());
        assert!(cfg.bridges.per_bridge.is_empty());
    }

    #[test]
    fn bridges_section_parses_full_toml() {
        let toml = r##"
            [bridges]
            allow_list = ["email", "slack"]
            deny_list = []

            [bridges.per_bridge.email]
            enabled = true
            rate_limit_per_minute = 60
            rate_limit_per_day = 5000
            allow_channels = ["#email-inbox", "#email-team"]

            [bridges.per_bridge.email.config]
            smtp_listen_addr = "0.0.0.0:25"
            resend_api_key = "rk_test"

            [bridges.per_bridge.slack]
            enabled = false
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.bridges.allow_list, vec!["email", "slack"]);
        assert!(cfg.bridges.deny_list.is_empty());

        let email = cfg.bridges.per_bridge.get("email").unwrap();
        assert!(email.enabled);
        assert_eq!(email.rate_limit_per_minute, Some(60));
        assert_eq!(email.rate_limit_per_day, Some(5000));
        assert_eq!(email.allow_channels, vec!["#email-inbox", "#email-team"]);
        assert_eq!(
            email
                .config
                .get("smtp_listen_addr")
                .and_then(|v| v.as_str()),
            Some("0.0.0.0:25"),
        );

        let slack = cfg.bridges.per_bridge.get("slack").unwrap();
        assert!(!slack.enabled);
    }

    #[test]
    fn bridge_permitted_default_deny_for_unknown() {
        // Empty config: nothing in allow_list, nothing in deny_list, no
        // per-bridge entry. Per spec: deny-by-default for unknown bridges.
        let cfg = JigServerConfig::default();
        assert!(!cfg.bridge_permitted("email"));
        assert!(!cfg.bridge_permitted("slack"));
    }

    #[test]
    fn bridge_permitted_allow_list_only() {
        let toml = r#"
            [bridges]
            allow_list = ["email"]

            [bridges.per_bridge.email]
            enabled = true
        "#;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        assert!(cfg.bridge_permitted("email"));
        assert!(!cfg.bridge_permitted("slack"));
    }

    #[test]
    fn bridge_permitted_deny_list_overrides_allow_list() {
        let toml = r#"
            [bridges]
            allow_list = ["email"]
            deny_list = ["*"]

            [bridges.per_bridge.email]
            enabled = true
        "#;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        // deny_list ["*"] blocks everything including allowlisted bridges.
        assert!(!cfg.bridge_permitted("email"));
    }

    #[test]
    fn bridge_permitted_per_bridge_enabled_false_overrides_allow_list() {
        let toml = r#"
            [bridges]
            allow_list = ["email"]

            [bridges.per_bridge.email]
            enabled = false
        "#;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        // Per-bridge kill-switch beats allowlist.
        assert!(!cfg.bridge_permitted("email"));
    }

    #[test]
    fn bridge_permitted_specific_deny_works() {
        let toml = r#"
            [bridges]
            allow_list = ["email", "slack"]
            deny_list = ["slack"]

            [bridges.per_bridge.email]
            enabled = true

            [bridges.per_bridge.slack]
            enabled = true
        "#;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        assert!(cfg.bridge_permitted("email"));
        assert!(!cfg.bridge_permitted("slack"));
    }

    #[test]
    fn single_backend_bridge_storage_flag_present_when_a_bridge_is_permitted() {
        let toml = r##"
            [bridges]
            allow_list = ["email"]
            [bridges.per_bridge.email]
            enabled = true
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        assert!(
            cfg.unsafe_options_active()
                .contains(&"naively_single_backend_bridge_storage".to_string()),
            "expected the single-backend flag when a bridge is permitted"
        );
    }

    #[test]
    fn no_bridge_storage_flag_when_no_bridge_permitted() {
        let cfg = JigServerConfig::default();
        assert!(
            !cfg.unsafe_options_active()
                .contains(&"naively_single_backend_bridge_storage".to_string()),
            "no bridge permitted by default -> flag absent"
        );
    }

    #[test]
    fn no_bridge_storage_flag_when_bridge_present_but_disabled() {
        // A bridge entry that is NOT permitted (enabled=false) must not trip the flag.
        let toml = r##"
            [bridges]
            allow_list = ["email"]
            [bridges.per_bridge.email]
            enabled = false
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        assert!(
            !cfg.unsafe_options_active()
                .contains(&"naively_single_backend_bridge_storage".to_string()),
            "disabled bridge is not permitted -> flag absent"
        );
    }
}
