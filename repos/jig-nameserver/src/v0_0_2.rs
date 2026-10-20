//! v0.0.2 hello-world milestone — additive layer in jig-nameserver.
//!
//! Mirrors `jig-server::v0_0_2`: holds the v0.0.2 AppState wiring
//! jig-pipeline, plus a router builder that mounts the v0.0.2
//! nameserver endpoints. Existing jig-nameserver modules (handler/
//! identity/pow/etc.) are untouched.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use jig_config::v0_0_2_server::JigServerConfig;
use jig_core::Did;
use jig_pipeline::{
    fanout::Fanout,
    hlc::HlcClock,
    identity::{IdentityResolver, TofuResolver},
    ingest::IngestContext,
    persist::SqliteStore,
};
use tokio::sync::RwLock;

use crate::v0_0_2_policy::Suffixes;

/// Default time-to-live for an issued challenge nonce. Picked to comfortably
/// exceed normal HTTP round-trip + signing time while staying small enough
/// that the in-memory map can't grow without bound under DoS.
pub(crate) const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(60);

/// The suffix of [`AppState::for_test`].
#[cfg(test)]
pub const TEST_SUFFIX: &str = "dj.jig";

/// The most challenges pending at once unless `[alias_rate_limits]
/// max_pending_challenges` says otherwise.
pub const DEFAULT_MAX_PENDING_CHALLENGES: usize = 100_000;

/// An issued challenge. `did` and `name` are set when the client named them
/// at issue time; a challenge so bound is consumed only by a request for that
/// DID and that `alias@suffix`. A challenge issued for an `action` carries the
/// effort promised for it (JEP-0008 rule 16), and its signed offer.
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    pub issued_at: Instant,
    pub did: Option<String>,
    pub name: Option<String>,
    pub action: Option<jig_core::pow::Action>,
    /// `0` when no work was asked.
    pub effort: u64,
    /// The `PowOffer` envelope, restated when a request comes without work.
    pub offer: Option<Vec<u8>>,
}

impl PendingChallenge {
    /// A challenge bound to nothing, as `GET /v1/challenge` issued before R1.
    pub fn unbound() -> Self {
        Self::bound(None, None)
    }

    /// Bound to `did` on `name`, for no particular action.
    pub fn bound(did: Option<String>, name: Option<String>) -> Self {
        Self {
            issued_at: Instant::now(),
            did,
            name,
            action: None,
            effort: 0,
            offer: None,
        }
    }

    /// Can a request for `action` by `did` on `name` use it?
    fn fits(&self, did: &str, name: &str, action: jig_core::pow::Action) -> bool {
        self.did.as_deref().is_none_or(|d| d == did)
            && self.name.as_deref().is_none_or(|n| n == name)
            && self.action.is_none_or(|a| a == action)
    }
}

/// Nameserver-scoped v0.0.2 boot state. Identity resolution in a
/// nameserver is always TOFU — nameservers don't query other
/// nameservers (recursion is a v0.0.3+ concern).
#[derive(Clone)]
pub struct AppState {
    pub config: JigServerConfig,
    pub ingest_ctx: Arc<IngestContext>,
    pub ns_did: Did,
    /// The suffixes this nameserver serves and their registration policy.
    pub suffixes: Arc<Suffixes>,
    /// Recently-issued challenge nonces with their issued-at timestamp and
    /// what they were issued for.
    /// A background task started in `new` / `for_test*` sweeps entries
    /// older than `challenge_ttl` every `challenge_ttl / 2`. Without the
    /// sweeper an attacker spamming GET /v1/challenge would grow this
    /// map without bound (issue #6).
    pub pending_challenges: Arc<RwLock<HashMap<String, PendingChallenge>>>,
    /// How long a challenge nonce remains valid before being swept. Configurable
    /// so tests can use a tight TTL instead of waiting 60s.
    pub challenge_ttl: Duration,
    /// At this many pending challenges, new ones are refused.
    pub max_pending_challenges: usize,
    /// How a client's address is read (`[network] trust_proxy`), for the
    /// penalties registration pricing keys on.
    pub network: crate::config::NetworkConfig,
}

impl AppState {
    /// Boot the v0.0.2 state. The nameserver-specific block-kind allowlist
    /// is enforced here: only `ns-*` and `fed-hello` blocks ingest.
    pub fn new(mut config: JigServerConfig, db_path: PathBuf, suffixes: Suffixes) -> Result<Self> {
        // Override the allowlist for nameserver mode (config defaults to text-render).
        config.server.allowed_block_kinds = vec![
            "ns-register".to_string(),
            "ns-rotate".to_string(),
            "ns-renew".to_string(),
            "fed-hello".to_string(),
        ];

        let store = Arc::new(SqliteStore::open(&db_path).context("opening SqliteStore")?);
        // Before suffixes, aliases were matched as typed. Rows from then are
        // re-signed from their columns on read, so lowercasing them is safe;
        // signed rows are already lowercase and are left byte-identical.
        let lowered = store
            .normalize_alias_case(
                crate::v0_0_2_register::is_legacy_row,
                chrono::Utc::now().timestamp(),
            )
            .context("lowercasing aliases stored before names were case-folded")?;
        if lowered > 0 {
            tracing::info!(
                rows = lowered,
                "lowercased aliases stored before case folding"
            );
        }
        let signing_key = load_or_generate_server_key(&config.server.server_did_keyfile)
            .context("loading nameserver signing key")?;
        // Before anything logs a DID: tags are keyed by this nameserver's seed.
        if !jig_core::did::set_log_tag_key(&signing_key.to_bytes()) {
            tracing::warn!(
                "a different log tag key is already in effect in this process; DID tags keep using it"
            );
        }
        let ns_did = Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());

        // Nameservers always run TOFU identity (they don't recurse).
        let identity: Arc<dyn IdentityResolver> = Arc::new(TofuResolver::new(store.clone()));
        let hlc_clock = Arc::new(HlcClock::new(ns_did.clone()));
        let fanout = Arc::new(Fanout::new());

        let naively_allow_unknown_handles_fallback =
            config.identity.naively_allow_unknown_handles_fallback;

        let ingest_ctx = Arc::new(IngestContext {
            admission: Arc::new(jig_pipeline::ingest::AdmitEveryone),
            store,
            identity,
            hlc_clock,
            allowed_block_kinds: config.server.allowed_block_kinds.clone(),
            server_did: ns_did.clone(),
            server_key: signing_key,
            fanout,
            server_url: format!("ws://{}", config.server.listen),
            naively_allow_unknown_handles_fallback,
            // `allowed_block_kinds` above never includes `text-render`, so this
            // nameserver has no use for a text-render Wasm module and shouldn't
            // pay to compile one. `None` means "does not execute Wasm kinds",
            // not "fall back" — a text-render block would be rejected outright.
            executor: None,
        });

        let pending_challenges = Arc::new(RwLock::new(HashMap::new()));
        spawn_challenge_sweeper(pending_challenges.clone(), DEFAULT_CHALLENGE_TTL);

        Ok(Self {
            config,
            ingest_ctx,
            ns_did,
            suffixes: Arc::new(suffixes),
            pending_challenges,
            challenge_ttl: DEFAULT_CHALLENGE_TTL,
            max_pending_challenges: DEFAULT_MAX_PENDING_CHALLENGES,
            network: crate::config::NetworkConfig::default(),
        })
    }

    /// Convenience for tests: in-memory store, freshly generated keys.
    #[cfg(test)]
    pub fn for_test() -> Result<Self> {
        Self::for_test_with_suffix(TEST_SUFFIX)
    }

    /// Tests-only constructor that overrides the challenge TTL so we can
    /// exercise expiry without waiting the full default. Otherwise identical
    /// to `for_test()`.
    #[cfg(test)]
    pub fn for_test_with_short_challenge_ttl(ttl: Duration) -> Result<Self> {
        let mut state = Self::for_test_with_suffix(TEST_SUFFIX)?;
        // The sweeper spawned in for_test_with_suffix already uses the default
        // TTL; replace pending_challenges + restart the sweeper at the new TTL.
        let pending = Arc::new(RwLock::new(HashMap::new()));
        spawn_challenge_sweeper(pending.clone(), ttl);
        state.pending_challenges = pending;
        state.challenge_ttl = ttl;
        Ok(state)
    }

    /// One open suffix with no minimum length and no reserved names, so tests
    /// can register short names like `dj`. Policy tests build their own.
    #[cfg(test)]
    pub fn for_test_with_suffix(alias_suffix: &str) -> Result<Self> {
        let mut cfg = jig_config::v0_0_2_server::SuffixConfig::new(alias_suffix);
        cfg.min_alias_len = 1;
        cfg.reserved.clear();
        cfg.reserved_contains.clear();
        cfg.reserved_affixes.clear();
        cfg.single_label_authority = true;
        // These tests are about naming; proof-of-work tests set their own.
        cfg.pow = jig_config::v0_0_2_server::PowPolicy::off();
        Self::for_test_with_suffixes(vec![cfg])
    }

    #[cfg(test)]
    pub fn for_test_with_suffixes(
        suffixes: Vec<jig_config::v0_0_2_server::SuffixConfig>,
    ) -> Result<Self> {
        use rand::Rng;

        let suffixes = Suffixes::from_config(&jig_config::v0_0_2_server::NameserverSection {
            alias_suffix: None,
            alias_suffixes: suffixes,
        })?;

        let store = Arc::new(SqliteStore::open_in_memory()?);
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let ns_did = Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());

        let identity: Arc<dyn IdentityResolver> = Arc::new(TofuResolver::new(store.clone()));
        let hlc_clock = Arc::new(HlcClock::new(ns_did.clone()));
        let fanout = Arc::new(Fanout::new());

        let mut config = JigServerConfig::default();
        config.server.allowed_block_kinds = vec![
            "ns-register".to_string(),
            "ns-rotate".to_string(),
            "ns-renew".to_string(),
            "fed-hello".to_string(),
        ];

        let ingest_ctx = Arc::new(IngestContext {
            admission: Arc::new(jig_pipeline::ingest::AdmitEveryone),
            store,
            identity,
            hlc_clock,
            allowed_block_kinds: config.server.allowed_block_kinds.clone(),
            server_did: ns_did.clone(),
            server_key: signing_key,
            fanout,
            server_url: format!("ws://{}", config.server.listen),
            naively_allow_unknown_handles_fallback: false,
            // Same rationale as the `new()` constructor above: nameservers never
            // allow `text-render`, so there's no Wasm module for this server to
            // execute. `None` is a hard "won't execute", not a fallback.
            executor: None,
        });

        let pending_challenges = Arc::new(RwLock::new(HashMap::new()));
        spawn_challenge_sweeper(pending_challenges.clone(), DEFAULT_CHALLENGE_TTL);

        Ok(Self {
            config,
            ingest_ctx,
            ns_did,
            suffixes: Arc::new(suffixes),
            pending_challenges,
            challenge_ttl: DEFAULT_CHALLENGE_TTL,
            max_pending_challenges: DEFAULT_MAX_PENDING_CHALLENGES,
            network: crate::config::NetworkConfig::default(),
        })
    }

    pub fn ns_did_string(&self) -> String {
        self.ns_did.to_did_jig_string()
    }

    /// The single suffix of a test state.
    #[cfg(test)]
    pub fn suffix(&self) -> &str {
        &self.suffixes.only().expect("one suffix").suffix
    }

    /// Record a challenge nonce so a later register, renew or rotate can verify
    /// it was issued, and for what. The background sweeper drops it once it is
    /// older than `challenge_ttl`. Returns false, recording nothing, when the
    /// map is full: live challenges are never evicted to make room. A tenth of
    /// `max_pending_challenges` is kept for renew and rotate, so a flood of
    /// registrations cannot stop holders keeping their names.
    pub async fn remember_challenge(&self, nonce: &str, pending: PendingChallenge) -> bool {
        use jig_core::pow::Action;
        let cap = match pending.action {
            Some(Action::NsRenew | Action::NsRotate) => self.max_pending_challenges,
            _ => self.max_pending_challenges - self.max_pending_challenges / 10,
        };
        let mut guard = self.pending_challenges.write().await;
        if guard.len() >= cap {
            return false;
        }
        guard.insert(nonce.to_string(), pending);
        true
    }

    /// The pending challenge `nonce`, if a request for `action` by `did` on
    /// `name` can use it now. Leaves it in place.
    pub async fn peek_challenge(
        &self,
        nonce: &str,
        did: &str,
        name: &str,
        action: jig_core::pow::Action,
    ) -> Option<PendingChallenge> {
        let guard = self.pending_challenges.read().await;
        guard
            .get(nonce)
            .filter(|p| p.issued_at.elapsed() <= self.challenge_ttl)
            .filter(|p| p.fits(did, name, action))
            .cloned()
    }

    /// Consume a challenge nonce for a request by `did` on `name`. Returns true
    /// if it was registered, is still within its TTL, and was either issued
    /// unbound or bound to this `did` and `name`. In every failure mode we
    /// return false without distinguishing, so callers surface the same
    /// "challenge not recognized" error and leak nothing about the nonce. A
    /// mismatched request leaves the challenge in place for its rightful use.
    pub async fn take_challenge(
        &self,
        nonce: &str,
        did: &str,
        name: &str,
        action: jig_core::pow::Action,
    ) -> bool {
        let mut guard = self.pending_challenges.write().await;
        let Some(pending) = guard.get(nonce) else {
            return false;
        };
        let fresh = pending.issued_at.elapsed() <= self.challenge_ttl;
        let bound_ok = pending.fits(did, name, action);
        if !fresh {
            guard.remove(nonce);
            return false;
        }
        if !bound_ok {
            return false;
        }
        guard.remove(nonce);
        true
    }

    /// Check if a `<local>@<suffix>` alias is already attested. Returns the
    /// existing DID if present.
    pub async fn alias_holder(&self, full_alias: &str) -> anyhow::Result<Option<String>> {
        let now = chrono::Utc::now().timestamp();
        let store = self.ingest_ctx.store.clone();
        let alias = full_alias.to_string();
        let row = tokio::task::spawn_blocking(move || store.find_alias_attestation(&alias, now))
            .await??;
        Ok(row.map(|r| r.did))
    }
}

/// Spawn a background task that drops challenge nonces older than `ttl`
/// every `ttl / 2`. The task holds a clone of the inner `Arc<RwLock<...>>`,
/// so when `AppState` is dropped the task continues briefly until the last
/// strong reference goes away — acceptable for v0.0.3 since the nameserver
/// only constructs `AppState` once per process. No teardown signaling: the
/// sweeper exits naturally when the map's last `Arc` is dropped (we check
/// `Arc::strong_count` each tick).
fn spawn_challenge_sweeper(pending: Arc<RwLock<HashMap<String, PendingChallenge>>>, ttl: Duration) {
    // Sweep at half the TTL so worst-case expired-but-still-present is bounded
    // by ttl/2. Floor at 1ms so test TTLs near zero don't spin.
    let interval = std::cmp::max(ttl / 2, Duration::from_millis(1));
    let weak = Arc::downgrade(&pending);
    drop(pending); // don't keep AppState alive ourselves

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // First tick fires immediately; skip it so we don't sweep an empty map.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let Some(pending) = weak.upgrade() else {
                // AppState gone — stop sweeping.
                break;
            };
            let mut guard = pending.write().await;
            guard.retain(|_, c| c.issued_at.elapsed() <= ttl);
        }
    });
}

/// Write a new nameserver signing key to `path` and return the DID the
/// nameserver will sign as when it loads that file. For a key ceremony on an
/// offline machine: the DID can be recorded before any server exists.
///
/// The file is created owner-only (0600) at open, never chmod'ed after, and
/// synced to disk. An existing file is never overwritten. Errors name the
/// path only, never key material.
pub fn keygen(path: &std::path::Path) -> Result<String> {
    let signing = jig_core::crypto::ed25519::generate_signing_key();
    jig_core::crypto::ed25519::write_new_key_file(path, &signing).with_context(|| {
        format!(
            "writing a new nameserver keyfile to {} (an existing file is never overwritten)",
            path.display()
        )
    })?;
    Ok(Did::from_ed25519_pubkey(signing.verifying_key().as_bytes()).to_did_jig_string())
}

fn load_or_generate_server_key(path: &str) -> Result<SigningKey> {
    let expanded = shellexpand::tilde(path).into_owned();
    let path = std::path::Path::new(&expanded);
    if path.exists() {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading nameserver keyfile at {}", path.display()))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "nameserver keyfile at {} is malformed: expected 32 bytes, got {}",
                path.display(),
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SigningKey::from_bytes(&arr))
    } else {
        let signing = jig_core::crypto::ed25519::generate_signing_key();
        jig_core::crypto::ed25519::write_new_key_file(path, &signing)
            .with_context(|| format!("writing nameserver keyfile to {}", path.display()))?;
        Ok(signing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn for_test_constructs_with_default_suffix() {
        let state = AppState::for_test().unwrap();
        assert_eq!(state.suffix(), TEST_SUFFIX);
        assert!(state.ns_did_string().starts_with("did:jig:z"));
    }

    #[tokio::test]
    async fn allowed_block_kinds_is_ns_specific() {
        let state = AppState::for_test().unwrap();
        let kinds = &state.ingest_ctx.allowed_block_kinds;
        assert!(kinds.contains(&"ns-register".to_string()));
        assert!(
            !kinds.contains(&"ns-attestation".to_string()),
            "an ns-attestation block would write an alias row the resolve path re-signs"
        );
        assert!(kinds.contains(&"fed-hello".to_string()));
        assert!(
            !kinds.contains(&"text-render".to_string()),
            "nameserver should NOT ingest text-render blocks"
        );
    }

    /// An `ns-attestation` block writes an alias row from its own metadata,
    /// and `Binding::from_row` re-signs a non-COSE row naming this nameserver.
    /// Accepting the kind would let any block author get a binding signed.
    #[tokio::test]
    async fn an_ns_attestation_block_is_refused() {
        use ed25519_dalek::Signer;
        use jig_core::{Author, BlockBundle, BlockKind, BlockManifest};
        use jig_pipeline::ingest::{IngestError, IngestSource, ingest};

        let state = AppState::for_test().unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut manifest = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: Did::from_ed25519_pubkey(key.verifying_key().as_bytes()),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap()
            .with_kind(BlockKind::NsAttestation);
        for (k, v) in [
            ("alias", "victim@dj.jig".to_string()),
            ("ns_did", state.ns_did_string()),
        ] {
            manifest
                .metadata
                .insert(k.to_string(), serde_json::json!(v));
        }
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let canonical = serde_json::to_vec(&(&manifest_bytes, &Vec::<u8>::new())).unwrap();
        let sig = key.sign(&canonical).to_bytes().to_vec();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &[],
            resources: vec![],
        };

        let err = ingest(
            &state.ingest_ctx,
            bundle,
            sig,
            IngestSource::LocalClient { conn_id: 1 },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, IngestError::DisallowedBlockKind { .. }),
            "{err:?}"
        );
        assert!(state.alias_holder("victim@dj.jig").await.unwrap().is_none());
    }

    /// A nonce as GET /v1/challenge issues one.
    fn fresh_nonce() -> String {
        use rand::Rng;
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        hex::encode(nonce)
    }

    #[tokio::test]
    async fn challenge_round_trip() {
        let state = AppState::for_test().unwrap();
        let n1 = fresh_nonce();
        state
            .remember_challenge(&n1, PendingChallenge::unbound())
            .await;
        assert!(
            state
                .take_challenge(&n1, "did:a", "a@dj.jig", jig_core::pow::Action::NsRegister)
                .await
        );
        // Already taken — consumed
        assert!(
            !state
                .take_challenge(&n1, "did:a", "a@dj.jig", jig_core::pow::Action::NsRegister)
                .await
        );
    }

    #[tokio::test]
    async fn a_bound_challenge_is_consumed_only_by_its_did_and_name() {
        let state = AppState::for_test().unwrap();
        let n = fresh_nonce();
        state
            .remember_challenge(
                &n,
                PendingChallenge::bound(Some("did:a".into()), Some("a@dj.jig".into())),
            )
            .await;
        assert!(
            !state
                .take_challenge(&n, "did:b", "a@dj.jig", jig_core::pow::Action::NsRegister)
                .await,
            "other DID"
        );
        assert!(
            !state
                .take_challenge(&n, "did:a", "b@dj.jig", jig_core::pow::Action::NsRegister)
                .await,
            "other name"
        );
        assert!(
            state
                .take_challenge(&n, "did:a", "a@dj.jig", jig_core::pow::Action::NsRegister)
                .await,
            "still usable"
        );
        assert!(
            !state
                .take_challenge(&n, "did:a", "a@dj.jig", jig_core::pow::Action::NsRegister)
                .await,
            "consumed"
        );
    }

    #[tokio::test]
    async fn challenge_nonces_expire_after_ttl() {
        // Tight TTL so the test doesn't sit in the runtime for 60s.
        let state =
            AppState::for_test_with_short_challenge_ttl(std::time::Duration::from_millis(50))
                .unwrap();

        let (na, nb) = (fresh_nonce(), fresh_nonce());
        state
            .remember_challenge(&na, PendingChallenge::unbound())
            .await;
        // Fresh: consume succeeds.
        assert!(
            state
                .take_challenge(&na, "did:a", "a@dj.jig", jig_core::pow::Action::NsRegister)
                .await,
            "fresh challenge must be accepted"
        );

        state
            .remember_challenge(&nb, PendingChallenge::unbound())
            .await;
        // Wait past the TTL and the sweep interval (sweep = ttl/2 = 25ms,
        // so 200ms guarantees at least one sweep has fired and dropped it).
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !state
                .take_challenge(&nb, "did:a", "a@dj.jig", jig_core::pow::Action::NsRegister)
                .await,
            "expired challenge must be rejected"
        );
    }

    #[tokio::test]
    async fn keygen_prints_the_did_the_nameserver_signs_as() {
        let dir = std::env::temp_dir().join(format!("jig-ns-keygen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key = dir.join("ns.key");
        let did = keygen(&key).unwrap();

        let mut config = JigServerConfig::default();
        config.server.server_did_keyfile = key.to_string_lossy().into_owned();
        let suffixes = Suffixes::from_config(&jig_config::v0_0_2_server::NameserverSection {
            alias_suffix: None,
            alias_suffixes: vec![jig_config::v0_0_2_server::SuffixConfig::new("dj.jig")],
        })
        .unwrap();
        let state = AppState::new(config, dir.join("ns.db"), suffixes).unwrap();
        assert_eq!(state.ns_did_string(), did);

        let before = std::fs::read(&key).unwrap();
        let err = keygen(&key).unwrap_err();
        assert!(format!("{err:#}").contains("never overwritten"), "{err:#}");
        assert_eq!(
            std::fs::read(&key).unwrap(),
            before,
            "the existing key is untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn alias_holder_returns_none_for_unattested() {
        let state = AppState::for_test().unwrap();
        let h = state.alias_holder("nobody@dj.jig").await.unwrap();
        assert!(h.is_none());
    }
}
