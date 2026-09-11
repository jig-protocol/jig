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

/// Default time-to-live for an issued challenge nonce. Picked to comfortably
/// exceed normal HTTP round-trip + signing time while staying small enough
/// that the in-memory map can't grow without bound under DoS.
const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(60);

/// Nameserver-scoped v0.0.2 boot state. Identity resolution in a
/// nameserver is always TOFU — nameservers don't query other
/// nameservers (recursion is a v0.0.3+ concern).
#[derive(Clone)]
pub struct AppState {
    pub config: JigServerConfig,
    pub ingest_ctx: Arc<IngestContext>,
    pub ns_did: Did,
    /// `dj.jig` etc. — the alias suffix this nameserver is authoritative for.
    /// Read from config.identity.trusted_nameservers[0] as a v0.0.2 placeholder;
    /// real config field lands in v0.0.3+.
    pub alias_suffix: String,
    /// Recently-issued challenge nonces with their issued-at timestamp.
    /// A background task started in `new` / `for_test*` sweeps entries
    /// older than `challenge_ttl` every `challenge_ttl / 2`. Without the
    /// sweeper an attacker spamming GET /v1/challenge would grow this
    /// map without bound (issue #6).
    pub pending_challenges: Arc<RwLock<HashMap<String, Instant>>>,
    /// How long a challenge nonce remains valid before being swept. Configurable
    /// so tests can use a tight TTL instead of waiting 60s.
    pub challenge_ttl: Duration,
}

impl AppState {
    /// Boot the v0.0.2 state. The nameserver-specific block-kind allowlist
    /// is enforced here: only `ns-*` and `fed-hello` blocks ingest.
    pub fn new(
        mut config: JigServerConfig,
        db_path: PathBuf,
        alias_suffix: String,
    ) -> Result<Self> {
        // Override the allowlist for nameserver mode (config defaults to text-render).
        config.server.allowed_block_kinds = vec![
            "ns-register".to_string(),
            "ns-rotate".to_string(),
            "ns-renew".to_string(),
            "ns-attestation".to_string(),
            "fed-hello".to_string(),
        ];

        let store = Arc::new(SqliteStore::open(&db_path).context("opening SqliteStore")?);
        let signing_key = load_or_generate_server_key(&config.server.server_did_keyfile)
            .context("loading nameserver signing key")?;
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
            alias_suffix,
            pending_challenges,
            challenge_ttl: DEFAULT_CHALLENGE_TTL,
        })
    }

    /// Convenience for tests: in-memory store, freshly generated keys.
    #[cfg(test)]
    pub fn for_test() -> Result<Self> {
        Self::for_test_with_suffix("dj.jig")
    }

    /// Tests-only constructor that overrides the challenge TTL so we can
    /// exercise expiry without waiting the full default. Otherwise identical
    /// to `for_test()`.
    #[cfg(test)]
    pub fn for_test_with_short_challenge_ttl(ttl: Duration) -> Result<Self> {
        let mut state = Self::for_test_with_suffix("dj.jig")?;
        // The sweeper spawned in for_test_with_suffix already uses the default
        // TTL; replace pending_challenges + restart the sweeper at the new TTL.
        let pending = Arc::new(RwLock::new(HashMap::new()));
        spawn_challenge_sweeper(pending.clone(), ttl);
        state.pending_challenges = pending;
        state.challenge_ttl = ttl;
        Ok(state)
    }

    #[cfg(test)]
    pub fn for_test_with_suffix(alias_suffix: &str) -> Result<Self> {
        use rand::Rng;

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
            "ns-attestation".to_string(),
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
            alias_suffix: alias_suffix.to_string(),
            pending_challenges,
            challenge_ttl: DEFAULT_CHALLENGE_TTL,
        })
    }

    pub fn ns_did_string(&self) -> String {
        self.ns_did.to_did_jig_string()
    }

    pub fn suffix(&self) -> &str {
        &self.alias_suffix
    }

    /// Record a challenge nonce so a later /v1/register can verify it was issued.
    /// The nonce is tagged with the current `Instant` so the background sweeper
    /// can drop it once it's older than `challenge_ttl`.
    pub async fn remember_challenge(&self, nonce: &str) {
        self.pending_challenges
            .write()
            .await
            .insert(nonce.to_string(), Instant::now());
    }

    /// Consume a challenge nonce. Returns true if it was registered AND still
    /// within its TTL; in either failure mode (never-issued, already-consumed,
    /// or expired-but-not-yet-swept) we return false without distinguishing —
    /// callers must surface the same "challenge not recognized" error to avoid
    /// leaking whether a nonce was swept vs never-issued.
    pub async fn take_challenge(&self, nonce: &str) -> bool {
        let mut guard = self.pending_challenges.write().await;
        match guard.remove(nonce) {
            Some(issued_at) if issued_at.elapsed() <= self.challenge_ttl => true,
            // Either no entry or stale entry — fall through to the same false.
            _ => false,
        }
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
fn spawn_challenge_sweeper(pending: Arc<RwLock<HashMap<String, Instant>>>, ttl: Duration) {
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
            guard.retain(|_, issued_at| issued_at.elapsed() <= ttl);
        }
    });
}

fn load_or_generate_server_key(path: &str) -> Result<SigningKey> {
    use rand::Rng;
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
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let signing = SigningKey::from_bytes(&secret);
        std::fs::write(path, signing.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(signing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn for_test_constructs_with_default_suffix() {
        let state = AppState::for_test().unwrap();
        assert_eq!(state.suffix(), "dj.jig");
        assert!(state.ns_did_string().starts_with("did:jig:z"));
    }

    #[tokio::test]
    async fn allowed_block_kinds_is_ns_specific() {
        let state = AppState::for_test().unwrap();
        let kinds = &state.ingest_ctx.allowed_block_kinds;
        assert!(kinds.contains(&"ns-register".to_string()));
        assert!(kinds.contains(&"ns-attestation".to_string()));
        assert!(kinds.contains(&"fed-hello".to_string()));
        assert!(
            !kinds.contains(&"text-render".to_string()),
            "nameserver should NOT ingest text-render blocks"
        );
    }

    #[tokio::test]
    async fn challenge_round_trip() {
        let state = AppState::for_test().unwrap();
        state.remember_challenge("nonce-1").await;
        assert!(state.take_challenge("nonce-1").await);
        // Already taken — consumed
        assert!(!state.take_challenge("nonce-1").await);
    }

    #[tokio::test]
    async fn challenge_nonces_expire_after_ttl() {
        // Tight TTL so the test doesn't sit in the runtime for 60s.
        let state =
            AppState::for_test_with_short_challenge_ttl(std::time::Duration::from_millis(50))
                .unwrap();

        state.remember_challenge("nonce-a").await;
        // Fresh: consume succeeds.
        assert!(
            state.take_challenge("nonce-a").await,
            "fresh challenge must be accepted"
        );

        state.remember_challenge("nonce-b").await;
        // Wait past the TTL and the sweep interval (sweep = ttl/2 = 25ms,
        // so 200ms guarantees at least one sweep has fired and dropped it).
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !state.take_challenge("nonce-b").await,
            "expired challenge must be rejected"
        );
    }

    #[tokio::test]
    async fn alias_holder_returns_none_for_unattested() {
        let state = AppState::for_test().unwrap();
        let h = state.alias_holder("nobody@dj.jig").await.unwrap();
        assert!(h.is_none());
    }
}
