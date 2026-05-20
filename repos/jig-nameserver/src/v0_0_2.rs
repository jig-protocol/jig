//! v0.0.2 hello-world milestone — additive layer in jig-nameserver.
//!
//! Mirrors `jig-server::v0_0_2`: holds the v0.0.2 AppState wiring
//! jig-pipeline, plus a router builder that mounts the v0.0.2
//! nameserver endpoints. Existing jig-nameserver modules (handler/
//! identity/pow/etc.) are untouched.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

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
    /// Recently-issued challenge nonces (in-memory, expire after ~60s).
    /// Production would use a TTL store; v0.0.2 keeps this simple.
    pub pending_challenges: Arc<RwLock<HashSet<String>>>,
}

impl AppState {
    /// Boot the v0.0.2 state. The nameserver-specific block-kind allowlist
    /// is enforced here: only `ns-*` and `fed-hello` blocks ingest.
    pub fn new(mut config: JigServerConfig, db_path: PathBuf, alias_suffix: String) -> Result<Self> {
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

        let ingest_ctx = Arc::new(IngestContext {
            store,
            identity,
            hlc_clock,
            allowed_block_kinds: config.server.allowed_block_kinds.clone(),
            server_did: ns_did.clone(),
            server_key: signing_key,
            fanout,
            server_url: format!("ws://{}", config.server.listen),
        });

        Ok(Self {
            config,
            ingest_ctx,
            ns_did,
            alias_suffix,
            pending_challenges: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    /// Convenience for tests: in-memory store, freshly generated keys.
    #[cfg(test)]
    pub fn for_test() -> Result<Self> {
        Self::for_test_with_suffix("dj.jig")
    }

    #[cfg(test)]
    pub fn for_test_with_suffix(alias_suffix: &str) -> Result<Self> {
        use rand::Rng;

        let store = Arc::new(SqliteStore::open_in_memory()?);
        let mut secret = [0u8; 32];
        rand::thread_rng().fill(&mut secret);
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
            store,
            identity,
            hlc_clock,
            allowed_block_kinds: config.server.allowed_block_kinds.clone(),
            server_did: ns_did.clone(),
            server_key: signing_key,
            fanout,
            server_url: format!("ws://{}", config.server.listen),
        });

        Ok(Self {
            config,
            ingest_ctx,
            ns_did,
            alias_suffix: alias_suffix.to_string(),
            pending_challenges: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    pub fn ns_did_string(&self) -> String {
        self.ns_did.to_did_jig_string()
    }

    pub fn suffix(&self) -> &str {
        &self.alias_suffix
    }

    /// Record a challenge nonce so a later /v1/register can verify it was issued.
    pub async fn remember_challenge(&self, nonce: &str) {
        self.pending_challenges.write().await.insert(nonce.to_string());
    }

    /// Consume a challenge nonce. Returns true if it was registered (and removes it).
    pub async fn take_challenge(&self, nonce: &str) -> bool {
        self.pending_challenges.write().await.remove(nonce)
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
        rand::thread_rng().fill(&mut secret);
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
    async fn alias_holder_returns_none_for_unattested() {
        let state = AppState::for_test().unwrap();
        let h = state.alias_holder("nobody@dj.jig").await.unwrap();
        assert!(h.is_none());
    }
}
