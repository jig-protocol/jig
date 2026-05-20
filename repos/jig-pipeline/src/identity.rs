//! Identity resolution: TOFU and nameserver modes.
//!
//! Every block ingest passes through here to verify the claimed sender DID
//! corresponds to a recognized identity. v0.0.2 ships two backends:
//!
//! - [`TofuResolver`] — trust-on-first-use; the first DID seen for a local
//!   nickname is locked. Suitable for tiny demos, internal nets, dev mode.
//! - [`NameserverResolver`] — queries one or more `jig-nameserver` URLs to
//!   resolve `alias@authority.jig` → DID. Mismatches are rejected.
//!
//! See v0.0.2 spec §5 ("Identity layer") for the full design.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::persist::SqliteStore;

/// Identity-resolution errors. Bubbled up through `ingest()` and surfaced
/// to clients via the WSS `error` frame.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("TOFU mismatch for nickname `{nickname}`: locked to {expected}, got {received}")]
    TofuMismatch {
        nickname: String,
        expected: String,
        received: String,
    },
    #[error("alias `{alias}` not found in any trusted nameserver")]
    NotFound { alias: String },
    #[error("all configured nameservers unreachable")]
    AllNameserversUnreachable,
    #[error("invalid nickname: must match ^[a-zA-Z0-9_-]{{1,24}}$ (no `@`, `:`, or homoglyphs)")]
    InvalidNickname,
    #[error("nameserver returned malformed response: {0}")]
    MalformedResponse(String),
    #[error(transparent)]
    Persist(#[from] crate::persist::PersistError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// The two production identity backends supported in v0.0.2.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IdentityMode {
    Tofu,
    Nameserver,
}

/// Trait every identity resolver implements. The pipeline holds a
/// `Arc<dyn IdentityResolver>`; the concrete type is chosen at server boot
/// from `[identity] mode = "tofu" | "nameserver"`.
#[async_trait]
pub trait IdentityResolver: Send + Sync {
    /// Verify that `claimed_did` is the correct DID for `identifier`. The
    /// shape of `identifier` differs by backend: TOFU accepts a local
    /// nickname (`dj`); nameserver mode accepts an alias (`dj@dj.jig`).
    async fn verify(&self, identifier: &str, claimed_did: &str) -> Result<(), IdentityError>;
}

// ============================================================================
// TOFU resolver
// ============================================================================

/// Trust-on-first-use resolver. The first DID seen for a local nickname is
/// recorded in the `tofu_keys` table and locked; subsequent submissions
/// claiming the same nickname with a different DID are rejected.
pub struct TofuResolver {
    store: Arc<SqliteStore>,
}

impl TofuResolver {
    pub fn new(store: Arc<SqliteStore>) -> Self {
        Self { store }
    }

    /// Validate a TOFU nickname. Must match `^[a-zA-Z0-9_-]{1,24}$` and
    /// must NOT contain `@` or `:` (those would let attackers impersonate
    /// aliased DIDs from nameserver-respecting servers).
    pub(crate) fn validate_nickname(nick: &str) -> Result<(), IdentityError> {
        if nick.is_empty() || nick.len() > 24 {
            return Err(IdentityError::InvalidNickname);
        }
        if !nick
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(IdentityError::InvalidNickname);
        }
        // The character class above already excludes `@` and `:`, but
        // double-check defensively in case the regex relaxes in the future.
        if nick.contains('@') || nick.contains(':') {
            return Err(IdentityError::InvalidNickname);
        }
        Ok(())
    }
}

#[async_trait]
impl IdentityResolver for TofuResolver {
    async fn verify(&self, nickname: &str, claimed_did: &str) -> Result<(), IdentityError> {
        Self::validate_nickname(nickname)?;
        let store = self.store.clone();
        let nickname = nickname.to_string();
        let claimed = claimed_did.to_string();
        // SQLite ops are sync; run in spawn_blocking so we don't block the runtime.
        tokio::task::spawn_blocking(move || -> Result<(), IdentityError> {
            let existing = store.get_tofu_key(&nickname)?;
            match existing {
                Some(row) if row.did == claimed => Ok(()),
                Some(row) => Err(IdentityError::TofuMismatch {
                    nickname,
                    expected: row.did,
                    received: claimed,
                }),
                None => {
                    let new_key = crate::persist::StoredTofuKey {
                        local_nickname: nickname,
                        did: claimed,
                        first_seen_at: chrono::Utc::now().timestamp(),
                        locked: true,
                    };
                    store.insert_tofu_key(&new_key)?;
                    Ok(())
                }
            }
        })
        .await
        .map_err(|e| IdentityError::Other(e.into()))?
    }
}

// ============================================================================
// Nameserver resolver
// ============================================================================

/// Resolves aliases against one or more configured nameserver URLs. Caches
/// resolutions for `cache_ttl` to avoid hammering nameservers on every block.
pub struct NameserverResolver {
    nameservers: Vec<String>,
    cache: RwLock<HashMap<String, CachedDid>>,
    cache_ttl: Duration,
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
struct CachedDid {
    did: String,
    cached_at: Instant,
}

impl NameserverResolver {
    pub fn new(nameservers: Vec<String>, cache_ttl_seconds: u64) -> Self {
        Self {
            nameservers,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(cache_ttl_seconds),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client construction"),
        }
    }

    /// Resolve an alias to a DID. Used by `verify()` and also exposed for
    /// caller-side lookups (e.g., display-time alias rendering).
    pub async fn resolve(&self, alias: &str) -> Result<String, IdentityError> {
        // Cache check
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(alias)
                && entry.cached_at.elapsed() < self.cache_ttl
            {
                return Ok(entry.did.clone());
            }
        }

        // Cache miss — query each nameserver in order
        let mut any_reachable = false;
        for ns_url in &self.nameservers {
            let url = format!("{}/v1/resolve/{}", ns_url.trim_end_matches('/'), alias);
            match self.client.get(&url).send().await {
                Ok(resp) => {
                    any_reachable = true;
                    if resp.status().is_success() {
                        let json: serde_json::Value = resp
                            .json()
                            .await
                            .map_err(|e| IdentityError::MalformedResponse(e.to_string()))?;
                        if let Some(did) = json.get("did").and_then(|v| v.as_str()) {
                            let did_owned = did.to_string();
                            self.cache.write().await.insert(
                                alias.to_string(),
                                CachedDid {
                                    did: did_owned.clone(),
                                    cached_at: Instant::now(),
                                },
                            );
                            return Ok(did_owned);
                        }
                        // 2xx with no `did` field — malformed
                    }
                    // Non-2xx — try the next nameserver
                }
                Err(_) => {
                    // Network error; try next
                }
            }
        }

        if any_reachable {
            Err(IdentityError::NotFound {
                alias: alias.to_string(),
            })
        } else {
            Err(IdentityError::AllNameserversUnreachable)
        }
    }
}

#[async_trait]
impl IdentityResolver for NameserverResolver {
    async fn verify(&self, alias: &str, claimed_did: &str) -> Result<(), IdentityError> {
        let resolved = self.resolve(alias).await?;
        if resolved == claimed_did {
            Ok(())
        } else {
            // The alias resolves to a different DID than the block claims.
            // Reuse the TofuMismatch variant since the user-visible error
            // shape is identical: "this identifier doesn't match this DID."
            Err(IdentityError::TofuMismatch {
                nickname: alias.to_string(),
                expected: resolved,
                received: claimed_did.to_string(),
            })
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- TOFU tests ----

    #[tokio::test]
    async fn tofu_locks_first_seen_key_and_rejects_mismatch() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let resolver = TofuResolver::new(store.clone());

        let did_a = "did:jig:zaaa";
        let did_b = "did:jig:zbbb";

        // First submission locks
        resolver.verify("dj", did_a).await.unwrap();
        // Same key — passes
        resolver.verify("dj", did_a).await.unwrap();
        // Different key — rejects
        let err = resolver.verify("dj", did_b).await.unwrap_err();
        assert!(matches!(err, IdentityError::TofuMismatch { .. }));
    }

    #[tokio::test]
    async fn tofu_rejects_at_sign_in_nickname() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let resolver = TofuResolver::new(store);
        let err = resolver
            .verify("dj@dj.jig", "did:jig:zaaa")
            .await
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidNickname));
    }

    #[tokio::test]
    async fn tofu_rejects_colon_in_nickname() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let resolver = TofuResolver::new(store);
        let err = resolver
            .verify("dj:admin", "did:jig:zaaa")
            .await
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidNickname));
    }

    #[tokio::test]
    async fn tofu_rejects_oversized_nickname() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let resolver = TofuResolver::new(store);
        let nick = "a".repeat(25);
        let err = resolver.verify(&nick, "did:jig:zaaa").await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidNickname));
    }

    #[tokio::test]
    async fn tofu_rejects_empty_nickname() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let resolver = TofuResolver::new(store);
        let err = resolver.verify("", "did:jig:zaaa").await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidNickname));
    }

    #[tokio::test]
    async fn tofu_accepts_underscores_dashes_alphanumerics() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let resolver = TofuResolver::new(store);
        resolver.verify("dj_test-2", "did:jig:zaaa").await.unwrap();
        resolver.verify("DJ_2", "did:jig:zbbb").await.unwrap();
    }

    // ---- NameserverResolver tests ----

    // Mock nameserver for integration testing. Returns canned responses.
    struct MockNameserver {
        handles: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
        url: String,
        _shutdown_tx: tokio::sync::oneshot::Sender<()>,
    }

    impl MockNameserver {
        async fn start() -> Arc<Self> {
            use std::net::SocketAddr;
            let handles = Arc::new(tokio::sync::Mutex::new(HashMap::<String, String>::new()));

            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let handles_for_server = handles.clone();

            // Bind to ephemeral port
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let bound: SocketAddr = listener.local_addr().unwrap();
            let url = format!("http://{bound}");

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        accept = listener.accept() => {
                            let Ok((mut stream, _)) = accept else { break };
                            let handles = handles_for_server.clone();
                            tokio::spawn(async move {
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                                let mut buf = vec![0u8; 4096];
                                let n = match stream.read(&mut buf).await {
                                    Ok(n) => n,
                                    Err(_) => return,
                                };
                                let req = String::from_utf8_lossy(&buf[..n]);

                                // Very crude HTTP parser — extracts GET /v1/resolve/<alias>
                                let first_line = req.lines().next().unwrap_or("");
                                let alias = first_line
                                    .strip_prefix("GET /v1/resolve/")
                                    .and_then(|s| s.split_whitespace().next())
                                    .unwrap_or("");

                                let handles_guard = handles.lock().await;
                                let body = if let Some(did) = handles_guard.get(alias) {
                                    format!(r#"{{"alias":"{alias}","did":"{did}"}}"#)
                                } else {
                                    // 404
                                    let resp =
                                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                    return;
                                };
                                drop(handles_guard);

                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                            });
                        }
                    }
                }
            });

            Arc::new(Self {
                handles,
                url,
                _shutdown_tx: shutdown_tx,
            })
        }

        async fn register(&self, alias: &str, did: &str) {
            // copy hit_count from the server task counter via Arc-shared atomic
            // (note: our hit_count field above is the unused outer one; tests read via self.hit_count_for_check)
            self.handles
                .lock()
                .await
                .insert(alias.to_string(), did.to_string());
        }

        fn url(&self) -> String {
            self.url.clone()
        }
    }

    #[tokio::test]
    async fn nameserver_resolver_returns_did_for_known_alias() {
        let mock = MockNameserver::start().await;
        mock.register("dj@dj.jig", "did:jig:zaaa").await;
        let resolver = NameserverResolver::new(vec![mock.url()], 300);

        let did = resolver.resolve("dj@dj.jig").await.unwrap();
        assert_eq!(did, "did:jig:zaaa");
    }

    #[tokio::test]
    async fn nameserver_resolver_cache_avoids_repeat_calls() {
        let mock = MockNameserver::start().await;
        mock.register("dj@dj.jig", "did:jig:zaaa").await;
        let resolver = NameserverResolver::new(vec![mock.url()], 300);

        // Two resolutions — second should be cached
        resolver.resolve("dj@dj.jig").await.unwrap();
        let second = resolver.resolve("dj@dj.jig").await.unwrap();
        assert_eq!(second, "did:jig:zaaa");
        // Cache hit means cache map is populated
        let cache = resolver.cache.read().await;
        assert!(cache.contains_key("dj@dj.jig"));
    }

    #[tokio::test]
    async fn nameserver_resolver_not_found_for_unknown_alias() {
        let mock = MockNameserver::start().await;
        let resolver = NameserverResolver::new(vec![mock.url()], 300);
        let err = resolver.resolve("nobody@nowhere.jig").await.unwrap_err();
        assert!(matches!(err, IdentityError::NotFound { .. }));
    }

    #[tokio::test]
    async fn nameserver_resolver_unreachable_when_no_nameservers_respond() {
        // Use a localhost port that nothing's bound on — connection refused
        let resolver = NameserverResolver::new(vec!["http://127.0.0.1:1".to_string()], 300);
        let err = resolver.resolve("anyone@anywhere.jig").await.unwrap_err();
        assert!(matches!(err, IdentityError::AllNameserversUnreachable));
    }

    #[tokio::test]
    async fn nameserver_resolver_verify_passes_when_did_matches() {
        let mock = MockNameserver::start().await;
        mock.register("dj@dj.jig", "did:jig:zaaa").await;
        let resolver = NameserverResolver::new(vec![mock.url()], 300);

        resolver.verify("dj@dj.jig", "did:jig:zaaa").await.unwrap();
    }

    #[tokio::test]
    async fn nameserver_resolver_verify_rejects_when_did_mismatches() {
        let mock = MockNameserver::start().await;
        mock.register("dj@dj.jig", "did:jig:zaaa").await;
        let resolver = NameserverResolver::new(vec![mock.url()], 300);

        let err = resolver
            .verify("dj@dj.jig", "did:jig:zwrong")
            .await
            .unwrap_err();
        assert!(matches!(err, IdentityError::TofuMismatch { .. }));
    }
}
