//! Identity resolution: TOFU and nameserver modes.
//!
//! Every block ingest passes through here to verify the claimed sender DID
//! corresponds to a recognized identity. v0.0.2 ships two backends:
//!
//! - [`TofuResolver`] — trust-on-first-use; the first DID seen for a local
//!   nickname is locked. Suitable for tiny demos, internal nets, dev mode.
//! - [`NameserverResolver`] — resolves `alias@suffix` → DID through the
//!   nameservers configured for the suffix, accepting only an attestation
//!   signed by one of the suffix's authorities (JEP-0004). Mismatches are
//!   rejected.
//!
//! See v0.0.2 spec §5 ("Identity layer") for the full design.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jig_config::v0_0_2_server::NameDelegation;
use jig_core::naming::{self, Attestation, Name, NamingError};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::persist::{SqliteStore, StoredNameEvidence};

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
    #[error("no delegation configured for suffix `{suffix}`")]
    NoDelegation { suffix: String },
    #[error("alias attestation refused: {0}")]
    Naming(#[from] NamingError),
    #[error("nameservers for `{alias}` attest different DIDs: {dids:?}")]
    Equivocation { alias: String, dids: Vec<String> },
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

/// Resolves `alias@suffix` against the nameservers `[identity.delegations]`
/// lists for its suffix, and accepts only an attestation signed by one of that
/// suffix's authorities, inside its validity window, for exactly this alias
/// (JEP-0004 rules 3 and 13). A suffix with no entry is refused: the server
/// does no discovery.
///
/// Every listed nameserver is asked. Two valid attestations naming different
/// DIDs are an equivocation: the alias is refused and both are kept as
/// evidence. A verified binding is cached until the earlier of `cache_ttl` and
/// the attestation's `valid_until`.
pub struct NameserverResolver {
    delegations: BTreeMap<String, NameDelegation>,
    store: Arc<SqliteStore>,
    cache: RwLock<HashMap<String, CachedDid>>,
    cache_ttl: Duration,
    client: reqwest::Client,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

#[derive(Debug, Clone)]
struct CachedDid {
    did: String,
    valid_until: i64,
    cached_at: Instant,
}

/// The largest resolve response read. An attestation is a few hundred bytes;
/// a nameserver that sends more is not given the memory.
const MAX_RESOLVE_RESPONSE: usize = 64 * 1024;

/// The body of `GET /v1/resolve/{alias}`. `links` and `reachability` are the
/// client's business; the server checks only the current binding.
#[derive(Debug, serde::Deserialize)]
struct ResolveResponse {
    /// The attestation's COSE_Sign1 bytes, unpadded base64url.
    attestation: String,
}

/// What one nameserver said.
enum Answer {
    Valid(Attestation),
    NotFound,
    Refused(NamingError),
    Malformed(String),
    Unreachable,
}

impl NameserverResolver {
    pub fn new(
        delegations: BTreeMap<String, NameDelegation>,
        cache_ttl_seconds: u64,
        store: Arc<SqliteStore>,
    ) -> Self {
        Self {
            // Suffixes compare in the lowercase form `Name::parse` produces.
            delegations: delegations
                .into_iter()
                .map(|(suffix, d)| (suffix.to_ascii_lowercase(), d))
                .collect(),
            store,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(cache_ttl_seconds),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client construction"),
            now: Arc::new(|| chrono::Utc::now().timestamp()),
        }
    }

    /// Resolve an alias to a DID. Used by `verify()` and also exposed for
    /// caller-side lookups (e.g., display-time alias rendering).
    pub async fn resolve(&self, alias: &str) -> Result<String, IdentityError> {
        // Before any request: a malformed alias never reaches a URL.
        let name = Name::parse(alias)?;
        let key = name.as_alias();
        let now = (self.now)();
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&key)
                && entry.cached_at.elapsed() < self.cache_ttl
                && now < entry.valid_until
            {
                return Ok(entry.did.clone());
            }
        }

        let deleg =
            self.delegations
                .get(&name.suffix)
                .ok_or_else(|| IdentityError::NoDelegation {
                    suffix: name.suffix.clone(),
                })?;

        let mut asks = tokio::task::JoinSet::new();
        for ns_url in &deleg.nameservers {
            // `Name::parse` admits only `[a-z0-9_-]`, `.` and one `@`, all
            // legal in a path segment, so the alias needs no escaping.
            let url = format!("{}/v1/resolve/{}", ns_url.trim_end_matches('/'), key);
            let client = self.client.clone();
            let name = name.clone();
            let authorities = deleg.authorities.clone();
            asks.spawn(async move { ask(&client, &url, &name, &authorities, now).await });
        }
        let mut valid: Vec<Attestation> = Vec::new();
        let mut refused = None;
        let mut malformed = None;
        let mut not_found = false;
        while let Some(answer) = asks.join_next().await {
            match answer.map_err(|e| IdentityError::Other(e.into()))? {
                Answer::Valid(att) => valid.push(att),
                Answer::NotFound => not_found = true,
                Answer::Refused(e) => refused = refused.or(Some(e)),
                Answer::Malformed(e) => malformed = malformed.or(Some(e)),
                Answer::Unreachable => {}
            }
        }

        let Some(first) = valid.first() else {
            return Err(if let Some(e) = refused {
                IdentityError::Naming(e)
            } else if not_found {
                IdentityError::NotFound { alias: key }
            } else if let Some(e) = malformed {
                IdentityError::MalformedResponse(e)
            } else {
                IdentityError::AllNameserversUnreachable
            });
        };
        let did = first.did.clone();
        let mut dids: Vec<String> = valid.iter().map(|a| a.did.clone()).collect();
        dids.sort_unstable();
        dids.dedup();

        // Evidence first: an equivocation is refused, and a binding acted on
        // is acted on only once it is kept (JEP-0004 rule 20).
        self.keep_evidence(&key, &name.suffix, &valid, now).await?;
        if dids.len() > 1 {
            tracing::warn!(
                alias = %key,
                "nameservers for this suffix signed different DIDs; refusing the alias"
            );
            return Err(IdentityError::Equivocation { alias: key, dids });
        }

        let valid_until = valid.iter().map(|a| a.valid_until).min().unwrap_or(now);
        self.cache.write().await.insert(
            key,
            CachedDid {
                did: did.clone(),
                valid_until,
                cached_at: Instant::now(),
            },
        );
        Ok(did)
    }

    async fn keep_evidence(
        &self,
        name: &str,
        root_id: &str,
        atts: &[Attestation],
        now: i64,
    ) -> Result<(), IdentityError> {
        let store = self.store.clone();
        let rows: Vec<StoredNameEvidence> = atts
            .iter()
            .map(|a| StoredNameEvidence {
                name: name.to_string(),
                root_id: root_id.to_string(),
                attestation_bytes: a.envelope.clone(),
                first_seen: now,
            })
            .collect();
        tokio::task::spawn_blocking(move || -> Result<(), IdentityError> {
            for row in &rows {
                store.record_name_evidence(row)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| IdentityError::Other(e.into()))?
    }
}

/// Ask one nameserver for `name` and check what comes back.
async fn ask(
    client: &reqwest::Client,
    url: &str,
    name: &Name,
    authorities: &[String],
    now: i64,
) -> Answer {
    let Ok(mut resp) = client.get(url).send().await else {
        return Answer::Unreachable;
    };
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Answer::NotFound;
    }
    if !resp.status().is_success() {
        return Answer::Unreachable;
    }
    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > MAX_RESOLVE_RESPONSE {
                    return Answer::Malformed("resolve response too large".into());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return Answer::Unreachable,
        }
    }
    let parsed: ResolveResponse = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return Answer::Malformed(e.to_string()),
    };
    let envelope = match URL_SAFE_NO_PAD.decode(parsed.attestation.as_bytes()) {
        Ok(b) => b,
        Err(e) => return Answer::Malformed(format!("attestation is not base64url: {e}")),
    };
    let att = match Attestation::from_envelope(&envelope) {
        Ok(a) => a,
        Err(e) => return Answer::Refused(e),
    };
    match naming::verify_attestation(&att, authorities, name, now) {
        Ok(()) => Answer::Valid(att),
        Err(e) => Answer::Refused(e),
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

    use ed25519_dalek::SigningKey;
    use jig_core::did::Did;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

    const NOW: i64 = 1_800_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn did_of(key: &SigningKey) -> String {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    fn attest(ns: &SigningKey, did: &str, alias: &str, valid_until: i64) -> Vec<u8> {
        Attestation::sign(ns, did, alias, NOW - 10, valid_until).envelope
    }

    fn body(envelope: &[u8]) -> String {
        format!(
            r#"{{"attestation":"{}","links":[],"reachability":null}}"#,
            URL_SAFE_NO_PAD.encode(envelope)
        )
    }

    /// A nameserver that serves canned resolve bodies and counts requests.
    struct MockNameserver {
        bodies: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
        hits: Arc<AtomicUsize>,
        url: String,
        _shutdown_tx: tokio::sync::oneshot::Sender<()>,
    }

    impl MockNameserver {
        async fn start() -> Arc<Self> {
            let bodies = Arc::new(tokio::sync::Mutex::new(HashMap::<String, String>::new()));
            let hits = Arc::new(AtomicUsize::new(0));
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());

            let (bodies_srv, hits_srv) = (bodies.clone(), hits.clone());
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        accept = listener.accept() => {
                            let Ok((mut stream, _)) = accept else { break };
                            let (bodies, hits) = (bodies_srv.clone(), hits_srv.clone());
                            tokio::spawn(async move {
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                                let mut buf = vec![0u8; 4096];
                                let Ok(n) = stream.read(&mut buf).await else { return };
                                hits.fetch_add(1, Ordering::SeqCst);
                                let req = String::from_utf8_lossy(&buf[..n]);
                                let alias = req
                                    .lines()
                                    .next()
                                    .and_then(|l| l.strip_prefix("GET /v1/resolve/"))
                                    .and_then(|s| s.split_whitespace().next())
                                    .unwrap_or("")
                                    .to_string();
                                let resp = match bodies.lock().await.get(&alias) {
                                    Some(body) => format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                        body.len(),
                                        body
                                    ),
                                    None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".into(),
                                };
                                let _ = stream.write_all(resp.as_bytes()).await;
                            });
                        }
                    }
                }
            });

            Arc::new(Self {
                bodies,
                hits,
                url,
                _shutdown_tx: shutdown_tx,
            })
        }

        async fn serve(&self, alias: &str, envelope: &[u8]) {
            self.serve_raw(alias, body(envelope)).await;
        }

        async fn serve_raw(&self, alias: &str, body: String) {
            self.bodies.lock().await.insert(alias.to_string(), body);
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    fn delegations(
        suffix: &str,
        authorities: &[&SigningKey],
        nameservers: &[&MockNameserver],
    ) -> BTreeMap<String, NameDelegation> {
        BTreeMap::from([(
            suffix.to_string(),
            NameDelegation {
                authorities: authorities.iter().map(|k| did_of(k)).collect(),
                nameservers: nameservers.iter().map(|m| m.url.clone()).collect(),
            },
        )])
    }

    /// A resolver for `dj.jig` with `authorities`, asking `nameservers`, on a
    /// clock the test moves.
    fn resolver(
        authorities: &[&SigningKey],
        nameservers: &[&MockNameserver],
    ) -> (NameserverResolver, Arc<SqliteStore>, Arc<AtomicI64>) {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let clock = Arc::new(AtomicI64::new(NOW));
        let mut r = NameserverResolver::new(
            delegations("dj.jig", authorities, nameservers),
            300,
            store.clone(),
        );
        let c = clock.clone();
        r.now = Arc::new(move || c.load(Ordering::SeqCst));
        (r, store, clock)
    }

    #[tokio::test]
    async fn an_attestation_by_a_suffix_authority_resolves_and_is_kept() {
        let (ns, alice) = (key(1), did_of(&key(9)));
        let mock = MockNameserver::start().await;
        mock.serve("dj@dj.jig", &attest(&ns, &alice, "dj@dj.jig", NOW + 100))
            .await;
        let (r, store, _) = resolver(&[&ns], &[&mock]);

        assert_eq!(r.resolve("DJ@dj.jig").await.unwrap(), alice);
        r.verify("dj@dj.jig", &alice).await.unwrap();
        let kept = store.list_name_evidence("dj@dj.jig").unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].root_id, "dj.jig");
        assert_eq!(kept[0].first_seen, NOW);
    }

    #[tokio::test]
    async fn an_attestation_by_a_did_outside_the_suffix_authorities_is_refused() {
        let (ns, stranger, alice) = (key(1), key(2), did_of(&key(9)));
        let mock = MockNameserver::start().await;
        mock.serve(
            "dj@dj.jig",
            &attest(&stranger, &alice, "dj@dj.jig", NOW + 100),
        )
        .await;
        let (r, _, _) = resolver(&[&ns], &[&mock]);

        let err = r.resolve("dj@dj.jig").await.unwrap_err();
        assert!(
            matches!(err, IdentityError::Naming(NamingError::NotAuthoritative(ref d, _)) if *d == did_of(&stranger)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_forged_signature_is_refused() {
        let (ns, alice) = (key(1), did_of(&key(9)));
        let mut forged = attest(&ns, &alice, "dj@dj.jig", NOW + 100);
        // The signature is the envelope's last 64 bytes.
        *forged.last_mut().unwrap() ^= 1;
        let mock = MockNameserver::start().await;
        mock.serve("dj@dj.jig", &forged).await;
        let (r, _, _) = resolver(&[&ns], &[&mock]);

        let err = r.resolve("dj@dj.jig").await.unwrap_err();
        assert!(
            matches!(err, IdentityError::Naming(NamingError::BadSignature(_))),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn an_attestation_for_another_alias_is_refused() {
        let (ns, alice) = (key(1), did_of(&key(9)));
        let mock = MockNameserver::start().await;
        mock.serve("dj@dj.jig", &attest(&ns, &alice, "eve@dj.jig", NOW + 100))
            .await;
        let (r, _, _) = resolver(&[&ns], &[&mock]);

        let err = r.resolve("dj@dj.jig").await.unwrap_err();
        assert!(
            matches!(err, IdentityError::Naming(NamingError::OtherAlias(..))),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn an_expired_attestation_is_refused() {
        let (ns, alice) = (key(1), did_of(&key(9)));
        let mock = MockNameserver::start().await;
        mock.serve("dj@dj.jig", &attest(&ns, &alice, "dj@dj.jig", NOW))
            .await;
        let (r, _, _) = resolver(&[&ns], &[&mock]);

        let err = r.resolve("dj@dj.jig").await.unwrap_err();
        assert!(
            matches!(err, IdentityError::Naming(NamingError::Expired(t)) if t == NOW),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_cached_binding_past_valid_until_is_fetched_again() {
        let (ns, alice, bob) = (key(1), did_of(&key(9)), did_of(&key(10)));
        let mock = MockNameserver::start().await;
        mock.serve("dj@dj.jig", &attest(&ns, &alice, "dj@dj.jig", NOW + 10))
            .await;
        let (r, _, clock) = resolver(&[&ns], &[&mock]);

        assert_eq!(r.resolve("dj@dj.jig").await.unwrap(), alice);
        assert_eq!(r.resolve("dj@dj.jig").await.unwrap(), alice);
        assert_eq!(mock.hits(), 1, "inside its validity the binding is cached");

        // The cache TTL (300 s) has not run out; the attestation has.
        clock.store(NOW + 10, Ordering::SeqCst);
        mock.serve("dj@dj.jig", &attest(&ns, &bob, "dj@dj.jig", NOW + 100))
            .await;
        assert_eq!(r.resolve("dj@dj.jig").await.unwrap(), bob);
        assert_eq!(mock.hits(), 2);
    }

    #[tokio::test]
    async fn nameservers_signing_different_dids_are_refused_and_both_kept() {
        let (ns1, ns2) = (key(1), key(2));
        let (alice, mallory) = (did_of(&key(9)), did_of(&key(66)));
        let (m1, m2) = (MockNameserver::start().await, MockNameserver::start().await);
        let a1 = attest(&ns1, &alice, "dj@dj.jig", NOW + 100);
        let a2 = attest(&ns2, &mallory, "dj@dj.jig", NOW + 100);
        m1.serve("dj@dj.jig", &a1).await;
        m2.serve("dj@dj.jig", &a2).await;
        let (r, store, _) = resolver(&[&ns1, &ns2], &[&m1, &m2]);

        let err = r.resolve("dj@dj.jig").await.unwrap_err();
        let mut want = vec![alice.clone(), mallory.clone()];
        want.sort();
        assert!(
            matches!(err, IdentityError::Equivocation { ref dids, .. } if *dids == want),
            "{err:?}"
        );
        assert!(r.verify("dj@dj.jig", &alice).await.is_err());

        let mut kept: Vec<Vec<u8>> = store
            .list_name_evidence("dj@dj.jig")
            .unwrap()
            .into_iter()
            .map(|e| e.attestation_bytes)
            .collect();
        kept.sort();
        let mut both = vec![a1, a2];
        both.sort();
        assert_eq!(kept, both);
    }

    #[tokio::test]
    async fn one_valid_answer_is_enough_when_the_others_say_nothing_valid() {
        let (ns, stranger, alice) = (key(1), key(2), did_of(&key(9)));
        let (m1, m2, m3) = (
            MockNameserver::start().await,
            MockNameserver::start().await,
            MockNameserver::start().await,
        );
        m1.serve("dj@dj.jig", &attest(&ns, &alice, "dj@dj.jig", NOW + 100))
            .await;
        m2.serve(
            "dj@dj.jig",
            &attest(&stranger, &did_of(&key(66)), "dj@dj.jig", NOW + 100),
        )
        .await;
        // m3 has never heard of the alias.
        let (r, _, _) = resolver(&[&ns], &[&m1, &m2, &m3]);

        assert_eq!(r.resolve("dj@dj.jig").await.unwrap(), alice);
    }

    #[tokio::test]
    async fn an_alias_with_a_slash_or_percent_is_refused_before_any_request() {
        let mock = MockNameserver::start().await;
        let (r, _, _) = resolver(&[&key(1)], &[&mock]);
        for alias in [
            "a/b@dj.jig",
            "../x@dj.jig",
            "dj%2f@dj.jig",
            "dj@dj.jig/x",
            "dj@dj.jig%2e",
            "dj@d j.jig",
        ] {
            let err = r.resolve(alias).await.unwrap_err();
            assert!(
                matches!(err, IdentityError::Naming(NamingError::BadName(_))),
                "{alias}: {err:?}"
            );
        }
        assert_eq!(mock.hits(), 0);
    }

    #[tokio::test]
    async fn a_suffix_with_no_delegation_is_refused_before_any_request() {
        let mock = MockNameserver::start().await;
        let (r, _, _) = resolver(&[&key(1)], &[&mock]);
        let err = r.resolve("dj@other.jig").await.unwrap_err();
        assert!(
            matches!(err, IdentityError::NoDelegation { ref suffix } if suffix == "other.jig"),
            "{err:?}"
        );
        assert_eq!(mock.hits(), 0);
    }

    #[tokio::test]
    async fn a_delegation_key_matches_whatever_its_case() {
        let (ns, alice) = (key(1), did_of(&key(9)));
        let mock = MockNameserver::start().await;
        mock.serve("dj@dj.jig", &attest(&ns, &alice, "dj@dj.jig", NOW + 100))
            .await;
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mut r = NameserverResolver::new(delegations("DJ.jig", &[&ns], &[&mock]), 300, store);
        r.now = Arc::new(|| NOW);
        assert_eq!(r.resolve("dj@dj.jig").await.unwrap(), alice);
    }

    #[tokio::test]
    async fn a_response_without_a_base64url_attestation_is_malformed() {
        let (ns, alice) = (key(1), did_of(&key(9)));
        let mock = MockNameserver::start().await;
        let (r, _, _) = resolver(&[&ns], &[&mock]);

        // The pre-JEP-0004 shape: a bare, unsigned DID.
        mock.serve_raw("dj@dj.jig", format!(r#"{{"did":"{alice}"}}"#))
            .await;
        let err = r.resolve("dj@dj.jig").await.unwrap_err();
        assert!(
            matches!(err, IdentityError::MalformedResponse(_)),
            "{err:?}"
        );

        // Padded base64 is not the wire encoding. The signed validity bound
        // moves the envelope's length until its encoding needs padding.
        let padded = (0..2)
            .map(|i| {
                base64::engine::general_purpose::URL_SAFE.encode(attest(
                    &ns,
                    &alice,
                    "dj@dj.jig",
                    NOW + 100 + (i << 32),
                ))
            })
            .find(|b| b.ends_with('='))
            .expect("one of two lengths pads");
        mock.serve_raw("dj@dj.jig", format!(r#"{{"attestation":"{padded}"}}"#))
            .await;
        let err = r.resolve("dj@dj.jig").await.unwrap_err();
        assert!(
            matches!(err, IdentityError::MalformedResponse(_)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn nameserver_resolver_not_found_for_unknown_alias() {
        let mock = MockNameserver::start().await;
        let (r, _, _) = resolver(&[&key(1)], &[&mock]);
        let err = r.resolve("nobody@dj.jig").await.unwrap_err();
        assert!(matches!(err, IdentityError::NotFound { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn nameserver_resolver_unreachable_when_no_nameservers_respond() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let delegations = BTreeMap::from([(
            "dj.jig".to_string(),
            NameDelegation {
                authorities: vec![did_of(&key(1))],
                // A localhost port nothing is bound on: connection refused.
                nameservers: vec!["http://127.0.0.1:1".to_string()],
            },
        )]);
        let r = NameserverResolver::new(delegations, 300, store);
        let err = r.resolve("anyone@dj.jig").await.unwrap_err();
        assert!(
            matches!(err, IdentityError::AllNameserversUnreachable),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn nameserver_resolver_verify_rejects_when_did_mismatches() {
        let (ns, alice) = (key(1), did_of(&key(9)));
        let mock = MockNameserver::start().await;
        mock.serve("dj@dj.jig", &attest(&ns, &alice, "dj@dj.jig", NOW + 100))
            .await;
        let (r, _, _) = resolver(&[&ns], &[&mock]);

        let err = r.verify("dj@dj.jig", "did:jig:zwrong").await.unwrap_err();
        assert!(matches!(err, IdentityError::TofuMismatch { .. }), "{err:?}");
    }
}
