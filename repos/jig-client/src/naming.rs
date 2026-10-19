//! Verified name resolution (JEP-0004 rules 4, 13–20).
//!
//! [`NameResolver::resolve`] turns `alias@suffix` into a DID the client may
//! act on:
//!
//! 1. Find the suffix's delegation: the client's own `config` entry first,
//!    else `dns` discovery at `https://<suffix>/.well-known/jig-ns-delegation`,
//!    over a certificate a CA vouches for and nothing else.
//! 2. Ask every nameserver the delegation names for `/v1/resolve/{alias}`,
//!    and verify each attestation: signer authoritative for the suffix,
//!    signature, validity window, alias. Two valid attestations naming
//!    different DIDs refuse the name.
//! 3. Compare with the pin for `(alias, suffix, root, root_id)` (rule 6).
//! 4. Hand what it acted on to the evidence writer (rule 20).
//!
//! Pins and evidence belong to other modules (lane L7's name pins and
//! `jig-evidence-v1` writer); this module reaches them through
//! [`NamePins`] and [`NameEvidence`], so either side can land first.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jig_core::naming::{
    self, Attestation, Name, NamingError, ReachabilityRecord, Root, SuffixDelegation,
};
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;

/// The largest response read from a nameserver or delegation host. Every
/// object served is a few hundred bytes.
const MAX_RESPONSE: usize = 64 * 1024;

/// One suffix in the client's `[naming.delegations]`: a `config` root.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDelegation {
    /// The DIDs whose attestations count for this suffix.
    pub authorities: Vec<String>,
    /// The nameserver URLs to ask; every one is asked.
    pub nameservers: Vec<String>,
}

/// The delegations this client holds itself, keyed by suffix. A suffix with
/// no entry is looked up through `dns` discovery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delegations {
    pub config: BTreeMap<String, ConfigDelegation>,
}

/// What a name means (rule 6), and what a name pin is keyed by.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NameKey {
    /// The normalised local part alone (`alice` in `alice@example.org`),
    /// never the full name: `suffix` is its own field, so a name has exactly
    /// one key.
    pub alias: String,
    pub suffix: String,
    pub root: Root,
    /// For `config`, the suffix (a local identifier, never sent anywhere);
    /// for `dns`, the domain.
    pub root_id: String,
}

/// What a client pinned for a name (rule 17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamePin {
    pub did: String,
    /// The nameserver whose attestation was pinned.
    pub ns_did: String,
}

/// The client's name pins. Lane L7's pin store implements this (its slice 9).
pub trait NamePins {
    fn name_pin(&self, key: &NameKey) -> Option<NamePin>;
}

/// Everything a resolution acted on, for the evidence writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameEvidenceBundle {
    pub key: NameKey,
    /// Each attestation's COSE_Sign1 bytes. An equivocation carries both.
    pub attestations: Vec<Vec<u8>>,
    /// The parties the bundle is held against: each attestation's signing
    /// nameserver, in the same order as `attestations`. Each is also inside
    /// its attestation's signed bytes, which is what makes it hold offline.
    pub ns_dids: Vec<String>,
    /// The rotation links served with them, as served.
    pub links: Vec<Vec<u8>>,
    /// When this client obtained them: Unix seconds on its own clock.
    pub observed_at: i64,
}

/// Where evidence goes. Lane L7's `jig-evidence-v1` writer implements this
/// (its slice 6).
pub trait NameEvidence {
    fn record(&self, bundle: &NameEvidenceBundle) -> Result<(), String>;
}

/// A binding that verified.
#[derive(Debug, Clone)]
pub struct Binding {
    pub key: NameKey,
    pub attestation: Attestation,
    /// Where the DID wants to be found, when the nameserver had a record
    /// signed by that DID.
    pub reachability: Option<ReachabilityRecord>,
}

impl Binding {
    pub fn did(&self) -> &str {
        &self.attestation.did
    }
}

/// A name the client may act on.
#[derive(Debug, Clone)]
pub enum Verified {
    /// No pin yet. The caller must pin before any E2EE use (rule 17).
    New(Binding),
    /// Matches the pin.
    Pinned(Binding),
    /// A chain of rotation links leads from the pinned DID to this one; the
    /// caller moves the pin and says so. Not returned until lane I's I3
    /// defines the link encoding: until then every change is a
    /// [`ResolveError::PinMismatch`].
    Rotated { binding: Binding, from: String },
}

/// Why a binding differs from its pin with nothing to justify the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchReason {
    /// The pinned nameserver now attests another DID and serves no rotation.
    ReRegistered,
    /// Another nameserver attests the name than the one pinned.
    OtherNameserver,
    /// Rotation links were served, but none this client can verify leads from
    /// the pinned DID.
    NoRotationProof,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error(transparent)]
    BadName(NamingError),
    #[error("no delegation for `{suffix}`: {reason}")]
    NoDelegation { suffix: String, reason: String },
    #[error("refused: {0}")]
    Refused(NamingError),
    #[error("`{0}` is not registered")]
    NotFound(String),
    #[error("no nameserver for `{0}` answered")]
    Unreachable(String),
    #[error("malformed answer: {0}")]
    Malformed(String),
    #[error("nameservers for `{name}` attest different DIDs: {dids:?}")]
    Equivocation { name: String, dids: Vec<String> },
    #[error(
        "`{name}` is pinned to {old} but now resolves to {new} ({reason:?}); \
         accept the change only if its holder confirms it"
    )]
    PinMismatch {
        name: String,
        reason: MismatchReason,
        old: String,
        new: String,
    },
    #[error("could not keep evidence: {0}")]
    Evidence(String),
}

/// The body of `GET /v1/resolve/{alias}`.
#[derive(Debug, Deserialize)]
struct ResolveResponse {
    attestation: String,
    #[serde(default)]
    links: Vec<String>,
    #[serde(default)]
    reachability: Option<String>,
}

/// The body of `/.well-known/jig-ns-delegation`.
#[derive(Debug, Deserialize)]
struct DelegationResponse {
    envelopes: Vec<String>,
}

/// One nameserver's verified answer.
struct Answer {
    attestation: Attestation,
    links: Vec<Vec<u8>>,
    reachability: Option<ReachabilityRecord>,
}

enum Asked {
    Valid(Answer),
    NotFound,
    Refused(NamingError),
    Malformed(String),
    Unreachable,
}

/// Where a suffix's authority comes from, once found.
struct Authority {
    key: NameKey,
    authorities: Vec<String>,
    /// For `dns`, the verified delegation, checked again with each binding.
    delegation: Option<SuffixDelegation>,
    nameservers: Vec<String>,
}

pub struct NameResolver {
    /// For listed nameservers.
    http: reqwest::Client,
    /// For `dns` discovery: HTTPS only, a CA-valid certificate only, no
    /// redirects.
    discovery: reqwest::Client,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl NameResolver {
    /// A resolver that trusts the platform's CA roots.
    pub fn new() -> Self {
        let mut roots = RootCertStore::empty();
        let _ = roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        Self::with_roots(roots, |b| b)
    }

    /// `tweak` adjusts both HTTP clients; tests use it to point a suffix at a
    /// local listener.
    fn with_roots(
        roots: RootCertStore,
        tweak: impl Fn(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
    ) -> Self {
        let ca_only = || {
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("ring supports TLS 1.3")
                .with_root_certificates(roots.clone())
                .with_no_client_auth()
        };
        let base = || {
            tweak(
                reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .redirect(reqwest::redirect::Policy::none())
                    .use_preconfigured_tls(ca_only()),
            )
        };
        Self {
            http: base().build().expect("reqwest client"),
            discovery: base().https_only(true).build().expect("reqwest client"),
            now: Arc::new(|| chrono::Utc::now().timestamp()),
        }
    }

    /// Resolve and verify `name`, and compare it with its pin.
    pub async fn resolve(
        &self,
        name: &str,
        delegations: &Delegations,
        pins: &dyn NamePins,
        evidence: &dyn NameEvidence,
    ) -> Result<Verified, ResolveError> {
        let name = Name::parse(name).map_err(ResolveError::BadName)?;
        let now = (self.now)();
        let authority = self.authority(&name, delegations, now).await?;
        let key = authority.key.clone();
        let wanted = name.as_alias();

        let mut asks = tokio::task::JoinSet::new();
        for ns in &authority.nameservers {
            // `Name::parse` admits only `[a-z0-9_-]`, `.` and one `@`, all
            // legal in a path segment.
            let url = format!("{}/v1/resolve/{wanted}", ns.trim_end_matches('/'));
            let http = self.http.clone();
            let (name, authorities, delegation) = (
                name.clone(),
                authority.authorities.clone(),
                authority.delegation.clone(),
            );
            asks.spawn(async move {
                ask(&http, &url, &name, &authorities, delegation.as_ref(), now).await
            });
        }
        let mut valid: Vec<Answer> = Vec::new();
        let (mut refused, mut malformed, mut not_found) = (None, None, false);
        while let Some(asked) = asks.join_next().await {
            match asked.map_err(|e| ResolveError::Malformed(e.to_string()))? {
                Asked::Valid(a) => valid.push(a),
                Asked::NotFound => not_found = true,
                Asked::Refused(e) => refused = refused.or(Some(e)),
                Asked::Malformed(e) => malformed = malformed.or(Some(e)),
                Asked::Unreachable => {}
            }
        }
        if valid.is_empty() {
            return Err(if let Some(e) = refused {
                ResolveError::Refused(e)
            } else if not_found {
                ResolveError::NotFound(wanted)
            } else if let Some(e) = malformed {
                ResolveError::Malformed(e)
            } else {
                ResolveError::Unreachable(wanted)
            });
        }

        let bundle = NameEvidenceBundle {
            key: key.clone(),
            attestations: valid
                .iter()
                .map(|a| a.attestation.envelope.clone())
                .collect(),
            ns_dids: valid.iter().map(|a| a.attestation.ns_did.clone()).collect(),
            links: valid.iter().flat_map(|a| a.links.clone()).collect(),
            observed_at: now,
        };
        evidence.record(&bundle).map_err(ResolveError::Evidence)?;

        let mut dids: Vec<String> = valid.iter().map(|a| a.attestation.did.clone()).collect();
        dids.sort_unstable();
        dids.dedup();
        if dids.len() > 1 {
            return Err(ResolveError::Equivocation { name: wanted, dids });
        }

        let answer = match pins.name_pin(&key) {
            // Prefer the pinned nameserver's answer when several agree.
            Some(pin) => {
                let i = valid
                    .iter()
                    .position(|a| a.attestation.ns_did == pin.ns_did)
                    .unwrap_or(0);
                valid.swap_remove(i)
            }
            None => valid.swap_remove(0),
        };
        let binding = Binding {
            key: key.clone(),
            attestation: answer.attestation,
            reachability: answer.reachability,
        };
        let Some(pin) = pins.name_pin(&key) else {
            return Ok(Verified::New(binding));
        };
        if pin.did == binding.attestation.did {
            return Ok(Verified::Pinned(binding));
        }
        // No link encoding exists until lane I's I3, so no chain verifies yet
        // and a change of DID is never accepted here.
        let reason = if binding.attestation.ns_did != pin.ns_did {
            MismatchReason::OtherNameserver
        } else if !answer.links.is_empty() {
            MismatchReason::NoRotationProof
        } else {
            MismatchReason::ReRegistered
        };
        Err(ResolveError::PinMismatch {
            name: wanted,
            reason,
            old: pin.did,
            new: binding.attestation.did,
        })
    }

    /// Rule 4: `config` first, else `dns`.
    async fn authority(
        &self,
        name: &Name,
        delegations: &Delegations,
        now: i64,
    ) -> Result<Authority, ResolveError> {
        let key = |root, root_id: &str| NameKey {
            alias: name.alias.clone(),
            suffix: name.suffix.clone(),
            root,
            root_id: root_id.to_string(),
        };
        let configured = delegations
            .config
            .iter()
            .find(|(suffix, _)| suffix.eq_ignore_ascii_case(&name.suffix));
        if let Some((_, d)) = configured {
            return Ok(Authority {
                key: key(Root::Config, &name.suffix),
                authorities: d.authorities.clone(),
                delegation: None,
                nameservers: d.nameservers.clone(),
            });
        }

        let suffix = &name.suffix;
        let no = |reason: String| ResolveError::NoDelegation {
            suffix: suffix.clone(),
            reason,
        };
        let url = format!("https://{suffix}/.well-known/jig-ns-delegation");
        let body = match fetch(&self.discovery, &url).await {
            Ok(Some(body)) => body,
            Ok(None) => return Err(no(format!("{url} serves none"))),
            Err(e) => return Err(no(e)),
        };
        let served: DelegationResponse =
            serde_json::from_slice(&body).map_err(|e| no(e.to_string()))?;
        let envelopes = served
            .envelopes
            .iter()
            .map(|e| URL_SAFE_NO_PAD.decode(e.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| no(format!("an envelope is not base64url: {e}")))?;
        let deleg = SuffixDelegation::from_envelopes(&envelopes).map_err(|e| no(e.to_string()))?;
        if deleg.root != Root::Dns || deleg.root_id != *suffix || deleg.suffix != *suffix {
            return Err(no(format!(
                "{url} serves a {} delegation for `{}` under `{}`",
                deleg.root.as_str(),
                deleg.suffix,
                deleg.root_id
            )));
        }
        if now >= deleg.valid_until {
            return Err(no(
                NamingError::DelegationExpired(deleg.valid_until).to_string()
            ));
        }
        Ok(Authority {
            key: key(Root::Dns, suffix),
            authorities: deleg.authorities.clone(),
            delegation: Some(deleg),
            // Under `dns` the suffix's own host is the nameserver.
            nameservers: vec![format!("https://{suffix}")],
        })
    }
}

impl Default for NameResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// GET `url`, at most [`MAX_RESPONSE`] bytes. `Ok(None)` is a 404.
async fn fetch(http: &reqwest::Client, url: &str) -> Result<Option<Vec<u8>>, String> {
    let mut resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetching {url}: {}", error_chain(&e)))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("fetching {url}: HTTP {}", resp.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("reading {url}: {e}"))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE {
            return Err(format!("{url}: response too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// The causes reqwest folds into one error; a certificate refusal is
/// otherwise just "error sending request".
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

/// Ask one nameserver for `name` and verify what it says.
async fn ask(
    http: &reqwest::Client,
    url: &str,
    name: &Name,
    authorities: &[String],
    delegation: Option<&SuffixDelegation>,
    now: i64,
) -> Asked {
    let body = match fetch(http, url).await {
        Ok(Some(body)) => body,
        Ok(None) => return Asked::NotFound,
        Err(_) => return Asked::Unreachable,
    };
    let served: ResolveResponse = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(e) => return Asked::Malformed(e.to_string()),
    };
    let decode = |s: &str| URL_SAFE_NO_PAD.decode(s.as_bytes());
    let (Ok(envelope), Ok(links)) = (
        decode(&served.attestation),
        served
            .links
            .iter()
            .map(|l| decode(l))
            .collect::<Result<Vec<_>, _>>(),
    ) else {
        return Asked::Malformed("an object is not base64url".into());
    };
    let attestation = match Attestation::from_envelope(&envelope) {
        Ok(a) => a,
        Err(e) => return Asked::Refused(e),
    };
    let checked = match delegation {
        Some(d) => naming::verify_binding(&attestation, d, name, now),
        None => naming::verify_attestation(&attestation, authorities, name, now),
    };
    if let Err(e) = checked {
        return Asked::Refused(e);
    }
    // A record the DID did not sign says nothing about where it is: drop it
    // rather than refuse the name.
    let reachability = served
        .reachability
        .and_then(|r| decode(&r).ok())
        .and_then(|r| ReachabilityRecord::from_envelope(&r).ok())
        .filter(|r| r.did == attestation.did);
    Asked::Valid(Answer {
        attestation,
        links,
        reachability,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jig_core::did::Did;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    const NOW: i64 = 1_800_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn did_of(key: &SigningKey) -> String {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn attest(ns: &SigningKey, did: &str, alias: &str) -> Vec<u8> {
        Attestation::sign(ns, did, alias, NOW - 10, NOW + 100).envelope
    }

    fn resolve_body(attestation: &[u8], links: &[&[u8]], reach: Option<&[u8]>) -> String {
        serde_json::json!({
            "attestation": b64(attestation),
            "links": links.iter().map(|l| b64(l)).collect::<Vec<_>>(),
            "reachability": reach.map(b64),
        })
        .to_string()
    }

    // ---- a stub HTTP(S) server: path → body, counting requests ----

    type Routes = Arc<Mutex<HashMap<String, String>>>;

    async fn respond<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, routes: Routes) {
        let mut buf = vec![0u8; 8192];
        let Ok(n) = stream.read(&mut buf).await else {
            return;
        };
        let req = String::from_utf8_lossy(&buf[..n]);
        let path = req
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("GET "))
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("")
            .to_string();
        let found = routes.lock().unwrap().get(&path).cloned();
        let resp = match found {
            Some(body) => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
            None => {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            }
        };
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.shutdown().await;
    }

    struct Stub {
        addr: SocketAddr,
        routes: Routes,
        hits: Arc<AtomicUsize>,
    }

    impl Stub {
        /// Plain HTTP, or TLS presenting `cert` when one is given.
        async fn start(cert: Option<(Vec<u8>, Vec<u8>)>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let routes: Routes = Arc::default();
            let hits = Arc::new(AtomicUsize::new(0));
            let acceptor = cert.map(|(cert, key)| {
                use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
                let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(cert)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
                )
                .unwrap();
                tokio_rustls::TlsAcceptor::from(Arc::new(config))
            });
            let (r, h) = (routes.clone(), hits.clone());
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let (routes, hits, acceptor) = (r.clone(), h.clone(), acceptor.clone());
                    tokio::spawn(async move {
                        match acceptor {
                            Some(a) => {
                                if let Ok(tls) = a.accept(tcp).await {
                                    hits.fetch_add(1, Ordering::SeqCst);
                                    respond(tls, routes).await;
                                }
                            }
                            None => {
                                hits.fetch_add(1, Ordering::SeqCst);
                                respond(tcp, routes).await;
                            }
                        }
                    });
                }
            });
            Self { addr, routes, hits }
        }

        fn url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn route(&self, path: &str, body: String) {
            self.routes.lock().unwrap().insert(path.to_string(), body);
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    // ---- pins and evidence in memory ----

    #[derive(Default)]
    struct MemPins(HashMap<NameKey, NamePin>);

    impl NamePins for MemPins {
        fn name_pin(&self, key: &NameKey) -> Option<NamePin> {
            self.0.get(key).cloned()
        }
    }

    #[derive(Default)]
    struct MemEvidence(Mutex<Vec<NameEvidenceBundle>>);

    impl NameEvidence for MemEvidence {
        fn record(&self, bundle: &NameEvidenceBundle) -> Result<(), String> {
            self.0.lock().unwrap().push(bundle.clone());
            Ok(())
        }
    }

    impl MemEvidence {
        fn bundles(&self) -> Vec<NameEvidenceBundle> {
            self.0.lock().unwrap().clone()
        }
    }

    fn resolver() -> NameResolver {
        // Tests talk to local listeners only; an ambient proxy would intercept.
        let mut r = NameResolver::with_roots(RootCertStore::empty(), |b| b.no_proxy());
        r.now = Arc::new(|| NOW);
        r
    }

    fn config(authorities: &[&SigningKey], stubs: &[&Stub]) -> Delegations {
        Delegations {
            config: BTreeMap::from([(
                "dj.jig".to_string(),
                ConfigDelegation {
                    authorities: authorities.iter().map(|k| did_of(k)).collect(),
                    nameservers: stubs.iter().map(|s| s.url()).collect(),
                },
            )]),
        }
    }

    fn config_key() -> NameKey {
        NameKey {
            alias: "dj".into(),
            suffix: "dj.jig".into(),
            root: Root::Config,
            root_id: "dj.jig".into(),
        }
    }

    const RESOLVE: &str = "/v1/resolve/dj@dj.jig";

    // ---- pin comparison (rule 18) ----

    #[tokio::test]
    async fn an_unpinned_name_is_new_and_its_attestation_is_kept() {
        let (ns, alice) = (key(1), did_of(&key(9)));
        let stub = Stub::start(None).await;
        let att = attest(&ns, &alice, "dj@dj.jig");
        stub.route(RESOLVE, resolve_body(&att, &[], None));
        let evidence = MemEvidence::default();

        let got = resolver()
            .resolve(
                "DJ@dj.jig",
                &config(&[&ns], &[&stub]),
                &MemPins::default(),
                &evidence,
            )
            .await
            .unwrap();
        let Verified::New(b) = got else {
            panic!("{got:?}")
        };
        assert_eq!(b.did(), alice);
        assert_eq!(b.key, config_key());
        assert_eq!(evidence.bundles().len(), 1);
        assert_eq!(evidence.bundles()[0].attestations, vec![att]);
    }

    #[tokio::test]
    async fn a_name_matching_its_pin_is_pinned() {
        let (ns, alice) = (key(1), did_of(&key(9)));
        let stub = Stub::start(None).await;
        stub.route(
            RESOLVE,
            resolve_body(&attest(&ns, &alice, "dj@dj.jig"), &[], None),
        );
        let pins = MemPins(HashMap::from([(
            config_key(),
            NamePin {
                did: alice.clone(),
                ns_did: did_of(&ns),
            },
        )]));

        let got = resolver()
            .resolve(
                "dj@dj.jig",
                &config(&[&ns], &[&stub]),
                &pins,
                &MemEvidence::default(),
            )
            .await
            .unwrap();
        assert!(
            matches!(got, Verified::Pinned(ref b) if b.did() == alice),
            "{got:?}"
        );
    }

    async fn mismatch(
        served_by: &SigningKey,
        authorities: &[&SigningKey],
        links: &[&[u8]],
    ) -> ResolveError {
        let (ns, alice, bob) = (key(1), did_of(&key(9)), did_of(&key(10)));
        let stub = Stub::start(None).await;
        stub.route(
            RESOLVE,
            resolve_body(&attest(served_by, &bob, "dj@dj.jig"), links, None),
        );
        let pins = MemPins(HashMap::from([(
            config_key(),
            NamePin {
                did: alice,
                ns_did: did_of(&ns),
            },
        )]));
        resolver()
            .resolve(
                "dj@dj.jig",
                &config(authorities, &[&stub]),
                &pins,
                &MemEvidence::default(),
            )
            .await
            .unwrap_err()
    }

    #[tokio::test]
    async fn a_new_did_from_the_pinned_nameserver_is_a_re_registration() {
        let ns = key(1);
        let err = mismatch(&ns, &[&ns], &[]).await;
        assert!(
            matches!(
                err,
                ResolveError::PinMismatch {
                    reason: MismatchReason::ReRegistered,
                    ref old,
                    ref new,
                    ..
                } if *old == did_of(&key(9)) && *new == did_of(&key(10))
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_new_did_from_another_nameserver_is_named_as_such() {
        let (ns, other) = (key(1), key(2));
        let err = mismatch(&other, &[&ns, &other], &[]).await;
        assert!(
            matches!(
                err,
                ResolveError::PinMismatch {
                    reason: MismatchReason::OtherNameserver,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn served_links_that_cannot_be_verified_are_no_rotation_proof() {
        let ns = key(1);
        let err = mismatch(&ns, &[&ns], &[b"not a link yet"]).await;
        assert!(
            matches!(
                err,
                ResolveError::PinMismatch {
                    reason: MismatchReason::NoRotationProof,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    // ---- verification (rules 5, 13, 15) ----

    #[tokio::test]
    async fn an_attestation_by_a_non_authority_is_refused() {
        let (ns, stranger, alice) = (key(1), key(2), did_of(&key(9)));
        let stub = Stub::start(None).await;
        stub.route(
            RESOLVE,
            resolve_body(&attest(&stranger, &alice, "dj@dj.jig"), &[], None),
        );
        let evidence = MemEvidence::default();
        let err = resolver()
            .resolve(
                "dj@dj.jig",
                &config(&[&ns], &[&stub]),
                &MemPins::default(),
                &evidence,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ResolveError::Refused(NamingError::NotAuthoritative(..))
            ),
            "{err:?}"
        );
        assert!(evidence.bundles().is_empty());
    }

    #[tokio::test]
    async fn an_equivocation_is_refused_and_kept_as_one_bundle() {
        let (ns1, ns2) = (key(1), key(2));
        let (s1, s2) = (Stub::start(None).await, Stub::start(None).await);
        let a1 = attest(&ns1, &did_of(&key(9)), "dj@dj.jig");
        let a2 = attest(&ns2, &did_of(&key(66)), "dj@dj.jig");
        s1.route(RESOLVE, resolve_body(&a1, &[], None));
        s2.route(RESOLVE, resolve_body(&a2, &[], None));
        let evidence = MemEvidence::default();

        let err = resolver()
            .resolve(
                "dj@dj.jig",
                &config(&[&ns1, &ns2], &[&s1, &s2]),
                &MemPins::default(),
                &evidence,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::Equivocation { .. }), "{err:?}");
        let bundles = evidence.bundles();
        assert_eq!(bundles.len(), 1);
        let mut kept = bundles[0].attestations.clone();
        kept.sort();
        let mut both = vec![a1, a2];
        both.sort();
        assert_eq!(kept, both);
        let mut accused = bundles[0].ns_dids.clone();
        accused.sort();
        let mut want = vec![did_of(&ns1), did_of(&ns2)];
        want.sort();
        assert_eq!(accused, want);
        assert_eq!(bundles[0].observed_at, NOW);
    }

    async fn resolve_body_as(
        ns: &SigningKey,
        body: serde_json::Value,
    ) -> Result<Verified, ResolveError> {
        let stub = Stub::start(None).await;
        stub.route(RESOLVE, body.to_string());
        resolver()
            .resolve(
                "dj@dj.jig",
                &config(&[ns], &[&stub]),
                &MemPins::default(),
                &MemEvidence::default(),
            )
            .await
    }

    #[tokio::test]
    async fn only_the_signed_attestation_counts_never_the_unsigned_hints() {
        let (ns, alice, mallory) = (key(1), did_of(&key(9)), did_of(&key(66)));
        let resolve = |body| resolve_body_as(&ns, body);

        // Transitional hints beside the attestation name another DID: ignored.
        let got = resolve(serde_json::json!({
            "attestation": b64(&attest(&ns, &alice, "dj@dj.jig")),
            "links": [],
            "reachability": null,
            "did": mallory,
            "alias": "dj@dj.jig",
            "valid_until": NOW + 100,
        }))
        .await
        .unwrap();
        assert!(
            matches!(got, Verified::New(ref b) if b.did() == alice),
            "{got:?}"
        );

        // Hints alone, with no attestation: refused, never read.
        let err = resolve(serde_json::json!({
            "did": alice, "alias": "dj@dj.jig", "valid_until": NOW + 100,
        }))
        .await
        .unwrap_err();
        assert!(matches!(err, ResolveError::Malformed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn a_bad_name_is_refused_before_any_request() {
        let stub = Stub::start(None).await;
        for name in ["a/b@dj.jig", "dj%2f@dj.jig", "dj@dj.jig/x", "dj"] {
            let err = resolver()
                .resolve(
                    name,
                    &config(&[&key(1)], &[&stub]),
                    &MemPins::default(),
                    &MemEvidence::default(),
                )
                .await
                .unwrap_err();
            assert!(matches!(err, ResolveError::BadName(_)), "{name}: {err:?}");
        }
        assert_eq!(stub.hits(), 0);
    }

    #[tokio::test]
    async fn reachability_is_kept_only_when_the_did_signed_it() {
        let (ns, alice_key) = (key(1), key(9));
        let alice = did_of(&alice_key);
        let own = ReachabilityRecord::sign(
            &alice_key,
            vec![("did:jig:zS".into(), "https://s.example".into())],
            1,
        );
        let foreign = ReachabilityRecord::sign(&key(66), vec![], 1);
        for (record, kept) in [(own, true), (foreign, false)] {
            let stub = Stub::start(None).await;
            stub.route(
                RESOLVE,
                resolve_body(
                    &attest(&ns, &alice, "dj@dj.jig"),
                    &[],
                    Some(&record.envelope),
                ),
            );
            let got = resolver()
                .resolve(
                    "dj@dj.jig",
                    &config(&[&ns], &[&stub]),
                    &MemPins::default(),
                    &MemEvidence::default(),
                )
                .await
                .unwrap();
            let Verified::New(b) = got else {
                panic!("{got:?}")
            };
            assert_eq!(b.reachability.is_some(), kept);
        }
    }

    // ---- `dns` discovery (rules 3, 4) ----

    const SUFFIX: &str = "example.jig";

    /// A CA, and a certificate it issued for `SUFFIX`: (root store, cert, key).
    fn ca_issued() -> (RootCertStore, Vec<u8>, Vec<u8>) {
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![SUFFIX.to_string()])
            .unwrap()
            .signed_by(&leaf_key, &ca)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        (roots, leaf.der().to_vec(), leaf_key.serialize_der())
    }

    /// A resolver trusting `roots` that reaches `SUFFIX` at `stub`.
    fn dns_resolver(roots: RootCertStore, stub: &Stub) -> NameResolver {
        let addr = stub.addr;
        let mut r = NameResolver::with_roots(roots, move |b| b.no_proxy().resolve(SUFFIX, addr));
        r.now = Arc::new(|| NOW);
        r
    }

    fn delegation_body(d: &SuffixDelegation) -> String {
        serde_json::json!({
            "envelopes": d.envelopes.iter().map(|e| b64(e)).collect::<Vec<_>>(),
        })
        .to_string()
    }

    const DNS_RESOLVE: &str = "/v1/resolve/dj@example.jig";
    const WELL_KNOWN: &str = "/.well-known/jig-ns-delegation";

    #[tokio::test]
    async fn a_dns_delegation_under_a_ca_valid_certificate_is_followed() {
        let (roots, cert, cert_key) = ca_issued();
        let (ns, alice) = (key(1), did_of(&key(9)));
        let stub = Stub::start(Some((cert, cert_key))).await;
        let deleg = SuffixDelegation::sign(&[&ns], SUFFIX, Root::Dns, SUFFIX, NOW + 1000);
        stub.route(WELL_KNOWN, delegation_body(&deleg));
        stub.route(
            DNS_RESOLVE,
            resolve_body(&attest(&ns, &alice, "dj@example.jig"), &[], None),
        );

        let got = dns_resolver(roots, &stub)
            .resolve(
                "dj@example.jig",
                &Delegations::default(),
                &MemPins::default(),
                &MemEvidence::default(),
            )
            .await
            .unwrap();
        let Verified::New(b) = got else {
            panic!("{got:?}")
        };
        assert_eq!(b.did(), alice);
        assert_eq!(b.key.root, Root::Dns);
        assert_eq!(b.key.root_id, SUFFIX);
    }

    #[tokio::test]
    async fn a_dns_delegation_over_a_self_signed_certificate_is_refused() {
        let ck = rcgen::generate_simple_self_signed(vec![SUFFIX.to_string()]).unwrap();
        let (ns, alice) = (key(1), did_of(&key(9)));
        let stub = Stub::start(Some((
            ck.cert.der().to_vec(),
            ck.signing_key.serialize_der(),
        )))
        .await;
        let deleg = SuffixDelegation::sign(&[&ns], SUFFIX, Root::Dns, SUFFIX, NOW + 1000);
        stub.route(WELL_KNOWN, delegation_body(&deleg));
        stub.route(
            DNS_RESOLVE,
            resolve_body(&attest(&ns, &alice, "dj@example.jig"), &[], None),
        );
        // The CA from another test, which did not issue this certificate.
        let (roots, _, _) = ca_issued();

        let err = dns_resolver(roots, &stub)
            .resolve(
                "dj@example.jig",
                &Delegations::default(),
                &MemPins::default(),
                &MemEvidence::default(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::NoDelegation { ref reason, .. } if reason.contains("certificate")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_config_delegation_takes_precedence_over_dns() {
        let (roots, cert, cert_key) = ca_issued();
        let (dns_ns, config_ns, alice) = (key(1), key(2), did_of(&key(9)));
        let tls = Stub::start(Some((cert, cert_key))).await;
        let deleg = SuffixDelegation::sign(&[&dns_ns], SUFFIX, Root::Dns, SUFFIX, NOW + 1000);
        tls.route(WELL_KNOWN, delegation_body(&deleg));
        let plain = Stub::start(None).await;
        plain.route(
            DNS_RESOLVE,
            resolve_body(&attest(&config_ns, &alice, "dj@example.jig"), &[], None),
        );
        let delegations = Delegations {
            config: BTreeMap::from([(
                SUFFIX.to_string(),
                ConfigDelegation {
                    authorities: vec![did_of(&config_ns)],
                    nameservers: vec![plain.url()],
                },
            )]),
        };

        let got = dns_resolver(roots, &tls)
            .resolve(
                "dj@example.jig",
                &delegations,
                &MemPins::default(),
                &MemEvidence::default(),
            )
            .await
            .unwrap();
        assert!(
            matches!(got, Verified::New(ref b) if b.key.root == Root::Config),
            "{got:?}"
        );
        assert_eq!(tls.hits(), 0, "dns is not consulted");
    }

    #[tokio::test]
    async fn a_dns_host_serving_a_delegation_for_another_root_or_suffix_is_refused() {
        let ns = key(1);
        for deleg in [
            SuffixDelegation::sign(&[&ns], SUFFIX, Root::Config, SUFFIX, NOW + 1000),
            SuffixDelegation::sign(&[&ns], "other.jig", Root::Dns, "other.jig", NOW + 1000),
            SuffixDelegation::sign(&[&ns], SUFFIX, Root::Dns, SUFFIX, NOW),
        ] {
            let (roots, cert, cert_key) = ca_issued();
            let stub = Stub::start(Some((cert, cert_key))).await;
            stub.route(WELL_KNOWN, delegation_body(&deleg));
            let err = dns_resolver(roots, &stub)
                .resolve(
                    "dj@example.jig",
                    &Delegations::default(),
                    &MemPins::default(),
                    &MemEvidence::default(),
                )
                .await
                .unwrap_err();
            assert!(
                matches!(err, ResolveError::NoDelegation { .. }),
                "{deleg:?}: {err:?}"
            );
        }
    }
}
