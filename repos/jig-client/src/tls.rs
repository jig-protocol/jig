//! TLS to a jig server: a certificate a CA vouches for, or the one the
//! server's DID vouches for.
//!
//! A jig server serves TLS by default with a certificate it made itself. No CA
//! vouches for it, so it carries a [`TlsBinding`] at `/.well-known/jig`: the
//! server's DID key, naming the certificate. [`probe`] fetches that document
//! once, over a connection that accepts any certificate but remembers which
//! one it was shown, and checks the binding against the DID the caller
//! expects. What it returns is a client config that accepts exactly that
//! certificate (or any a CA vouches for, for the host) and nothing else.
//!
//! The DID is the anchor, not the certificate: a server that rotates its
//! certificate is still accepted if the same DID vouches for the new one, and
//! a stranger with a certificate of their own is refused because it cannot
//! sign for the DID. On first contact the caller has no DID to expect, and the
//! probe takes the one the server names — trust on first use, which the
//! caller then pins.
//!
//! Every handshake checks that the server holds the certificate's key; only
//! the question of whose certificate it is gets decided here.

use std::sync::{Arc, Mutex};

use jig_core::tls_binding::{TlsBinding, cert_hash};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use serde::Deserialize;

pub use rustls::ClientConfig as TlsConfig;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("bad server URL `{0}`")]
    BadUrl(String),
    #[error("fetching {url}: {reason}")]
    Fetch { url: String, reason: String },
    #[error(
        "{server} is not the server this device expects: it names itself {presented}, \
         not {expected}{}",
        .rotated_past.as_ref().map(|r| format!("; {r}")).unwrap_or_default()
    )]
    OtherServer {
        server: String,
        expected: String,
        presented: String,
        /// The key links it served, base64, oldest first: ones that do not
        /// move from `expected`, but may fork a link the caller already
        /// followed.
        key_links: Vec<String>,
        /// Set when that link moves to `presented` from another DID than
        /// `expected`: the server changed its key more than once since it
        /// was pinned, or is an impostor. Says so, and that re-pinning is
        /// trust on first use again.
        rotated_past: Option<String>,
    },
    #[error(
        "{server} presented a certificate no CA vouches for and its DID does not vouch for \
         either: {reason}"
    )]
    Unvouched { server: String, reason: String },
    #[error(
        "{server} names itself {presented}, which is not one of the authorities for this \
         suffix: {authorities:?}"
    )]
    NotAnAuthority {
        server: String,
        presented: String,
        authorities: Vec<String>,
    },
    #[error("{server} is plaintext; a nameserver is reached only over TLS its DID vouches for")]
    Plaintext { server: String },
    #[error("{server}'s certificate is not vouched for by its DID: {reason}")]
    Unbound { server: String, reason: String },
}

/// What [`probe`] learned.
pub struct Probed {
    /// The DID the server names, checked against the one expected when there
    /// was one.
    pub server_did: Option<String>,
    /// The well-known document, as served.
    pub well_known: serde_json::Value,
    /// For every later connection: accepts the certificate the DID vouched
    /// for, or one a CA vouches for. `None` for a plaintext server.
    pub config: Option<Arc<ClientConfig>>,
    /// Set when the server names another DID than the one expected and
    /// serves a public key link from that one to it (JEP-0012): the expected
    /// DID it moved from. The caller moves its pin ([`crate::pins::Pins::move_server`]).
    pub moved_from: Option<String>,
    /// The links the server serves, base64, oldest first, ending at its
    /// DID: `prior_key_links` and then `key_link`.
    pub key_links: Vec<String>,
    /// When the pin moved: the links from `moved_from` on, the hops followed.
    pub followed: Vec<String>,
}

/// Fetch `server`'s `/.well-known/jig` and work out which certificate to
/// trust for it.
///
/// `expected_did` is the DID this caller already holds for the server — a
/// pin, or a federation peer's configured `expected_did`. A server naming any
/// other DID is refused, whatever its certificate. With `None`, the server's
/// own word is taken and the caller should pin it.
///
/// A plaintext (`http://`, `ws://`) server is fetched as is; there is nothing
/// to bind.
pub async fn probe(server: &str, expected_did: Option<&str>) -> Result<Probed, TlsError> {
    probe_at(server, "/.well-known/jig", expected_did).await
}

/// [`probe`] for a service that publishes `server_did` and `tls_binding` in
/// another document: a nameserver's `/.well-known/jig-ns`.
pub async fn probe_at(
    server: &str,
    well_known_path: &str,
    expected_did: Option<&str>,
) -> Result<Probed, TlsError> {
    let base = http_base(server)?;
    let url = format!("{base}{well_known_path}");
    let tls = base.starts_with("https://");
    let verifier = Arc::new(DidBoundVerifier::new(None, true, true));
    let mut http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15));
    if tls {
        http = http.use_preconfigured_tls(client_config(verifier.clone()));
    }
    let fetch = |reason: String| TlsError::Fetch {
        url: url.clone(),
        reason,
    };
    let http = http.build().map_err(|e| fetch(e.to_string()))?;
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| fetch(error_chain(&e)))?;
    if !resp.status().is_success() {
        return Err(fetch(format!("HTTP {}", resp.status())));
    }
    // Read before anything is pinned, from a server not yet trusted.
    let well_known: serde_json::Value =
        crate::limits::json_capped(resp, crate::limits::MAX_DOCUMENT_BYTES)
            .await
            .map_err(|e| fetch(e.to_string()))?;

    #[derive(Deserialize)]
    struct Advertised {
        server_did: Option<String>,
        tls_binding: Option<TlsBinding>,
        key_link: Option<String>,
        #[serde(default)]
        prior_key_links: Vec<String>,
    }
    let advertised: Advertised =
        serde_json::from_value(well_known.clone()).map_err(|e| fetch(e.to_string()))?;
    // Another DID than the expected one only through a public link the
    // expected key signed to it.
    // The chain it serves, oldest first: earlier links, then the newest.
    let key_links: Vec<String> = match &advertised.key_link {
        Some(newest) => advertised
            .prior_key_links
            .iter()
            .chain([newest])
            .cloned()
            .collect(),
        None => Vec::new(),
    };
    let mut moved_from = None;
    let mut followed = Vec::new();
    if let (Some(expected), Some(presented)) = (expected_did, advertised.server_did.as_deref())
        && !jig_pipeline::handshake::same_did(expected, presented)
    {
        match jig_pipeline::handshake::chain_moves(&key_links, expected, presented) {
            Ok(hops) => {
                moved_from = Some(expected.to_string());
                followed = hops;
            }
            Err(_) => {
                let rotated_past =
                    jig_pipeline::handshake::link_from_elsewhere(&key_links, expected, presented)
                        .map(|left| jig_pipeline::handshake::rotated_past(expected, &left));
                return Err(TlsError::OtherServer {
                    server: server.to_string(),
                    expected: expected.to_string(),
                    presented: presented.to_string(),
                    key_links,
                    rotated_past,
                });
            }
        }
    }
    let server_did = advertised.server_did.or(expected_did.map(str::to_string));
    if !tls {
        return Ok(Probed {
            server_did,
            well_known,
            config: None,
            moved_from,
            key_links,
            followed,
        });
    }

    let seen = verifier.seen();
    let accepted = if seen.ca_valid {
        // A CA vouches for this host's certificate; the DID still has to be
        // the expected one, which was checked above.
        None
    } else {
        let unvouched = |reason: &str| TlsError::Unvouched {
            server: server.to_string(),
            reason: reason.to_string(),
        };
        let cert = seen
            .cert
            .ok_or_else(|| unvouched("no certificate was presented"))?;
        let did = server_did
            .as_deref()
            .ok_or_else(|| unvouched("the server names no DID"))?;
        let binding = advertised
            .tls_binding
            .ok_or_else(|| unvouched("the server publishes no tls_binding"))?;
        binding
            .verify(did, cert.as_ref())
            .map_err(|e| unvouched(&e.to_string()))?;
        Some(cert_hash(cert.as_ref()))
    };
    Ok(Probed {
        server_did,
        well_known,
        config: Some(Arc::new(client_config(Arc::new(DidBoundVerifier::new(
            accepted, false, true,
        ))))),
        moved_from,
        key_links,
        followed,
    })
}

/// [`probe_at`] for a server that must be one of `authorities`, vouched for
/// by its DID and nothing else: a nameserver a `config` (or `contract`)
/// delegation lists.
///
/// The server must name one of `authorities` and publish a `tls_binding`
/// that DID signed for the certificate it presented. A certificate a CA
/// vouches for counts for nothing here: whoever can get a CA certificate for
/// the host is not thereby an authority for the suffix. The returned config
/// accepts that one certificate and no other, CA-issued or not.
///
/// Plaintext is refused with [`TlsError::Plaintext`]; a caller that allows
/// it, for local testing, does not probe.
pub async fn probe_bound(
    server: &str,
    well_known_path: &str,
    authorities: &[String],
) -> Result<Probed, TlsError> {
    probe_bound_to(server, well_known_path, Some(authorities)).await
}

/// [`probe_bound`] to whatever DID the server names: its certificate must be
/// one that DID vouches for, and the caller checks the DID it gets back in
/// [`Probed::server_did`] against what it trusts (a delegation the server
/// itself publishes, or nothing, for a diagnostic).
pub async fn probe_self_bound(server: &str, well_known_path: &str) -> Result<Probed, TlsError> {
    probe_bound_to(server, well_known_path, None).await
}

async fn probe_bound_to(
    server: &str,
    well_known_path: &str,
    authorities: Option<&[String]>,
) -> Result<Probed, TlsError> {
    let base = http_base(server)?;
    if !base.starts_with("https://") {
        return Err(TlsError::Plaintext {
            server: server.to_string(),
        });
    }
    let url = format!("{base}{well_known_path}");
    let verifier = Arc::new(DidBoundVerifier::new(None, true, false));
    let fetch = |reason: String| TlsError::Fetch {
        url: url.clone(),
        reason,
    };
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(client_config(verifier.clone()))
        .build()
        .map_err(|e| fetch(e.to_string()))?;
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| fetch(error_chain(&e)))?;
    if !resp.status().is_success() {
        return Err(fetch(format!("HTTP {}", resp.status())));
    }
    // Read before anything is pinned, from a server not yet trusted.
    let well_known: serde_json::Value =
        crate::limits::json_capped(resp, crate::limits::MAX_DOCUMENT_BYTES)
            .await
            .map_err(|e| fetch(e.to_string()))?;

    #[derive(Deserialize)]
    struct Advertised {
        server_did: Option<String>,
        tls_binding: Option<TlsBinding>,
    }
    let advertised: Advertised =
        serde_json::from_value(well_known.clone()).map_err(|e| fetch(e.to_string()))?;
    let unbound = |reason: &str| TlsError::Unbound {
        server: server.to_string(),
        reason: reason.to_string(),
    };
    let did = advertised
        .server_did
        .ok_or_else(|| unbound("the server names no DID"))?;
    if let Some(authorities) = authorities
        && !authorities.contains(&did)
    {
        return Err(TlsError::NotAnAuthority {
            server: server.to_string(),
            presented: did,
            authorities: authorities.to_vec(),
        });
    }
    let cert = verifier
        .seen()
        .cert
        .ok_or_else(|| unbound("no certificate was presented"))?;
    advertised
        .tls_binding
        .ok_or_else(|| unbound("the server publishes no tls_binding"))?
        .verify(&did, cert.as_ref())
        .map_err(|e| unbound(&e.to_string()))?;
    Ok(Probed {
        server_did: Some(did),
        well_known,
        config: Some(Arc::new(client_config(Arc::new(DidBoundVerifier::new(
            Some(cert_hash(cert.as_ref())),
            false,
            false,
        ))))),
        // An authority is whoever the delegation lists: a key link from one
        // of them to another DID moves nothing here.
        moved_from: None,
        key_links: Vec::new(),
        followed: Vec::new(),
    })
}

/// `server` as an `http(s)://` base, without a trailing slash.
pub fn http_base(server: &str) -> Result<String, TlsError> {
    let url = url::Url::parse(server.trim()).map_err(|_| TlsError::BadUrl(server.to_string()))?;
    let scheme = match url.scheme() {
        "https" | "wss" => "https",
        "http" | "ws" => "http",
        _ => return Err(TlsError::BadUrl(server.to_string())),
    };
    let host = url
        .host_str()
        .ok_or_else(|| TlsError::BadUrl(server.to_string()))?;
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    Ok(format!("{scheme}://{host}{port}"))
}

/// The causes reqwest folds into one opaque error, joined; a certificate
/// refusal is otherwise just "error sending request".
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

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn client_config(verifier: Arc<DidBoundVerifier>) -> ClientConfig {
    // TLS 1.3 only (transports.md, "TLS 1.3 Only").
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// What a probing verifier was shown.
#[derive(Default, Clone)]
struct Seen {
    cert: Option<CertificateDer<'static>>,
    ca_valid: bool,
}

/// Accepts a certificate a CA vouches for (unless `ca_roots` is off), or the
/// one whose [`cert_hash`] is `accepted`. A probing verifier accepts anything
/// and remembers it; the decision is made after the fact, from the binding.
#[derive(Debug)]
struct DidBoundVerifier {
    roots: Option<Arc<WebPkiServerVerifier>>,
    algorithms: WebPkiSupportedAlgorithms,
    accepted: Option<[u8; 32]>,
    probing: bool,
    seen: Mutex<Option<(CertificateDer<'static>, bool)>>,
}

impl DidBoundVerifier {
    fn new(accepted: Option<[u8; 32]>, probing: bool, ca_roots: bool) -> Self {
        let provider = provider();
        let mut store = RootCertStore::empty();
        // A host with no readable CA store still reaches DID-vouched servers.
        if ca_roots {
            let _ = store.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        }
        let roots = (!store.is_empty())
            .then(|| {
                WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider.clone())
                    .build()
                    .ok()
            })
            .flatten();
        Self {
            roots,
            algorithms: provider.signature_verification_algorithms,
            accepted,
            probing,
            seen: Mutex::new(None),
        }
    }

    fn seen(&self) -> Seen {
        match self.seen.lock().expect("verifier lock").clone() {
            Some((cert, ca_valid)) => Seen {
                cert: Some(cert),
                ca_valid,
            },
            None => Seen::default(),
        }
    }
}

impl ServerCertVerifier for DidBoundVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ca_valid = self.roots.as_ref().is_some_and(|roots| {
            roots
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .is_ok()
        });
        if self.probing {
            *self.seen.lock().expect("verifier lock") =
                Some((end_entity.clone().into_owned(), ca_valid));
            return Ok(ServerCertVerified::assertion());
        }
        if ca_valid || self.accepted == Some(cert_hash(end_entity.as_ref())) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    // The handshake signatures are always checked, probing or not: whoever
    // presents a certificate must hold its key.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_base_maps_every_scheme_and_drops_the_path() {
        assert_eq!(
            http_base("wss://Host:7117/api/v1/ws").unwrap(),
            "https://host:7117"
        );
        assert_eq!(http_base("ws://h:1").unwrap(), "http://h:1");
        assert_eq!(http_base("https://h").unwrap(), "https://h");
        assert!(http_base("ftp://h").is_err());
        assert!(http_base("not a url").is_err());
    }
}
