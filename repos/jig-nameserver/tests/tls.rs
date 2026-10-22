//! The nameserver serves TLS by default (JEP-0004 rule 12), with a self-signed
//! certificate its DID vouches for at `/.well-known/jig-ns`. Plaintext needs
//! `[tls] enabled = false`, which the nameserver advertises.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use jig_client::tls::{TlsConfig, TlsError, probe_at, probe_bound, probe_self_bound};
use jig_core::tls_binding::TlsBinding;
use jig_nameserver::NameServerConfig;
use tokio::net::TcpListener;

const WELL_KNOWN: &str = "/.well-known/jig-ns";

/// A scratch directory that deletes itself on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "jig-ns-tls-{name}-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A new nameserver key at `key`, sealed to the test credential beside it,
/// and the DID it signs as.
fn new_did(key: &Path) -> String {
    let unlock = jig_client::server_key::credential_for_tests(key.parent().unwrap());
    jig_nameserver::v0_0_2::keygen(key, &[unlock]).unwrap()
}

/// Start a nameserver in `dir` with `extra` appended to its config, and
/// return its DID and address.
async fn start(dir: &Path, extra: &str) -> (String, std::net::SocketAddr) {
    let key = dir.join("ns.key");
    let did = new_did(&key);
    let unlock = jig_client::server_key::credential_for_tests(dir);
    let path = dir.join("ns.toml");
    std::fs::write(
        &path,
        format!(
            "[storage]\ndatabase_path = {db:?}\n\n\
             [v0_0_2.server]\nserver_did_keyfile = {key:?}\n\n\
             [v0_0_2.keys]\nunlock = {unlock:?}\n\n\
             [[v0_0_2.nameserver.alias_suffixes]]\nsuffix = \"names.example.org\"\n\n{extra}",
            db = dir.join("ns.db"),
        ),
    )
    .unwrap();
    let cfg = NameServerConfig::load_from_path(&path).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { jig_nameserver::server::serve(&cfg, listener).await });
    (did, addr)
}

async fn get(
    base: &str,
    path: &str,
    tls: Option<&Arc<TlsConfig>>,
) -> reqwest::Result<reqwest::Response> {
    let mut client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10));
    if let Some(tls) = tls {
        client = client.use_preconfigured_tls(tls.as_ref().clone());
    }
    client
        .build()
        .unwrap()
        .get(format!("{base}{path}"))
        .send()
        .await
}

#[tokio::test]
async fn a_client_that_pins_the_nameservers_did_connects() {
    let dir = Scratch::new("pinned");
    let (did, addr) = start(&dir.0, "").await;
    let base = format!("https://{addr}");

    let probed = probe_at(&base, WELL_KNOWN, Some(&did)).await.unwrap();
    assert_eq!(probed.server_did.as_deref(), Some(did.as_str()));
    assert_eq!(
        probed.well_known["unsafe_options_active"],
        serde_json::json!([])
    );
    let tls = probed.config.expect("a TLS config");

    let health = get(&base, "/v1/health", Some(&tls)).await.unwrap();
    assert!(health.status().is_success());
    let suffixes: serde_json::Value = get(&base, "/v1/suffixes", Some(&tls))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(suffixes["ns_did"], did.as_str());

    // The certificate is the self-signed one, kept apart from jig-server's.
    assert!(dir.0.join("nameserver/tls/self-signed.crt").exists());
}

#[tokio::test]
async fn a_client_that_pins_another_did_is_refused() {
    let dir = Scratch::new("other");
    let (_, addr) = start(&dir.0, "").await;
    let other = new_did(&dir.0.join("other.key"));

    let refused = probe_at(&format!("https://{addr}"), WELL_KNOWN, Some(&other)).await;
    assert!(
        matches!(refused, Err(TlsError::OtherServer { .. })),
        "{:?}",
        refused.err()
    );
}

#[tokio::test]
async fn plaintext_is_refused_unless_tls_is_turned_off_and_advertised() {
    let dir = Scratch::new("default");
    let (_, addr) = start(&dir.0, "").await;
    assert!(
        get(&format!("http://{addr}"), "/v1/health", None)
            .await
            .is_err(),
        "a default nameserver does not speak plaintext"
    );

    let dir = Scratch::new("plaintext");
    let (_, addr) = start(&dir.0, "[tls]\nenabled = false\n").await;
    let doc: serde_json::Value = get(&format!("http://{addr}"), WELL_KNOWN, None)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        doc["unsafe_options_active"],
        serde_json::json!(["tls.enabled=false"])
    );
    assert!(doc.get("tls_binding").is_none());
}

// ---------------------------------------------------------------------------
// probe_bound: what a resolver uses for a `config` suffix's nameservers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_nameserver_bound_to_any_listed_authority_is_accepted() {
    let dir = Scratch::new("bound");
    let (did, addr) = start(&dir.0, "").await;
    let base = format!("https://{addr}");
    let other = new_did(&dir.0.join("other.key"));

    // The lists are not paired with nameservers: any listed DID will do.
    let probed = probe_bound(&base, WELL_KNOWN, &[other, did.clone()])
        .await
        .unwrap();
    assert_eq!(probed.server_did.as_deref(), Some(did.as_str()));
    let tls = probed.config.expect("a TLS config");
    let suffixes: serde_json::Value = get(&base, "/v1/suffixes", Some(&tls))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(suffixes["ns_did"], did.as_str());

    let probed = probe_self_bound(&base, WELL_KNOWN).await.unwrap();
    assert_eq!(probed.server_did.as_deref(), Some(did.as_str()));
}

#[tokio::test]
async fn a_nameserver_bound_to_an_unlisted_did_is_refused() {
    let dir = Scratch::new("unlisted");
    let (_, addr) = start(&dir.0, "").await;
    let listed = new_did(&dir.0.join("listed.key"));

    let refused = probe_bound(&format!("https://{addr}"), WELL_KNOWN, &[listed]).await;
    assert!(
        matches!(refused, Err(TlsError::NotAnAuthority { .. })),
        "{:?}",
        refused.err()
    );
}

#[tokio::test]
async fn plaintext_is_refused_by_a_bound_probe() {
    let dir = Scratch::new("bound-plain");
    let (did, addr) = start(&dir.0, "[tls]\nenabled = false\n").await;
    let refused = probe_bound(&format!("http://{addr}"), WELL_KNOWN, &[did]).await;
    assert!(
        matches!(refused, Err(TlsError::Plaintext { .. })),
        "{:?}",
        refused.err()
    );
}

/// A TLS listener serving `doc` at every path, under a fresh self-signed
/// certificate made in `dir`. Returns its address and the certificate.
async fn stub_tls(dir: &Path, doc: serde_json::Value) -> (std::net::SocketAddr, Vec<u8>) {
    let (cert, key) = jig_config::tls::TlsConfig::default()
        .material(dir, &["localhost".to_string()])
        .unwrap();
    let (config, leaf) = jig_config::tls::load_rustls_config(&cert, &key).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = doc.to_string();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, body) = (acceptor.clone(), body.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, leaf.as_ref().to_vec())
}

/// The cases a CA certificate would also be: one the listed DID does not
/// vouch for. A bound probe never consults CA roots, so a certificate's being
/// CA-issued cannot make up for a missing or wrong binding.
#[tokio::test]
async fn a_certificate_its_did_does_not_vouch_for_is_refused() {
    let key = jig_core::crypto::ed25519::generate_signing_key();
    let did =
        jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string();

    // No binding at all: what a CA-certified host that is not a jig
    // nameserver, or one behind a TLS-terminating proxy, serves.
    let dir = Scratch::new("no-binding");
    let (addr, _) = stub_tls(&dir.0, serde_json::json!({ "server_did": did })).await;
    let refused = probe_bound(
        &format!("https://{addr}"),
        WELL_KNOWN,
        std::slice::from_ref(&did),
    )
    .await;
    assert!(
        matches!(refused, Err(TlsError::Unbound { .. })),
        "{:?}",
        refused.err()
    );
    // A probe that takes the server's word for its DID still needs the
    // binding.
    let refused = probe_self_bound(&format!("https://{addr}"), WELL_KNOWN).await;
    assert!(
        matches!(refused, Err(TlsError::Unbound { .. })),
        "{:?}",
        refused.err()
    );

    // A genuine binding, but for another certificate.
    let elsewhere = Scratch::new("elsewhere");
    let (cert, cert_key) = jig_config::tls::TlsConfig::default()
        .material(&elsewhere.0, &["localhost".to_string()])
        .unwrap();
    let (_, other_leaf) = jig_config::tls::load_rustls_config(&cert, &cert_key).unwrap();
    let binding = TlsBinding::sign(&key, other_leaf.as_ref());
    let dir = Scratch::new("wrong-binding");
    let (addr, _) = stub_tls(
        &dir.0,
        serde_json::json!({ "server_did": did, "tls_binding": binding }),
    )
    .await;
    let refused = probe_bound(&format!("https://{addr}"), WELL_KNOWN, &[did]).await;
    assert!(
        matches!(refused, Err(TlsError::Unbound { .. })),
        "{:?}",
        refused.err()
    );
}
