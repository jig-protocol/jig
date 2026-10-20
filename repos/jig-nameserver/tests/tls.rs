//! The nameserver serves TLS by default (JEP-0004 rule 12), with a self-signed
//! certificate its DID vouches for at `/.well-known/jig-ns`. Plaintext needs
//! `[tls] enabled = false`, which the nameserver advertises.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use jig_client::tls::{TlsConfig, TlsError, probe_at};
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

/// Start a nameserver in `dir` with `extra` appended to its config, and
/// return its DID and address.
async fn start(dir: &Path, extra: &str) -> (String, std::net::SocketAddr) {
    let key = dir.join("ns.key");
    let did = jig_nameserver::v0_0_2::keygen(&key).unwrap();
    let path = dir.join("ns.toml");
    std::fs::write(
        &path,
        format!(
            "[storage]\ndatabase_path = {db:?}\n\n\
             [v0_0_2.server]\nserver_did_keyfile = {key:?}\n\n\
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
    let other = jig_nameserver::v0_0_2::keygen(&dir.0.join("other.key")).unwrap();

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
