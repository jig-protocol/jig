//! H10 — the nameserver BINARY's HTTP surface.
//!
//! Every other nameserver test drives routers it assembled itself. That is how
//! the v0.0.2 alias API stayed green while `jig-nameserver serve` shipped only
//! the legacy `app_router`: `GET /v1/challenge` answered 405 (legacy registers
//! POST there) and register/resolve/handles answered 404.
//!
//! So this file boots `jig_nameserver::server::build_app` — the same function
//! `run_http_server` calls — over a real TCP listener, and drives it with a
//! real HTTP client. If someone unmounts a router, this fails.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use jig_core::Did;
use jig_nameserver::config::NameServerConfig;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const ALIAS_SUFFIX: &str = "h10.jig";

struct BinarySurface {
    addr: SocketAddr,
    client: reqwest::Client,
    _tempdir: TempDir,
    _handle: JoinHandle<()>,
}

impl BinarySurface {
    /// Boot the production router on an ephemeral port. `list_handles` mirrors
    /// `[v0_0_2.debug] list_handles`, which gates alias enumeration.
    async fn start(list_handles: bool) -> Result<Self> {
        let tempdir = tempfile::tempdir().context("tempdir")?;

        let mut cfg = NameServerConfig::default();
        cfg.storage.database_path = tempdir.path().join("nameserver.db");
        cfg.pow.server_secret = "h10-test-secret".to_string();
        cfg.federation.enabled = false;
        cfg.v0_0_2.server.server_did_keyfile = tempdir
            .path()
            .join("nameserver.key")
            .to_string_lossy()
            .into_owned();
        cfg.v0_0_2.nameserver.alias_suffix = ALIAS_SUFFIX.to_string();
        cfg.v0_0_2.debug.list_handles = list_handles;
        cfg.validate().context("config must be valid")?;

        let (router, coordinator) = jig_nameserver::server::build_app(&cfg).context("build_app")?;
        assert!(
            coordinator.is_none(),
            "federation disabled — build_app must not hand back a coordinator"
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let addr = listener.local_addr().context("local_addr")?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        Ok(Self {
            addr,
            client: reqwest::Client::new(),
            _tempdir: tempdir,
            _handle: handle,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

fn fresh_identity() -> (String, SigningKey) {
    use rand::Rng;
    let mut secret = [0u8; 32];
    rand::thread_rng().fill(&mut secret);
    let key = SigningKey::from_bytes(&secret);
    let did = Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
    (did.to_did_jig_string(), key)
}

/// The whole alias lifecycle over the production router: challenge → register
/// → resolve → handles. Pre-fix, the first request alone returned 405.
#[tokio::test]
async fn build_app_serves_the_v0_0_2_alias_lifecycle() {
    let ns = BinarySurface::start(true).await.expect("start");

    // 1. GET /v1/challenge — was 405 when only app_router was mounted.
    let resp = ns
        .client
        .get(ns.url("/v1/challenge"))
        .send()
        .await
        .expect("GET /v1/challenge");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "GET /v1/challenge must be served by the binary's router"
    );
    let body: serde_json::Value = resp.json().await.expect("challenge json");
    let challenge = body["challenge"]
        .as_str()
        .expect("challenge field")
        .to_string();
    assert_eq!(challenge.len(), 64, "expected a 32-byte hex nonce");

    // 2. POST /v1/register
    let (did, key) = fresh_identity();
    let sig = key.sign(challenge.as_bytes());
    let resp = ns
        .client
        .post(ns.url("/v1/register"))
        .json(&serde_json::json!({
            "did": did,
            "requested_alias": "alice",
            "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            "challenge": challenge,
        }))
        .send()
        .await
        .expect("POST /v1/register");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "register must be mounted"
    );
    let attestation: serde_json::Value = resp.json().await.expect("attestation json");
    let expected_alias = format!("alice@{ALIAS_SUFFIX}");
    assert_eq!(
        attestation["alias"], expected_alias,
        "alias suffix must come from [v0_0_2.nameserver].alias_suffix"
    );
    assert_eq!(attestation["did"], did);

    // 3. GET /v1/resolve/:alias
    let resp = ns
        .client
        .get(ns.url(&format!("/v1/resolve/{expected_alias}")))
        .send()
        .await
        .expect("GET /v1/resolve");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "resolve must be mounted"
    );
    let resolved: serde_json::Value = resp.json().await.expect("resolve json");
    assert_eq!(resolved["did"], did);

    // 4. GET /v1/handles
    let resp = ns
        .client
        .get(ns.url("/v1/handles"))
        .send()
        .await
        .expect("GET /v1/handles");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "handles must be mounted"
    );
    let handles: serde_json::Value = resp.json().await.expect("handles json");
    let aliases = handles["aliases"].as_array().expect("aliases array");
    assert!(
        aliases.iter().any(|a| a["alias"] == expected_alias.as_str()
            || a.as_str() == Some(expected_alias.as_str())),
        "registered alias must appear in /v1/handles, got {handles}"
    );
}

/// The merge must not cost the legacy surface: `/v1/health` is legacy-only and
/// `POST /v1/challenge` is the legacy handler sharing a path with the v0.0.2
/// GET. Both must still answer.
#[tokio::test]
async fn build_app_keeps_the_legacy_surface() {
    let ns = BinarySurface::start(false).await.expect("start");

    let resp = ns
        .client
        .get(ns.url("/v1/health"))
        .send()
        .await
        .expect("GET /v1/health");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "legacy health check"
    );

    let resp = ns
        .client
        .post(ns.url("/v1/challenge"))
        .json(&serde_json::json!({
            "action": "claim",
            "subject": "alice@example.com",
            "ttl_seconds": 120,
            "difficulty": 8
        }))
        .send()
        .await
        .expect("POST /v1/challenge");
    assert_ne!(
        resp.status(),
        reqwest::StatusCode::METHOD_NOT_ALLOWED,
        "legacy POST /v1/challenge must survive merging with the v0.0.2 GET"
    );
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // ...and the v0.0.2 GET is live on the same path in the same process.
    let resp = ns
        .client
        .get(ns.url("/v1/challenge"))
        .send()
        .await
        .expect("GET /v1/challenge");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Alias enumeration is opt-in; this instance left it off.
    let resp = ns
        .client
        .get(ns.url("/v1/handles"))
        .send()
        .await
        .expect("GET /v1/handles");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "/v1/handles must stay unmounted unless [v0_0_2.debug].list_handles is set"
    );
}
