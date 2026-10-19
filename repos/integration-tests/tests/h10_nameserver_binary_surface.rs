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
use base64::engine::general_purpose::URL_SAFE_NO_PAD as b64u;
use ed25519_dalek::SigningKey;
use jig_core::Did;
use jig_core::naming::{self, Action, SuffixDelegation};
use jig_nameserver::config::NameServerConfig;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const ALIAS_SUFFIX: &str = "h10.example.org";

/// The verified attestation in a register or resolve response body.
fn attestation_in(body: &serde_json::Value) -> naming::Attestation {
    let envelope = b64u
        .decode(body["attestation"].as_str().expect("attestation field"))
        .expect("attestation is base64url");
    naming::Attestation::from_envelope(&envelope).expect("attestation verifies")
}

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
        cfg.v0_0_2.nameserver.alias_suffixes =
            vec![jig_config::v0_0_2_server::SuffixConfig::new(ALIAS_SUFFIX)];
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
    rand::rng().fill_bytes(&mut secret);
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
    // The nameserver's DID, from its signed suffix delegation.
    let resp = ns
        .client
        .get(ns.url("/.well-known/jig-ns-delegation"))
        .send()
        .await
        .expect("GET /.well-known/jig-ns-delegation");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "delegation must be mounted"
    );
    let body: serde_json::Value = resp.json().await.expect("delegation json");
    let envelopes: Vec<Vec<u8>> = body["envelopes"]
        .as_array()
        .expect("envelopes array")
        .iter()
        .map(|e| b64u.decode(e.as_str().unwrap()).unwrap())
        .collect();
    let delegation = SuffixDelegation::from_envelopes(&envelopes).expect("delegation verifies");
    assert_eq!(delegation.suffix, ALIAS_SUFFIX);
    let ns_did = delegation.authorities[0].clone();

    let (did, key) = fresh_identity();
    let expected_alias = format!("alice@{ALIAS_SUFFIX}");
    let proof = naming::sign_proof(&key, Action::Register, &ns_did, &expected_alias, &challenge);
    let resp = ns
        .client
        .post(ns.url("/v1/register"))
        .json(&serde_json::json!({
            "did": did,
            "requested_alias": "alice",
            "proof_of_control": b64u.encode(proof),
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
    let registered: serde_json::Value = resp.json().await.expect("register json");
    let attestation = attestation_in(&registered);
    assert_eq!(
        attestation.alias, expected_alias,
        "alias suffix must come from [v0_0_2.nameserver].alias_suffixes"
    );
    assert_eq!(attestation.did, did);

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
    let attestation = attestation_in(&resolved);
    assert_eq!(attestation.did, did);
    naming::verify_binding(
        &attestation,
        &delegation,
        &naming::Name::parse(&expected_alias).unwrap(),
        chrono::Utc::now().timestamp(),
    )
    .expect("the served binding verifies against the served delegation");

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

/// `/v1/health` stays, and the legacy v0.0.1 `POST /v1/challenge` is gone:
/// only the v0.0.2 GET answers on that path.
#[tokio::test]
async fn build_app_serves_health_and_not_the_legacy_challenge() {
    let ns = BinarySurface::start(false).await.expect("start");

    let resp = ns
        .client
        .get(ns.url("/v1/health"))
        .send()
        .await
        .expect("GET /v1/health");
    assert_eq!(resp.status(), reqwest::StatusCode::OK, "health check");

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
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::METHOD_NOT_ALLOWED,
        "legacy POST /v1/challenge is removed"
    );

    // The v0.0.2 GET is live on the same path.
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
