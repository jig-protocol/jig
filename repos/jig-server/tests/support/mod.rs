//! Shared scaffolding for authentication integration tests.
//!
//! Deliberately small and honest about what it does: it builds a real router
//! over an in-memory store, signs requests the way a correct client would, and
//! returns `(status, json)`. Nothing here fakes authentication — a request that
//! this module says is signed is signed, so a test asserting a 200 is asserting
//! the server verified a real ed25519 signature.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use jig_config::v0_0_2_server::JigServerConfig;
use jig_core::did::Did;
use jig_server::auth::authenticate::headers;
use jig_server::runtime::ExecutionConfig;
use jig_server::v0_0_2::AppState;
use jig_server::v0_0_2_blocks::build_blocks_router;
use std::sync::Arc;
use tower::ServiceExt as _;

/// A test identity: a signing key and the DID derived from it.
///
/// Seeded deterministically. Random keys would make a failure depend on which
/// key you happened to draw, and these tests are about the protocol, not about
/// key material.
pub struct Identity {
    signing: SigningKey,
    did: Did,
}

impl Identity {
    pub fn new(seed: u8) -> Self {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let did = Did::from_ed25519_pubkey(&signing.verifying_key().to_bytes());
        Self { signing, did }
    }

    pub fn did(&self) -> &Did {
        &self.did
    }
}

/// A signed request, kept as data so a test can send the SAME one twice and
/// exercise replay defence. Rebuilding it would produce a fresh nonce and prove
/// nothing.
pub struct SignedRequest {
    pub method: String,
    pub path: String,
    pub did: String,
    pub hlc_wall_ms: u64,
    pub hlc_logical: u32,
    pub nonce: String,
    pub sig_b64: String,
}

/// A server under test.
///
/// Built through the REAL `AppState::new`, not a test-only shortcut, so these
/// tests exercise the same boot path production does.
pub struct TestServer {
    state: Arc<AppState>,
    /// Held for the server's lifetime. `AppState::new` writes a SQLite database
    /// AND a server key file; the config default for the latter is
    /// `~/.jig/server/server.key`, which is real user state that tests must
    /// never touch. Both are redirected in here and removed on drop.
    _tmp: tempfile::TempDir,
}

impl TestServer {
    /// Build a server with authentication required (the production default).
    pub fn authenticated() -> Self {
        Self::with_auth(true)
    }

    /// Build a server with the documented migration escape hatch set.
    pub fn unauthenticated() -> Self {
        Self::with_auth(false)
    }

    fn with_auth(require: bool) -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");

        let mut config = JigServerConfig::default();
        config.auth.require_authenticated_reads = require;
        config.server.server_did_keyfile =
            tmp.path().join("server.key").to_string_lossy().into_owned();

        let state = AppState::new(
            config,
            tmp.path().join("jig-test.db"),
            ExecutionConfig::default(),
        )
        .expect("test server boots");

        Self {
            state: Arc::new(state),
            _tmp: tmp,
        }
    }

    /// Sign a GET for `path`, exactly as a correct client would.
    ///
    /// `now_ms` is the server's clock at send time; the request is stamped with
    /// it so it lands inside the acceptance window.
    pub fn sign_get(&self, who: &Identity, path: &str) -> SignedRequest {
        let now_ms = now_ms();
        let nonce = format!("nonce-{now_ms}-{}", path.len());
        let hash =
            jig_core::request_auth::canonical_request_hash("GET", path, b"", now_ms, 0, &nonce);
        SignedRequest {
            method: "GET".to_string(),
            path: path.to_string(),
            did: who.did.to_did_jig_string(),
            hlc_wall_ms: now_ms,
            hlc_logical: 0,
            nonce,
            sig_b64: base64::engine::general_purpose::STANDARD
                .encode(who.signing.sign(hash.as_bytes()).to_bytes()),
        }
    }

    /// Send a previously-signed request. Sending the same one twice is how the
    /// replay test works.
    pub async fn send(&self, req: &SignedRequest) -> (StatusCode, serde_json::Value) {
        let http = Request::builder()
            .method(req.method.as_str())
            .uri(&req.path)
            .header(headers::DID, &req.did)
            .header(headers::HLC_WALL_MS, req.hlc_wall_ms.to_string())
            .header(headers::HLC_LOGICAL, req.hlc_logical.to_string())
            .header(headers::NONCE, &req.nonce)
            .header(headers::SIGNATURE, &req.sig_b64)
            .body(Body::empty())
            .unwrap();
        self.dispatch(http).await
    }

    /// Send a GET carrying no proof at all.
    pub async fn send_unsigned(&self, path: &str) -> (StatusCode, serde_json::Value) {
        let http = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        self.dispatch(http).await
    }

    async fn dispatch(&self, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        // A fresh router per call, over the SAME state — so the replay guard
        // and store persist across requests, which is what makes the replay
        // test meaningful.
        let router = build_blocks_router(self.state.clone());
        let resp = router.oneshot(req).await.expect("router responds");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_millis() as u64
}
