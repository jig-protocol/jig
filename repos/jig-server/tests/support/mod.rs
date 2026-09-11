//! Shared scaffolding for authentication integration tests.
//!
//! Deliberately small and honest about what it does: it builds a real router
//! over an in-memory store, signs requests the way a correct client would, and
//! returns `(status, json)`. Nothing here fakes authentication — a request that
//! this module says is signed is signed, so a test asserting a 200 is asserting
//! the server verified a real ed25519 signature.

// Each integration-test binary compiles this module separately and uses only
// the helpers it needs; the rest would warn as dead code binary by binary.
#![allow(dead_code)]

pub mod ws;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use jig_client::blocks::{
    BuiltBlock, build_channel_archive, build_channel_create, build_member_add, build_text_render,
};
use jig_config::v0_0_2_server::JigServerConfig;
use jig_core::HlcTimestamp;
use jig_core::did::Did;
use jig_server::auth::authenticate::headers;
use jig_server::runtime::ExecutionConfig;
use jig_server::v0_0_2::AppState;
use jig_server::v0_0_2_admin::build_admin_router;
use jig_server::v0_0_2_blocks::build_blocks_router;
use std::sync::Arc;
use tower::ServiceExt as _;

/// A test identity: a signing key and the DID derived from it.
///
/// Seeded deterministically. Random keys would make a failure depend on which
/// key you happened to draw, and these tests are about the protocol, not about
/// key material.
pub struct Identity {
    pub(crate) signing: SigningKey,
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

    /// The same key as a `jig_client::Identity`, so control-plane blocks are
    /// built by the real client builders rather than a test-only imitation.
    pub fn as_client(&self) -> jig_client::Identity {
        jig_client::Identity::from_signing_key(self.signing.clone())
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
        let mut config = JigServerConfig::default();
        config.auth.require_authenticated_reads = require;
        Self::with_config(config)
    }

    /// Build a server with authentication required and this `[auth.admission]`
    /// section — the gate-2 tests' entry point.
    pub fn with_admission(admission: jig_config::v0_0_2_server::AdmissionSection) -> Self {
        let mut config = JigServerConfig::default();
        config.auth.admission = admission;
        Self::with_config(config)
    }

    /// Build a server from a complete config, for tests that combine knobs.
    pub fn with_full_config(config: JigServerConfig) -> Self {
        Self::with_config(config)
    }

    fn with_config(mut config: JigServerConfig) -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
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

    /// Create `slug` owned by `owner` through the real admin endpoint, so the
    /// channel row and the owner's membership are written by the same effect
    /// code production runs — not seeded into the store by hand.
    pub async fn create_channel(&self, owner: &Identity, slug: &str, visibility: &str) {
        let owner = owner.as_client();
        let block = build_channel_create(
            &owner,
            slug,
            visibility,
            HlcTimestamp::now_wall(owner.did().clone()),
        );
        let (status, body) = self.post_admin("/_admin_v0_0_2/channels", &block).await;
        assert_eq!(status, StatusCode::OK, "channel-create failed: {body}");
    }

    /// Archive `slug` as `owner` through the real admin endpoint — the
    /// v0.0.2 channel delete, a soft delete that keeps every block.
    pub async fn archive_channel(&self, owner: &Identity, slug: &str) {
        let owner = owner.as_client();
        let block =
            build_channel_archive(&owner, slug, HlcTimestamp::now_wall(owner.did().clone()));
        let path = format!("/_admin_v0_0_2/channels/{}/archive", encode_slug(slug));
        let (status, body) = self.post_admin(&path, &block).await;
        assert_eq!(status, StatusCode::OK, "channel-archive failed: {body}");
    }

    /// Add `member` to `slug`, the block signed by `by`. Asserts success; use
    /// [`try_add_member`](Self::try_add_member) to observe a refusal.
    pub async fn add_member(&self, by: &Identity, slug: &str, member: &Identity) {
        let (status, body) = self.try_add_member(by, slug, member).await;
        assert_eq!(status, StatusCode::OK, "member-add failed: {body}");
    }

    /// Submit a `member-add` for `member` on `slug`, signed by `by`, through
    /// the admin endpoint. Returns whatever the server said.
    pub async fn try_add_member(
        &self,
        by: &Identity,
        slug: &str,
        member: &Identity,
    ) -> (StatusCode, serde_json::Value) {
        let by = by.as_client();
        let block = build_member_add(
            &by,
            slug,
            &member.did().to_did_jig_string(),
            HlcTimestamp::now_wall(by.did().clone()),
        );
        let path = format!("/_admin_v0_0_2/channels/{}/members", encode_slug(slug));
        self.post_admin(&path, &block).await
    }

    /// Post a `text-render` block to `slug` as `who` through the public
    /// submit path, asserting it was accepted.
    pub async fn post_text(&self, who: &Identity, slug: &str, body: &str) {
        let who = who.as_client();
        let block = build_text_render(&who, slug, body, HlcTimestamp::now_wall(who.did().clone()));
        let (status, resp) = self.try_submit(&block).await;
        assert_eq!(status, StatusCode::OK, "text-render failed: {resp}");
    }

    /// Submit any signed block through the public, always-on
    /// `POST /api/v1/blocks` — the path a stranger with a keypair would use.
    pub async fn try_submit(&self, block: &BuiltBlock) -> (StatusCode, serde_json::Value) {
        let http = Request::builder()
            .method("POST")
            .uri("/api/v1/blocks")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&submission(block)).unwrap()))
            .unwrap();
        self.dispatch(http).await
    }

    async fn post_admin(&self, path: &str, block: &BuiltBlock) -> (StatusCode, serde_json::Value) {
        let http = Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&submission(block)).unwrap()))
            .unwrap();
        let router = build_admin_router(self.state.clone());
        let resp = router.oneshot(http).await.expect("admin router responds");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
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

/// The `{ bundle_b64, sig_b64 }` body every submit-style endpoint takes.
fn submission(block: &BuiltBlock) -> serde_json::Value {
    serde_json::json!({
        "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
        "sig_b64": base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
    })
}

/// `#private` as it appears in a URL path. Also the form that gets signed: the
/// canonical hash covers the path as sent, so tests must sign this exact form.
pub fn encode_slug(slug: &str) -> String {
    slug.replace('#', "%23")
}

/// The history path for `slug`, in its signable form.
pub fn history_path(slug: &str) -> String {
    format!("/api/v1/channels/{}/blocks", encode_slug(slug))
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_millis() as u64
}
