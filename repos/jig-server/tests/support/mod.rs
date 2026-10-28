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
    BuiltBlock, build_channel_archive, build_channel_create, build_member_add, build_sealed_text,
    build_text_render, build_with_metadata,
};
use jig_client::secure::Session;
use jig_config::v0_0_2_server::JigServerConfig;
use jig_core::HlcTimestamp;
use jig_core::did::Did;
use jig_server::auth::authenticate::headers;
use jig_server::runtime::ExecutionConfig;
use jig_server::v0_0_2::AppState;
use jig_server::v0_0_2_admin::build_channel_ops_router;
use jig_server::v0_0_2_blocks::build_blocks_router;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
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
    /// Restricted channels are MLS groups (D25), so every identity that
    /// creates, joins or posts to one does it through a real MLS session.
    mls: Mls,
}

/// The MLS side of the test clients: one session per identity, and what each
/// has seen of every encrypted channel's control plane.
struct Mls {
    root: tempfile::TempDir,
    sessions: Mutex<HashMap<String, Session>>,
    /// Slugs created as `mls`.
    sealed: Mutex<HashSet<String>>,
    /// Accepted commit-carrying blocks per slug, in order.
    log: Mutex<HashMap<String, Vec<BuiltBlock>>>,
    /// How far into a slug's log each DID has caught up.
    cursor: Mutex<HashMap<(String, String), usize>>,
}

/// The server name the MLS sessions key their groups under.
const MLS_SERVER: &str = "test-server";

impl Mls {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().expect("mls dir"),
            sessions: Mutex::default(),
            sealed: Mutex::default(),
            log: Mutex::default(),
            cursor: Mutex::default(),
        }
    }

    /// Run `f` with `who`'s session, opening it on first use.
    fn with<T>(&self, who: &Identity, f: impl FnOnce(&Session) -> T) -> T {
        let did = who.did().to_did_jig_string();
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.entry(did).or_insert_with(|| {
            Session::open(self.root.path(), who.as_client()).expect("mls session")
        });
        f(session)
    }

    fn is_sealed(&self, slug: &str) -> bool {
        self.sealed.lock().unwrap().contains(slug)
    }

    /// Whether `who` holds `slug`'s group, after catching up on its commits.
    fn holds(&self, who: &Identity, slug: &str) -> bool {
        if !self.is_sealed(slug) {
            return false;
        }
        let did = who.did().to_did_jig_string();
        let key = (did.clone(), slug.to_string());
        let Some(&from) = self.cursor.lock().unwrap().get(&key) else {
            return false;
        };
        let log = self
            .log
            .lock()
            .unwrap()
            .get(slug)
            .cloned()
            .unwrap_or_default();
        self.with(who, |session| {
            for block in &log[from.min(log.len())..] {
                let opened = jig_client::open::open(&delivered(block)).expect("open block");
                if opened.sender != did {
                    session.observe(MLS_SERVER, &opened);
                }
            }
        });
        self.cursor.lock().unwrap().insert(key, log.len());
        true
    }

    /// Record an accepted commit; `joiner` starts reading the log at it.
    fn accepted(&self, slug: &str, block: &BuiltBlock, joiner: Option<&Identity>) {
        let mut log = self.log.lock().unwrap();
        let entries = log.entry(slug.to_string()).or_default();
        if let Some(j) = joiner {
            self.cursor.lock().unwrap().insert(
                (j.did().to_did_jig_string(), slug.to_string()),
                entries.len(),
            );
        }
        entries.push(block.clone());
    }
}

fn delivered(block: &BuiltBlock) -> jig_client::DeliveredBlock {
    let b64 = base64::engine::general_purpose::STANDARD;
    jig_client::DeliveredBlock {
        bundle_b64: b64.encode(block.canonical_bytes()),
        sig_b64: Some(b64.encode(&block.sender_sig)),
        receipts: vec![],
        delivery_cid: block.cid(),
        ingest: None,
    }
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
        config.keys.unlock = Some(jig_client::server_key::credential_for_tests(tmp.path()));

        let state = AppState::new(
            config,
            tmp.path().join("jig-test.db"),
            ExecutionConfig::default(),
        )
        .expect("test server boots");

        Self {
            state: Arc::new(state),
            _tmp: tmp,
            mls: Mls::new(),
        }
    }

    /// Sign a GET for `path`, exactly as a correct client would.
    ///
    /// `now_ms` is the server's clock at send time; the request is stamped with
    /// it so it lands inside the acceptance window.
    pub fn sign_get(&self, who: &Identity, path: &str) -> SignedRequest {
        let now_ms = now_ms();
        // A counter, not the path length: two requests in one millisecond to
        // paths of equal length would otherwise share a nonce and the second
        // would be refused as a replay — a flake that reads as a gate failure.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = format!(
            "nonce-{now_ms}-{}",
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
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
    /// code production runs — not seeded into the store by hand. A restricted
    /// channel is created `mls`, its group started in the owner's session.
    pub async fn create_channel(&self, owner: &Identity, slug: &str, visibility: &str) {
        let me = owner.as_client();
        let hlc = HlcTimestamp::now_wall(me.did().clone());
        let block = if visibility == "open" {
            build_channel_create(&me, slug, visibility, &self.server_did(), hlc)
        } else {
            let mut meta = self.mls_genesis(owner, slug);
            meta["slug"] = slug.into();
            meta["visibility"] = visibility.into();
            build_with_metadata(&me, jig_core::BlockKind::ChannelCreate, hlc, meta)
        };
        let (status, body) = self.post_admin("/api/v1/channels", &block).await;
        assert_eq!(status, StatusCode::OK, "channel-create failed: {body}");
    }

    /// Start `slug`'s MLS group in `owner`'s session and return the
    /// creation-block metadata that carries it, for tests that build their
    /// own `channel-create`.
    pub fn mls_genesis(&self, owner: &Identity, slug: &str) -> serde_json::Value {
        let b64 = base64::engine::general_purpose::STANDARD;
        let created = self
            .mls
            .with(owner, |s| s.create_group(MLS_SERVER, slug))
            .expect("create group");
        self.mls.sealed.lock().unwrap().insert(slug.to_string());
        self.mls
            .cursor
            .lock()
            .unwrap()
            .insert((owner.did().to_did_jig_string(), slug.to_string()), 0);
        serde_json::json!({
            "suite": "mls",
            "sequencer": self.server_did(),
            "mls_group_info": b64.encode(&created.group_info),
            "mls_ratchet_tree": b64.encode(&created.ratchet_tree),
        })
    }

    /// Archive `slug` as `owner` through the real admin endpoint — the
    /// v0.0.2 channel delete, a soft delete that keeps every block.
    pub async fn archive_channel(&self, owner: &Identity, slug: &str) {
        let owner = owner.as_client();
        let block =
            build_channel_archive(&owner, slug, HlcTimestamp::now_wall(owner.did().clone()));
        let path = format!("/api/v1/channels/{}/archive", encode_slug(slug));
        let (status, body) = self.post_admin(&path, &block).await;
        assert_eq!(status, StatusCode::OK, "channel-archive failed: {body}");
    }

    /// Submit any `channel-archive` block through the admin route and return
    /// whatever the server said.
    pub async fn try_archive(
        &self,
        slug: &str,
        block: &BuiltBlock,
    ) -> (StatusCode, serde_json::Value) {
        let path = format!("/api/v1/channels/{}/archive", encode_slug(slug));
        self.post_admin(&path, block).await
    }

    /// Add `member` to `slug`, the block signed by `by`. Asserts success; use
    /// [`try_add_member`](Self::try_add_member) to observe a refusal.
    pub async fn add_member(&self, by: &Identity, slug: &str, member: &Identity) {
        let (status, body) = self.try_add_member(by, slug, member).await;
        assert_eq!(status, StatusCode::OK, "member-add failed: {body}");
    }

    /// Submit a `member-add` for `member` on `slug`, signed by `by`, through
    /// the admin endpoint. Returns whatever the server said. On an encrypted
    /// channel `by` commits the add if it holds the group; a caller who does
    /// not sends the bare block, which is what a stranger can send.
    pub async fn try_add_member(
        &self,
        by: &Identity,
        slug: &str,
        member: &Identity,
    ) -> (StatusCode, serde_json::Value) {
        let block = self.member_add_block(by, slug, member);
        let path = format!("/api/v1/channels/{}/members", encode_slug(slug));
        let (status, body) = self.post_admin(&path, &block).await;
        self.settle_member_add(by, slug, member, &block, status == StatusCode::OK);
        (status, body)
    }

    /// The `member-add` `by` would send for `member`: with an MLS commit on an
    /// encrypted channel whose group `by` holds. Follow it with
    /// [`settle_member_add`](Self::settle_member_add).
    pub fn member_add_block(&self, by: &Identity, slug: &str, member: &Identity) -> BuiltBlock {
        let me = by.as_client();
        let hlc = HlcTimestamp::now_wall(me.did().clone());
        let member_did = member.did().to_did_jig_string();
        if !self.mls.holds(by, slug) {
            return build_member_add(&me, slug, &member_did, hlc);
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        let key_package = self
            .mls
            .with(member, |s| s.key_packages(1, false))
            .expect("key package")
            .pop()
            .expect("one key package");
        let c = self
            .mls
            .with(by, |s| {
                s.prepare_add(MLS_SERVER, slug, &key_package, &member_did)
            })
            .expect("prepare add");
        let mut meta = serde_json::json!({
            "channel": slug,
            "member_did": member_did,
            "mls_commit": b64.encode(&c.commit),
            "mls_epoch": c.epoch,
        });
        if let Some(w) = &c.welcome {
            meta["mls_welcome"] = b64.encode(w).into();
        }
        if let Some(i) = &c.group_info {
            meta["mls_group_info"] = b64.encode(i).into();
        }
        build_with_metadata(&me, jig_core::BlockKind::MemberAdd, hlc, meta)
    }

    /// Settle the commit in `block` after the server's answer: kept and
    /// handed to the new member if `accepted`, dropped if not.
    pub fn settle_member_add(
        &self,
        by: &Identity,
        slug: &str,
        member: &Identity,
        block: &BuiltBlock,
        accepted: bool,
    ) {
        if !self.mls.is_sealed(slug)
            || !self.mls.with(by, |s| {
                s.has_pending_commit(MLS_SERVER, slug).unwrap_or(false)
            })
        {
            return;
        }
        if accepted {
            self.mls
                .with(by, |s| s.confirm(MLS_SERVER, slug))
                .expect("confirm");
            self.mls.accepted(slug, block, Some(member));
        } else {
            self.mls
                .with(by, |s| s.abandon(MLS_SERVER, slug))
                .expect("abandon");
        }
    }

    /// A `text-render` from `who` to `slug`: sealed for the group on an
    /// encrypted channel whose group `who` holds, plaintext otherwise (all a
    /// stranger can send).
    pub fn text(&self, who: &Identity, slug: &str, body: &str) -> BuiltBlock {
        let me = who.as_client();
        let hlc = HlcTimestamp::now_wall(me.did().clone());
        if !self.mls.holds(who, slug) {
            return build_text_render(&me, slug, body, hlc);
        }
        let (msg, epoch) = self
            .mls
            .with(who, |s| s.encrypt(MLS_SERVER, slug, body))
            .expect("encrypt");
        build_sealed_text(&me, slug, &msg, epoch, hlc)
    }

    /// Post a `text-render` block to `slug` as `who` through the public
    /// submit path, asserting it was accepted.
    pub async fn post_text(&self, who: &Identity, slug: &str, body: &str) {
        let block = self.text(who, slug, body);
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
        let router = build_channel_ops_router(self.state.clone());
        let resp = router.oneshot(http).await.expect("admin router responds");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// POST a block to `/api/v1/blocks`, as `jig send` does over REST.
    pub async fn post_block(&self, block: &BuiltBlock) -> (StatusCode, serde_json::Value) {
        let http = Request::builder()
            .method("POST")
            .uri("/api/v1/blocks")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&submission(block)).unwrap()))
            .unwrap();
        self.dispatch(http).await
    }

    /// An unsigned GET through the full v0.0.2 router, arriving from `from`
    /// as a listener with connection info would deliver it.
    pub async fn get_from(&self, from: std::net::SocketAddr, path: &str) -> StatusCode {
        let mut http = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        http.extensions_mut()
            .insert(axum::extract::ConnectInfo(from));
        let router = jig_server::v0_0_2_ws::build_v0_0_2_router(self.state.clone());
        router
            .oneshot(http)
            .await
            .expect("router responds")
            .status()
    }

    /// This server's DID, as `/.well-known/jig` advertises it.
    /// The store, for rows no endpoint here writes.
    pub fn store(&self) -> &jig_pipeline::persist::SqliteStore {
        &self.state.ingest_ctx.store
    }

    /// The id of the local channel `slug`.
    pub fn channel_id(&self, slug: &str) -> String {
        self.store()
            .get_channel_by_slug_including_archived(slug)
            .expect("store answers")
            .unwrap_or_else(|| panic!("no local channel {slug}"))
            .id
    }

    /// Store a carried channel: an open channel named `slug` that another
    /// server sequences, so no endpoint here creates it. It holds `member`,
    /// one block and an MLS group with a group info, each told apart from a
    /// local channel's by its contents. Returns its id and its block.
    pub fn carry_channel(
        &self,
        slug: &str,
        member: &Identity,
    ) -> (String, jig_pipeline::persist::StoredBlock) {
        use jig_pipeline::persist::{StoredBlock, StoredChannel, StoredMembership, StoredMlsGroup};
        let id = jig_core::canonical_cid::of(format!("carried {slug}").as_bytes()).to_string();
        let store = self.store();
        let channel = StoredChannel {
            id: id.clone(),
            slug: slug.to_string(),
            visibility: "open".to_string(),
            created_at: 0,
            owner_did: member.did().to_did_jig_string(),
            suite: "none".to_string(),
            sequencer_did: Identity::new(250).did().to_did_jig_string(),
            co_owners: Vec::new(),
        };
        store.upsert_channel(&channel).expect("carried channel");
        store
            .upsert_membership(&StoredMembership {
                channel_id: id.clone(),
                member_did: member.did().to_did_jig_string(),
                role: "owner".to_string(),
                joined_at: 0,
                source_block_cid: id.clone(),
            })
            .expect("carried membership");
        let block = StoredBlock {
            cid: jig_core::canonical_cid::of(format!("carried block {slug}").as_bytes())
                .to_string(),
            channel_id: Some(id.clone()),
            block_kind: "text-render".to_string(),
            sender_did: member.did().to_did_jig_string(),
            sender_sig: Vec::new(),
            bundle_bytes: b"carried".to_vec(),
            is_synthetic: false,
            hlc_wall_ms: 1,
            hlc_logical: 0,
            hlc_origin: member.did().to_did_jig_string(),
            posted_at: 1,
            origin_server: "elsewhere".to_string(),
            federated_from: Some("elsewhere".to_string()),
        };
        store.insert_block(&block).expect("carried block");
        store
            .put_mls_group(&StoredMlsGroup {
                channel_id: id.clone(),
                group_id: b"carried".to_vec(),
                state: Vec::new(),
                epoch: 7,
                group_info: Some(b"carried group info".to_vec()),
            })
            .expect("carried group");
        (id, block)
    }

    /// POST a signed channel-op block to `path` on the channel-op routes.
    pub async fn post_channel_op(
        &self,
        path: &str,
        block: &BuiltBlock,
    ) -> (StatusCode, serde_json::Value) {
        self.post_admin(path, block).await
    }

    pub fn server_did(&self) -> String {
        self.state.server_did.to_did_jig_string()
    }

    /// Send a signed request through the full v0.0.2 router, for routes the
    /// blocks router does not carry.
    pub async fn send_full(&self, req: &SignedRequest) -> (StatusCode, serde_json::Value) {
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
        self.dispatch_full(http).await
    }

    /// An unsigned GET through the full v0.0.2 router.
    pub async fn send_unsigned_full(&self, path: &str) -> (StatusCode, serde_json::Value) {
        let http = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        self.dispatch_full(http).await
    }

    /// POST `body` as JSON through the full v0.0.2 router.
    pub async fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let http = Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        self.dispatch_full(http).await
    }

    /// POST raw `body` bytes as JSON through the full v0.0.2 router.
    pub async fn post_raw(&self, path: &str, body: Vec<u8>) -> (StatusCode, serde_json::Value) {
        let http = Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();
        self.dispatch_full(http).await
    }

    async fn dispatch_full(&self, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let router = jig_server::v0_0_2_ws::build_v0_0_2_router(self.state.clone());
        let resp = router.oneshot(req).await.expect("router responds");
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
pub fn submission(block: &BuiltBlock) -> serde_json::Value {
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
