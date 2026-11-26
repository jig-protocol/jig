//! Shared test harness — `TestJigServer` and `TestNameserver`.
//!
//! Each test instance binds an ephemeral port (`127.0.0.1:0`), spawns
//! the axum server in a background tokio task, and holds the `AppState`
//! Arc so tests can read directly from the store when needed.
//!
//! Notes on design:
//! - `create_channel` and `send_text_render` go through real HTTP /
//!   WSS so we exercise the same path the CLI uses.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine as _;
use jig_client::{Identity, blocks::BuiltBlock};
use jig_config::v0_0_2_server::{
    FederationSection, IdentityMode, IdentitySection, JigServerConfig, ServerSection,
};
use jig_pipeline::persist::{StoredBlock, StoredReceipt};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

// ---------------------------------------------------------------------------
// TestJigServer
// ---------------------------------------------------------------------------

/// Build a signed `Frame::Subscribe`, as a real client would.
///
/// Servers require a proof of possession on subscribe by default, so a raw
/// unsigned frame is refused. Tests that are about delivery rather than about
/// authentication still need a valid one — this is the one place that knows how
/// to mint it, so the ceremony is not copied into every test.
///
/// `audience` is the DID of the server the frame is sent to
/// ([`TestJigServer::server_did_string`]).
pub fn signed_subscribe(
    identity: &Identity,
    audience: &str,
    scope: jig_pipeline::envelope::Scope,
) -> jig_pipeline::envelope::Envelope {
    use base64::Engine as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    let hlc_wall_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    // Unique per call: a server refuses a nonce it has already seen inside its
    // acceptance window, and one test may subscribe several times.
    let nonce = format!("test-{hlc_wall_ms}-{}", SEQ.fetch_add(1, Ordering::Relaxed));

    let hash = jig_core::request_auth::canonical_request_hash(
        audience,
        &identity.did_string(),
        "SUBSCRIBE",
        &scope.canonical_string(),
        b"",
        hlc_wall_ms,
        0,
        &nonce,
    );

    jig_pipeline::envelope::Envelope::new(jig_pipeline::envelope::Frame::Subscribe {
        auth: Some(jig_pipeline::envelope::SubscribeAuth {
            did: identity.did_string(),
            audience: Some(audience.to_string()),
            hlc_wall_ms,
            hlc_logical: 0,
            nonce,
            sig_b64: base64::engine::general_purpose::STANDARD
                .encode(identity.sign(hash.as_bytes()).to_bytes()),
        }),
        scope,
    })
}

/// The DID the server serving `url` signs as, from its `/.well-known/jig`:
/// the audience a request proof to it is addressed to. For helpers that hold
/// a URL and not the [`TestJigServer`]; a client takes it from a signed
/// welcome instead.
pub async fn audience_for(url: &str) -> String {
    let parsed = reqwest::Url::parse(url).expect("a URL");
    let origin = parsed.origin().ascii_serialization();
    let info: serde_json::Value = reqwest::get(format!("{origin}/.well-known/jig"))
        .await
        .expect("GET /.well-known/jig")
        .json()
        .await
        .expect("server info");
    info["server_did"].as_str().expect("server_did").to_string()
}

/// A `jig-server` running on `127.0.0.1:<random>` for tests. Owns the
/// tempdir holding the SQLite DB; drop the struct to tear everything down.
pub struct TestJigServer {
    pub bound_addr: std::net::SocketAddr,
    pub state: Arc<jig_server::v0_0_2::AppState>,
    pub server_did_string: String,
    /// Whether it runs the channel contract ([`Self::start_federated_pair`]),
    /// kept across [`Self::restart`].
    contract: bool,
    _tempdir: TempDir,
    _handle: JoinHandle<()>,
}

impl TestJigServer {
    /// Default: TOFU mode, full v0.0.2
    /// allowed_block_kinds (text-render + channel-create + member-add).
    pub async fn start() -> Result<Self> {
        Self::start_with_config(base_config()?).await
    }

    /// Start with ONLY text-render in allowed_block_kinds. Used by H1
    /// where the test is about block-kind ingest determinism, not channels.
    pub async fn start_with_text_render_only() -> Result<Self> {
        let mut config = base_config()?;
        config.server.allowed_block_kinds = vec!["text-render".to_string()];
        Self::start_with_config(config).await
    }

    /// Start with all the v0.0.2 client-facing kinds enabled.
    /// Same as [`Self::start`] but explicit at the call site for readability.
    pub async fn start_with_full_kinds() -> Result<Self> {
        Self::start().await
    }

    /// Start in nameserver mode pointed at the given NS. `alias_suffix` is
    /// the `.jig` namespace the NS is authoritative for (e.g. `"dj.jig"`).
    pub async fn start_with_nameserver(ns: &TestNameserver, _alias_suffix: &str) -> Result<Self> {
        let mut config = base_config()?;
        config.identity = IdentitySection {
            mode: IdentityMode::Nameserver,
            trusted_nameservers: vec![],
            cache_ttl_seconds: 1, // short for tests so cache misses re-resolve
            naively_allow_unknown_handles_fallback: false,
            delegations: ns.delegations(),
            // TestNameserver serves plaintext on loopback.
            dangerously_allow_plaintext_nameservers: true,
            refused_suffixes: vec![],
        };
        Self::start_with_config(config).await
    }

    /// Start with a fully-customized config — useful for the more exotic
    /// H-series tests (H5 unsafe-options-flag flips, etc.).
    pub async fn start_with_config(config: JigServerConfig) -> Result<Self> {
        let tempdir = tempfile::tempdir().context("tempdir")?;
        Self::boot(config, tempdir).await
    }

    /// Two servers, each a configured peer of the other (JEP-0005 rule 17),
    /// with the channel contract running on both as `jig-server` runs it:
    /// the manifest published, the contract's frames handled and its timers
    /// started, and each side dialing the other. `a_offers` and `b_offers`
    /// are what each does with an offer from the other: hold it for the
    /// operator, or accept it.
    ///
    /// Each server is booted once to mint its key, so that the other's
    /// config can name its DID, then again over the same tempdir on a port
    /// bound in advance, so that the other's config can name its URL. Both
    /// links are plaintext loopback.
    pub async fn start_federated_pair(
        a_offers: jig_config::v0_0_2_server::OfferPolicy,
        b_offers: jig_config::v0_0_2_server::OfferPolicy,
    ) -> Result<(Self, Self)> {
        let (dir_a, did_a) = Self::mint_key().await?;
        let (dir_b, did_b) = Self::mint_key().await?;
        let listener_a = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let listener_b = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let url = |l: &TcpListener| -> Result<String> {
            Ok(format!("ws://{}", l.local_addr().context("local_addr")?))
        };
        let peer = |url: String, did: &str, offers| jig_config::v0_0_2_server::FederationPeer {
            url,
            expected_did: did.to_string(),
            alias: None,
            publish: false,
            quota: None,
            offers,
        };
        let config_for = |peer| -> Result<JigServerConfig> {
            let mut config = base_config()?;
            // The kinds a deployed server takes, the contract's records
            // among them, which the harness's narrower list leaves out.
            config.server.allowed_block_kinds =
                JigServerConfig::default().server.allowed_block_kinds;
            config.federation.dangerously_allow_plaintext_federation = true;
            config.federation.peers = vec![peer];
            Ok(config)
        };
        let config_a = config_for(peer(url(&listener_b)?, &did_b, a_offers))?;
        let config_b = config_for(peer(url(&listener_a)?, &did_a, b_offers))?;
        let a = Self::boot_on(config_a, dir_a, listener_a, true).await?;
        let b = Self::boot_on(config_b, dir_b, listener_b, true).await?;
        anyhow::ensure!(
            a.server_did_string == did_a && b.server_did_string == did_b,
            "a server came back under another DID"
        );
        Ok((a, b))
    }

    /// A tempdir holding a fresh server key, and its server's DID.
    async fn mint_key() -> Result<(TempDir, String)> {
        let server = Self::start().await?;
        let did = server.server_did_string.clone();
        server._handle.abort();
        Ok((server._tempdir, did))
    }

    /// Whether `self` and `other` each have a live peer connection to the
    /// other.
    pub fn connected_to(&self, other: &Self) -> bool {
        self.state
            .peers
            .sender_for(&other.state.server_did)
            .is_some()
            && other
                .state
                .peers
                .sender_for(&self.state.server_did)
                .is_some()
    }

    /// Stop this server and boot a fresh one over the SAME tempdir — same
    /// `server.db` and same `server.key`. This is the restart-persistence
    /// path: the process is new, the on-disk state is not.
    ///
    /// The new instance binds a NEW ephemeral port, so callers must re-read
    /// `ws_url()` / `http_url()`; only the on-disk state is carried over.
    pub async fn restart(self) -> Result<Self> {
        let config = self.state.config.clone();
        let tempdir = self._tempdir;
        let contract = self.contract;
        self._handle.abort();
        // Let the aborted task release the old listener before we rebind.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        Self::boot_on(config, tempdir, listener, contract).await
    }

    /// Shared boot path for [`Self::start_with_config`] and [`Self::restart`].
    async fn boot(config: JigServerConfig, tempdir: TempDir) -> Result<Self> {
        // Bind ephemeral port BEFORE spawning so we can record it.
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        Self::boot_on(config, tempdir, listener, false).await
    }

    /// [`Self::boot`] on `listener`. With `contract`, the server also
    /// publishes its manifest and runs the channel contract, as
    /// `jig-server`'s main does.
    async fn boot_on(
        config: JigServerConfig,
        tempdir: TempDir,
        listener: TcpListener,
        contract: bool,
    ) -> Result<Self> {
        let db_path = tempdir.path().join("server.db");

        // Override the keyfile path to live inside the tempdir so multiple
        // test servers don't share ~/.jig/server/server.key.
        let mut config = config;
        config.server.server_did_keyfile = tempdir
            .path()
            .join("server.key")
            .to_string_lossy()
            .into_owned();
        // Sealed, the way a deployed server keeps it: a credential slot.
        config.keys.unlock = Some(jig_client::server_key::credential_for_tests(tempdir.path()));
        // listen field is informational only (we bind our own listener);
        // overwrite to make federation-peer URLs sensible.
        config.server.listen = "127.0.0.1:0".to_string();

        let state = Arc::new(jig_server::v0_0_2::AppState::new(
            config,
            db_path,
            jig_server::runtime::ExecutionConfig {
                timeout_ms: TEST_RENDER_TIMEOUT_MS,
                ..Default::default()
            },
        )?);
        let server_did_string = state.server_did.to_did_jig_string();

        let bound_addr = listener.local_addr().context("local_addr")?;
        if contract {
            // Before anything is served, as in `jig-server`'s main: every
            // welcome cites the manifest, and every offer.
            jig_server::v0_0_2_manifest_log::publish(&state)
                .await
                .context("manifest log")?;
            jig_server::v0_0_2_contract::start(&state);
        }

        // The router itself is built in jig-server::v0_0_2_ws.
        let router = jig_server::v0_0_2_ws::build_v0_0_2_router(state.clone())
            // Also mount the v0.0.1 well-known handler so H7 can hit it.
            // We use the v0.0.1 handler.rs path which already wires v0.0.2
            // metadata. Build a minimal v0.0.1 AppState that shares the
            // tempdir's DB file (but separate logical SQLiteBlockStore).
            .merge(build_legacy_routes(state.clone(), &bound_addr)?);

        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        // Update server_url in the IngestContext to match the bound port,
        // so the URL it advertises is right. Since the
        // server_url field on IngestContext is set at boot from
        // config.server.listen (which was "127.0.0.1:0"), no good fix
        // is possible without redesigning AppState — but the URL is
        // informational on the wire, not load-bearing for v0.0.2 tests.

        // Spawn federation peers AFTER binding so we know the bound URL.
        // For the default constructor there are no peers, so this is a no-op.
        jig_server::v0_0_2_federation::spawn_federation_peers(state.clone());

        // Give axum a brief moment to start accepting connections.
        tokio::time::sleep(Duration::from_millis(20)).await;

        Ok(Self {
            bound_addr,
            state,
            server_did_string,
            contract,
            _tempdir: tempdir,
            _handle: handle,
        })
    }

    /// The directory holding this server's on-disk state (`server.db` and
    /// its WAL sidecars, `server.key`). For tests that inspect what the
    /// server actually wrote.
    pub fn data_dir(&self) -> &std::path::Path {
        self._tempdir.path()
    }

    pub fn ws_url(&self) -> String {
        format!("ws://{}", self.bound_addr)
    }

    pub fn http_url(&self) -> String {
        format!("http://{}", self.bound_addr)
    }

    /// Seed a channel STRAIGHT INTO THE STORE, bypassing ingest.
    ///
    /// Use this when a channel's existence is a *precondition* of the test
    /// rather than part of what it exercises. Ingest now rejects a text-render
    /// block whose channel does not exist, so tests that only care about
    /// receipts, render-hash parity or TOFU pinning need the channel to be
    /// there — but several of them deliberately run with
    /// `allowed_block_kinds = ["text-render"]`, which makes it impossible to
    /// create one through the channel-op endpoint.
    ///
    /// Going around ingest keeps `allowed_block_kinds` meaningful in those
    /// tests instead of widening it just to satisfy a precondition. Reach for
    /// [`Self::create_channel`] whenever the test is actually about channel
    /// creation.
    pub fn seed_channel(&self, owner: &Identity, slug: &str) -> Result<String> {
        let id = jig_pipeline::ingest_record::label_cid(&format!("seeded {slug}"));
        self.state
            .ingest_ctx
            .store
            .upsert_channel(&jig_pipeline::persist::StoredChannel {
                id: id.clone(),
                slug: slug.to_string(),
                visibility: "open".to_string(),
                created_at: chrono::Utc::now().timestamp_millis(),
                owner_did: owner.did().to_did_jig_string(),
                suite: "none".to_string(),
                sequencer_did: String::new(),
                co_owners: Vec::new(),
                tiering: jig_pipeline::persist::ChannelTiering::current("open", "none"),
            })?;
        Ok(id)
    }

    /// Write a restricted, plaintext channel row, with `owner` as its owner
    /// member, the way a server before D25 created one. No server creates
    /// these any more; tests use this for the channels that still exist.
    pub fn seed_plaintext_restricted_channel(
        &self,
        owner: &Identity,
        slug: &str,
    ) -> Result<String> {
        let id = jig_pipeline::ingest_record::label_cid(&format!("seeded {slug}"));
        let store = &self.state.ingest_ctx.store;
        let now = chrono::Utc::now().timestamp_millis();
        store.upsert_channel(&jig_pipeline::persist::StoredChannel {
            id: id.clone(),
            slug: slug.to_string(),
            visibility: "restricted".to_string(),
            created_at: now,
            owner_did: owner.did().to_did_jig_string(),
            suite: "none".to_string(),
            sequencer_did: String::new(),
            co_owners: Vec::new(),
            tiering: jig_pipeline::persist::ChannelTiering::current("restricted", "none"),
        })?;
        store.upsert_membership(&jig_pipeline::persist::StoredMembership {
            channel_id: id.clone(),
            member_did: owner.did().to_did_jig_string(),
            role: "owner".to_string(),
            joined_at: now,
            source_block_cid: id.clone(),
        })?;
        Ok(id)
    }

    /// Create a channel via the channel-op REST endpoint. Returns the channel CID
    /// (the channel's `id` in the StoredChannel table).
    pub async fn create_channel(
        &self,
        owner: &Identity,
        slug: &str,
        visibility: &str,
    ) -> Result<String> {
        let hlc = jig_core::HlcTimestamp {
            wall_ms: chrono::Utc::now().timestamp_millis() as u64,
            logical: 0,
            server_did: owner.did().clone(),
        };
        let block = jig_client::blocks::build_channel_create(
            owner,
            slug,
            visibility,
            &self.server_did_string,
            hlc,
        );
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/api/v1/channels", self.http_url()))
            .json(&submission_payload(&block))
            .send()
            .await
            .context("POST /api/v1/channels")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("create_channel failed: {status} body={body}");
        }
        let body: serde_json::Value = resp.json().await?;
        Ok(body["block_cid"].as_str().unwrap_or_default().to_string())
    }

    /// Create a restricted channel the way `jig channel create` does: one MLS
    /// group holding only the owner, its epoch-0 state on the creation block.
    /// Restricted channels are always `mls` (D25).
    pub async fn create_restricted_channel(
        &self,
        owner: &Identity,
        session: &jig_client::secure::Session,
        slug: &str,
    ) -> Result<String> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let created = session.create_group(&self.http_url(), slug)?;
        let block = jig_client::blocks::build_with_metadata(
            owner,
            jig_core::BlockKind::ChannelCreate,
            jig_core::HlcTimestamp::now_wall(owner.did().clone()),
            serde_json::json!({
                "slug": slug,
                "visibility": "restricted",
                "sequencer": self.server_did_string,
                "suite": "mls",
                "mls_group_info": b64.encode(&created.group_info),
                "mls_ratchet_tree": b64.encode(&created.ratchet_tree),
            }),
        );
        self.post_channel_op("/api/v1/channels", &block).await
    }

    /// Add `member` to a restricted channel: the owner's commit adding the
    /// member's key package, with its welcome, as `jig channel add` sends it.
    pub async fn add_restricted_member(
        &self,
        owner: &Identity,
        session: &jig_client::secure::Session,
        slug: &str,
        member: &jig_client::secure::Session,
    ) -> Result<String> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let server = self.http_url();
        let key_package = member
            .key_packages(1, false)?
            .pop()
            .context("no key package")?;
        let c = session.prepare_add(&server, slug, &key_package, member.did())?;
        let mut meta = serde_json::json!({
            "channel": slug,
            "member_did": member.did(),
            "mls_commit": b64.encode(&c.commit),
            "mls_epoch": c.epoch,
        });
        if let Some(w) = &c.welcome {
            meta["mls_welcome"] = b64.encode(w).into();
        }
        if let Some(i) = &c.group_info {
            meta["mls_group_info"] = b64.encode(i).into();
        }
        let block = jig_client::blocks::build_with_metadata(
            owner,
            jig_core::BlockKind::MemberAdd,
            jig_core::HlcTimestamp::now_wall(owner.did().clone()),
            meta,
        );
        let path = format!("/api/v1/channels/{}/members", urlencode(slug));
        let cid = self.post_channel_op(&path, &block).await?;
        session.confirm(&server, slug)?;
        Ok(cid)
    }

    async fn post_channel_op(&self, path: &str, block: &BuiltBlock) -> Result<String> {
        let resp = reqwest::Client::new()
            .post(format!("{}{path}", self.http_url()))
            .json(&submission_payload(block))
            .send()
            .await
            .with_context(|| format!("POST {path}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST {path} failed: {status} body={body}");
        }
        let body: serde_json::Value = resp.json().await?;
        Ok(body["block_cid"].as_str().unwrap_or_default().to_string())
    }

    /// Add a member to an existing channel via the channel-op endpoint.
    pub async fn add_member(
        &self,
        owner: &Identity,
        slug: &str,
        member_did: &str,
    ) -> Result<String> {
        let hlc = jig_core::HlcTimestamp {
            wall_ms: chrono::Utc::now().timestamp_millis() as u64,
            logical: 0,
            server_did: owner.did().clone(),
        };
        let block = jig_client::blocks::build_member_add(owner, slug, member_did, hlc);
        let client = reqwest::Client::new();
        // URL-encode the channel slug (it contains `#`).
        let url_slug = urlencode(slug);
        let resp = client
            .post(format!(
                "{}/api/v1/channels/{url_slug}/members",
                self.http_url()
            ))
            .json(&submission_payload(&block))
            .send()
            .await
            .context("POST /api/v1/channels/:slug/members")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("add_member failed: {status} body={body}");
        }
        let body: serde_json::Value = resp.json().await?;
        Ok(body["block_cid"].as_str().unwrap_or_default().to_string())
    }

    /// Submit a pre-built block via the REST endpoint.
    pub async fn submit_block(&self, block: &BuiltBlock) -> Result<String> {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/api/v1/blocks", self.http_url()))
            // As a current client: it labels `public` channels (JEP-0014).
            .header("jig-capabilities", "tiers")
            .json(&submission_payload(block))
            .send()
            .await
            .context("POST /api/v1/blocks")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("submit_block failed: {status} body={body}");
        }
        let body: serde_json::Value = resp.json().await?;
        Ok(body["block_cid"].as_str().unwrap_or_default().to_string())
    }

    /// Build, sign, and send a text-render block. Returns the CID.
    pub async fn send_text_render(
        &self,
        sender: &Identity,
        channel_slug: &str,
        body: &str,
    ) -> Result<String> {
        let hlc = jig_core::HlcTimestamp {
            wall_ms: chrono::Utc::now().timestamp_millis() as u64,
            logical: 0,
            server_did: sender.did().clone(),
        };
        let block = jig_client::blocks::build_text_render(sender, channel_slug, body, hlc);
        self.submit_block(&block).await
    }

    /// Read receipts for a block CID directly from the store.
    pub fn receipts_for(&self, cid: &str) -> Result<Vec<StoredReceipt>> {
        Ok(self.state.ingest_ctx.store.get_receipts_for_block(cid)?)
    }

    /// Read a block by CID directly from the store. None if not present.
    pub fn block_for(&self, cid: &str) -> Result<Option<StoredBlock>> {
        Ok(self.state.ingest_ctx.store.get_block(cid)?)
    }
}

// ---------------------------------------------------------------------------
// TestNameserver
// ---------------------------------------------------------------------------

/// How much proof-of-work a [`TestNameserver`] asks for, and how many
/// strangers it admits.
pub use jig_config::v0_0_2_server::{PoolPolicy, PowPolicy};

/// A `jig-nameserver` running on `127.0.0.1:<random>` for tests.
pub struct TestNameserver {
    pub bound_addr: std::net::SocketAddr,
    pub state: Arc<jig_nameserver::v0_0_2::AppState>,
    pub alias_suffix: String,
    /// Serving its default TLS: a self-signed certificate its DID vouches
    /// for in `/.well-known/jig-ns`. Otherwise plaintext.
    pub tls: bool,
    /// Reaches this nameserver: trusts its DID-bound certificate under TLS.
    client: reqwest::Client,
    _tempdir: TempDir,
    _handle: JoinHandle<()>,
}

impl TestNameserver {
    /// An `[identity.delegations]` naming this nameserver as the only
    /// authority for its suffix, reached at its own URL.
    pub fn delegations(
        &self,
    ) -> std::collections::BTreeMap<String, jig_config::v0_0_2_server::NameDelegation> {
        std::collections::BTreeMap::from([(
            self.alias_suffix.clone(),
            jig_config::v0_0_2_server::NameDelegation {
                authorities: vec![self.state.ns_did_string()],
                nameservers: vec![self.http_url()],
            },
        )])
    }

    /// Start a nameserver authoritative for the `dj.jig` alias suffix.
    pub async fn start() -> Result<Self> {
        Self::start_with_suffix("dj.jig").await
    }

    pub async fn start_with_suffix(alias_suffix: &str) -> Result<Self> {
        Self::start_inner(
            alias_suffix,
            None,
            Self::test_pow(),
            PoolPolicy::off(),
            false,
        )
        .await
    }

    /// Start a nameserver for `alias_suffix` whose DID key has the given
    /// seed, so a test can name it as an authority before it boots.
    pub async fn start_with_key(alias_suffix: &str, seed: [u8; 32]) -> Result<Self> {
        Self::start_inner(
            alias_suffix,
            Some(seed),
            Self::test_pow(),
            PoolPolicy::off(),
            false,
        )
        .await
    }

    /// A nameserver for `alias_suffix` as `jig-nameserver serve` runs it by
    /// default: over TLS, with a self-signed certificate its DID vouches for.
    pub async fn start_tls_with_suffix(alias_suffix: &str) -> Result<Self> {
        Self::start_inner(
            alias_suffix,
            None,
            Self::test_pow(),
            PoolPolicy::off(),
            true,
        )
        .await
    }

    /// [`Self::start_with_key`] over its default TLS.
    pub async fn start_tls_with_key(alias_suffix: &str, seed: [u8; 32]) -> Result<Self> {
        Self::start_inner(
            alias_suffix,
            Some(seed),
            Self::test_pow(),
            PoolPolicy::off(),
            true,
        )
        .await
    }

    /// An HTTP client that reaches this nameserver: under TLS, it trusts the
    /// certificate the nameserver's DID vouches for and no other.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Hold this nameserver's stranger pool: while `held` it does not
    /// refill, so a test decides when a waiting registration gets through;
    /// releasing it refills it at once.
    pub fn hold_pool(&self, held: bool) {
        self.state
            .suffixes
            .get(&self.alias_suffix)
            .expect("the nameserver serves its suffix")
            .hold_pool(held);
    }

    /// The proof-of-work a test nameserver asks for unless told otherwise:
    /// on, at the recommended floor of 2^20 to register, but without the
    /// length multiplier, so a 3-letter test alias costs a tenth of a second
    /// in a debug build rather than seconds. Pass
    /// [`PowPolicy::off`] only to a test that is about something else.
    pub fn test_pow() -> PowPolicy {
        PowPolicy {
            short_name_factor: 1,
            ..PowPolicy::recommended()
        }
    }

    /// A plaintext nameserver for `alias_suffix` that asks for proof-of-work
    /// as `pow` says (JEP-0008). Its registration pool is off: tests register
    /// many names within a second, which the recommended 60 an hour would
    /// refuse.
    pub async fn start_with_pow(
        alias_suffix: &str,
        pow: jig_config::v0_0_2_server::PowPolicy,
    ) -> Result<Self> {
        Self::start_with_policies(alias_suffix, pow, PoolPolicy::off()).await
    }

    /// [`Self::start_with_pow`] over its default TLS.
    pub async fn start_tls_with_pow(
        alias_suffix: &str,
        pow: jig_config::v0_0_2_server::PowPolicy,
    ) -> Result<Self> {
        Self::start_inner(alias_suffix, None, pow, PoolPolicy::off(), true).await
    }

    /// A plaintext nameserver for `alias_suffix` with these proof-of-work and
    /// pool policies.
    pub async fn start_with_policies(
        alias_suffix: &str,
        pow: PowPolicy,
        pool: PoolPolicy,
    ) -> Result<Self> {
        Self::start_inner(alias_suffix, None, pow, pool, false).await
    }

    /// [`Self::start_with_policies`] over its default TLS.
    pub async fn start_tls_with_policies(
        alias_suffix: &str,
        pow: PowPolicy,
        pool: PoolPolicy,
    ) -> Result<Self> {
        Self::start_inner(alias_suffix, None, pow, pool, true).await
    }

    async fn start_inner(
        alias_suffix: &str,
        seed: Option<[u8; 32]>,
        pow: PowPolicy,
        pool: PoolPolicy,
        tls: bool,
    ) -> Result<Self> {
        let mut suffix = jig_config::v0_0_2_server::SuffixConfig::new(alias_suffix);
        suffix.pow = pow;
        suffix.pool = pool;
        // A single-label suffix is trusted only through clients' own config;
        // a test that serves one means it.
        suffix.single_label_authority = !alias_suffix.contains('.');
        Self::start_with_parts(suffix, seed, tls).await
    }

    /// A plaintext nameserver serving one suffix with every policy `suffix`
    /// sets: registration, allowlist, proof-of-work and pool.
    pub async fn start_with_suffix_config(
        suffix: jig_config::v0_0_2_server::SuffixConfig,
    ) -> Result<Self> {
        Self::start_with_parts(suffix, None, false).await
    }

    async fn start_with_parts(
        suffix: jig_config::v0_0_2_server::SuffixConfig,
        seed: Option<[u8; 32]>,
        tls: bool,
    ) -> Result<Self> {
        let alias_suffix = suffix.suffix.clone();
        let tempdir = tempfile::tempdir().context("tempdir")?;
        let keyfile = tempdir.path().join("nameserver.key");
        let unlock = jig_client::server_key::credential_for_tests(tempdir.path());
        if let Some(seed) = seed {
            // A known key, sealed as an operator would import one: raw at
            // 0600, then `keys seal`, which keeps its DID.
            let mut raw = std::fs::OpenOptions::new();
            raw.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut raw, 0o600);
            std::io::Write::write_all(&mut raw.open(&keyfile).context("keyfile")?, &seed)
                .context("keyfile")?;
            jig_client::server_key::seal_raw(
                &keyfile,
                std::slice::from_ref(&unlock),
                &jig_client::server_key::ServerKeyOptions::new("nameserver", "jig-nameserver"),
            )
            .context("sealing the test nameserver key")?;
        }

        let mut config = base_config()?;
        config.server.server_did_keyfile = keyfile.to_string_lossy().into_owned();
        config.keys.unlock = Some(unlock);
        config.server.listen = "127.0.0.1:0".to_string();
        config.nameserver.alias_suffixes = vec![suffix];
        // Tests enumerate registered aliases; production leaves this off.
        config.debug.list_handles = true;

        // Go through the same `build_app` the binary serves. Hand-assembling
        // the v0.0.2 routers here is what let `jig-nameserver serve` ship with
        // none of them mounted while these tests stayed green.
        let mut ns_config = jig_nameserver::config::NameServerConfig::default();
        ns_config.storage.database_path = tempdir.path().join("nameserver.db");
        ns_config.v0_0_2 = config;

        ns_config.tls.enabled = tls;
        let app = jig_nameserver::server::build_app_parts(&ns_config).context("build_app_parts")?;
        let state = app.v0_0_2_state.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let bound_addr = listener.local_addr().context("local_addr")?;

        let handle = tokio::spawn(async move {
            let _ = jig_nameserver::server::serve_app(&ns_config, app, listener).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let scheme = if tls { "https" } else { "http" };
        let client = if tls {
            let probed = jig_client::tls::probe_bound(
                &format!("{scheme}://{bound_addr}"),
                "/.well-known/jig-ns",
                &[state.ns_did_string()],
            )
            .await
            .context("probing the test nameserver's TLS")?;
            let config = probed.config.context("a TLS config")?;
            reqwest::Client::builder()
                .use_preconfigured_tls(config.as_ref().clone())
                .build()?
        } else {
            reqwest::Client::new()
        };

        Ok(Self {
            bound_addr,
            state,
            alias_suffix,
            tls,
            client,
            _tempdir: tempdir,
            _handle: handle,
        })
    }

    /// The nameserver's base URL: `https://` under TLS, else `http://`.
    pub fn http_url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}", self.bound_addr)
    }

    /// Register `alias_local@<suffix>` with a fresh identity. Returns the
    /// identity so the caller can sign blocks with it.
    pub async fn register(&self, alias_local: &str) -> Result<Identity> {
        let key = jig_core::crypto::ed25519::generate_signing_key();
        self.register_with_key(alias_local, &key).await?;
        Ok(Identity::from_signing_key(key))
    }

    /// Register an alias for `key`'s DID with an action-bound proof of
    /// control (JEP-0004 rule 10).
    pub async fn register_with_key(
        &self,
        alias_local: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<serde_json::Value> {
        let body = self.prepare_registration(alias_local, key).await?;
        let attempt = self.submit_registration(&body).await?;
        if !attempt.status.is_success() {
            anyhow::bail!("register failed: {} body={}", attempt.status, attempt.body);
        }
        Ok(attempt.body)
    }

    /// Everything `POST /v1/register` takes for `alias_local` and `key`:
    /// the challenge, the proof of control and the work its offer asks.
    /// Nothing is sent to `/v1/register`, so a test can solve many and then
    /// send them at once.
    pub async fn prepare_registration(
        &self,
        alias_local: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<serde_json::Value> {
        let client = &self.client;
        let did =
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string();
        let alias = format!("{alias_local}@{}", self.alias_suffix).to_ascii_lowercase();
        let ns_did = self.state.ns_did_string();

        // 1. A challenge for this registration, with the work it asks
        let ch: serde_json::Value = client
            .get(format!(
                "{}/v1/challenge?action=register&did={did}&name={alias}",
                self.http_url()
            ))
            .send()
            .await
            .context("GET /v1/challenge")?
            .json()
            .await?;
        let challenge = ch["challenge"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("challenge missing: {ch}"))?
            .to_string();

        // 2. Prove control for this action, alias and nameserver
        let proof = jig_core::naming::sign_proof(
            key,
            jig_core::naming::Action::Register,
            &ns_did,
            &alias,
            &challenge,
        );

        // 3. The proof-of-work the nameserver's signed offer asks for (JEP-0008),
        //    as `jig init --request-alias` solves it
        let pow = match ch["pow_offer"].as_str() {
            None => None,
            Some(offer) => {
                let offer = jig_client::pow::verify_offer(
                    offer,
                    &ns_did,
                    &challenge,
                    jig_core::pow::Action::NsRegister,
                    &alias,
                    &did,
                )?;
                match std::num::NonZeroU64::new(u64::from(offer.effort)) {
                    None => None,
                    Some(effort) => {
                        let binding = jig_core::naming::proof_hash(
                            jig_core::naming::Action::Register,
                            &ns_did,
                            &alias,
                            &challenge,
                        );
                        let puzzle = jig_client::pow::Puzzle::new(
                            &ns_did,
                            &did,
                            jig_core::pow::Action::NsRegister,
                            binding,
                        );
                        Some(jig_client::pow::solve(puzzle, effort, None, |_| {}).await?)
                    }
                }
            }
        };

        Ok(serde_json::json!({
            "did": did,
            "requested_alias": alias_local,
            "proof_of_control": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(proof),
            "challenge": challenge,
            "pow": pow,
        }))
    }

    /// Send a body from [`Self::prepare_registration`] to `/v1/register`
    /// and return the answer, whatever its status.
    pub async fn submit_registration(&self, body: &serde_json::Value) -> Result<RegisterAttempt> {
        let resp = self
            .client
            .post(format!("{}/v1/register", self.http_url()))
            .json(body)
            .send()
            .await
            .context("POST /v1/register")?;
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let text = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
        Ok(RegisterAttempt {
            status,
            retry_after,
            body,
        })
    }
}

/// What `POST /v1/register` answered.
#[derive(Debug)]
pub struct RegisterAttempt {
    pub status: reqwest::StatusCode,
    /// The `Retry-After` header, in seconds.
    pub retry_after: Option<u64>,
    pub body: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Module-level helpers
// ---------------------------------------------------------------------------

/// Convenience: generate a fresh identity in a tempdir. The tempdir leaks
/// (intentionally — tests are short-lived and tempfiles cleanup at OS exit).
pub fn test_identity() -> Identity {
    let dir = tempfile::tempdir().expect("tempdir");
    // Use `keep` so the file lives long enough for the test; we don't
    // explicitly delete because tests are short-lived.
    let path = dir.keep();
    Identity::generate_for_tests(&path)
}

/// Variant that also returns the keyfile directory so the caller can
/// load the identity multiple times (e.g. once for signing, once to
/// pass into `Client::connect` which takes ownership).
///
/// Use `Identity::load_for_tests(&keys_dir, &did_str)` to re-load.
pub fn test_identity_with_dir() -> (Identity, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.keep();
    let id = Identity::generate_for_tests(&path);
    (id, path)
}

/// Re-load an Identity from its keyfile directory, given the DID.
pub fn load_identity(keys_dir: &std::path::Path, did_str: &str) -> Identity {
    Identity::load_for_tests(keys_dir, did_str)
}

/// Build the JSON body for the `/api/v1/blocks` and `/api/v1/channels*`
/// REST endpoints. Both accept the same `{bundle_b64, sig_b64}` shape.
fn submission_payload(block: &BuiltBlock) -> serde_json::Value {
    serde_json::json!({
        "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
        "sig_b64": base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
    })
}

/// The wall-clock deadline for each render on a test server, in ms. Fuel
/// bounds what a render may cost; the deadline is a backstop against a slow
/// or loaded machine, and the default (250 ms) is shorter than a render can
/// wait for a CPU on a CI runner busy with the whole test suite. A render
/// that ran out of time there failed its send with `RENDER_FAILED
/// deadline-exceeded`, and the test with it.
const TEST_RENDER_TIMEOUT_MS: u64 = 10_000;

fn base_config() -> Result<JigServerConfig> {
    Ok(JigServerConfig {
        server: ServerSection {
            listen: "127.0.0.1:0".to_string(),
            server_did_keyfile: String::new(), // overridden by caller
            allowed_block_kinds: vec![
                "text-render".to_string(),
                "channel-create".to_string(),
                "member-add".to_string(),
                "member-remove".to_string(),
                "channel-promote".to_string(),
                "role-assign".to_string(),
                "role-unassign".to_string(),
                "fed-hello".to_string(),
            ],
            ..ServerSection::default()
        },
        identity: IdentitySection::default(),
        federation: FederationSection::default(),
        debug: jig_config::v0_0_2_server::DebugSection::default(),
        bridges: jig_config::v0_0_2_server::BridgesSection::default(),
        // Spread the remainder so adding a section to JigServerConfig doesn't
        // break every integration test that only cares about the fields above.
        ..Default::default()
    })
}

/// Minimal URL-encode for `#` (channel slugs in URLs).
fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for ch in input.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(ch),
            _ => {
                for b in ch.to_string().as_bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
        }
    }
    out
}

/// Build a minimal v0.0.1-style legacy router that exposes the
/// `/.well-known/jig` endpoint with v0.0.2 metadata. Used so H7 can hit
/// the well-known endpoint via reqwest without spinning up the full
/// v0.0.1 handler tree.
fn build_legacy_routes(
    state: Arc<jig_server::v0_0_2::AppState>,
    bound_addr: &std::net::SocketAddr,
) -> Result<axum::Router> {
    use axum::{Json, Router, routing::get};

    let state_for_handler = state.clone();
    let bound_str = bound_addr.to_string();
    let handler = move || {
        let state = state_for_handler.clone();
        let bound = bound_str.clone();
        async move {
            // The admission work this server asks of a new DID, as
            // `jig_server::handler::server_info` advertises it.
            let pow_bits = state.auth.pow_bits();
            let admission_pow = pow_bits.map(|bits| {
                serde_json::json!({
                    "alg": jig_core::pow::Alg::Blake3,
                    "effort": jig_core::admission_pow::effort_for_bits(bits).get(),
                    "salt_id": jig_core::pow::EMPTY_SALT_ID,
                })
            });
            let peers: Vec<serde_json::Value> = state
                .config
                .federation
                .peers
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "url": p.url,
                        "alias": p.alias,
                    })
                })
                .collect();
            Json(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "host_id": "integration-test",
                "endpoints": { "http": format!("http://{}", bound) },
                "server_did": state.server_did.to_did_jig_string(),
                "unsafe_options_active": state.config.unsafe_options_active(),
                "allowed_block_kinds": state.config.server.allowed_block_kinds,
                "peers": peers,
                // The v0.0.2 router above pages history forward, as
                // `jig_server::handler::server_info` advertises.
                "history_after": true,
                "admission_pow_bits": pow_bits,
                "admission_pow": admission_pow,
            }))
        }
    };
    Ok(Router::new().route("/.well-known/jig", get(handler)))
}
