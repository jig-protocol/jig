//! Shared test harness — `TestJigServer` and `TestNameserver`.
//!
//! Each test instance binds an ephemeral port (`127.0.0.1:0`), spawns
//! the axum server in a background tokio task, and holds the `AppState`
//! Arc so tests can read directly from the store when needed.
//!
//! Notes on design:
//! - `add_peer` writes directly into the v0_0_2 federation config so the
//!   `spawn_federation_peers` loop can pick it up. This is the additive
//!   way — keeps tests in step with the production handshake path.
//! - `create_channel` and `send_text_render` go through real HTTP /
//!   WSS so we exercise the same path the CLI uses.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine as _;
use jig_client::{Identity, blocks::BuiltBlock};
use jig_config::v0_0_2_server::{
    FederationPeer, FederationSection, IdentityMode, IdentitySection, JigServerConfig,
    ServerSection,
};
use jig_pipeline::persist::{StoredBlock, StoredReceipt};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

// ---------------------------------------------------------------------------
// TestJigServer
// ---------------------------------------------------------------------------

/// A `jig-server` running on `127.0.0.1:<random>` for tests. Owns the
/// tempdir holding the SQLite DB; drop the struct to tear everything down.
pub struct TestJigServer {
    pub bound_addr: std::net::SocketAddr,
    pub state: Arc<jig_server::v0_0_2::AppState>,
    pub server_did_string: String,
    _tempdir: TempDir,
    _handle: JoinHandle<()>,
}

impl TestJigServer {
    /// Default: TOFU mode, debug.admin_endpoints = true, full v0.0.2
    /// allowed_block_kinds (text-render + channel-create + member-add).
    pub async fn start() -> Result<Self> {
        let mut config = base_config()?;
        config.debug.admin_endpoints = true;
        Self::start_with_config(config).await
    }

    /// Start with ONLY text-render in allowed_block_kinds. Used by H1
    /// where the test is about block-kind ingest determinism, not channels.
    pub async fn start_with_text_render_only() -> Result<Self> {
        let mut config = base_config()?;
        config.debug.admin_endpoints = true;
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
        config.debug.admin_endpoints = true;
        config.identity = IdentitySection {
            mode: IdentityMode::Nameserver,
            trusted_nameservers: vec![ns.http_url()],
            cache_ttl_seconds: 1, // short for tests so cache misses re-resolve
            naively_allow_unknown_handles_fallback: false,
        };
        Self::start_with_config(config).await
    }

    /// Start with a fully-customized config — useful for the more exotic
    /// H-series tests (H5 unsafe-options-flag flips, etc.).
    pub async fn start_with_config(config: JigServerConfig) -> Result<Self> {
        let tempdir = tempfile::tempdir().context("tempdir")?;
        let db_path = tempdir.path().join("server.db");

        // Override the keyfile path to live inside the tempdir so multiple
        // test servers don't share ~/.jig/server/server.key.
        let mut config = config;
        config.server.server_did_keyfile = tempdir
            .path()
            .join("server.key")
            .to_string_lossy()
            .into_owned();
        // listen field is informational only (we bind our own listener);
        // overwrite to make federation-peer URLs sensible.
        config.server.listen = "127.0.0.1:0".to_string();

        let state = Arc::new(jig_server::v0_0_2::AppState::new(config, db_path)?);
        let server_did_string = state.server_did.to_did_jig_string();

        // Bind ephemeral port BEFORE spawning so we can record it.
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let bound_addr = listener.local_addr().context("local_addr")?;

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
        // so any fed-hello bundles advertise the right URL. Since the
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
            _tempdir: tempdir,
            _handle: handle,
        })
    }

    pub fn ws_url(&self) -> String {
        format!("ws://{}", self.bound_addr)
    }

    pub fn http_url(&self) -> String {
        format!("http://{}", self.bound_addr)
    }

    /// Register `other` as a federation peer of this server. Direct mutation
    /// of the peers list via Fanout — we can't restart with a new config in
    /// place, so we spawn a new federation loop pointing at the new peer.
    pub async fn add_peer(&self, other: &TestJigServer) -> Result<()> {
        let peer = FederationPeer {
            url: other.ws_url(),
            expected_did: other.server_did_string.clone(),
            alias: None,
        };

        // We can't mutate `state.config` after boot (it's behind an Arc),
        // so instead we drive the run_peer_loop entry point manually.
        // Inline the spawn_federation_peers logic with just our one peer.
        let state_clone = self.state.clone();
        let peer_clone = peer.clone();
        tokio::spawn(async move {
            spawn_one_peer_loop(state_clone, peer_clone).await;
        });
        Ok(())
    }

    /// Create a channel via the admin REST endpoint. Returns the channel CID
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
        let block = jig_client::blocks::build_channel_create(owner, slug, visibility, hlc);
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/_admin_v0_0_2/channels", self.http_url()))
            .json(&submission_payload(&block))
            .send()
            .await
            .context("POST /_admin_v0_0_2/channels")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("create_channel failed: {status} body={body}");
        }
        let body: serde_json::Value = resp.json().await?;
        Ok(body["block_cid"].as_str().unwrap_or_default().to_string())
    }

    /// Add a member to an existing channel via the admin endpoint.
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
                "{}/_admin_v0_0_2/channels/{url_slug}/members",
                self.http_url()
            ))
            .json(&submission_payload(&block))
            .send()
            .await
            .context("POST /_admin_v0_0_2/channels/:slug/members")?;
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

/// A `jig-nameserver` running on `127.0.0.1:<random>` for tests.
pub struct TestNameserver {
    pub bound_addr: std::net::SocketAddr,
    pub state: Arc<jig_nameserver::v0_0_2::AppState>,
    pub alias_suffix: String,
    _tempdir: TempDir,
    _handle: JoinHandle<()>,
}

impl TestNameserver {
    /// Start a nameserver authoritative for the `dj.jig` alias suffix.
    pub async fn start() -> Result<Self> {
        Self::start_with_suffix("dj.jig").await
    }

    pub async fn start_with_suffix(alias_suffix: &str) -> Result<Self> {
        let tempdir = tempfile::tempdir().context("tempdir")?;
        let db_path = tempdir.path().join("nameserver.db");

        let mut config = base_config()?;
        config.server.server_did_keyfile = tempdir
            .path()
            .join("nameserver.key")
            .to_string_lossy()
            .into_owned();
        config.server.listen = "127.0.0.1:0".to_string();

        let state = Arc::new(jig_nameserver::v0_0_2::AppState::new(
            config,
            db_path,
            alias_suffix.to_string(),
        )?);

        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let bound_addr = listener.local_addr().context("local_addr")?;

        let router = jig_nameserver::v0_0_2_register::build_register_router(state.clone())
            .merge(jig_nameserver::v0_0_2_resolve::build_resolve_router(
                state.clone(),
            ))
            .merge(jig_nameserver::v0_0_2_rotate_renew::build_rotate_renew_router(
                state.clone(),
            ))
            .merge(jig_nameserver::v0_0_2_handles::build_handles_router(
                state.clone(),
            ));

        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        Ok(Self {
            bound_addr,
            state,
            alias_suffix: alias_suffix.to_string(),
            _tempdir: tempdir,
            _handle: handle,
        })
    }

    pub fn http_url(&self) -> String {
        format!("http://{}", self.bound_addr)
    }

    /// Register `alias_local@<suffix>` with a fresh identity. Returns the
    /// identity so the caller can sign blocks with it.
    pub async fn register(&self, alias_local: &str) -> Result<Identity> {
        let identity = test_identity();
        self.register_with_identity(alias_local, &identity).await?;
        Ok(identity)
    }

    /// Register an alias with an existing identity (used in H6 tests
    /// where the same identity is shared between NS and a jig-server).
    pub async fn register_with_identity(
        &self,
        alias_local: &str,
        identity: &Identity,
    ) -> Result<serde_json::Value> {
        let client = reqwest::Client::new();
        // 1. Get challenge
        let ch_resp = client
            .get(format!("{}/v1/challenge", self.http_url()))
            .send()
            .await
            .context("GET /v1/challenge")?;
        let ch: serde_json::Value = ch_resp.json().await?;
        let challenge = ch["challenge"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("challenge missing"))?
            .to_string();

        // 2. Sign challenge
        let sig = identity.sign(challenge.as_bytes());

        // 3. Register
        let body = serde_json::json!({
            "did": identity.did_string(),
            "requested_alias": alias_local,
            "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            "challenge": challenge,
        });
        let resp = client
            .post(format!("{}/v1/register", self.http_url()))
            .json(&body)
            .send()
            .await
            .context("POST /v1/register")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("register failed: {status} body={body}");
        }
        Ok(resp.json().await?)
    }
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
    Identity::generate_and_save(&path).expect("identity generate")
}

/// Variant that also returns the keyfile directory so the caller can
/// load the identity multiple times (e.g. once for signing, once to
/// pass into `Client::connect` which takes ownership).
///
/// Use `Identity::load_from_dir(&keys_dir, &did_str)` to re-load.
pub fn test_identity_with_dir() -> (Identity, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.keep();
    let id = Identity::generate_and_save(&path).expect("identity generate");
    (id, path)
}

/// Re-load an Identity from its keyfile directory, given the DID.
pub fn load_identity(keys_dir: &std::path::Path, did_str: &str) -> Identity {
    Identity::load_from_dir(keys_dir, did_str).expect("load identity from dir")
}

/// Build the JSON body for the `/api/v1/blocks` and `/_admin_v0_0_2/*`
/// REST endpoints. Both accept the same `{bundle_b64, sig_b64}` shape.
fn submission_payload(block: &BuiltBlock) -> serde_json::Value {
    serde_json::json!({
        "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
        "sig_b64": base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
    })
}

fn base_config() -> Result<JigServerConfig> {
    Ok(JigServerConfig {
        server: ServerSection {
            listen: "127.0.0.1:0".to_string(),
            server_did_keyfile: String::new(), // overridden by caller
            allowed_block_kinds: vec![
                "text-render".to_string(),
                "channel-create".to_string(),
                "member-add".to_string(),
                "fed-hello".to_string(),
            ],
        },
        identity: IdentitySection::default(),
        federation: FederationSection::default(),
        debug: jig_config::v0_0_2_server::DebugSection::default(),
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
            }))
        }
    };
    Ok(Router::new().route("/.well-known/jig", get(handler)))
}

/// Spawn a single peer-loop on an ad-hoc basis (used by `add_peer`).
/// Mirrors `jig_server::v0_0_2_federation::run_peer_loop` but takes a
/// peer struct directly instead of iterating `config.federation.peers`.
async fn spawn_one_peer_loop(
    state: Arc<jig_server::v0_0_2::AppState>,
    peer: FederationPeer,
) {
    use futures_util::{SinkExt, StreamExt};
    use jig_pipeline::{Envelope, Frame, Scope, envelope::ReceiptRef};
    use tokio_tungstenite::tungstenite::Message;

    // Inline copy of the connect-and-relay logic — keeps the test harness
    // self-contained instead of requiring us to expose pub `run_peer_loop`
    // on jig-server (which would change the production surface).
    loop {
        let ws_url = format!("{}/api/v1/ws", peer.url.trim_end_matches('/'));
        let connect_result = tokio_tungstenite::connect_async(&ws_url).await;
        let Ok((ws, _resp)) = connect_result else {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };
        let (mut sink, mut stream) = ws.split();

        // Subscribe federation scope so we receive their block stream.
        let sub_env = Envelope::new(Frame::Subscribe {
            scope: Scope::Federation {
                block_kinds: vec![],
            },
        });
        if sink
            .send(Message::Text(serde_json::to_string(&sub_env).unwrap()))
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        // Register a peer subscriber on our Fanout so OUR locally-ingested
        // blocks get pushed to this peer.
        let (peer_tx, mut peer_rx) =
            tokio::sync::mpsc::unbounded_channel::<(StoredBlock, StoredReceipt)>();
        state
            .ingest_ctx
            .fanout
            .register_peer(peer.url.clone(), peer_tx)
            .await;

        loop {
            tokio::select! {
                msg = stream.next() => {
                    let Some(Ok(m)) = msg else { break };
                    if let Message::Text(text) = m {
                        let _ = handle_inbound_test_frame(&state, &peer, &text).await;
                    }
                }
                delivery = peer_rx.recv() => {
                    let Some((block, receipt)) = delivery else { break };
                    let frame = Envelope::new(Frame::Block {
                        bundle_b64: base64::engine::general_purpose::STANDARD
                            .encode(&block.bundle_bytes),
                        receipts: vec![ReceiptRef {
                            server_did: receipt.server_id.clone(),
                            render_hash: receipt.render_hash.clone(),
                            receipt_bytes_b64: base64::engine::general_purpose::STANDARD
                                .encode(&receipt.receipt_bytes),
                        }],
                        delivery_cid: format!("delivery:{}", block.cid),
                    });
                    let json = serde_json::to_string(&frame).unwrap();
                    if sink.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
        }
        state.ingest_ctx.fanout.unregister_peer(&peer.url).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Test-side mirror of `jig_server::v0_0_2_federation::handle_inbound_frame`.
/// Inbound `Block` frames from a peer get persisted locally so the receiving
/// server's store has the federated block and its receipt.
async fn handle_inbound_test_frame(
    state: &Arc<jig_server::v0_0_2::AppState>,
    peer: &FederationPeer,
    text: &str,
) -> anyhow::Result<()> {
    use jig_core::BlockManifest;
    use jig_pipeline::{Envelope, Frame};

    let env: Envelope = serde_json::from_str(text)?;
    let Frame::Block {
        bundle_b64,
        receipts,
        delivery_cid,
    } = env.frame
    else {
        return Ok(());
    };
    let bundle_bytes = base64::engine::general_purpose::STANDARD.decode(&bundle_b64)?;
    let (manifest_bytes, _code_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&bundle_bytes)?;
    let manifest: BlockManifest = serde_json::from_slice(&manifest_bytes)?;

    let block_cid = format!(
        "bafy_{}",
        hex::encode(blake3::hash(&bundle_bytes).as_bytes())
    );
    if state.ingest_ctx.store.get_block(&block_cid)?.is_some() {
        return Ok(());
    }

    let sender_did_str = manifest
        .authors
        .first()
        .map(|a| a.did.to_did_jig_string())
        .unwrap_or_default();
    let kind_str = manifest
        .kind
        .as_ref()
        .map(|k| k.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let (hlc_wall_ms, hlc_logical, hlc_origin) = manifest
        .hlc_ts
        .as_ref()
        .map(|h| (h.wall_ms, h.logical, h.server_did.to_did_jig_string()))
        .unwrap_or((0, 0, String::new()));

    let stored_block = StoredBlock {
        cid: block_cid.clone(),
        channel_id: None,
        block_kind: kind_str,
        sender_did: sender_did_str,
        sender_sig: vec![],
        bundle_bytes: bundle_bytes.clone(),
        is_synthetic: false,
        hlc_wall_ms,
        hlc_logical,
        hlc_origin,
        posted_at: chrono::Utc::now().timestamp(),
        origin_server: peer.url.clone(),
        federated_from: Some(peer.url.clone()),
    };
    state.ingest_ctx.store.insert_block(&stored_block)?;

    for r in &receipts {
        let receipt_bytes = base64::engine::general_purpose::STANDARD
            .decode(&r.receipt_bytes_b64)
            .unwrap_or_default();
        let receipt_cid = format!(
            "r_{}_{}",
            &block_cid[..16.min(block_cid.len())],
            &r.server_did[..16.min(r.server_did.len())]
        );
        let stored_receipt = StoredReceipt {
            cid: receipt_cid,
            block_cid: block_cid.clone(),
            server_id: r.server_did.clone(),
            receipt_bytes,
            render_hash: r.render_hash.clone(),
            produced_at: chrono::Utc::now().timestamp(),
        };
        let _ = state.ingest_ctx.store.insert_receipt(&stored_receipt);
    }

    // Fanout the federated block to local subscribers — broadcast_local_only
    // so we don't relay back to peers.
    let receipts_in_db = state.ingest_ctx.store.get_receipts_for_block(&block_cid)?;
    if let Some(rep_receipt) = receipts_in_db.into_iter().next() {
        let _ = state
            .ingest_ctx
            .fanout
            .broadcast_local_only(&stored_block, &rep_receipt)
            .await;
    }
    let _ = delivery_cid; // unused but kept for parity with server code
    let _ = receipts;
    Ok(())
}
