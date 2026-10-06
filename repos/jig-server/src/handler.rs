//! HTTP API for ingesting and retrieving Jig blocks.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use cid::Cid;
use jig_core::{Artifact, BlockBundle, BlockManifest};
use serde::{Deserialize, Serialize};

use crate::{
    config::ServerConfig,
    runtime::BlockRuntime,
    storage::{SqliteBlockStore, StoredBlock, StoredReceipt, StoredResource, encode_resource_data},
};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<SqliteBlockStore>,
    pub runtime: Arc<BlockRuntime>,
    pub config: ServerConfig,
    /// v0.0.2 hello-world pipeline state (Phase D wiring). `None` when the
    /// v0.0.2 module isn't constructed (e.g., in some unit tests). When
    /// `Some(...)`, the well-known handler emits server_did +
    /// unsafe_options_active + allowed_block_kinds + peers fields from this
    /// state so federated peers can detect misconfigured neighbors (§6.6).
    pub v0_0_2: Option<Arc<crate::v0_0_2::AppState>>,
}

pub fn build_router(state: AppState) -> Router {
    // The v0.0.1 REST surface takes an attacker-chosen author DID with no
    // signature anywhere in the request, executes the supplied Wasm, and signs
    // a receipt attesting to it. It bypasses the v0.0.2 signature and
    // allowed_block_kinds gates entirely, so it is off unless an operator
    // opts in. `/.well-known/jig` stays mounted either way — peers need it to
    // detect a misconfigured neighbour.
    let legacy_enabled = state.config.dangerously_enable_v0_0_1_rest;

    let mut router = Router::new()
        .route("/.well-known/jig", get(server_info))
        // Deliberately OUTSIDE the v0.0.1 gate: systemd and uptime checks must
        // be able to tell "up" from "crash-looping" on a default deployment,
        // and a scrape target that disappears when the operator locks the
        // server down is not a scrape target.
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics));

    if legacy_enabled {
        router = router
            .route("/blocks", get(list_blocks))
            .route("/blocks", post(ingest_block))
            .route("/blocks/:cid", get(get_block))
            .route("/receipts/:cid", get(get_receipt));
    }

    router.with_state(state).layer(http_trace_layer())
}

/// Request/response tracing for the HTTP surface.
///
/// Levels are pinned to INFO because tower-http defaults span AND events to
/// DEBUG, and `RUST_LOG=info` is what operators actually run — at the default
/// levels a whole session of traffic produces no log lines at all. The span
/// level matters as much as the events': it carries the method and URI, so a
/// DEBUG span under an INFO filter yields "started processing request" with no
/// indication of what was requested.
///
/// Public so `v0_0_2_ws::build_v0_0_2_router` can apply the same layer: axum's
/// `Router::layer` only wraps routes already added, and `server.rs` merges the
/// two routers after each is built.
pub fn http_trace_layer() -> tower_http::trace::TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
> {
    use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
    TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(tracing::Level::INFO))
        .on_request(DefaultOnRequest::new().level(tracing::Level::INFO))
        .on_response(DefaultOnResponse::new().level(tracing::Level::INFO))
}

/// Liveness probe. Deliberately trivial: it answers "this process is serving
/// HTTP", nothing more. It does NOT touch the block store, so it stays honest
/// under load and cannot itself become the thing that fails.
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

/// Prometheus text exposition of the v0.0.2 WebSocket counters.
///
/// The numbers are hand-rolled `AtomicU64`s living in
/// [`crate::v0_0_2_ws::metrics`] — see that module for what is and is not
/// counted (federation and bridge ingest are NOT).
async fn metrics() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        crate::v0_0_2_ws::metrics::render_prometheus(),
    )
}

#[derive(Serialize)]
struct ServerInfoResponse {
    version: String,
    host_id: String,
    endpoints: ServerEndpoints,
    /// v0.0.2: server's DID for federation handshake verification (§6.6).
    /// Absent when v0.0.2 module is not active — v0.0.1 consumers see no schema drift.
    #[serde(skip_serializing_if = "Option::is_none")]
    server_did: Option<String>,
    /// v0.0.2: active antipattern flags so peers can refuse federation with
    /// misconfigured neighbors. Always includes `naively_unbounded_clock_skew`
    /// in v0.0.2. Absent (not serialized) when v0.0.2 module is not active.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unsafe_options_active: Vec<String>,
    /// v0.0.2: block kinds this server accepts on ingest. Absent when v0.0.2
    /// module is not active.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_block_kinds: Vec<String>,
    /// v0.0.2: federated peers configured in TOML. Absent when v0.0.2 module
    /// is not active or when no peers are configured.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    peers: Vec<PeerInfo>,
    /// v0.0.3: bridges currently permitted to load (per `[bridges]` policy).
    /// Empty when no bridges are allowlisted or all are disabled. Absent
    /// (not serialized) for v0.0.2 consumers thanks to skip_serializing_if.
    /// Federated peers can observe what's bridged on this server before
    /// deciding to peer with it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bridges: Vec<String>,
}

#[derive(Serialize, Clone)]
pub struct PeerInfo {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

#[derive(Serialize)]
struct ServerEndpoints {
    http: String,
}

/// The origin a federated peer should dial, as advertised at
/// `/.well-known/jig`.
///
/// `public_url` wins when set. Otherwise this derives
/// `{scheme}://{bind_address}:{port}`, taking the scheme from `[tls] enabled` —
/// the scheme used to be hardcoded `http://`, so a TLS deployment advertised an
/// origin no peer could use.
///
/// The derived form is still only correct for plaintext deployments. Under TLS,
/// `bind_address` is typically an IP while the certificate is issued for a
/// hostname, so a peer following it hits a certificate-name mismatch. That is
/// why `public_url` exists, and why the operator docs tell you to set it
/// whenever you enable TLS.
fn advertised_origin(config: &ServerConfig) -> String {
    if let Some(url) = config.public_url.as_deref() {
        let trimmed = url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let scheme = if config.tls.enabled { "https" } else { "http" };
    format!("{scheme}://{}:{}", config.bind_address, config.port)
}

async fn server_info(State(state): State<AppState>) -> Result<Json<ServerInfoResponse>, ApiError> {
    let (server_did, unsafe_options_active, allowed_block_kinds, peers, bridges) =
        if let Some(v002) = &state.v0_0_2 {
            let peers = v002
                .config
                .federation
                .peers
                .iter()
                .map(|p| PeerInfo {
                    url: p.url.clone(),
                    alias: p.alias.clone(),
                })
                .collect();
            (
                Some(v002.server_did.to_did_jig_string()),
                v002.config.unsafe_options_active(),
                v002.config.server.allowed_block_kinds.clone(),
                peers,
                v002.bridges.permitted_names().to_vec(),
            )
        } else {
            (None, vec![], vec![], vec![], vec![])
        };

    Ok(Json(ServerInfoResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        host_id: state.config.host_id.clone(),
        endpoints: ServerEndpoints {
            http: advertised_origin(&state.config),
        },
        server_did,
        unsafe_options_active,
        allowed_block_kinds,
        peers,
        bridges,
    }))
}

#[derive(Debug, Deserialize)]
struct IngestBlockRequest {
    manifest: serde_json::Value,
    #[serde(default)]
    code_b64: Option<String>,
    #[serde(default)]
    resources: Vec<ResourceUpload>,
}

#[derive(Debug, Deserialize)]
struct ResourceUpload {
    name: String,
    mime: String,
    data_b64: String,
}

#[derive(Serialize)]
struct IngestBlockResponse {
    block_id: String,
    receipt: serde_json::Value,
}

async fn ingest_block(
    State(state): State<AppState>,
    Json(req): Json<IngestBlockRequest>,
) -> Result<Json<IngestBlockResponse>, ApiError> {
    let manifest: BlockManifest = serde_json::from_value(req.manifest.clone())
        .map_err(|e| ApiError::bad_request(format!("invalid manifest: {e}")))?;
    let manifest_bytes = manifest
        .to_canonical_bytes()
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let code_bytes = if let Some(code_b64) = req.code_b64 {
        general_purpose::STANDARD
            .decode(code_b64)
            .map_err(|e| ApiError::bad_request(format!("invalid code base64: {e}")))?
    } else {
        Vec::new()
    };

    let mut resource_buffers = Vec::new();
    for upload in req.resources {
        let data = general_purpose::STANDARD
            .decode(upload.data_b64)
            .map_err(|e| ApiError::bad_request(format!("invalid resource base64: {e}")))?;
        resource_buffers.push(ResourceBuffer {
            name: upload.name,
            mime: upload.mime,
            data,
        });
    }

    let artifacts: Vec<Artifact<'_>> = resource_buffers
        .iter()
        .map(|buf| Artifact {
            label: buf.name.as_str(),
            bytes: buf.data.as_slice(),
        })
        .collect();

    let bundle = BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: artifacts,
    };

    let block_cid = bundle
        .block_cid()
        .map_err(|e| ApiError::internal_error(format!("failed to compute block CID: {e}")))?;

    let receipt = state
        .runtime
        .execute(&block_cid, &manifest, &bundle)
        .map_err(|e| ApiError::internal_error(format!("block execution failed: {e}")))?;

    let created_at = Utc::now();
    let stored_resources = resource_buffers
        .into_iter()
        .map(|buf| StoredResource {
            name: buf.name,
            mime: buf.mime,
            data: buf.data,
        })
        .collect();

    let stored_block = StoredBlock {
        cid: block_cid,
        manifest: manifest.clone(),
        code: code_bytes,
        resources: stored_resources,
        created_at,
    };
    state
        .store
        .store_block(&stored_block)
        .map_err(ApiError::from_error)?;

    let stored_receipt = StoredReceipt {
        cid: block_cid,
        receipt: receipt.clone(),
        created_at: Utc::now(),
    };
    state
        .store
        .store_receipt(&stored_receipt)
        .map_err(ApiError::from_error)?;

    Ok(Json(IngestBlockResponse {
        block_id: block_cid.to_string(),
        receipt: serde_json::to_value(receipt)
            .map_err(|e| ApiError::internal_error(format!("failed to encode receipt: {e}")))?,
    }))
}

#[derive(Debug, Deserialize)]
struct ListBlocksQuery {
    limit: Option<usize>,
}

#[derive(Serialize)]
struct BlockSummaryResponse {
    block_id: String,
    manifest: serde_json::Value,
    created_at: String,
}

async fn list_blocks(
    State(state): State<AppState>,
    Query(query): Query<ListBlocksQuery>,
) -> Result<Json<Vec<BlockSummaryResponse>>, ApiError> {
    let limit = query.limit.unwrap_or(50).min(200);
    let summaries = state
        .store
        .list_blocks(limit)
        .map_err(ApiError::from_error)?;

    let response = summaries
        .into_iter()
        .map(|summary| BlockSummaryResponse {
            block_id: summary.cid.to_string(),
            manifest: serde_json::to_value(summary.manifest)
                .unwrap_or_else(|_| serde_json::json!({})),
            created_at: summary.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(response))
}

#[derive(Serialize)]
struct BlockResponse {
    block_id: String,
    manifest: serde_json::Value,
    code_b64: Option<String>,
    resources: Vec<BlockResourceResponse>,
    created_at: String,
}

#[derive(Serialize)]
struct BlockResourceResponse {
    name: String,
    mime: String,
    data_b64: String,
}

async fn get_block(
    State(state): State<AppState>,
    Path(cid_str): Path<String>,
) -> Result<Json<BlockResponse>, ApiError> {
    let cid: Cid = cid_str
        .parse()
        .map_err(|e| ApiError::bad_request(format!("invalid CID: {e}")))?;

    let stored = state.store.get_block(&cid).map_err(ApiError::from_error)?;

    let Some(block) = stored else {
        return Err(ApiError::not_found("block not found"));
    };

    Ok(Json(block_to_response(block)))
}

#[derive(Serialize)]
struct ReceiptResponse {
    block_id: String,
    receipt: serde_json::Value,
    created_at: String,
}

async fn get_receipt(
    State(state): State<AppState>,
    Path(cid_str): Path<String>,
) -> Result<Json<ReceiptResponse>, ApiError> {
    let cid: Cid = cid_str
        .parse()
        .map_err(|e| ApiError::bad_request(format!("invalid CID: {e}")))?;

    let stored = state
        .store
        .get_receipt(&cid)
        .map_err(ApiError::from_error)?;

    let Some(receipt) = stored else {
        return Err(ApiError::not_found("receipt not found"));
    };

    Ok(Json(ReceiptResponse {
        block_id: receipt.cid.to_string(),
        receipt: serde_json::to_value(receipt.receipt).unwrap_or_else(|_| serde_json::json!({})),
        created_at: receipt.created_at.to_rfc3339(),
    }))
}

struct ResourceBuffer {
    name: String,
    mime: String,
    data: Vec<u8>,
}

fn block_to_response(block: StoredBlock) -> BlockResponse {
    BlockResponse {
        block_id: block.cid.to_string(),
        manifest: serde_json::to_value(block.manifest).unwrap_or_else(|_| serde_json::json!({})),
        code_b64: if block.code.is_empty() {
            None
        } else {
            Some(encode_resource_data(&block.code))
        },
        resources: block
            .resources
            .into_iter()
            .map(|res| BlockResourceResponse {
                name: res.name,
                mime: res.mime,
                data_b64: encode_resource_data(&res.data),
            })
            .collect(),
        created_at: block.created_at.to_rfc3339(),
    }
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }

    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }

    fn internal_error(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    fn from_error<E: std::fmt::Display>(err: E) -> Self {
        Self::internal_error(err.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.message });
        (self.status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::tempdir;

    /// `/.well-known/jig` is what a federated peer reads to learn how to reach
    /// us. Advertising the wrong scheme, or an address the TLS cert does not
    /// cover, makes the peer fail with a confusing error rather than a clear
    /// one — so the advertised origin is pinned by tests.
    fn advertised_http(cfg: ServerConfig) -> String {
        advertised_origin(&cfg)
    }

    #[test]
    fn advertised_origin_is_http_when_tls_is_off() {
        let cfg = ServerConfig {
            bind_address: "100.64.0.10".into(),
            port: 7117,
            ..Default::default()
        };
        assert_eq!(advertised_http(cfg), "http://100.64.0.10:7117");
    }

    #[test]
    fn advertised_origin_is_https_when_tls_is_on() {
        let mut cfg = ServerConfig {
            bind_address: "100.64.0.10".into(),
            port: 7117,
            ..Default::default()
        };
        cfg.tls.enabled = true;
        assert_eq!(advertised_http(cfg), "https://100.64.0.10:7117");
    }

    #[test]
    fn public_url_overrides_the_derived_origin() {
        // The bind address is an IP, but a TLS cert is issued for a hostname.
        // Peers must be told the name the cert actually covers, or they hit a
        // certificate-name mismatch.
        let mut cfg = ServerConfig {
            bind_address: "100.64.0.10".into(),
            port: 7117,
            ..Default::default()
        };
        cfg.tls.enabled = true;
        cfg.public_url = Some("https://jig-vps.example.ts.net:7117".into());
        assert_eq!(advertised_http(cfg), "https://jig-vps.example.ts.net:7117");
    }

    #[test]
    fn public_url_trailing_slash_is_trimmed() {
        let cfg = ServerConfig {
            public_url: Some("https://jig.example:7117/".into()),
            ..Default::default()
        };
        assert_eq!(advertised_http(cfg), "https://jig.example:7117");
    }

    /// The v0.0.1 REST surface executes caller-supplied Wasm with no signature
    /// check at all. Default-off is the security property; these two tests are
    /// what keep it from silently regressing to always-on.
    async fn router_status(
        enable_legacy: bool,
        method: &str,
        path: &str,
    ) -> axum::http::StatusCode {
        use tower::ServiceExt;
        let dir = tempdir().unwrap();
        let config = ServerConfig {
            database_path: dir.path().join("gate.db"),
            dangerously_enable_v0_0_1_rest: enable_legacy,
            ..Default::default()
        };
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let app = build_router(AppState {
            store,
            runtime,
            config,
            v0_0_2: None,
        });
        let req = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    /// Full response (status, content-type, body) for a GET against a router
    /// built with the v0.0.1 gate in the given position.
    async fn router_get(enable_legacy: bool, path: &str) -> (StatusCode, String, String) {
        use tower::ServiceExt;
        let dir = tempdir().unwrap();
        let config = ServerConfig {
            database_path: dir.path().join("probe.db"),
            dangerously_enable_v0_0_1_rest: enable_legacy,
            ..Default::default()
        };
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let app = build_router(AppState {
            store,
            runtime,
            config,
            v0_0_2: None,
        });
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, content_type, String::from_utf8_lossy(&bytes).into())
    }

    /// systemd and uptime checks need to tell "up" from "crash-looping" on a
    /// DEFAULT deployment, so /healthz must not sit behind the v0.0.1 gate.
    #[tokio::test]
    async fn healthz_is_200_outside_the_v0_0_1_gate() {
        for legacy in [false, true] {
            let (status, _ct, body) = router_get(legacy, "/healthz").await;
            assert_eq!(
                status,
                StatusCode::OK,
                "/healthz must be 200 with dangerously_enable_v0_0_1_rest={legacy}"
            );
            assert!(!body.is_empty(), "/healthz must return a body");
        }
    }

    #[tokio::test]
    async fn metrics_exposes_prometheus_text_outside_the_v0_0_1_gate() {
        for legacy in [false, true] {
            let (status, content_type, body) = router_get(legacy, "/metrics").await;
            assert_eq!(
                status,
                StatusCode::OK,
                "/metrics must be 200 with dangerously_enable_v0_0_1_rest={legacy}"
            );
            assert!(
                content_type.starts_with("text/plain"),
                "Prometheus scrapes need text/plain, got {content_type:?}"
            );
            for metric in [
                "jig_ws_blocks_ingested_total",
                "jig_ws_subscribers_active",
                "jig_ws_channel_messages_total",
            ] {
                assert!(
                    body.contains(&format!("# TYPE {metric} ")),
                    "missing TYPE line for {metric}; body was:\n{body}"
                );
            }
        }
    }

    #[tokio::test]
    async fn v0_0_1_rest_routes_are_absent_by_default() {
        for (m, p) in [
            ("GET", "/blocks"),
            ("POST", "/blocks"),
            ("GET", "/blocks/bafyfake"),
            ("GET", "/receipts/bafyfake"),
        ] {
            assert_eq!(
                router_status(false, m, p).await,
                axum::http::StatusCode::NOT_FOUND,
                "{m} {p} must not be routable when the opt-in flag is false"
            );
        }
        // The discovery endpoint is deliberately unaffected by the gate.
        assert_ne!(
            router_status(false, "GET", "/.well-known/jig").await,
            axum::http::StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn v0_0_1_rest_routes_mount_when_operator_opts_in() {
        for (m, p) in [("GET", "/blocks"), ("GET", "/blocks/bafyfake")] {
            assert_ne!(
                router_status(true, m, p).await,
                axum::http::StatusCode::NOT_FOUND,
                "{m} {p} must be routable when the operator opts in"
            );
        }
    }

    #[tokio::test]
    async fn list_blocks_clamps_limit_to_200() {
        use blake3::hash;
        use jig_core::manifest::{Author as MAuthor, RenderDescriptor};
        let dir = tempdir().unwrap();
        let config = ServerConfig {
            database_path: dir.path().join("test.db"),
            ..Default::default()
        };
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store: store.clone(),
            runtime,
            config: config.clone(),
            v0_0_2: None,
        };

        let code_bytes: Vec<u8> = vec![0u8];
        for i in 0..205u64 {
            let module_hash = hash(&code_bytes).to_hex().to_string();
            let manifest = BlockManifest::builder()
                .version(semver::Version::new(1, 0, i))
                .author(MAuthor {
                    did: format!("did:jig:test-{i}").into(),
                    ..Default::default()
                })
                .render(RenderDescriptor {
                    entry: "index.html".into(),
                    expected_hash: module_hash.clone(),
                    output_type: "application/wasm".into(),
                })
                .build()
                .unwrap();
            let manifest_bytes = manifest.to_canonical_bytes().unwrap();
            let bundle = BlockBundle {
                manifest_bytes: &manifest_bytes,
                code_bytes: &code_bytes,
                resources: vec![],
            };
            let cid = bundle.block_cid().unwrap();
            store
                .store_block(&StoredBlock {
                    cid,
                    manifest,
                    code: code_bytes.clone(),
                    resources: vec![],
                    created_at: Utc::now(),
                })
                .unwrap();
        }

        let res = list_blocks(State(state), Query(ListBlocksQuery { limit: Some(999) }))
            .await
            .unwrap();
        assert_eq!(res.0.len(), 200);
    }

    #[tokio::test]
    async fn server_info_returns_basic_metadata() {
        let dir = tempdir().unwrap();
        let config = ServerConfig {
            database_path: dir.path().join("test.db"),
            bind_address: "127.0.0.1".into(),
            port: 7117,
            ..Default::default()
        };
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store,
            runtime,
            config: config.clone(),
            v0_0_2: None,
        };

        let res = server_info(State(state)).await.unwrap();
        let body = res.0;
        assert_eq!(body.host_id, config.host_id);
        assert!(body.endpoints.http.contains(&config.bind_address));
        assert!(!body.version.is_empty());
        // v0_0_2 is None — new fields must be absent from response (skip_serializing_if)
        assert!(body.server_did.is_none());
        assert!(body.unsafe_options_active.is_empty());
        assert!(body.allowed_block_kinds.is_empty());
        assert!(body.peers.is_empty());
    }

    #[tokio::test]
    async fn server_info_includes_v0_0_2_fields_when_v0_0_2_state_present() {
        let dir = tempdir().unwrap();
        let config = ServerConfig {
            database_path: dir.path().join("test.db"),
            bind_address: "127.0.0.1".into(),
            port: 7117,
            ..Default::default()
        };
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());

        let v002 = Arc::new(crate::v0_0_2::AppState::for_test().unwrap());
        let v002_did = v002.server_did.to_did_jig_string();

        let state = AppState {
            store,
            runtime,
            config: config.clone(),
            v0_0_2: Some(v002),
        };

        let res = server_info(State(state)).await.unwrap();
        let body = res.0;

        // server_did must be present and match the v0.0.2 state's DID
        assert_eq!(body.server_did.as_deref(), Some(v002_did.as_str()));
        // naively_unbounded_clock_skew is always present in v0.0.2
        assert!(
            body.unsafe_options_active
                .contains(&"naively_unbounded_clock_skew".to_string()),
            "expected naively_unbounded_clock_skew in unsafe_options_active"
        );
        // default config includes "text-render" in allowed_block_kinds
        assert!(
            body.allowed_block_kinds
                .contains(&"text-render".to_string()),
            "expected text-render in allowed_block_kinds"
        );
        // default config has no federation peers configured
        assert!(body.peers.is_empty());
        // default config has no bridges configured (deny-by-default)
        assert!(body.bridges.is_empty());
    }

    #[tokio::test]
    async fn server_info_advertises_permitted_bridges() {
        use jig_config::v0_0_2_server::JigServerConfig;

        let dir = tempdir().unwrap();
        let config = ServerConfig {
            database_path: dir.path().join("test.db"),
            bind_address: "127.0.0.1".into(),
            port: 7117,
            ..Default::default()
        };
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());

        // Build a v0.0.2 AppState with a bridge policy that permits one bridge.
        let mut v002 = crate::v0_0_2::AppState::for_test().unwrap();
        let toml_cfg = r##"
            [bridges]
            allow_list = ["email"]

            [bridges.per_bridge.email]
            enabled = true

            [bridges.per_bridge.slack]
            enabled = false
        "##;
        v002.config = toml::from_str::<JigServerConfig>(toml_cfg).unwrap();
        v002.bridges = Arc::new(crate::v0_0_2_bridges::BridgeRegistry::new(&v002.config));
        let v002 = Arc::new(v002);

        let state = AppState {
            store,
            runtime,
            config: config.clone(),
            v0_0_2: Some(v002),
        };

        let res = server_info(State(state)).await.unwrap();
        let body = res.0;
        // Only "email" should appear; slack is disabled (kill-switch).
        assert_eq!(body.bridges, vec!["email".to_string()]);
    }

    #[tokio::test]
    async fn get_block_and_receipt_not_found_return_404() {
        let dir = tempdir().unwrap();
        let config = ServerConfig {
            database_path: dir.path().join("test.db"),
            ..Default::default()
        };
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store,
            runtime,
            config: config.clone(),
            v0_0_2: None,
        };

        let e = get_block(State(state.clone()), Path("not-a-cid".to_string()))
            .await
            .err()
            .unwrap();
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let cid: Cid = "bafkqaaa".parse().unwrap();
        let e2 = get_receipt(State(state), Path(cid.to_string()))
            .await
            .err()
            .unwrap();
        let resp2 = e2.into_response();
        assert_eq!(resp2.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn ingest_block_rejects_invalid_manifest_and_base64() {
        let dir = tempdir().unwrap();
        let config = ServerConfig {
            database_path: dir.path().join("test.db"),
            ..Default::default()
        };
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store,
            runtime,
            config: config.clone(),
            v0_0_2: None,
        };

        let bad_manifest = serde_json::json!({ "not": "a manifest" });
        let req = IngestBlockRequest {
            manifest: bad_manifest,
            code_b64: None,
            resources: vec![],
        };
        let err = ingest_block(State(state.clone()), Json(req))
            .await
            .err()
            .unwrap();
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);

        use blake3::hash;
        use jig_core::manifest::{Author as MAuthor, RenderDescriptor};
        let code_bytes: Vec<u8> = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
            0x03, 0x02, 0x01, 0x00, 0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00,
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
        ];
        let module_hash = hash(&code_bytes).to_hex().to_string();
        let manifest = BlockManifest::builder()
            .version(semver::Version::new(1, 0, 0))
            .author(MAuthor {
                did: "did:jig:test".into(),
                ..Default::default()
            })
            .render(RenderDescriptor {
                entry: "index.html".into(),
                expected_hash: module_hash,
                output_type: "application/wasm".into(),
            })
            .build()
            .unwrap();
        let req2 = IngestBlockRequest {
            manifest: serde_json::to_value(&manifest).unwrap(),
            code_b64: Some("not_base64!!".into()),
            resources: vec![],
        };
        let err2 = ingest_block(State(state.clone()), Json(req2))
            .await
            .err()
            .unwrap();
        assert_eq!(err2.into_response().status(), StatusCode::BAD_REQUEST);

        let req3 = IngestBlockRequest {
            manifest: serde_json::to_value(&manifest).unwrap(),
            code_b64: None,
            resources: vec![ResourceUpload {
                name: "a.txt".into(),
                mime: "text/plain".into(),
                data_b64: "@@@".into(),
            }],
        };
        let err3 = ingest_block(State(state), Json(req3)).await.err().unwrap();
        assert_eq!(err3.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_blocks_applies_limit_and_formats_payload() {
        let dir = tempdir().unwrap();
        let config = ServerConfig {
            database_path: dir.path().join("test.db"),
            ..Default::default()
        };
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store: store.clone(),
            runtime,
            config: config.clone(),
            v0_0_2: None,
        };

        use blake3::hash;
        use jig_core::manifest::{Author as MAuthor, RenderDescriptor};
        for i in 0..3 {
            let code_bytes: Vec<u8> = vec![0u8];
            let module_hash = hash(&code_bytes).to_hex().to_string();
            let manifest = BlockManifest::builder()
                .version(semver::Version::new(1, 0, i))
                .author(MAuthor {
                    did: format!("did:jig:test-{i}").into(),
                    ..Default::default()
                })
                .render(RenderDescriptor {
                    entry: "index.html".into(),
                    expected_hash: module_hash,
                    output_type: "application/wasm".into(),
                })
                .build()
                .unwrap();
            let manifest_bytes = manifest.to_canonical_bytes().unwrap();
            let bundle = BlockBundle {
                manifest_bytes: &manifest_bytes,
                code_bytes: &code_bytes,
                resources: vec![],
            };
            let cid = bundle.block_cid().unwrap();
            store
                .store_block(&StoredBlock {
                    cid,
                    manifest,
                    code: vec![],
                    resources: vec![],
                    created_at: Utc::now(),
                })
                .unwrap();
        }

        let res = list_blocks(State(state), Query(ListBlocksQuery { limit: Some(2) }))
            .await
            .unwrap();
        let list = res.0;
        assert_eq!(list.len(), 2);
        for item in list {
            assert!(!item.block_id.is_empty());
            assert!(!item.created_at.is_empty());
        }
    }

    #[test]
    fn block_to_response_encodes_resources_and_code() {
        let code = vec![1u8, 2, 3];
        let block = StoredBlock {
            cid: "bafkqaaa".parse().unwrap(),
            manifest: BlockManifest::builder()
                .version(semver::Version::new(1, 0, 0))
                .author(jig_core::manifest::Author {
                    did: "did:jig:test".into(),
                    ..Default::default()
                })
                .render(jig_core::manifest::RenderDescriptor {
                    entry: "index.html".into(),
                    expected_hash: "hash".into(),
                    output_type: "text/html".into(),
                })
                .build()
                .unwrap(),
            code: code.clone(),
            resources: vec![StoredResource {
                name: "a.bin".into(),
                mime: "application/octet-stream".into(),
                data: vec![9, 8, 7],
            }],
            created_at: Utc::now(),
        };
        let resp = block_to_response(block);
        assert!(resp.code_b64.is_some());
        assert_eq!(resp.resources.len(), 1);
    }

    #[tokio::test]
    async fn ingest_then_get_block_and_receipt_success() {
        let dir = tempdir().unwrap();
        let config = ServerConfig {
            database_path: dir.path().join("test.db"),
            ..Default::default()
        };
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store: store.clone(),
            runtime,
            config: config.clone(),
            v0_0_2: None,
        };

        use blake3::hash;
        use jig_core::manifest::{Author as MAuthor, RenderDescriptor};
        let code_bytes: Vec<u8> = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
            0x03, 0x02, 0x01, 0x00, 0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00,
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
        ];
        let module_hash = hash(&code_bytes).to_hex().to_string();
        let manifest = BlockManifest::builder()
            .version(semver::Version::new(1, 0, 0))
            .author(MAuthor {
                did: "did:jig:test".into(),
                ..Default::default()
            })
            .render(RenderDescriptor {
                entry: "index.html".into(),
                expected_hash: module_hash,
                output_type: "application/wasm".into(),
            })
            .build()
            .unwrap();
        let req = IngestBlockRequest {
            manifest: serde_json::to_value(&manifest).unwrap(),
            code_b64: Some(base64::engine::general_purpose::STANDARD.encode(&code_bytes)),
            resources: vec![],
        };
        let resp = ingest_block(State(state.clone()), Json(req)).await.unwrap();
        let block_id = resp.0.block_id.clone();
        assert!(!block_id.is_empty());

        let cid: Cid = block_id.parse().unwrap();
        let got_block = get_block(State(state.clone()), Path(cid.to_string()))
            .await
            .unwrap();
        assert_eq!(got_block.0.block_id, block_id);

        let got_receipt = get_receipt(State(state), Path(cid.to_string()))
            .await
            .unwrap();
        assert_eq!(got_receipt.0.block_id, block_id);
    }
}
