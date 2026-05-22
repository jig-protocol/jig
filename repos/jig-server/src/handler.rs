//! HTTP API for ingesting and retrieving Jig blocks.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use cid::Cid;
use jig_core::{Artifact, BlockBundle, BlockManifest};
use serde::{Deserialize, Serialize};

use crate::analytics::{ReceiptStats, TimeRange, receipt_stats_for_range};
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
    #[cfg(feature = "analytics_clickhouse")]
    pub dispatcher: Option<crate::analytics::dispatcher::AnalyticsDispatcher>,
    /// v0.0.2 hello-world pipeline state (Phase D wiring). `None` when the
    /// v0.0.2 module isn't constructed (e.g., in some unit tests). When
    /// `Some(...)`, the well-known handler emits server_did +
    /// unsafe_options_active + allowed_block_kinds + peers fields from this
    /// state so federated peers can detect misconfigured neighbors (§6.6).
    pub v0_0_2: Option<Arc<crate::v0_0_2::AppState>>,
}

#[derive(Debug, Deserialize)]
struct AnalyticsQuery {
    #[serde(default)]
    range: Option<String>,
    #[serde(default)]
    start_ts: Option<i64>,
    #[serde(default)]
    end_ts: Option<i64>,
    #[serde(default)]
    backend: Option<String>,
}

fn parse_time_range(q: &AnalyticsQuery) -> Result<TimeRange, ApiError> {
    let range = q
        .range
        .as_deref()
        .unwrap_or("last_day")
        .to_ascii_lowercase();
    match range.as_str() {
        "last_hour" => Ok(TimeRange::LastHour),
        "last_day" => Ok(TimeRange::LastDay),
        "last_week" => Ok(TimeRange::LastWeek),
        "last_month" => Ok(TimeRange::LastMonth),
        "custom" => {
            let (Some(s), Some(e)) = (q.start_ts, q.end_ts) else {
                return Err(ApiError::bad_request(
                    "custom range requires start_ts and end_ts",
                ));
            };
            Ok(TimeRange::Custom {
                start_ts: s,
                end_ts: e,
            })
        }

        _ => Err(ApiError::bad_request("invalid range value")),
    }
}

async fn get_receipt_stats(
    State(state): State<AppState>,
    Query(q): Query<AnalyticsQuery>,
) -> Result<Json<ReceiptStats>, ApiError> {
    let range = parse_time_range(&q)?;
    // Optional: backend=duckdb (when feature enabled)
    if let Some(b) = q.backend.as_deref()
        && b.eq_ignore_ascii_case("duckdb")
    {
        #[cfg(feature = "analytics_duckdb")]
        {
            use crate::analytics::duckdb::DuckDbAnalytics;
            use chrono::TimeZone;

            // Build path next to SQLite DB
            let mut duck_path = state.config.database_path.clone();
            duck_path.set_file_name("analytics.duckdb");
            let duck = DuckDbAnalytics::new(&duck_path).map_err(ApiError::from_error)?;

            // Load receipts for requested range into DuckDB projection table
            let (start_ts, end_ts) = range.to_timestamp_range();
            let start = chrono::Utc
                .timestamp_opt(start_ts, 0)
                .single()
                .unwrap_or_else(chrono::Utc::now);
            let end = chrono::Utc
                .timestamp_opt(end_ts, 0)
                .single()
                .unwrap_or_else(chrono::Utc::now);
            let receipts = state
                .store
                .list_receipts_in_range(Some(start), Some(end), None)
                .map_err(ApiError::from_error)?;

            for r in receipts {
                let executed_at = r.receipt.executed_at.unix_timestamp();
                let fuel_used = r.receipt.fuel_used;
                let outcome = r
                    .receipt
                    .outcome
                    .as_ref()
                    .map(|o| format!("{:?}", o.status))
                    .unwrap_or_else(|| "ok".to_string());
                let host = r.receipt.host.clone();
                let capability = r.receipt.counters.as_ref().and_then(|c| {
                    c.fuel_by_capability
                        .iter()
                        .max_by_key(|(_, v)| *v)
                        .map(|(k, _)| k.as_str())
                });
                duck.insert_receipt(
                    &r.cid.to_string(),
                    executed_at,
                    fuel_used,
                    &outcome,
                    &host,
                    capability,
                )
                .map_err(ApiError::from_error)?;
            }

            let stats = duck
                .receipt_stats_for_range(range)
                .map_err(ApiError::from_error)?;
            return Ok(Json(stats));
        }
        #[cfg(not(feature = "analytics_duckdb"))]
        {
            return Err(ApiError::bad_request(
                "duckdb backend requires analytics_duckdb feature",
            ));
        }
    }

    let stats = receipt_stats_for_range(&state.store, range).map_err(ApiError::from_error)?;
    Ok(Json(stats))
}

pub fn build_router(state: AppState) -> Router {
    #[allow(unused_mut)]
    let mut router = Router::new()
        .route("/.well-known/jig", get(server_info))
        .route("/blocks", get(list_blocks))
        .route("/blocks", post(ingest_block))
        .route("/blocks/:cid", get(get_block))
        .route("/receipts/:cid", get(get_receipt))
        .route("/analytics/receipt-stats", get(get_receipt_stats));

    #[cfg(feature = "telemetry_v0_2")]
    {
        router = router.route("/metrics/timings", get(get_timings_metrics));
    }

    router.with_state(state)
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

async fn server_info(State(state): State<AppState>) -> Result<Json<ServerInfoResponse>, ApiError> {
    let (server_did, unsafe_options_active, allowed_block_kinds, peers) =
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
            )
        } else {
            (None, vec![], vec![], vec![])
        };

    Ok(Json(ServerInfoResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        host_id: state.config.host_id.clone(),
        endpoints: ServerEndpoints {
            http: format!("http://{}:{}", state.config.bind_address, state.config.port),
        },
        server_did,
        unsafe_options_active,
        allowed_block_kinds,
        peers,
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

    #[cfg(feature = "analytics_clickhouse")]
    if let Some(dispatcher) = &state.dispatcher {
        use crate::analytics::dispatcher::AnalyticsRow;
        let executed_at = receipt.executed_at.unix_timestamp();
        let fuel_used = receipt.fuel_used;
        let outcome = receipt
            .outcome
            .as_ref()
            .map(|o| format!("{:?}", o.status))
            .unwrap_or_else(|| "ok".to_string());
        let capability = receipt.counters.as_ref().and_then(|c| {
            c.fuel_by_capability
                .iter()
                .max_by_key(|(_, v)| *v)
                .map(|(k, _)| k.clone())
        });
        let row = AnalyticsRow {
            block_id: block_cid.to_string(),
            executed_at,
            fuel_used,
            outcome,
            host: receipt.host.clone(),
            capability,
        };
        let _ = dispatcher.enqueue(row);
    }

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

#[cfg(feature = "telemetry_v0_2")]
#[derive(Serialize)]
struct PercentilesDto {
    p50: u64,
    p95: u64,
    p99: u64,
}

#[cfg(feature = "telemetry_v0_2")]
#[derive(Serialize)]
struct TimingsMetricsResponse {
    samples: u64,
    queue_wait: PercentilesDto,
    init: PercentilesDto,
    exec: PercentilesDto,
    total: PercentilesDto,
}

#[cfg(feature = "telemetry_v0_2")]
async fn get_timings_metrics(
    State(state): State<AppState>,
) -> Result<Json<TimingsMetricsResponse>, ApiError> {
    let snap = state.runtime.timings_snapshot();
    let map = |p: crate::telemetry::Percentiles| PercentilesDto {
        p50: p.p50,
        p95: p.p95,
        p99: p.p99,
    };
    let body = TimingsMetricsResponse {
        samples: snap.samples,
        queue_wait: map(snap.queue_wait),
        init: map(snap.init),
        exec: map(snap.exec),
        total: map(snap.total),
    };
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "analytics_duckdb")]
    use jig_core::manifest::Author;
    #[cfg(feature = "analytics_duckdb")]
    use jig_core::receipt::{CountersBuilder, Outcome, OutcomeStatus, ReasonCode, Timings};
    #[cfg(feature = "analytics_duckdb")]
    use semver::Version;
    use std::sync::Arc;
    use tempfile::tempdir;
    #[cfg(feature = "analytics_duckdb")]
    use time::OffsetDateTime;

    // ... (rest of the code remains the same)

    #[test]
    fn parse_time_range_custom_ok() {
        let tr = parse_time_range(&AnalyticsQuery {
            range: Some("custom".into()),
            start_ts: Some(100),
            end_ts: Some(200),
            backend: None,
        })
        .unwrap();
        match tr {
            crate::analytics::TimeRange::Custom { start_ts, end_ts } => {
                assert_eq!(start_ts, 100);
                assert_eq!(end_ts, 200);
            }
            _ => panic!("expected custom range"),
        }
    }

    #[tokio::test]
    async fn list_blocks_clamps_limit_to_200() {
        use blake3::hash;
        use jig_core::manifest::{Author as MAuthor, RenderDescriptor};
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store: store.clone(),
            runtime,
            config: config.clone(),
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher: None,
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

    #[cfg(feature = "telemetry_v0_2")]
    #[tokio::test]
    async fn metrics_timings_endpoint_reports_percentiles() {
        let dir = tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store,
            runtime: runtime.clone(),
            config: config.clone(),
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher: None,
            v0_0_2: None,
        };

        // Execute simple WASM a few times to populate histograms
        let code_bytes: Vec<u8> = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
            0x03, 0x02, 0x01, 0x00, 0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00,
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
        ];
        let manifest = {
            use blake3::hash;
            use jig_core::manifest::{Author, RenderDescriptor};
            let module_hash = hash(&code_bytes).to_hex().to_string();
            jig_core::manifest::BlockManifest::builder()
                .version(semver::Version::new(1, 0, 0))
                .author(Author {
                    did: "did:jig:test".into(),
                    ..Default::default()
                })
                .render(RenderDescriptor {
                    entry: "index.html".into(),
                    expected_hash: module_hash,
                    output_type: "application/wasm".into(),
                })
                .build()
                .unwrap()
        };
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &code_bytes,
            resources: vec![],
        };
        let cid = bundle.block_cid().unwrap();
        for _ in 0..5 {
            let _ = runtime.execute(&cid, &manifest, &bundle).unwrap();
        }

        let res = get_timings_metrics(State(state)).await.unwrap();
        let body = res.0;
        assert!(body.samples >= 5);
        assert!(body.exec.p50 >= 0);
    }

    #[cfg(not(feature = "analytics_duckdb"))]
    #[tokio::test]
    async fn analytics_duckdb_backend_requires_feature() {
        let dir = tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store,
            runtime,
            config: config.clone(),
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher: None,
            v0_0_2: None,
        };

        let res = get_receipt_stats(
            State(state),
            Query(AnalyticsQuery {
                range: Some("last_day".into()),
                start_ts: None,
                end_ts: None,
                backend: Some("duckdb".into()),
            }),
        )
        .await;

        assert!(res.is_err());
        let resp = res.err().unwrap().into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(feature = "analytics_duckdb")]
    #[tokio::test]
    async fn analytics_duckdb_backend_returns_stats() {
        use blake3::hash;
        use jig_core::manifest::RenderDescriptor;

        let dir = tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store: store.clone(),
            runtime,
            config: config.clone(),
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher: None,
            v0_0_2: None,
        };

        // Insert two receipts: one ok with capability fuel, one hard_fail
        let code_bytes: Vec<u8> = vec![0u8];
        let module_hash = hash(&code_bytes).to_hex().to_string();
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
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
        let cid_a = bundle.block_cid().unwrap();
        store
            .store_block(&StoredBlock {
                cid: cid_a,
                manifest: manifest.clone(),
                code: code_bytes.clone(),
                resources: vec![],
                created_at: Utc::now(),
            })
            .unwrap();

        let executed_at = OffsetDateTime::now_utc();
        let usage = jig_core::capability_scope::CapabilityUsageKey::without_scope("core:compute");
        let counters = CountersBuilder::new()
            .fuel_total(100)
            .add_fuel(&usage, 100)
            .build();
        let receipt_ok = jig_core::receipt::BlockReceipt::builder(cid_a)
            .host("did:jig:server:local")
            .executed_at(executed_at)
            .render_hash("sha256:abcd")
            .fuel_used(100)
            .counters(counters)
            .capability("core:compute")
            .timings(Timings::new(0, 5, 10))
            .build()
            .unwrap();
        store
            .store_receipt(&StoredReceipt {
                cid: cid_a,
                receipt: receipt_ok,
                created_at: Utc::now(),
            })
            .unwrap();

        // Second hard-fail receipt
        let manifest_b = BlockManifest::builder()
            .version(Version::new(0, 1, 1))
            .author(Author {
                did: "did:jig:test-b".into(),
                ..Default::default()
            })
            .render(RenderDescriptor {
                entry: "index.html".into(),
                expected_hash: module_hash.clone(),
                output_type: "application/wasm".into(),
            })
            .build()
            .unwrap();
        let mb = manifest_b.to_canonical_bytes().unwrap();
        let bundle_b = BlockBundle {
            manifest_bytes: &mb,
            code_bytes: &code_bytes,
            resources: vec![],
        };
        let cid_b = bundle_b.block_cid().unwrap();
        store
            .store_block(&StoredBlock {
                cid: cid_b,
                manifest: manifest_b,
                code: code_bytes.clone(),
                resources: vec![],
                created_at: Utc::now(),
            })
            .unwrap();
        let receipt_fail = jig_core::receipt::BlockReceipt::builder(cid_b)
            .host("did:jig:server:local")
            .executed_at(executed_at)
            .render_hash("sha256:cafe")
            .fuel_used(50)
            .outcome(Outcome {
                status: OutcomeStatus::HardFail,
                affordances: vec![],
                reason: Some(ReasonCode::CapabilityDenied),
            })
            .build()
            .unwrap();
        store
            .store_receipt(&StoredReceipt {
                cid: cid_b,
                receipt: receipt_fail,
                created_at: Utc::now(),
            })
            .unwrap();

        // Query stats with backend=duckdb
        let res = get_receipt_stats(
            State(state),
            Query(AnalyticsQuery {
                range: Some("last_day".into()),
                start_ts: None,
                end_ts: None,
                backend: Some("duckdb".into()),
            }),
        )
        .await
        .unwrap();
        let stats = res.0;
        assert_eq!(stats.total_receipts, 2);
        assert_eq!(stats.total_fuel_used, 150);
        assert!((stats.avg_fuel_per_receipt - 75.0).abs() < f64::EPSILON);
        assert!(stats.success_rate >= 0.49 && stats.success_rate <= 0.51);
        assert!(
            stats
                .top_hosts
                .iter()
                .any(|(h, _)| h == "did:jig:server:local")
        );
        assert_eq!(
            stats
                .fuel_by_capability
                .get("core:compute")
                .copied()
                .unwrap_or(0),
            100
        );
    }

    #[tokio::test]
    async fn server_info_returns_basic_metadata() {
        let dir = tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        config.bind_address = "127.0.0.1".into();
        config.port = 7117;
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store,
            runtime,
            config: config.clone(),
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher: None,
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
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher: None,
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
    }

    #[test]
    fn parse_time_range_errors_on_invalid_and_custom_missing() {
        let e = parse_time_range(&AnalyticsQuery {
            range: Some("bogus".into()),
            start_ts: None,
            end_ts: None,
            backend: None,
        })
        .err()
        .unwrap();
        let resp: Response = e.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let e2 = parse_time_range(&AnalyticsQuery {
            range: Some("custom".into()),
            start_ts: Some(1),
            end_ts: None,
            backend: None,
        })
        .err()
        .unwrap();
        let resp2: Response = e2.into_response();
        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_block_and_receipt_not_found_return_404() {
        let dir = tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store,
            runtime,
            config: config.clone(),
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher: None,
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
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store,
            runtime,
            config: config.clone(),
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher: None,
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
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store: store.clone(),
            runtime,
            config: config.clone(),
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher: None,
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
    async fn receipt_stats_default_backend_returns_stats() {
        use blake3::hash;
        use jig_core::manifest::{Author as MAuthor, RenderDescriptor};
        use jig_core::receipt::{CountersBuilder, Outcome, OutcomeStatus};
        use semver::Version;
        use time::OffsetDateTime;

        let dir = tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store: store.clone(),
            runtime,
            config: config.clone(),
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher: None,
            v0_0_2: None,
        };

        let code_bytes: Vec<u8> = vec![0u8];
        let module_hash = hash(&code_bytes).to_hex().to_string();
        let manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(MAuthor {
                did: "did:jig:test".into(),
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
        let cid_a = bundle.block_cid().unwrap();
        store
            .store_block(&StoredBlock {
                cid: cid_a,
                manifest: manifest.clone(),
                code: code_bytes.clone(),
                resources: vec![],
                created_at: Utc::now(),
            })
            .unwrap();

        let executed_at = OffsetDateTime::now_utc();
        let usage = jig_core::capability_scope::CapabilityUsageKey::without_scope("core:compute");
        let counters = CountersBuilder::new()
            .fuel_total(100)
            .add_fuel(&usage, 100)
            .build();
        let receipt_ok = jig_core::receipt::BlockReceipt::builder(cid_a)
            .host("did:jig:server:local")
            .executed_at(executed_at)
            .render_hash("sha256:abcd")
            .fuel_used(100)
            .counters(counters)
            .capability("core:compute")
            .build()
            .unwrap();
        store
            .store_receipt(&StoredReceipt {
                cid: cid_a,
                receipt: receipt_ok,
                created_at: Utc::now(),
            })
            .unwrap();

        let manifest_b = BlockManifest::builder()
            .version(Version::new(0, 1, 1))
            .author(MAuthor {
                did: "did:jig:test-b".into(),
                ..Default::default()
            })
            .render(RenderDescriptor {
                entry: "index.html".into(),
                expected_hash: module_hash.clone(),
                output_type: "application/wasm".into(),
            })
            .build()
            .unwrap();
        let mb = manifest_b.to_canonical_bytes().unwrap();
        let bundle_b = BlockBundle {
            manifest_bytes: &mb,
            code_bytes: &code_bytes,
            resources: vec![],
        };
        let cid_b = bundle_b.block_cid().unwrap();
        store
            .store_block(&StoredBlock {
                cid: cid_b,
                manifest: manifest_b,
                code: code_bytes.clone(),
                resources: vec![],
                created_at: Utc::now(),
            })
            .unwrap();
        let receipt_fail = jig_core::receipt::BlockReceipt::builder(cid_b)
            .host("did:jig:server:local")
            .executed_at(executed_at)
            .render_hash("sha256:cafe")
            .fuel_used(50)
            .outcome(Outcome {
                status: OutcomeStatus::HardFail,
                affordances: vec![],
                reason: Some(jig_core::receipt::ReasonCode::CapabilityDenied),
            })
            .build()
            .unwrap();
        store
            .store_receipt(&StoredReceipt {
                cid: cid_b,
                receipt: receipt_fail,
                created_at: Utc::now(),
            })
            .unwrap();

        let res = get_receipt_stats(
            State(state),
            Query(AnalyticsQuery {
                range: Some("last_day".into()),
                start_ts: None,
                end_ts: None,
                backend: None,
            }),
        )
        .await
        .unwrap();
        let stats = res.0;
        assert_eq!(stats.total_receipts, 2);
        assert_eq!(stats.total_fuel_used, 150);
        assert!((stats.avg_fuel_per_receipt - 75.0).abs() < f64::EPSILON);
        assert!(stats.success_rate >= 0.49 && stats.success_rate <= 0.51);
        assert!(
            stats
                .fuel_by_capability
                .get("core:compute")
                .copied()
                .unwrap_or(0)
                >= 100
        );
    }

    #[cfg(feature = "analytics_clickhouse")]
    #[tokio::test]
    async fn ingest_enqueues_analytics_row_when_dispatcher_present() {
        use crate::analytics::dispatcher::{AnalyticsDispatcher, AnalyticsRow, AnalyticsSink};
        use std::sync::Mutex;

        struct TestSink {
            rows: Mutex<Vec<AnalyticsRow>>,
        }

        #[async_trait::async_trait]
        impl AnalyticsSink for TestSink {
            async fn insert_batch(&self, rows: &[AnalyticsRow]) -> crate::error::Result<()> {
                self.rows.lock().unwrap().extend_from_slice(rows);
                Ok(())
            }
        }

        let dir = tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());

        let sink = Arc::new(TestSink {
            rows: Mutex::new(vec![]),
        });
        let dispatcher =
            AnalyticsDispatcher::new(sink.clone(), 8, 1, std::time::Duration::from_millis(5));

        let state = AppState {
            store,
            runtime,
            config: config.clone(),
            dispatcher: Some(dispatcher),
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

        let _ = ingest_block(State(state), Json(req)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let rows = sink.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].block_id.is_empty());
        assert!(rows[0].fuel_used > 0);
    }

    #[tokio::test]
    async fn ingest_then_get_block_and_receipt_success() {
        let dir = tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        let store = Arc::new(SqliteBlockStore::new(&config.database_path).unwrap());
        let runtime = Arc::new(BlockRuntime::new(config.execution_config()).unwrap());
        let state = AppState {
            store: store.clone(),
            runtime,
            config: config.clone(),
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher: None,
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
            resources: vec![ResourceUpload {
                name: "greet.txt".into(),
                mime: "text/plain".into(),
                data_b64: base64::engine::general_purpose::STANDARD.encode(b"hi"),
            }],
        };

        let resp = ingest_block(State(state.clone()), Json(req)).await.unwrap();
        let block_id = resp.0.block_id;

        let got_block = get_block(State(state.clone()), Path(block_id.clone()))
            .await
            .unwrap()
            .0;
        assert!(got_block.code_b64.is_some());
        assert_eq!(got_block.resources.len(), 1);

        let got_receipt = get_receipt(State(state), Path(block_id)).await.unwrap().0;
        assert!(!got_receipt.created_at.is_empty());
    }
}
