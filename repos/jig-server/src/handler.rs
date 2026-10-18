//! Discovery, liveness and metrics routes shared by every jig-server.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use serde::Serialize;

use crate::config::ServerConfig;

#[derive(Clone)]
pub struct AppState {
    pub config: ServerConfig,
    /// v0.0.2 hello-world pipeline state (Phase D wiring). `None` when the
    /// v0.0.2 module isn't constructed (e.g., in some unit tests). When
    /// `Some(...)`, the well-known handler emits server_did +
    /// unsafe_options_active + allowed_block_kinds + peers fields from this
    /// state so federated peers can detect misconfigured neighbors (§6.6).
    pub v0_0_2: Option<Arc<crate::v0_0_2::AppState>>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/jig", get(server_info))
        // systemd and uptime checks must be able to tell "up" from
        // "crash-looping" on a default deployment.
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .with_state(state)
        .layer(http_trace_layer())
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
    /// misconfigured neighbors. Absent (not serialized) when the v0.0.2 module
    /// is not active or no flag is set.
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
    /// Bits of proof of work a new DID owes before this server deals with it
    /// (`POST /api/v1/admission`). Absent when it asks for none.
    #[serde(skip_serializing_if = "Option::is_none")]
    admission_pow_bits: Option<u8>,
    /// The server DID's signature over the TLS certificate it serves, so a
    /// client can trust a certificate no CA issued. Absent over plaintext.
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_binding: Option<jig_core::tls_binding::TlsBinding>,
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

async fn server_info(State(state): State<AppState>) -> Json<ServerInfoResponse> {
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

    Json(ServerInfoResponse {
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
        admission_pow_bits: state.v0_0_2.as_ref().and_then(|v| v.auth.pow_bits()),
        tls_binding: state
            .v0_0_2
            .as_ref()
            .and_then(|v| v.tls_binding.get().cloned()),
    })
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
        let mut cfg = ServerConfig {
            bind_address: "100.64.0.10".into(),
            port: 7117,
            ..Default::default()
        };
        cfg.tls.enabled = false;
        assert_eq!(advertised_http(cfg), "http://100.64.0.10:7117");
    }

    #[test]
    fn advertised_origin_is_https_when_tls_is_on() {
        // On by default.
        let cfg = ServerConfig {
            bind_address: "100.64.0.10".into(),
            port: 7117,
            ..Default::default()
        };
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

    /// Full response (status, content-type, body) for a request against the
    /// router.
    async fn router_send(method: &str, path: &str) -> (StatusCode, String, String) {
        use tower::ServiceExt;
        let app = build_router(AppState {
            config: ServerConfig::default(),
            v0_0_2: None,
        });
        let req = axum::http::Request::builder()
            .method(method)
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

    #[tokio::test]
    async fn healthz_is_200() {
        let (status, _ct, body) = router_send("GET", "/healthz").await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.is_empty(), "/healthz must return a body");
    }

    #[tokio::test]
    async fn metrics_exposes_prometheus_text() {
        let (status, content_type, body) = router_send("GET", "/metrics").await;
        assert_eq!(status, StatusCode::OK);
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

    /// The v0.0.1 REST surface executed sender-supplied Wasm with no signature
    /// check and was removed (D28). Nothing may answer on its paths again.
    #[tokio::test]
    async fn v0_0_1_rest_routes_are_gone() {
        for (m, p) in [
            ("GET", "/blocks"),
            ("POST", "/blocks"),
            ("GET", "/blocks/bafyfake"),
            ("GET", "/receipts/bafyfake"),
        ] {
            let (status, _, _) = router_send(m, p).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{m} {p} must not be routable"
            );
        }
        let (status, _, _) = router_send("GET", "/.well-known/jig").await;
        assert_eq!(status, StatusCode::OK);
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
        let state = AppState {
            config: config.clone(),
            v0_0_2: None,
        };

        let res = server_info(State(state)).await;
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

        let v002 = Arc::new(crate::v0_0_2::AppState::for_test().unwrap());
        let v002_did = v002.server_did.to_did_jig_string();

        let state = AppState {
            config: config.clone(),
            v0_0_2: Some(v002),
        };

        let res = server_info(State(state)).await;
        let body = res.0;

        // server_did must be present and match the v0.0.2 state's DID
        assert_eq!(body.server_did.as_deref(), Some(v002_did.as_str()));
        // A default install sets no unsafe option; the clock is bounded.
        assert!(
            body.unsafe_options_active.is_empty(),
            "expected no unsafe option, got {:?}",
            body.unsafe_options_active
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
            config: config.clone(),
            v0_0_2: Some(v002),
        };

        let res = server_info(State(state)).await;
        let body = res.0;
        // Only "email" should appear; slack is disabled (kill-switch).
        assert_eq!(body.bridges, vec!["email".to_string()]);
    }
}
