//! HTTP server for Jig Nameserver

use crate::config::NameServerConfig;
use crate::error::{NameServerError, Result};
use axum::{Json, Router, extract::State, routing::get};
use hyper_util::rt::TokioIo;
use jig_core::tls_binding::TlsBinding;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tower::ServiceExt as _; // oneshot

#[derive(Clone)]
pub struct AppState {
    pub cfg: NameServerConfig,
    /// The v0.0.2 DID: it signs every attestation and vouches for the TLS
    /// certificate.
    pub server_did: Option<String>,
    /// The DID's word for the listener's certificate, set when TLS starts.
    /// Empty over plaintext.
    pub tls_binding: Arc<OnceLock<TlsBinding>>,
}

pub fn app_router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/jig-ns", get(well_known))
        .route("/.well-known/jig-ns/capabilities", get(get_capabilities))
        .route("/v1/health", get(health))
        .with_state(state)
}

#[derive(Serialize)]
struct WellKnownNsInfo {
    version: String,
    endpoints: serde_json::Value,
    policy: serde_json::Value,
    /// With `tls_binding`, what `jig_client::tls::probe_at` checks a
    /// self-signed certificate against; the same fields as `/.well-known/jig`.
    #[serde(skip_serializing_if = "Option::is_none")]
    server_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_binding: Option<TlsBinding>,
    /// JEP-0004 rule 12: plaintext only behind an advertised flag.
    unsafe_options_active: Vec<String>,
}

async fn well_known(State(state): State<AppState>) -> Result<Json<WellKnownNsInfo>> {
    let endpoints = serde_json::json!({
        "health": "/v1/health",
    });
    let policy = serde_json::json!({
        "alias_rate_limits": {
            "enabled": state.cfg.alias_rate_limits.enabled,
            "per_ip_per_min": state.cfg.alias_rate_limits.per_ip_per_min,
            "per_did_per_min": state.cfg.alias_rate_limits.per_did_per_min,
        },
        "automation": {
            "enabled": state.cfg.automation.enabled,
            "power_law_alpha": state.cfg.automation.power_law_alpha,
            "pile_on_factor": state.cfg.automation.pile_on_factor,
            "max_multiplier": state.cfg.automation.max_multiplier,
            "quorum": state.cfg.automation.quorum,
            "evidence_window_secs": state.cfg.automation.evidence_window_secs,
            "human_review_window_secs": state.cfg.automation.human_review_window_secs,
        },
        "reputation": state.cfg.reputation.clone(),
    });
    Ok(Json(WellKnownNsInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        endpoints,
        policy,
        server_did: state.server_did.clone(),
        tls_binding: state.tls_binding.get().cloned(),
        unsafe_options_active: state.cfg.unsafe_options_active(),
    }))
}

async fn get_capabilities(State(state): State<AppState>) -> String {
    state.cfg.capabilities.to_capabilities_text()
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Result<Json<HealthResponse>> {
    Ok(Json(HealthResponse { status: "ok" }))
}

/// Everything [`build_app_parts`] assembles.
///
/// [`build_app`] returns only the router the binary serves. This superset
/// exists so tests can reach the v0.0.2 store the mounted routers write to —
/// without it, a test harness would have to hand-assemble its own `AppState`,
/// which is exactly the divergence that let the binary ship with the alias
/// routers unmounted while the harness tests stayed green.
pub struct NameServerApp {
    pub router: Router,
    pub v0_0_2_state: Arc<crate::v0_0_2::AppState>,
    /// What `/.well-known/jig-ns` publishes as `tls_binding`.
    pub tls_binding: Arc<OnceLock<TlsBinding>>,
}

impl NameServerApp {
    /// Have the nameserver's DID vouch for `cert_der`, the leaf certificate
    /// the listener serves. Only the first call counts.
    pub fn bind_tls_certificate(&self, cert_der: &[u8]) {
        let _ = self
            .tls_binding
            .get_or_init(|| TlsBinding::sign(&self.v0_0_2_state.ingest_ctx.server_key, cert_der));
    }
}

/// jig-server's keyfile default (`~/.jig/server/server.key`) belongs to the
/// chat server. A nameserver signing alias attestations with that key would
/// attest under the chat server's DID, so treat the untouched default (and an
/// empty string) as "operator did not choose" and derive a sibling of the
/// nameserver database instead.
pub fn resolve_v0_0_2_keyfile(cfg: &NameServerConfig) -> String {
    let configured = cfg.v0_0_2.server.server_did_keyfile.trim();
    let jig_server_default = jig_config::v0_0_2_server::ServerSection::default().server_did_keyfile;
    if !configured.is_empty() && configured != jig_server_default {
        return configured.to_string();
    }
    db_sibling(&cfg.storage.database_path, "_v002.key")
        .to_string_lossy()
        .into_owned()
}

/// The alias store (`jig_pipeline::persist::SqliteStore`) and the signing key
/// are derived as siblings of `[storage] database_path`, so a one-line deploy
/// needs no extra path (mirrors the `_v002.db` convention in jig-server's
/// `main.rs`). Nothing opens `database_path` itself any more: it only anchors
/// these names.
// TODO(v0.3): replace the anchor with a `data_dir`.
fn db_sibling(database_path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let stem = database_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "nameserver".to_string());
    database_path.with_file_name(format!("{stem}{suffix}"))
}

/// Construct the router the binary serves: the legacy v0.0.1 `app_router`
/// merged with the four v0.0.2 alias routers (challenge/register, resolve,
/// rotate/renew, handles).
///
/// Spawns no background work of its own, so callers control when — and
/// whether — the gossip loop starts. (`v0_0_2::AppState::new` does spawn its
/// own challenge-nonce sweeper internally, so a tokio runtime must be live.)
pub fn build_app(cfg: &NameServerConfig) -> Result<Router> {
    let app = build_app_parts(cfg)?;
    Ok(app.router)
}

/// [`build_app`] plus the v0.0.2 state — see [`NameServerApp`].
pub fn build_app_parts(cfg: &NameServerConfig) -> Result<NameServerApp> {
    let mut v0_0_2_cfg = cfg.v0_0_2.clone();
    v0_0_2_cfg.server.server_did_keyfile = resolve_v0_0_2_keyfile(cfg);
    let mut v0_0_2_state = crate::v0_0_2::AppState::new(
        v0_0_2_cfg,
        db_sibling(&cfg.storage.database_path, "_v002.db"),
        crate::v0_0_2_policy::Suffixes::from_config(&cfg.v0_0_2.nameserver)?,
    )?;
    v0_0_2_state.max_pending_challenges = cfg.alias_rate_limits.max_pending_challenges;
    v0_0_2_state.network = cfg.network.clone();
    let v0_0_2_state = Arc::new(v0_0_2_state);

    let tls_binding = Arc::new(OnceLock::new());
    let state = AppState {
        cfg: cfg.clone(),
        server_did: Some(v0_0_2_state.ns_did_string()),
        tls_binding: Arc::clone(&tls_binding),
    };

    // `merge` is safe here even though both halves register `/v1/challenge`:
    // the legacy handler is POST and the v0.0.2 handler is GET, and axum
    // merges method-disjoint routers for the same path. Adding a same-method
    // duplicate would panic at startup — covered by
    // `both_challenge_methods_survive_the_merge`.
    // register/rotate/renew sit behind the per-IP and per-DID limiter; it
    // passes GETs (the challenge route) straight through.
    let limiter = crate::v0_0_2_rate_limit::AliasRateLimiter::new(
        cfg.alias_rate_limits.clone(),
        cfg.network.clone(),
    );
    let rate_limited =
        axum::middleware::from_fn_with_state(limiter, crate::v0_0_2_rate_limit::limit);
    let mut router = app_router(state)
        .merge(
            crate::v0_0_2_register::build_register_router(v0_0_2_state.clone())
                .layer(rate_limited.clone()),
        )
        .merge(crate::v0_0_2_resolve::build_resolve_router(
            v0_0_2_state.clone(),
        ))
        .merge(crate::v0_0_2_metrics::build_metrics_router(
            v0_0_2_state.clone(),
        ))
        .merge(
            crate::v0_0_2_rotate_renew::build_rotate_renew_router(v0_0_2_state.clone())
                .layer(rate_limited),
        );

    // `/v1/handles` enumerates every registered alias. `build_handles_router`
    // documents that the caller must gate it; honour that here rather than
    // exposing a directory of every DID on the nameserver by default.
    if cfg.v0_0_2.debug.list_handles {
        router = router.merge(crate::v0_0_2_handles::build_handles_router(
            v0_0_2_state.clone(),
        ));
    }

    // `[network] max_body_bytes` on every route, rather than axum's implicit
    // default.
    let router = router.layer(axum::extract::DefaultBodyLimit::max(
        cfg.network.max_body_bytes,
    ));

    Ok(NameServerApp {
        router,
        v0_0_2_state,
        tls_binding,
    })
}

/// Load config, apply the CLI overrides, and serve until SIGTERM or SIGINT,
/// then shut down gracefully (#438). `config` is `jig-nameserver --config`,
/// else `JIG_NS_CONFIG` is read. `bind_override` / `port_override` come from
/// `jig-nameserver serve --bind/--port` and win over both the config file and
/// `JIG_NS_BIND`/`JIG_NS_PORT`, which `load` has already applied.
pub async fn run_http_server(
    config: Option<&std::path::Path>,
    bind_override: Option<String>,
    port_override: Option<u16>,
) -> Result<()> {
    // Before anything binds, so a signal once the server is listening is
    // always graceful, never the default action.
    let stop = crate::shutdown::signal();
    let mut cfg = NameServerConfig::load(config)?;
    if let Some(bind) = bind_override {
        cfg.network.bind = bind;
    }
    if let Some(port) = port_override {
        cfg.network.port = port;
    }

    let addr = format!("{}:{}", cfg.network.bind, cfg.network.port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("binding {addr}: {e}")))?;
    let app = build_app_parts(&cfg)?;
    // A second signal cuts the drain short.
    serve_app_until(&cfg, app, listener, stop, crate::shutdown::signal).await
}

/// Serve `cfg`'s nameserver on `listener`: over TLS (JEP-0004 rule 12) unless
/// `[tls] enabled = false`. Serves until the future is dropped.
pub async fn serve(cfg: &NameServerConfig, listener: TcpListener) -> Result<()> {
    serve_app(cfg, build_app_parts(cfg)?, listener).await
}

/// [`serve`] an app already built from `cfg`, for a caller that keeps a
/// handle on its state (tests register names through it).
pub async fn serve_app(
    cfg: &NameServerConfig,
    app: NameServerApp,
    listener: TcpListener,
) -> Result<()> {
    serve_app_until(
        cfg,
        app,
        listener,
        std::future::pending(),
        std::future::pending,
    )
    .await
}

/// [`serve_app`] until `stop`, then shut down gracefully (#438): stop
/// accepting, let the requests in flight finish within `[network]
/// shutdown_drain_ms` (or until `cut`), and return.
pub async fn serve_app_until<S, C, CF>(
    cfg: &NameServerConfig,
    app: NameServerApp,
    listener: TcpListener,
    stop: S,
    cut: C,
) -> Result<()>
where
    S: std::future::Future<Output = ()>,
    C: FnOnce() -> CF,
    CF: std::future::Future<Output = ()>,
{
    let other = |e: String| NameServerError::Other(anyhow::anyhow!(e));
    let addr = listener
        .local_addr()
        .map_err(|e| NameServerError::Other(e.into()))?;
    let shutdown = crate::shutdown::Shutdown::new();
    let listening: tokio::task::JoinHandle<Result<()>> = if !cfg.tls.enabled {
        tracing::warn!(
            "[tls] enabled = false: serving plaintext on http://{addr}. This is an unsafe \
             option, listed in /.well-known/jig-ns; use it only on loopback or behind a proxy \
             that terminates TLS"
        );
        let make_svc = app
            .router
            .into_make_service_with_connect_info::<SocketAddr>();
        let stopped = shutdown.cancelled_owned();
        shutdown.spawn(async move {
            axum::serve(listener, make_svc)
                .with_graceful_shutdown(stopped)
                .await
                .map_err(|e| NameServerError::Other(e.into()))
        })
    } else {
        // Not jig-server's `tls/`: the two often share a data directory, and each
        // DID vouches for its own certificate.
        let dir = cfg
            .storage
            .database_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."))
            .join("nameserver");
        let (cert, key) = cfg
            .tls
            .material(&dir, &tls_names(&cfg.network.bind))
            .map_err(other)?;
        let (rustls_config, leaf) =
            jig_config::tls::load_rustls_config(&cert, &key).map_err(other)?;
        app.bind_tls_certificate(leaf.as_ref());
        tracing::info!("nameserver listening on https://{addr}");
        shutdown.spawn(serve_tls(
            listener,
            app.router,
            rustls_config,
            shutdown.clone(),
        ))
    };
    // The listener lives no longer than this future: dropped early, or
    // returning once the drain has run out or been cut, it stops accepting
    // and frees the port rather than serving on detached.
    let _listener_lifetime = AbortOnDrop(listening.abort_handle());

    tokio::pin!(listening);
    tokio::pin!(stop);
    tokio::select! {
        served = &mut listening => {
            return match served {
                Ok(result) => result,
                Err(e) => Err(other(format!("listener task failed: {e}"))),
            };
        }
        () = &mut stop => {}
    }
    shutdown.begin();
    let drain = std::time::Duration::from_millis(cfg.network.shutdown_drain_ms);
    tracing::info!(
        in_flight = shutdown.in_flight(),
        drain_ms = cfg.network.shutdown_drain_ms,
        "shutting down: no new connections; draining in-flight requests"
    );
    tokio::select! {
        drained = shutdown.drain(drain) => {
            if drained {
                tracing::info!("shutdown complete: every connection drained");
            } else {
                tracing::warn!(
                    still_open = shutdown.in_flight(),
                    "shutdown drain ran out; cutting what is still open"
                );
            }
        }
        () = cut() => {
            tracing::warn!(
                still_open = shutdown.in_flight(),
                "second signal: cutting the drain short"
            );
        }
    }
    Ok(())
}

/// Aborts a task when dropped.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Names a self-signed certificate is made for: `localhost`, and the bind
/// address unless it is a wildcard. Clients trust it through the DID, not
/// these names.
fn tls_names(bind: &str) -> Vec<String> {
    let mut names = vec!["localhost".to_string()];
    if !matches!(bind, "0.0.0.0" | "::" | "[::]") && bind != "localhost" {
        names.push(bind.to_string());
    }
    names
}

/// Serve `router` over rustls. Each connection's handshake runs in its own
/// task, so a slow one can't block accept.
///
/// Once `shutdown` begins this stops accepting and returns, dropping the
/// listener. A connection still in its TLS handshake is closed; a served one
/// finishes the request in flight, then closes instead of keeping alive.
async fn serve_tls(
    listener: TcpListener,
    router: Router,
    rustls_config: RustlsServerConfig,
    shutdown: crate::shutdown::Shutdown,
) -> Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(rustls_config));
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = shutdown.cancelled() => return Ok(()),
        };
        let (tcp, peer) =
            accepted.map_err(|e| NameServerError::Other(anyhow::anyhow!("accept error: {e}")))?;
        let (acceptor, router, watched) = (acceptor.clone(), router.clone(), shutdown.clone());
        shutdown.spawn(async move {
            let tls = tokio::select! {
                tls = acceptor.accept(tcp) => match tls {
                    Ok(tls) => tls,
                    Err(e) => {
                        tracing::debug!("TLS handshake failed: {e}");
                        return;
                    }
                },
                () = watched.cancelled() => return,
            };
            let service = hyper::service::service_fn(
                move |mut req: hyper::Request<hyper::body::Incoming>| {
                    // What `into_make_service_with_connect_info` gives the
                    // plaintext listener: the rate limiter keys on it.
                    req.extensions_mut()
                        .insert(axum::extract::ConnectInfo(peer));
                    router.clone().oneshot(req)
                },
            );
            // ALPN offers only http/1.1.
            let conn = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service);
            tokio::pin!(conn);
            let served = tokio::select! {
                served = conn.as_mut() => served,
                () = watched.cancelled() => {
                    // Finish the request in flight, then close.
                    conn.as_mut().graceful_shutdown();
                    conn.as_mut().await
                }
            };
            if let Err(e) = served {
                tracing::debug!("connection error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use axum::http::StatusCode;
    use axum::{body::Body, http::Response};
    use http_body_util::BodyExt as _; // for collect
    use tower::util::ServiceExt; // for `oneshot`

    // -----------------------------------------------------------------------
    // build_app: the router the binary actually serves
    // -----------------------------------------------------------------------

    /// Unique scratch directory that deletes itself on drop. jig-nameserver has
    /// no `tempfile` dev-dependency and this lane may not add one.
    struct ScratchDir(std::path::PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos();
            let mut path = std::env::temp_dir();
            path.push(format!("jig-ns-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create scratch dir");
            Self(path)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch_config(dir: &ScratchDir, alias_suffix: &str) -> NameServerConfig {
        let mut cfg = NameServerConfig::default();
        cfg.storage.database_path = dir.0.join("nameserver.db");
        let mut suffix = jig_config::v0_0_2_server::SuffixConfig::new(alias_suffix);
        // These tests are about routes and rate limits, not proof-of-work.
        suffix.pow = jig_config::v0_0_2_server::PowPolicy::off();
        cfg.v0_0_2.nameserver.alias_suffixes = vec![suffix];
        cfg.v0_0_2.server.server_did_keyfile = dir.0.join("ns.key").to_string_lossy().into_owned();
        cfg.v0_0_2.keys.unlock = Some(jig_client::server_key::credential_for_tests(&dir.0));
        // Off by default in production; on here so the route-presence assertions
        // exercise the mounted handler.
        cfg.v0_0_2.debug.list_handles = true;
        cfg
    }

    async fn get(router: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// `app_router` alone serves only health and the well-known documents; the
    /// alias API comes from the v0.0.2 routers `build_app` merges in. Shipping
    /// `app_router` as the whole app once made the binary 404 on
    /// challenge/register/resolve/handles.
    #[tokio::test]
    async fn legacy_router_alone_does_not_serve_the_alias_api() {
        let cfg = NameServerConfig::default();
        let router = app_router(AppState {
            cfg,
            server_did: None,
            tls_binding: Default::default(),
        });

        let (status, _) = get(&router, "/v1/health").await;
        assert_eq!(status, StatusCode::OK);
        for uri in ["/v1/challenge", "/v1/resolve/nobody@dj.jig", "/v1/handles"] {
            let (status, _) = get(&router, uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri} is not in app_router");
        }
    }

    #[tokio::test]
    async fn build_app_mounts_the_v0_0_2_alias_routers() {
        let dir = ScratchDir::new("build-app-surface");
        let cfg = scratch_config(&dir, "dj.jig");
        let router = build_app(&cfg).expect("build_app");

        let (status, body) = get(&router, "/v1/challenge").await;
        assert_eq!(status, StatusCode::OK, "GET /v1/challenge must be served");
        assert!(
            body["challenge"].as_str().is_some_and(|c| c.len() == 64),
            "expected a 32-byte hex nonce, got {body}"
        );

        let (status, body) = get(&router, "/v1/handles").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["aliases"].is_array(), "got {body}");

        // A mounted-but-empty resolve answers with the handler's JSON error;
        // an unmounted route would 404 with an empty body.
        let (status, body) = get(&router, "/v1/resolve/nobody@dj.jig").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "NOT_FOUND", "got {body}");
    }

    #[tokio::test]
    async fn handles_stays_unmounted_unless_debug_list_handles_is_set() {
        let dir = ScratchDir::new("handles-gated");
        let mut cfg = scratch_config(&dir, "dj.jig");
        cfg.v0_0_2.debug.list_handles = false;
        let router = build_app(&cfg).expect("build_app");

        let (status, _) = get(&router, "/v1/handles").await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "alias enumeration must stay off unless the operator opts in"
        );
        // The rest of the alias API is unaffected by the flag.
        let (status, _) = get(&router, "/v1/challenge").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The legacy v0.0.1 surface (POST challenge, claim, alias, policy,
    /// reputation, tribunal, work, transparency, federation, receipts,
    /// attestations, anomalies, admin) is gone; only the v0.0.2 GET challenge
    /// remains on `/v1/challenge`.
    #[tokio::test]
    async fn legacy_routes_are_not_served() {
        let dir = ScratchDir::new("challenge-merge");
        let cfg = scratch_config(&dir, "dj.jig");
        let router = build_app(&cfg).expect("build_app");

        let (status, _) = get(&router, "/v1/challenge").await;
        assert_eq!(status, StatusCode::OK, "v0.0.2 GET handler");

        let legacy = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/challenge")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "action": "claim",
                            "subject": "alice@example.com",
                            "ttl_seconds": 120,
                            "difficulty": 8
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            legacy.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "legacy POST /v1/challenge is removed"
        );

        for uri in [
            "/v1/policy",
            "/v1/resolve?name=alice@example.com",
            "/v1/admin/rate?key=x",
            "/v1/reputation/user/alice/observations",
            "/v1/tribunal/cases",
            "/v1/transparency/entries",
            "/v1/federation/peers",
            "/v1/receipts",
            "/v1/attestations",
        ] {
            let (status, _) = get(&router, uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri} must be gone");
        }
    }

    #[tokio::test]
    async fn build_app_uses_the_configured_alias_suffix() {
        let dir = ScratchDir::new("alias-suffix");
        let cfg = scratch_config(&dir, "names.example.org");
        let app = build_app_parts(&cfg).expect("build_app_parts");
        assert_eq!(app.v0_0_2_state.suffix(), "names.example.org");
    }

    /// A database from before suffixes and case folding: the old table key and
    /// a mixed-case alias in the old JSON encoding. Boot rebuilds the table and
    /// lowercases the alias, so the name resolves as clients now ask for it.
    #[tokio::test]
    async fn boot_migrates_a_pre_suffix_database() {
        let dir = ScratchDir::new("pre-suffix");
        let cfg = scratch_config(&dir, "dj.jig");
        let did = jig_core::Did::from_ed25519_pubkey(&[7; 32]).to_did_jig_string();
        let now = chrono::Utc::now().timestamp();
        // The nameserver's DID comes from its keyfile, written at first boot;
        // then the database is replaced by one in the old shape.
        let ns_did = build_app_parts(&cfg)
            .expect("first boot")
            .v0_0_2_state
            .ns_did_string();
        let db = db_sibling(&cfg.storage.database_path, "_v002.db");
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", db.display()));
        }
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE alias_attestations (
                     did TEXT NOT NULL, alias TEXT NOT NULL, ns_did TEXT NOT NULL,
                     valid_from INTEGER NOT NULL, valid_until INTEGER NOT NULL,
                     attestation_bytes BLOB NOT NULL, PRIMARY KEY (did, ns_did));",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO alias_attestations VALUES (?, 'DJ@dj.jig', ?, ?, ?, ?)",
                rusqlite::params![
                    did,
                    ns_did,
                    now - 10,
                    now + 1000,
                    br#"{"legacy":true}"#.to_vec()
                ],
            )
            .unwrap();
        }

        let app = build_app_parts(&cfg).expect("second boot");
        let router = crate::v0_0_2_resolve::build_resolve_router(app.v0_0_2_state.clone());
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/v1/resolve/dj@dj.jig")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Pins the well-known `policy` keys, and that the published rate limits
    /// are the ones the alias routes enforce.
    #[tokio::test]
    async fn well_known_publishes_the_enforced_alias_rate_limits() {
        let dir = ScratchDir::new("well-known");
        let mut cfg = scratch_config(&dir, "dj.jig");
        cfg.alias_rate_limits.per_ip_per_min = 7;
        cfg.alias_rate_limits.per_did_per_min = 3;
        let router = build_app(&cfg).expect("build_app");

        let (status, body) = get(&router, "/.well-known/jig-ns").await;
        assert_eq!(status, StatusCode::OK);
        let policy = body["policy"].as_object().expect("policy object");
        let mut keys: Vec<&str> = policy.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["alias_rate_limits", "automation", "reputation"]);
        assert_eq!(
            policy["alias_rate_limits"],
            serde_json::json!({ "enabled": true, "per_ip_per_min": 7, "per_did_per_min": 3 })
        );
        // The legacy identity is gone: the nameserver is known by its DID only.
        assert!(body.get("ns_id").is_none(), "{body}");
    }

    /// `[storage] database_path` only anchors the v0.0.2 file names. Nothing
    /// creates the legacy registry, whose `ns_identity` row held a raw key.
    #[tokio::test]
    async fn build_app_creates_no_legacy_database() {
        let dir = ScratchDir::new("no-legacy-db");
        let cfg = scratch_config(&dir, "dj.jig");
        let _router = build_app(&cfg).expect("build_app");
        assert!(
            !cfg.storage.database_path.exists(),
            "{} was created",
            cfg.storage.database_path.display()
        );
        assert!(db_sibling(&cfg.storage.database_path, "_v002.db").exists());
    }

    async fn post_json(router: &Router, uri: &str, body: serde_json::Value) -> Response<Body> {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn fresh_challenge(router: &Router) -> String {
        let (status, body) = get(router, "/v1/challenge").await;
        assert_eq!(status, StatusCode::OK);
        body["challenge"].as_str().unwrap().to_string()
    }

    /// `[network] max_body_bytes`: a body at the limit reaches the handler,
    /// one byte over is refused with 413 before it is parsed.
    #[tokio::test]
    async fn a_body_over_max_body_bytes_is_413() {
        let dir = ScratchDir::new("body-limit");
        let mut cfg = scratch_config(&dir, "dj.jig");
        cfg.network.max_body_bytes = 4096;
        let router = build_app(&cfg).expect("build_app");
        let post = |len: usize| {
            let mut body = b"{}".to_vec();
            body.resize(len, b' ');
            router.clone().oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
        };
        let at = post(4096).await.unwrap();
        assert_ne!(at.status(), StatusCode::PAYLOAD_TOO_LARGE, "at the limit");
        let over = post(4097).await.unwrap();
        assert_eq!(
            over.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "one byte over"
        );
    }

    #[test]
    fn a_zero_body_limit_does_not_boot() {
        let dir = ScratchDir::new("body-limit-zero");
        let mut cfg = scratch_config(&dir, "dj.jig");
        cfg.network.max_body_bytes = 0;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("max_body_bytes"), "{err}");
    }

    #[test]
    fn a_drain_over_the_maximum_does_not_boot() {
        let dir = ScratchDir::new("drain-max");
        let mut cfg = scratch_config(&dir, "dj.jig");
        cfg.network.shutdown_drain_ms = crate::config::MAX_SHUTDOWN_DRAIN_MS;
        cfg.validate().expect("the maximum itself boots");
        cfg.network.shutdown_drain_ms = crate::config::MAX_SHUTDOWN_DRAIN_MS + 1;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("shutdown_drain_ms"), "{err}");
    }

    /// `GET /v1/challenge` has a per-IP bucket of its own (JEP-0008 rule 31).
    #[tokio::test]
    async fn challenges_are_rate_limited_per_ip() {
        let dir = ScratchDir::new("challenge-rate-limit");
        let mut cfg = scratch_config(&dir, "dj.jig");
        cfg.alias_rate_limits.challenge_per_ip_per_min = 2;
        let router = build_app(&cfg).expect("build_app");
        fresh_challenge(&router).await;
        fresh_challenge(&router).await;
        let (status, body) = get(&router, "/v1/challenge").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        assert_eq!(body["code"], "RATE_LIMITED");
        // Other GETs are not counted.
        assert_eq!(get(&router, "/v1/health").await.0, StatusCode::OK);
    }

    /// The limiter sits in front of the mounted register/rotate/renew
    /// handlers. Requests with forged proofs naming DID X are rejected by the
    /// handler and do not use up X's bucket, so X's own signed register still
    /// succeeds; with a per-DID limit of 1, the next request naming X is
    /// then refused with 429 + Retry-After before reaching a handler.
    #[tokio::test]
    async fn alias_routes_are_rate_limited_per_verified_did() {
        use base64::Engine as _;

        let dir = ScratchDir::new("alias-rate-limit");
        let mut cfg = scratch_config(&dir, "dj.jig");
        cfg.alias_rate_limits.per_did_per_min = 1;
        let app = build_app_parts(&cfg).expect("build_app_parts");
        let (router, ns_did) = (app.router, app.v0_0_2_state.ns_did_string());

        let key = jig_core::crypto::ed25519::generate_signing_key();
        let did =
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string();

        // An attacker floods forged registers naming the victim's DID.
        for i in 1..=5 {
            let challenge = fresh_challenge(&router).await;
            let resp = post_json(
                &router,
                "/v1/register",
                serde_json::json!({
                    "did": did,
                    "requested_alias": "victim",
                    "proof_of_control": "AAAA",
                    "challenge": challenge,
                }),
            )
            .await;
            assert!(
                resp.status().is_client_error() && resp.status() != StatusCode::TOO_MANY_REQUESTS,
                "forged request {i} is rejected by the handler, not the limiter: {}",
                resp.status()
            );
        }

        // The key holder's own signed register still gets through.
        let challenge = fresh_challenge(&router).await;
        let proof =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(jig_core::naming::sign_proof(
                &key,
                jig_core::naming::Action::Register,
                &ns_did,
                "victim@dj.jig",
                &challenge,
            ));
        let resp = post_json(
            &router,
            "/v1/register",
            serde_json::json!({
                "did": did,
                "requested_alias": "victim",
                "proof_of_control": proof,
                "challenge": challenge,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "verified register admitted");

        // That verified request used the DID's one slot: the next is refused.
        let resp = post_json(
            &router,
            "/v1/renew",
            serde_json::json!({
                "alias": "victim@dj.jig",
                "did": did,
                "challenge": "00",
                "proof_of_control": "AAAA",
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key("retry-after"));
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["code"], "RATE_LIMITED");
    }

    // -----------------------------------------------------------------------
    // Graceful shutdown (#438), on a real socket, over plaintext and TLS
    // -----------------------------------------------------------------------

    /// A nameserver on a real socket, with two test routes merged in:
    /// `/hang` (holds until `release`, after reporting on `started`) and
    /// `/peer` (the `ConnectInfo` the rate limiter keys on).
    struct Served {
        _dir: ScratchDir,
        addr: SocketAddr,
        tls: bool,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        cut: Option<tokio::sync::oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<Result<()>>,
        started: tokio::sync::mpsc::UnboundedReceiver<()>,
        release: Arc<tokio::sync::Notify>,
    }

    impl Served {
        async fn start(tag: &str, tls: bool, drain_ms: u64) -> Self {
            let dir = ScratchDir::new(tag);
            let mut cfg = scratch_config(&dir, "dj.jig");
            cfg.tls.enabled = tls;
            cfg.network.shutdown_drain_ms = drain_ms;
            let mut app = build_app_parts(&cfg).expect("build_app_parts");
            let (started_tx, started) = tokio::sync::mpsc::unbounded_channel();
            let release = Arc::new(tokio::sync::Notify::new());
            let held = release.clone();
            app.router = app
                .router
                .route(
                    "/hang",
                    axum::routing::get(move || {
                        let (started_tx, held) = (started_tx.clone(), held.clone());
                        async move {
                            let _ = started_tx.send(());
                            held.notified().await;
                            "released"
                        }
                    }),
                )
                .route(
                    "/peer",
                    axum::routing::get(
                        |axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<
                            SocketAddr,
                        >| async move { peer.ip().to_string() },
                    ),
                );
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
            let (cut, cut_rx) = tokio::sync::oneshot::channel::<()>();
            let task = tokio::spawn(async move {
                serve_app_until(
                    &cfg,
                    app,
                    listener,
                    async move {
                        let _ = stop_rx.await;
                    },
                    move || async move {
                        let _ = cut_rx.await;
                    },
                )
                .await
            });
            Self {
                _dir: dir,
                addr,
                tls,
                stop: Some(stop),
                cut: Some(cut),
                task,
                started,
                release,
            }
        }

        fn url(&self, path: &str) -> String {
            let scheme = if self.tls { "https" } else { "http" };
            format!("{scheme}://{}{path}", self.addr)
        }

        /// A fresh client: the self-signed certificate is trusted through the
        /// DID elsewhere (`tests/tls.rs`); these tests are about shutdown.
        fn client() -> reqwest::Client {
            reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap()
        }

        fn stop(&mut self) {
            self.stop.take().unwrap().send(()).unwrap();
        }

        async fn accepts(&self) -> bool {
            tokio::net::TcpStream::connect(self.addr).await.is_ok()
        }
    }

    /// A request in flight when the signal arrives gets its answer; a new
    /// connection is refused; the server returns once drained.
    #[tokio::test]
    async fn shutdown_finishes_the_request_in_flight_and_refuses_new_connections() {
        for tls in [false, true] {
            let mut served = Served::start("drain-finish", tls, 10_000).await;
            let url = served.url("/hang");
            let in_flight = tokio::spawn(async move { Served::client().get(url).send().await });
            served.started.recv().await.expect("/hang reached");
            served.stop();
            // Give the listener a moment to stop, then let /hang answer.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert!(!served.accepts().await, "tls={tls}: still accepting");
            served.release.notify_one();
            let answer = in_flight
                .await
                .unwrap()
                .expect("the request in flight is answered");
            assert_eq!(answer.status(), StatusCode::OK, "tls={tls}");
            assert_eq!(answer.text().await.unwrap(), "released");
            tokio::time::timeout(std::time::Duration::from_secs(5), served.task)
                .await
                .unwrap_or_else(|_| panic!("tls={tls}: did not return once drained"))
                .unwrap()
                .unwrap();
        }
    }

    /// A request that never finishes holds the server only until the drain
    /// runs out, or until a second signal cuts it short.
    #[tokio::test]
    async fn shutdown_is_bounded_by_the_drain_and_cut_by_a_second_signal() {
        for tls in [false, true] {
            for cut_short in [false, true] {
                let drain = if cut_short { 600_000 } else { 300 };
                let mut served = Served::start("drain-bound", tls, drain).await;
                let url = served.url("/hang");
                let _in_flight =
                    tokio::spawn(async move { Served::client().get(url).send().await });
                served.started.recv().await.expect("/hang reached");
                served.stop();
                let stopped = std::time::Instant::now();
                if cut_short {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    assert!(
                        !served.task.is_finished(),
                        "tls={tls}: the drain waits for /hang"
                    );
                    served.cut.take().unwrap().send(()).unwrap();
                }
                tokio::time::timeout(std::time::Duration::from_secs(5), &mut served.task)
                    .await
                    .unwrap_or_else(|_| panic!("tls={tls} cut={cut_short}: not bounded"))
                    .unwrap()
                    .unwrap();
                if !cut_short {
                    assert!(
                        stopped.elapsed() >= std::time::Duration::from_millis(250),
                        "tls={tls}: returned before the drain ran out"
                    );
                }
            }
        }
    }

    /// A server future dropped before its signal (a caller aborting it) takes
    /// its listener with it.
    #[tokio::test]
    async fn dropping_the_server_stops_its_listener() {
        for tls in [false, true] {
            let served = Served::start("dropped", tls, 5_000).await;
            assert!(served.accepts().await, "tls={tls}: serving");
            served.task.abort();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert!(
                !served.accepts().await,
                "tls={tls}: still accepting once dropped"
            );
        }
    }

    /// Both listeners still hand each request its peer address, which the
    /// per-IP rate limits key on (`v0_0_2_rate_limit::client_ip`).
    #[tokio::test]
    async fn the_rate_limiter_still_sees_the_peer_on_both_listeners() {
        for tls in [false, true] {
            let served = Served::start("peer", tls, 5_000).await;
            let client = Served::client();
            let peer = client.get(served.url("/peer")).send().await.unwrap();
            assert_eq!(peer.status(), StatusCode::OK, "tls={tls}");
            assert_eq!(peer.text().await.unwrap(), "127.0.0.1", "tls={tls}");
        }
    }

    #[test]
    fn v0_0_2_keyfile_defaults_to_a_sibling_of_the_nameserver_db() {
        let mut cfg = NameServerConfig::default();
        cfg.storage.database_path = std::path::PathBuf::from("/var/lib/jig-ns/nameserver.db");
        // Untouched jig-server default → derived, never ~/.jig/server/server.key.
        cfg.v0_0_2.server.server_did_keyfile =
            jig_config::v0_0_2_server::ServerSection::default().server_did_keyfile;
        assert_eq!(
            resolve_v0_0_2_keyfile(&cfg),
            "/var/lib/jig-ns/nameserver_v002.key"
        );

        cfg.v0_0_2.server.server_did_keyfile = "/etc/jig/ns.key".to_string();
        assert_eq!(resolve_v0_0_2_keyfile(&cfg), "/etc/jig/ns.key");
    }
}
