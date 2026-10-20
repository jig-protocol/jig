//! HTTP server for Jig Nameserver

use crate::config::NameServerConfig;
use crate::error::{NameServerError, Result};
use crate::identity::{get_or_create as ns_get_or_create, ns_id_from_pubkey};
use crate::storage::{MemoryStorage, NamesStorage, SqliteStorage};
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use std::sync::Arc;

pub struct AppState {
    pub cfg: NameServerConfig,
    pub storage: Arc<dyn NamesStorage>,
    pub ns_id: String,
    pub ns_pubkey_hex: String,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            storage: Arc::clone(&self.storage),
            ns_id: self.ns_id.clone(),
            ns_pubkey_hex: self.ns_pubkey_hex.clone(),
        }
    }
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
    ns_id: String,
    endpoints: serde_json::Value,
    policy: serde_json::Value,
}

async fn well_known(State(state): State<AppState>) -> Result<Json<WellKnownNsInfo>> {
    let ns_id = state.ns_id.clone();
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
        "public_key": state.ns_pubkey_hex,
    });
    Ok(Json(WellKnownNsInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        ns_id,
        endpoints,
        policy,
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
}

/// jig-server's keyfile default (`~/.jig/server/server.key`) belongs to the
/// chat server. A nameserver signing alias attestations with that key would
/// attest under the chat server's DID, so treat the untouched default (and an
/// empty string) as "operator did not choose" and derive a sibling of the
/// nameserver database instead.
fn resolve_v0_0_2_keyfile(cfg: &NameServerConfig) -> String {
    let configured = cfg.v0_0_2.server.server_did_keyfile.trim();
    let jig_server_default = jig_config::v0_0_2_server::ServerSection::default().server_did_keyfile;
    if !configured.is_empty() && configured != jig_server_default {
        return configured.to_string();
    }
    db_sibling(&cfg.storage.database_path, "_v002.key")
        .to_string_lossy()
        .into_owned()
}

/// Alias attestations live in `jig_pipeline::persist::SqliteStore`, a different
/// database from the legacy `SqliteStorage`. Derive it as a sibling of the
/// configured DB so a one-line deploy needs no extra path (mirrors the
/// `_v002.db` convention in jig-server's `main.rs`).
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
    // Prefer persistent SQLite storage using configured DB path
    let storage: Arc<dyn NamesStorage> = match SqliteStorage::new(cfg.storage.database_path.clone())
    {
        Ok(sqlite) => Arc::new(sqlite),
        Err(e) => {
            tracing::warn!("sqlite init failed ({}), falling back to memory storage", e);
            Arc::new(MemoryStorage::default())
        }
    };
    // Initialize nameserver identity (ed25519)
    let ns_identity = ns_get_or_create(&cfg.storage.database_path)?;
    let ns_pubkey_hex = hex::encode(ns_identity.public_key.as_bytes());
    let ns_id = ns_id_from_pubkey(&ns_identity.public_key);

    let state = AppState {
        cfg: cfg.clone(),
        storage,
        ns_id,
        ns_pubkey_hex,
    };

    let mut v0_0_2_cfg = cfg.v0_0_2.clone();
    v0_0_2_cfg.server.server_did_keyfile = resolve_v0_0_2_keyfile(cfg);
    let mut v0_0_2_state = crate::v0_0_2::AppState::new(
        v0_0_2_cfg,
        db_sibling(&cfg.storage.database_path, "_v002.db"),
        crate::v0_0_2_policy::Suffixes::from_config(&cfg.v0_0_2.nameserver)?,
    )?;
    v0_0_2_state.max_pending_challenges = cfg.alias_rate_limits.max_pending_challenges;
    let v0_0_2_state = Arc::new(v0_0_2_state);

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

    Ok(NameServerApp {
        router,
        v0_0_2_state,
    })
}

/// Load config, apply the CLI overrides, and serve. `bind_override` /
/// `port_override` come from `jig-nameserver serve --bind/--port` and win over
/// both the config file and `JIG_NS_BIND`/`JIG_NS_PORT`, which `load` has
/// already applied.
pub async fn run_http_server(
    bind_override: Option<String>,
    port_override: Option<u16>,
) -> Result<()> {
    let mut cfg = NameServerConfig::load()?;
    if let Some(bind) = bind_override {
        cfg.network.bind = bind;
    }
    if let Some(port) = port_override {
        cfg.network.port = port;
    }

    let app = build_app(&cfg)?;

    let addr = format!("{}:{}", cfg.network.bind, cfg.network.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| NameServerError::Other(e.into()))?;
    tracing::info!("nameserver listening on {}", addr);
    let make_svc = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    axum::serve(listener, make_svc)
        .await
        .map_err(|e| NameServerError::Other(e.into()))
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
        cfg.v0_0_2.nameserver.alias_suffixes =
            vec![jig_config::v0_0_2_server::SuffixConfig::new(alias_suffix)];
        cfg.v0_0_2.server.server_did_keyfile = dir.0.join("ns.key").to_string_lossy().into_owned();
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
            storage: Arc::new(MemoryStorage::default()),
            ns_id: "test".into(),
            ns_pubkey_hex: String::new(),
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
        assert_eq!(
            keys,
            [
                "alias_rate_limits",
                "automation",
                "public_key",
                "reputation",
            ]
        );
        assert_eq!(
            policy["alias_rate_limits"],
            serde_json::json!({ "enabled": true, "per_ip_per_min": 7, "per_did_per_min": 3 })
        );
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
