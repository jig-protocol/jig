//! Main Jig server orchestration.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tower::ServiceExt; // oneshot

use crate::config::ServerConfig;
use crate::error::{Result, ServerError};
use crate::handler::{self, AppState};

/// The TLS session's exporter value for the jig handshake (JEP-0002 rule 2,
/// RFC 9266). [`serve_tls`] puts it in every request it serves, so the
/// WebSocket handshake can sign it; a plaintext request has none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsExporter(pub [u8; jig_pipeline::handshake::TLS_EXPORTER_LEN]);

impl TlsExporter {
    fn of(conn: &rustls::ServerConnection) -> Option<Self> {
        conn.export_keying_material(
            [0u8; jig_pipeline::handshake::TLS_EXPORTER_LEN],
            jig_pipeline::handshake::TLS_EXPORTER_LABEL,
            None,
        )
        .map(Self)
        .map_err(|e| tracing::warn!("TLS exporter unavailable: {e}"))
        .ok()
    }
}

pub struct JigServer {
    config: ServerConfig,
    /// v0.0.2 pipeline state. `None` when the module failed to initialize.
    v0_0_2: Option<Arc<crate::v0_0_2::AppState>>,
}

/// Boot-time check that used to run while building the v0.0.1 REST state:
/// the `[execution]` limits make a valid runtime. Kept so that removing those
/// routes does not also change which configs boot.
fn boot_checks(config: &ServerConfig) -> Result<()> {
    jig_runtime::component::ComponentRuntime::with_config(
        &crate::v0_0_2::runtime_config_from(&config.execution_config()),
        jig_runtime::component::Backend::Native,
    )
    .map_err(|e| ServerError::Runtime(format!("failed to create jig-runtime: {e}")))?;
    crate::v0_0_2_limits::Limits::validate(&config.limits).map_err(ServerError::Config)?;
    let drain = config.server.shutdown_drain_ms;
    if drain > jig_config::v0_0_2_server::MAX_SHUTDOWN_DRAIN_MS {
        return Err(ServerError::Config(format!(
            "[server] shutdown_drain_ms = {drain} is over the {} ms maximum",
            jig_config::v0_0_2_server::MAX_SHUTDOWN_DRAIN_MS
        )));
    }
    Ok(())
}

impl JigServer {
    pub fn new(config: ServerConfig) -> Result<Self> {
        Self::new_with_v0_0_2(config, None)
    }

    /// Construct a JigServer with the v0.0.2 pipeline state wired in. When
    /// `v0_0_2` is `Some(...)`, the `/.well-known/jig` handler emits the
    /// v0.0.2 discovery fields (server_did, unsafe_options_active,
    /// allowed_block_kinds, peers) so federated peers can detect
    /// misconfigured neighbors (spec §6.6).
    pub fn new_with_v0_0_2(
        config: ServerConfig,
        v0_0_2: Option<Arc<crate::v0_0_2::AppState>>,
    ) -> Result<Self> {
        boot_checks(&config)?;
        Ok(Self { config, v0_0_2 })
    }

    /// Serve until SIGTERM or SIGINT, then shut down gracefully (#424): stop
    /// accepting, drain in-flight requests and WebSocket sessions within
    /// `[server] shutdown_drain_ms`, and return. A second signal cuts the
    /// drain short.
    pub async fn start(&self) -> Result<()> {
        // Registered before anything is bound: from here a SIGTERM stops the
        // server gracefully rather than killing it.
        let (stop, cut) = crate::shutdown::signals();
        self.serve_until(stop, move || cut).await
    }

    /// [`JigServer::start`] with the signals as futures: `stop` starts the
    /// shutdown, and `cut`, called once it has, ends the drain early.
    pub async fn serve_until<S, C, CF>(&self, stop: S, cut: C) -> Result<()>
    where
        S: std::future::Future<Output = ()>,
        C: FnOnce() -> CF,
        CF: std::future::Future<Output = ()>,
    {
        tracing::info!(
            "Starting Jig server on {}:{}",
            self.config.bind_address,
            self.config.port
        );

        let app_state = AppState {
            config: self.config.clone(),
            v0_0_2: self.v0_0_2.clone(),
        };

        let main_router: Router = handler::build_router(app_state);

        // Merge the v0.0.2 WSS router when the pipeline state is present.
        // The v0.0.2 routes have their own AppState (Arc<v0_0_2::AppState>).
        let router = if let Some(v002_state) = &self.v0_0_2 {
            main_router.merge(crate::v0_0_2_ws::build_v0_0_2_router(v002_state.clone()))
        } else {
            main_router
        };
        // `[limits] max_request_body_bytes` on every route, the v0.0.1 ones
        // included, rather than axum's implicit default.
        let router = router.layer(axum::extract::DefaultBodyLimit::max(
            crate::v0_0_2_limits::Limits::resolve(&self.config.limits).request_body,
        ));
        let drain = std::time::Duration::from_millis(self.config.server.shutdown_drain_ms);

        let addr: SocketAddr = format!("{}:{}", self.config.bind_address, self.config.port)
            .parse()
            .map_err(|e| ServerError::Config(format!("invalid bind address: {e}")))?;

        let proxy =
            crate::proxy_protocol::ProxyProtocol::from_config(&self.config.server.proxy_protocol)
                .map_err(ServerError::Config)?
                .map(Arc::new);
        if let Some(proxy) = &proxy {
            let trusted: Vec<String> = proxy.trusted().iter().map(|n| n.to_string()).collect();
            tracing::info!(
                trusted = %trusted.join(", "),
                "PROXY protocol v2 required from these proxies; their connections are served \
                 under the client address the header names"
            );
        }

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ServerError::Server(format!("binding {addr}: {e}")))?;

        let tls = if self.config.tls.enabled {
            let data_dir = self
                .config
                .database_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            let (cert, key) = self
                .config
                .tls
                .material(data_dir, &self.config.tls_names())
                .map_err(ServerError::Config)?;
            let (rustls_config, leaf) = load_rustls_config(&cert, &key)?;
            match &self.v0_0_2 {
                Some(v0_0_2) => v0_0_2.bind_tls_certificate(leaf.as_ref()),
                None => tracing::warn!(
                    "no v0.0.2 module, so no server DID vouches for {}: jig clients will \
                     accept it only if a CA issued it",
                    cert.display()
                ),
            }
            tracing::info!(
                "HTTPS (rustls) listening on https://{}",
                listener.local_addr()?
            );
            Some(rustls_config)
        } else {
            tracing::info!("HTTP API listening on http://{}", listener.local_addr()?);
            None
        };

        serve_listener(listener, router, tls, proxy, drain, stop, cut).await
    }
}

/// Serve `router` on `listener` until `stop`, then shut down gracefully
/// (#424): stop accepting, drain in-flight requests and WebSocket sessions
/// within `drain` (or until `cut`), and return.
///
/// Over TLS when `tls` is set ([`serve_tls`]), else plain HTTP
/// ([`serve_plain`]); both with PROXY protocol when `proxy` is set. Each
/// connection is served by hyper-util's auto builder (HTTP/1, or HTTP/2,
/// over plain HTTP by prior knowledge) and runs as a task that a drain which
/// runs out, or is cut, ends before this future returns. An HTTP/2 stream's
/// handler, which hyper runs on a task of its own, ends once its connection
/// is cut.
pub(crate) async fn serve_listener<S, C, CF>(
    listener: TcpListener,
    router: Router,
    tls: Option<RustlsServerConfig>,
    proxy: Option<Arc<crate::proxy_protocol::ProxyProtocol>>,
    drain: std::time::Duration,
    stop: S,
    cut: C,
) -> Result<()>
where
    S: std::future::Future<Output = ()>,
    C: FnOnce() -> CF,
    CF: std::future::Future<Output = ()>,
{
    // The WebSocket handler finds the shutdown signal here, on every path a
    // request can come in by.
    let shutdown = crate::shutdown::Shutdown::new();
    let router = router.layer(axum::Extension(shutdown.clone()));

    let mut listening: tokio::task::JoinHandle<Result<()>> = match (tls, proxy) {
        (Some(rustls_config), proxy) => shutdown.spawn(serve_tls(
            listener,
            router,
            rustls_config,
            proxy,
            shutdown.clone(),
        )),
        (None, proxy) => {
            let watched = shutdown.clone();
            shutdown.spawn(async move {
                serve_plain(listener, router, proxy, watched).await;
                Ok(())
            })
        }
    };

    // The listener lives no longer than this future: dropped early (a caller
    // aborting it), or returning once the drain has run out or been cut, it
    // stops accepting and frees the port rather than serving on detached.
    let _listener_lifetime = AbortOnDrop(listening.abort_handle());

    // Serve until the signal, or until the listener fails.
    tokio::pin!(stop);
    tokio::select! {
        served = &mut listening => {
            return match served {
                Ok(result) => result,
                Err(e) => Err(ServerError::Server(format!("listener task failed: {e}"))),
            };
        }
        () = &mut stop => {}
    }
    shutdown.begin();
    tracing::info!(
        in_flight = shutdown.in_flight(),
        drain_ms = drain.as_millis() as u64,
        "shutting down: no new connections; draining in-flight requests and closing \
         WebSocket sessions (1001)"
    );
    let drained = tokio::select! {
        drained = shutdown.drain(drain) => {
            if drained {
                tracing::info!("shutdown complete: every connection drained");
            } else {
                tracing::warn!(
                    still_open = shutdown.in_flight(),
                    "shutdown drain ran out; cutting what is still open"
                );
            }
            drained
        }
        () = cut() => {
            tracing::warn!(
                still_open = shutdown.in_flight(),
                "second signal: cutting the drain short"
            );
            false
        }
    };
    // What is still open is cut here, not left to the runtime's end: an
    // embedder that keeps its runtime running gets nothing back.
    if !drained && !shutdown.cut(CUT_WAIT).await {
        tracing::warn!(
            still_open = shutdown.in_flight(),
            "connections still running after the cut"
        );
    }
    Ok(())
}

/// How long [`serve_listener`] waits for the tasks a cut ends to finish.
/// They end at their next poll; this bounds one stuck in a blocking call.
const CUT_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// Aborts a task when dropped.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// [`jig_config::tls::load_rustls_config`], with its error as a config error.
fn load_rustls_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<(RustlsServerConfig, CertificateDer<'static>)> {
    jig_config::tls::load_rustls_config(cert_path, key_path).map_err(ServerError::Config)
}

/// Serve `router` over rustls on an already-bound TcpListener. Each accepted
/// TCP connection is handed to its own task that performs the TLS handshake
/// (so a slow handshake can't block accept) and serves it via hyper-util's
/// auto (http1/http2) builder WITH upgrade support (required for WSS).
///
/// With `proxy`, a connection from a trusted proxy first gives up its PROXY
/// protocol v2 header, in its own task, and is served under the client it
/// names; without a valid one it is closed.
///
/// Once `shutdown` begins this stops accepting and returns, dropping the
/// listener. Connections still in their PROXY header or TLS handshake are
/// closed; served ones finish the request in flight ([`serve_connection`]).
async fn serve_tls(
    listener: TcpListener,
    router: Router,
    rustls_config: RustlsServerConfig,
    proxy: Option<Arc<crate::proxy_protocol::ProxyProtocol>>,
    shutdown: crate::shutdown::Shutdown,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(rustls_config));
    loop {
        let (mut tcp, peer) = tokio::select! {
            accepted = listener.accept() => {
                accepted.map_err(|e| ServerError::Server(format!("accept error: {e}")))?
            }
            () = shutdown.cancelled() => return Ok(()),
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        let proxy = proxy.clone();
        let watched = shutdown.clone();
        shutdown.spawn_cut(async move {
            let shutdown = watched;
            let handshake = async {
                let peer = client_addr(proxy.as_deref(), &mut tcp, peer).await?;
                match acceptor.accept(tcp).await {
                    Ok(tls) => Some((peer, tls)),
                    Err(e) => {
                        tracing::debug!("TLS handshake failed: {e}");
                        None
                    }
                }
            };
            let accepted = tokio::select! {
                done = handshake => done,
                () = shutdown.cancelled() => None,
            };
            let Some((peer, tls)) = accepted else {
                return;
            };
            let exporter = TlsExporter::of(tls.get_ref().1);
            let service = hyper::service::service_fn(
                move |mut req: hyper::Request<hyper::body::Incoming>| {
                    // What `into_make_service_with_connect_info` gives the
                    // plain listener: the per-address rate limit needs it.
                    req.extensions_mut()
                        .insert(axum::extract::ConnectInfo(peer));
                    if let Some(exporter) = exporter {
                        req.extensions_mut().insert(exporter);
                    }
                    router.clone().oneshot(req)
                },
            );
            serve_connection(TokioIo::new(tls), service, &shutdown).await;
        });
    }
}

/// Serve one connection until it ends. Once `shutdown` begins, hyper's own
/// graceful shutdown lets the request in flight finish and then closes:
/// HTTP/1 stops keeping the connection alive, HTTP/2 sends GOAWAY. A
/// connection upgraded to a WebSocket is the session's from then on; the
/// session closes itself with 1001 (`v0_0_2_ws::handle_socket`). A cut ends
/// the connection's task; an HTTP/2 stream's handler ends with it, as hyper
/// drops a stream whose connection is gone.
async fn serve_connection<I, S, B>(io: I, service: S, shutdown: &crate::shutdown::Shutdown)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: hyper::service::Service<
            hyper::Request<hyper::body::Incoming>,
            Response = hyper::Response<B>,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let builder = AutoBuilder::new(TokioExecutor::new());
    let conn = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(conn);
    let served = tokio::select! {
        served = conn.as_mut() => served,
        () = shutdown.cancelled() => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    if let Err(e) = served {
        tracing::debug!("connection error: {e}");
    }
}

/// The address to serve `tcp` under: `peer`, or with `proxy` the client a
/// trusted proxy's PROXY header names. `None` closes the connection.
async fn client_addr(
    proxy: Option<&crate::proxy_protocol::ProxyProtocol>,
    tcp: &mut tokio::net::TcpStream,
    peer: SocketAddr,
) -> Option<SocketAddr> {
    let Some(proxy) = proxy else {
        return Some(peer);
    };
    match proxy.client_addr(tcp, peer).await {
        Ok(client) => Some(client),
        Err(e) => {
            tracing::info!(proxy = %peer, error = %e, "PROXY header refused; connection closed");
            None
        }
    }
}

/// Plain HTTP: [`serve_tls`]'s accept loop without the TLS step, with PROXY
/// protocol when `proxy` is set. Accept errors are handled as `axum::serve`
/// handles them, by waiting a second, so running out of file descriptors
/// does not end the server. Returns once `shutdown` begins, as [`serve_tls`]
/// does.
async fn serve_plain(
    listener: TcpListener,
    router: Router,
    proxy: Option<Arc<crate::proxy_protocol::ProxyProtocol>>,
    shutdown: crate::shutdown::Shutdown,
) {
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = shutdown.cancelled() => return,
        };
        let (mut tcp, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::error!("accept error: {e}");
                tokio::select! {
                    () = tokio::time::sleep(std::time::Duration::from_secs(1)) => continue,
                    () = shutdown.cancelled() => return,
                }
            }
        };
        let router = router.clone();
        let proxy = proxy.clone();
        let watched = shutdown.clone();
        shutdown.spawn_cut(async move {
            let shutdown = watched;
            let peer = tokio::select! {
                peer = client_addr(proxy.as_deref(), &mut tcp, peer) => peer,
                () = shutdown.cancelled() => None,
            };
            let Some(peer) = peer else {
                return;
            };
            let service = hyper::service::service_fn(
                move |mut req: hyper::Request<hyper::body::Incoming>| {
                    req.extensions_mut()
                        .insert(axum::extract::ConnectInfo(peer));
                    router.clone().oneshot(req)
                },
            );
            serve_connection(TokioIo::new(tcp), service, &shutdown).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn server_initializes() {
        let dir = tempdir().unwrap();
        let config = ServerConfig {
            database_path: dir.path().join("test.db"),
            bind_address: "127.0.0.1".into(),
            port: 0,
            ..Default::default()
        };

        let server = JigServer::new(config.clone()).expect("server");

        let handle = tokio::spawn(async move { server.start().await });

        tokio::time::sleep(Duration::from_millis(50)).await;

        if handle.is_finished() {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(ServerError::Io(err)))
                    if err.kind() == std::io::ErrorKind::PermissionDenied => {}
                Ok(Err(err)) => panic!("server failed to start: {err:?}"),
                Err(join_err) => panic!("server task join error: {join_err:?}"),
            }
        } else {
            handle.abort();
            if let Err(join_err) = handle.await {
                assert!(
                    join_err.is_cancelled(),
                    "server task unexpected state: {join_err:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn serve_tls_completes_https_round_trip() {
        use axum::routing::get;

        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let cert_pem = ck.cert.pem();
        let key_pem = ck.signing_key.serialize_pem();
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let (rustls_config, _) = load_rustls_config(&cert_path, &key_path).expect("rustls config");
        let router: Router = Router::new().route("/.well-known/jig", get(|| async { "ok" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();

        let task = tokio::spawn(async move {
            let _ = serve_tls(
                listener,
                router,
                rustls_config,
                None,
                crate::shutdown::Shutdown::new(),
            )
            .await;
        });

        // use_rustls_tls: force the reqwest 0.11 client onto the rustls backend
        // so it talks to our rustls 0.22 server (the default on macOS is
        // native-tls / Security.framework which rejects self-signed certs even
        // when danger_accept_invalid_certs is set at the hyper layer).
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let resp = client
            .get(format!("https://{bound}/.well-known/jig"))
            .send()
            .await
            .expect("https request");
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), "ok");

        task.abort();
    }

    /// Over TLS a welcome is bound to the session it was signed on (JEP-0002
    /// rule 12): a client on that session accepts it, a dialer proves its DID
    /// over it, and a welcome checked against another session's value, as a
    /// relay that terminates TLS would present it, is refused.
    #[tokio::test]
    async fn a_welcome_over_tls_is_bound_to_its_session() {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .expect("self-signed cert");
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, ck.cert.pem()).unwrap();
        std::fs::write(&key_path, ck.signing_key.serialize_pem()).unwrap();
        let (rustls_config, _) = load_rustls_config(&cert_path, &key_path).expect("rustls config");

        let state = Arc::new(crate::v0_0_2::AppState::for_test().unwrap());
        let server_did = state.server_did.to_did_jig_string();
        let router = crate::v0_0_2_ws::build_v0_0_2_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = serve_tls(
                listener,
                router,
                rustls_config,
                None,
                crate::shutdown::Shutdown::new(),
            )
            .await;
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ck.cert.der().clone()).unwrap();
        let client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let identity = jig_client::Identity::generate_for_tests(dir.path());
        let client = jig_client::Client::connect_with_tls(
            &format!("wss://{bound}"),
            identity,
            jig_pipeline::handshake::ClientOffer::default(),
            Some(client_config.clone()),
        )
        .await
        .expect("a client on the session the welcome was signed on accepts it");
        assert_eq!(
            client.welcome().unwrap().tls_exporter.len(),
            jig_pipeline::handshake::TLS_EXPORTER_LEN
        );

        let dial = || async {
            let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
                format!("wss://{bound}/api/v1/ws"),
                None,
                false,
                Some(tokio_tungstenite::Connector::Rustls(client_config.clone())),
            )
            .await
            .unwrap();
            ws
        };
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let mut ws = dial().await;
        let exporter = crate::v0_0_2_federation::tls_exporter_of(ws.get_ref());
        crate::v0_0_2_federation::complete_peer_handshake(&mut ws, &server_did, &exporter, &key)
            .await
            .expect("a dialer proves its DID over the session");

        let mut ws = dial().await;
        let elsewhere = [7u8; jig_pipeline::handshake::TLS_EXPORTER_LEN];
        let err = crate::v0_0_2_federation::complete_peer_handshake(
            &mut ws,
            &server_did,
            &elsewhere,
            &key,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("another TLS session"), "{err}");

        task.abort();
    }

    /// Every request over TLS carries its session's exporter value: one value
    /// per session, so two connections never share one.
    #[tokio::test]
    async fn serve_tls_hands_each_session_its_exporter() {
        use axum::Extension;
        use axum::routing::get;

        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, ck.cert.pem()).unwrap();
        std::fs::write(&key_path, ck.signing_key.serialize_pem()).unwrap();

        let (rustls_config, _) = load_rustls_config(&cert_path, &key_path).expect("rustls config");
        let router: Router = Router::new().route(
            "/exporter",
            get(|exporter: Option<Extension<TlsExporter>>| async move {
                exporter
                    .map(|Extension(e)| hex::encode(e.0))
                    .unwrap_or_default()
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = serve_tls(
                listener,
                router,
                rustls_config,
                None,
                crate::shutdown::Shutdown::new(),
            )
            .await;
        });

        // Trust exactly the server's own certificate, by name, so the check
        // stays on.
        let root = reqwest::Certificate::from_pem(ck.cert.pem().as_bytes()).unwrap();
        let mut seen = Vec::new();
        for _ in 0..2 {
            // A fresh client per request, so each one is its own TLS session.
            let client = reqwest::Client::builder()
                .use_rustls_tls()
                .tls_built_in_root_certs(false)
                .add_root_certificate(root.clone())
                .resolve("localhost", bound)
                .build()
                .unwrap();
            let body = client
                .get(format!("https://localhost:{}/exporter", bound.port()))
                .send()
                .await
                .expect("https request")
                .text()
                .await
                .unwrap();
            assert_eq!(
                body.len(),
                2 * jig_pipeline::handshake::TLS_EXPORTER_LEN,
                "{body:?}"
            );
            seen.push(body);
        }
        assert_ne!(seen[0], seen[1]);

        task.abort();
    }

    /// A router that answers with the address a request is served under, as
    /// `per_ip_rate` and the REST relay-slot key read it.
    fn addr_router() -> Router {
        use axum::routing::get;
        Router::new().route(
            "/addr",
            get(|extensions: axum::http::Extensions| async move {
                let ip = crate::v0_0_2_ws::client_ip(&extensions);
                format!(
                    "ip={} slot={}",
                    ip.map(|ip| ip.to_string()).unwrap_or_default(),
                    crate::v0_0_2_relay::rest_caller(ip, "did:jig:zauthor")
                )
            }),
        )
    }

    fn trusting(entries: &[&str]) -> Arc<crate::proxy_protocol::ProxyProtocol> {
        Arc::new(
            crate::proxy_protocol::ProxyProtocol::from_config(
                &jig_config::v0_0_2_server::ProxyProtocolSection {
                    trusted: entries.iter().map(|e| e.to_string()).collect(),
                    header_timeout_ms: 2_000,
                },
            )
            .unwrap()
            .unwrap(),
        )
    }

    const GET_ADDR: &[u8] = b"GET /addr HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";

    fn client_header(server: SocketAddr) -> Vec<u8> {
        crate::proxy_protocol::tests::v2_header("198.51.100.7:40000".parse().unwrap(), server, 0)
    }

    /// Write `prefix`, then read everything the server sends until it closes.
    async fn exchange(server: SocketAddr, prefix: &[u8]) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut tcp = tokio::net::TcpStream::connect(server).await.unwrap();
        tcp.write_all(prefix).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), tcp.read_to_end(&mut out))
            .await
            .expect("the server closes the connection");
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn plain_http_behind_a_trusted_proxy_serves_the_client_it_names() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_plain(
            listener,
            addr_router(),
            Some(trusting(&["127.0.0.1"])),
            crate::shutdown::Shutdown::new(),
        ));

        let mut request = client_header(bound);
        request.extend_from_slice(GET_ADDR);
        let answer = exchange(bound, &request).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(
            answer.ends_with("ip=198.51.100.7 slot=rest:ip:198.51.100.7"),
            "the per-address limit and the relay slot count the client: {answer}"
        );

        // Fails closed: a trusted proxy's connection without a header is
        // closed unanswered, never served as the proxy.
        assert_eq!(exchange(bound, GET_ADDR).await, "");

        task.abort();
    }

    #[tokio::test]
    async fn a_proxy_header_from_an_untrusted_peer_is_never_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_plain(
            listener,
            addr_router(),
            Some(trusting(&["10.0.0.5"])),
            crate::shutdown::Shutdown::new(),
        ));

        // Not a trusted proxy: served as itself.
        let answer = exchange(bound, GET_ADDR).await;
        assert!(
            answer.ends_with("ip=127.0.0.1 slot=rest:ip:127.0.0.1"),
            "{answer}"
        );
        // Its PROXY header is just bytes in front of the request, which HTTP refuses.
        let mut spoofed = client_header(bound);
        spoofed.extend_from_slice(GET_ADDR);
        let answer = exchange(bound, &spoofed).await;
        assert!(!answer.contains("198.51.100.7"), "{answer}");
        assert!(!answer.starts_with("HTTP/1.1 200"), "{answer}");

        task.abort();
    }

    /// The TLS listener reads the header before the handshake, and only from a
    /// trusted proxy: from anyone else it breaks the handshake.
    #[tokio::test]
    async fn tls_behind_a_trusted_proxy_reads_the_header_before_the_handshake() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, ck.cert.pem()).unwrap();
        std::fs::write(&key_path, ck.signing_key.serialize_pem()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ck.cert.der().clone()).unwrap();
        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        );
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

        for (trusted, served) in [("127.0.0.1", true), ("10.0.0.5", false)] {
            let (rustls_config, _) =
                load_rustls_config(&cert_path, &key_path).expect("rustls config");
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let bound = listener.local_addr().unwrap();
            let router = addr_router();
            let proxy = trusting(&[trusted]);
            let task = tokio::spawn(async move {
                let _ = serve_tls(
                    listener,
                    router,
                    rustls_config,
                    Some(proxy),
                    crate::shutdown::Shutdown::new(),
                )
                .await;
            });

            let mut tcp = tokio::net::TcpStream::connect(bound).await.unwrap();
            tcp.write_all(&client_header(bound)).await.unwrap();
            let tls = connector.connect(name.clone(), tcp).await;
            if !served {
                assert!(tls.is_err(), "a header from an untrusted peer breaks TLS");
                task.abort();
                continue;
            }
            let mut tls = tls.expect("the handshake follows the header");
            tls.write_all(GET_ADDR).await.unwrap();
            let mut out = Vec::new();
            let _ = tls.read_to_end(&mut out).await;
            let answer = String::from_utf8_lossy(&out);
            assert!(
                answer.ends_with("ip=198.51.100.7 slot=rest:ip:198.51.100.7"),
                "{answer}"
            );
            task.abort();
        }
    }

    // ---- graceful shutdown (#424) ------------------------------------------

    #[test]
    fn a_drain_over_the_maximum_refuses_the_boot() {
        let dir = tempdir().unwrap();
        let mut config = ServerConfig {
            database_path: dir.path().join("test.db"),
            ..Default::default()
        };
        config.server.shutdown_drain_ms = jig_config::v0_0_2_server::MAX_SHUTDOWN_DRAIN_MS;
        assert!(JigServer::new(config.clone()).is_ok());
        config.server.shutdown_drain_ms += 1;
        let err = JigServer::new(config).err().expect("refused");
        assert!(err.to_string().contains("shutdown_drain_ms"), "{err}");
    }

    /// The three ways a request reaches the router.
    #[derive(Clone, Copy, Debug)]
    enum Listening {
        /// Plain HTTP (`serve_plain`).
        Plain,
        /// Plain HTTP behind a trusted PROXY protocol proxy (`serve_plain`).
        Proxied,
        /// TLS (`serve_tls`).
        Tls,
    }

    trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
    impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

    struct Harness {
        bound: SocketAddr,
        tls: Option<(tokio_rustls::TlsConnector, tempfile::TempDir)>,
        mode: Listening,
    }

    impl Harness {
        /// Start `router` in `mode`, stopping on `stop`; `cut` ends the drain.
        async fn start<C, CF>(
            mode: Listening,
            router: Router,
            drain: Duration,
            stop: tokio::sync::oneshot::Receiver<()>,
            cut: C,
        ) -> (Self, tokio::task::JoinHandle<Result<()>>)
        where
            C: FnOnce() -> CF + Send + 'static,
            CF: std::future::Future<Output = ()> + Send + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let bound = listener.local_addr().unwrap();
            let (tls, rustls_config) = match mode {
                Listening::Tls => {
                    let ck =
                        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
                    let dir = tempdir().unwrap();
                    let cert = dir.path().join("cert.pem");
                    let key = dir.path().join("key.pem");
                    std::fs::write(&cert, ck.cert.pem()).unwrap();
                    std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();
                    let (server, _) = load_rustls_config(&cert, &key).unwrap();
                    let mut roots = rustls::RootCertStore::empty();
                    roots.add(ck.cert.der().clone()).unwrap();
                    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
                        rustls::crypto::ring::default_provider(),
                    ))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                    (
                        Some((tokio_rustls::TlsConnector::from(Arc::new(client)), dir)),
                        Some(server),
                    )
                }
                _ => (None, None),
            };
            let proxy = matches!(mode, Listening::Proxied).then(|| trusting(&["127.0.0.1"]));
            let task = tokio::spawn(serve_listener(
                listener,
                router,
                rustls_config,
                proxy,
                drain,
                async move {
                    let _ = stop.await;
                },
                cut,
            ));
            (Self { bound, tls, mode }, task)
        }

        /// A connection to the server, past the PROXY header and TLS as needed.
        async fn connect(&self) -> std::io::Result<Box<dyn Io>> {
            use tokio::io::AsyncWriteExt;
            let mut tcp = tokio::net::TcpStream::connect(self.bound).await?;
            if let Listening::Proxied = self.mode {
                tcp.write_all(&client_header(self.bound)).await?;
            }
            match &self.tls {
                Some((connector, _)) => {
                    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
                    Ok(Box::new(connector.connect(name, tcp).await?))
                }
                None => Ok(Box::new(tcp)),
            }
        }

        /// Whether a new connection is still accepted. A closed listener
        /// refuses the TCP connect itself.
        async fn accepts(&self) -> bool {
            tokio::net::TcpStream::connect(self.bound).await.is_ok()
        }
    }

    /// `/slow` reports that it started, then answers once released; `/hang`
    /// never answers.
    fn slow_router(
        started: tokio::sync::mpsc::UnboundedSender<()>,
        release: Arc<tokio::sync::Notify>,
    ) -> Router {
        use axum::routing::get;
        Router::new()
            .route(
                "/slow",
                get(move || async move {
                    let _ = started.send(());
                    release.notified().await;
                    "done"
                }),
            )
            .route("/hang", get(std::future::pending::<&'static str>))
    }

    /// The request is keep-alive (no `Connection: close`), so the server
    /// closing the connection after it is the graceful shutdown's doing.
    const GET_SLOW: &[u8] = b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n";
    const GET_HANG: &[u8] = b"GET /hang HTTP/1.1\r\nHost: x\r\n\r\n";

    /// On every listener: a request in flight when the signal arrives is
    /// answered, its keep-alive connection is then closed, a new connection
    /// is refused, and the server returns as soon as the drain is done.
    #[tokio::test]
    async fn shutdown_finishes_the_request_in_flight_and_refuses_new_connections() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for mode in [Listening::Plain, Listening::Proxied, Listening::Tls] {
            let (started_tx, mut started) = tokio::sync::mpsc::unbounded_channel();
            let release = Arc::new(tokio::sync::Notify::new());
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let (harness, served) = Harness::start(
                mode,
                slow_router(started_tx, release.clone()),
                Duration::from_secs(10),
                stop_rx,
                std::future::pending,
            )
            .await;

            let mut conn = harness.connect().await.unwrap();
            conn.write_all(GET_SLOW).await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), started.recv())
                .await
                .expect("the request reached the handler");

            stop_tx.send(()).unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while harness.accepts().await {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{mode:?}: still accepting after the signal"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                !served.is_finished(),
                "{mode:?}: returned with a request in flight"
            );

            release.notify_one();
            let mut out = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut out))
                .await
                .unwrap_or_else(|_| panic!("{mode:?}: the connection is closed after its answer"))
                .ok();
            let answer = String::from_utf8_lossy(&out);
            assert!(answer.starts_with("HTTP/1.1 200"), "{mode:?}: {answer}");
            assert!(answer.ends_with("done"), "{mode:?}: {answer}");

            tokio::time::timeout(Duration::from_secs(5), served)
                .await
                .unwrap_or_else(|_| panic!("{mode:?}: the drain finished"))
                .unwrap()
                .unwrap();
        }
    }

    /// A server future dropped before its signal (a caller aborting it) takes
    /// its listener with it: the port stops accepting at once.
    #[tokio::test]
    async fn dropping_the_server_stops_its_listener() {
        for mode in [Listening::Plain, Listening::Proxied, Listening::Tls] {
            let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let (harness, served) = Harness::start(
                mode,
                Router::new(),
                Duration::from_secs(5),
                stop_rx,
                std::future::pending,
            )
            .await;
            assert!(harness.accepts().await, "{mode:?}: serving");
            served.abort();
            let _ = served.await;
            assert!(
                !harness.accepts().await,
                "{mode:?}: still accepting once dropped"
            );
        }
    }

    /// Sets its flag when dropped: shows a request's handler was ended.
    struct SetOnDrop(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// `/ok` answers at once; `/watched` reports on `started` and never
    /// answers, setting `ended` when its handler is dropped.
    fn watched_router(
        started: tokio::sync::mpsc::UnboundedSender<()>,
        ended: Arc<std::sync::atomic::AtomicBool>,
    ) -> Router {
        use axum::routing::get;
        Router::new().route("/ok", get(|| async { "ok" })).route(
            "/watched",
            get(move || {
                let (started, ended) = (started.clone(), ended.clone());
                async move {
                    let _ended = SetOnDrop(ended);
                    let _ = started.send(());
                    std::future::pending::<&'static str>().await
                }
            }),
        )
    }

    /// An HTTP/2 GET over `io`, by prior knowledge (h2c on plain HTTP): the
    /// response, or `None` when the connection ended first. The response is
    /// read on its own task, so `send` returns once the request is sent.
    async fn h2_get(
        io: Box<dyn Io>,
        path: &str,
    ) -> tokio::task::JoinHandle<Option<hyper::StatusCode>> {
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            TokioIo::new(io),
        )
        .await
        .expect("h2 handshake");
        tokio::spawn(conn);
        let request = hyper::Request::get(format!("http://localhost{path}"))
            .body(String::new())
            .unwrap();
        tokio::spawn(async move { sender.send_request(request).await.ok().map(|r| r.status()) })
    }

    /// Plain HTTP still speaks HTTP/2 by prior knowledge, as `axum::serve`
    /// did, with and without PROXY protocol.
    #[tokio::test]
    async fn plain_http_answers_h2c_by_prior_knowledge() {
        for mode in [Listening::Plain, Listening::Proxied] {
            let (started, _) = tokio::sync::mpsc::unbounded_channel();
            let router = watched_router(started, Arc::default());
            let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let (harness, served) = Harness::start(
                mode,
                router,
                Duration::from_secs(5),
                stop_rx,
                std::future::pending,
            )
            .await;
            let answer = h2_get(harness.connect().await.unwrap(), "/ok").await;
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), answer)
                    .await
                    .unwrap()
                    .unwrap(),
                Some(hyper::StatusCode::OK),
                "{mode:?}"
            );
            served.abort();
        }
    }

    /// A drain that runs out ends the requests still open, over HTTP/1 on
    /// every listener and over h2c, before the server returns: nothing is
    /// left running for a caller whose runtime carries on.
    #[tokio::test]
    async fn a_drain_that_runs_out_ends_the_requests_still_open() {
        use tokio::io::AsyncWriteExt;
        let cases = [
            (Listening::Plain, false),
            (Listening::Proxied, false),
            (Listening::Tls, false),
            (Listening::Plain, true),
        ];
        for (mode, h2) in cases {
            let (started_tx, mut started) = tokio::sync::mpsc::unbounded_channel();
            let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let router = watched_router(started_tx, ended.clone());
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let (harness, served) = Harness::start(
                mode,
                router,
                Duration::from_millis(200),
                stop_rx,
                std::future::pending,
            )
            .await;
            let mut _held = None;
            let _answer = if h2 {
                Some(h2_get(harness.connect().await.unwrap(), "/watched").await)
            } else {
                let mut conn = harness.connect().await.unwrap();
                conn.write_all(b"GET /watched HTTP/1.1\r\nHost: x\r\n\r\n")
                    .await
                    .unwrap();
                _held = Some(conn);
                None
            };
            tokio::time::timeout(std::time::Duration::from_secs(5), started.recv())
                .await
                .expect("timed out waiting for the request to reach its handler")
                .expect("/watched reached");
            stop_tx.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), served)
                .await
                .unwrap_or_else(|_| panic!("{mode:?} h2={h2}: not bounded"))
                .unwrap()
                .unwrap();
            assert!(
                ended.load(std::sync::atomic::Ordering::SeqCst),
                "{mode:?} h2={h2}: the request outlived the server"
            );
        }
    }

    /// A request that never finishes holds the server only until the drain
    /// runs out, or until a second signal cuts it short.
    #[tokio::test]
    async fn shutdown_is_bounded_by_the_drain_and_cut_by_a_second_signal() {
        use tokio::io::AsyncWriteExt;
        for mode in [Listening::Plain, Listening::Proxied, Listening::Tls] {
            for cut_short in [false, true] {
                let (started_tx, _started) = tokio::sync::mpsc::unbounded_channel();
                let router = slow_router(started_tx, Arc::new(tokio::sync::Notify::new()));
                let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
                let (cut_tx, cut_rx) = tokio::sync::oneshot::channel::<()>();
                // Cut short: a drain that would outlast the test, ended by the
                // second signal. Otherwise a short drain and no second signal.
                let drain = if cut_short {
                    Duration::from_secs(600)
                } else {
                    Duration::from_millis(300)
                };
                let (harness, served) =
                    Harness::start(mode, router, drain, stop_rx, move || async {
                        let _ = cut_rx.await;
                    })
                    .await;

                let mut conn = harness.connect().await.unwrap();
                conn.write_all(GET_HANG).await.unwrap();
                // Let the request reach the router before stopping.
                tokio::time::sleep(Duration::from_millis(100)).await;
                stop_tx.send(()).unwrap();
                let stopped = tokio::time::Instant::now();
                // Held to the end of the iteration: a dropped sender would
                // resolve the cut and end every drain at once.
                let mut cut_tx = Some(cut_tx);
                if cut_short {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    assert!(!served.is_finished(), "{mode:?}: the drain waits for /hang");
                    cut_tx.take().unwrap().send(()).unwrap();
                }
                tokio::time::timeout(Duration::from_secs(5), served)
                    .await
                    .unwrap_or_else(|_| panic!("{mode:?} cut={cut_short}: not bounded"))
                    .unwrap()
                    .unwrap();
                if !cut_short {
                    assert!(
                        stopped.elapsed() >= Duration::from_millis(250),
                        "{mode:?}: returned before the drain ran out"
                    );
                }
                drop((conn, cut_tx));
            }
        }
    }
}
