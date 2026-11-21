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

    pub async fn start(&self) -> Result<()> {
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

        if self.config.tls.enabled {
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
            serve_tls(listener, router, rustls_config, proxy).await?;
        } else {
            tracing::info!("HTTP API listening on http://{}", listener.local_addr()?);
            match proxy {
                // Without PROXY protocol, axum's own server, exactly as before.
                None => axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .map_err(|e| ServerError::Server(format!("HTTP server error: {e}")))?,
                Some(proxy) => serve_plain(listener, router, proxy).await,
            }
        }

        Ok(())
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
async fn serve_tls(
    listener: TcpListener,
    router: Router,
    rustls_config: RustlsServerConfig,
    proxy: Option<Arc<crate::proxy_protocol::ProxyProtocol>>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(rustls_config));
    loop {
        let (mut tcp, peer) = listener
            .accept()
            .await
            .map_err(|e| ServerError::Server(format!("accept error: {e}")))?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let Some(peer) = client_addr(proxy.as_deref(), &mut tcp, peer).await else {
                return;
            };
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("TLS handshake failed: {e}");
                    return;
                }
            };
            let exporter = TlsExporter::of(tls.get_ref().1);
            let io = TokioIo::new(tls);
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
            if let Err(e) = AutoBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                tracing::debug!("connection error: {e}");
            }
        });
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

/// Plain HTTP with PROXY protocol: [`serve_tls`]'s accept loop without the
/// TLS step. Accept errors are handled as `axum::serve` handles them, by
/// waiting a second, so running out of file descriptors does not end the
/// server. Without PROXY protocol the plain listener stays on `axum::serve`.
async fn serve_plain(
    listener: TcpListener,
    router: Router,
    proxy: Arc<crate::proxy_protocol::ProxyProtocol>,
) -> ! {
    loop {
        let (mut tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::error!("accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        let router = router.clone();
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let Some(peer) = client_addr(Some(&proxy), &mut tcp, peer).await else {
                return;
            };
            let service = hyper::service::service_fn(
                move |mut req: hyper::Request<hyper::body::Incoming>| {
                    req.extensions_mut()
                        .insert(axum::extract::ConnectInfo(peer));
                    router.clone().oneshot(req)
                },
            );
            if let Err(e) = AutoBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(tcp), service)
                .await
            {
                tracing::debug!("connection error: {e}");
            }
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
            let _ = serve_tls(listener, router, rustls_config, None).await;
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
            let _ = serve_tls(listener, router, rustls_config, None).await;
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
            let _ = serve_tls(listener, router, rustls_config, None).await;
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
            trusting(&["127.0.0.1"]),
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
            trusting(&["10.0.0.5"]),
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
                let _ = serve_tls(listener, router, rustls_config, Some(proxy)).await;
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
}
