//! Main Jig server orchestration.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tower::ServiceExt; // oneshot

use crate::config::ServerConfig;
use crate::error::{Result, ServerError};
use crate::handler::{self, AppState};
use crate::runtime::BlockRuntime;
use crate::storage::SqliteBlockStore;

pub struct JigServer {
    config: ServerConfig,
    store: Arc<SqliteBlockStore>,
    runtime: Arc<BlockRuntime>,
    /// v0.0.2 pipeline state. `None` when only running v0.0.1 routes.
    v0_0_2: Option<Arc<crate::v0_0_2::AppState>>,
}

impl JigServer {
    pub fn new(config: ServerConfig) -> Result<Self> {
        let store = Arc::new(SqliteBlockStore::new(&config.database_path)?);
        store.health_check()?;

        let runtime = Arc::new(BlockRuntime::new(config.execution_config())?);

        Ok(Self {
            config,
            store,
            runtime,
            v0_0_2: None,
        })
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
        let store = Arc::new(SqliteBlockStore::new(&config.database_path)?);
        store.health_check()?;

        let runtime = Arc::new(BlockRuntime::new(config.execution_config())?);

        Ok(Self {
            config,
            store,
            runtime,
            v0_0_2,
        })
    }

    pub async fn start(&self) -> Result<()> {
        tracing::info!(
            "Starting Jig server on {}:{}",
            self.config.bind_address,
            self.config.port
        );

        let app_state = AppState {
            store: self.store.clone(),
            runtime: self.runtime.clone(),
            config: self.config.clone(),
            v0_0_2: self.v0_0_2.clone(),
        };

        let main_router: Router = handler::build_router(app_state);

        // Merge the v0.0.2 WSS router when the pipeline state is present.
        // The v0.0.2 routes have their own AppState (Arc<v0_0_2::AppState>)
        // and do not conflict with any existing v0.0.1 routes.
        let router = if let Some(v002_state) = &self.v0_0_2 {
            main_router.merge(crate::v0_0_2_ws::build_v0_0_2_router(v002_state.clone()))
        } else {
            main_router
        };

        let addr: SocketAddr = format!("{}:{}", self.config.bind_address, self.config.port)
            .parse()
            .map_err(|e| ServerError::Config(format!("invalid bind address: {e}")))?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ServerError::Server(format!("binding {addr}: {e}")))?;

        if self.config.tls.enabled {
            let (cert, key) = self
                .config
                .tls
                .resolved_paths()
                .map_err(ServerError::Config)?;
            let rustls_config = load_rustls_config(cert, key)?;
            tracing::info!(
                "HTTPS (rustls) listening on https://{}",
                listener.local_addr()?
            );
            serve_tls(listener, router, rustls_config).await?;
        } else {
            tracing::info!("HTTP API listening on http://{}", listener.local_addr()?);
            axum::serve(listener, router)
                .await
                .map_err(|e| ServerError::Server(format!("HTTP server error: {e}")))?;
        }

        Ok(())
    }
}

/// Load a PEM cert chain + private key and build a rustls 0.22 ServerConfig.
/// ALPN advertises only http/1.1 — it carries everything the edge needs today
/// (Resend's inbound webhook POST plus client/federation WSS, which upgrade
/// over http/1.1), so HTTP/2 is a deferred optimization rather than a
/// requirement. Uses rustls 0.22's default `ring` provider (same as the
/// federation client config in v0_0_2_federation_tls).
fn load_rustls_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<RustlsServerConfig> {
    // PEM parsing via rustls-pki-types rather than rustls-pemfile: the latter is
    // unmaintained (RUSTSEC-2025-0134) and was only ever a thin wrapper over
    // these same types. This also drops the manual File/BufReader dance.
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| ServerError::Config(format!("opening TLS cert {}: {e}", cert_path.display())))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Config(format!("parsing TLS cert: {e}")))?;
    if certs.is_empty() {
        return Err(ServerError::Config(format!(
            "no certificates in {}",
            cert_path.display()
        )));
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| ServerError::Config(format!("reading TLS key {}: {e}", key_path.display())))?;
    let mut config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ServerError::Config(format!("building rustls config: {e}")))?;
    // http/1.1 only: it carries the webhook POST and the WSS upgrades, so
    // HTTP/2 multiplexing isn't needed for the MVP edge (deferred).
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Serve `router` over rustls on an already-bound TcpListener. Each accepted
/// TCP connection is handed to its own task that performs the TLS handshake
/// (so a slow handshake can't block accept) and serves it via hyper-util's
/// auto (http1/http2) builder WITH upgrade support (required for WSS).
async fn serve_tls(
    listener: TcpListener,
    router: Router,
    rustls_config: RustlsServerConfig,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(rustls_config));
    loop {
        let (tcp, _peer) = listener
            .accept()
            .await
            .map_err(|e| ServerError::Server(format!("accept error: {e}")))?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("TLS handshake failed: {e}");
                    return;
                }
            };
            let io = TokioIo::new(tls);
            let service =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    router.clone().oneshot(req)
                });
            if let Err(e) = AutoBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
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
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        config.bind_address = "127.0.0.1".into();

        config.port = 0;

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
        let key_pem = ck.key_pair.serialize_pem();
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let rustls_config = load_rustls_config(&cert_path, &key_path).expect("rustls config");
        let router: Router = Router::new().route("/.well-known/jig", get(|| async { "ok" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();

        let task = tokio::spawn(async move {
            let _ = serve_tls(listener, router, rustls_config).await;
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
}
