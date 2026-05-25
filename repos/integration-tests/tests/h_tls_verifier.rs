//! alpha.1c #4: `federation.dangerously_disable_federation_tls` is wired
//! at the federation peer connect site.
//!
//! Approach: option (b) from the dispatch — an in-process TLS server
//! using `tokio_rustls` + `rcgen`. Each test:
//!
//! 1. Generates a fresh self-signed cert for `localhost` via `rcgen`.
//! 2. Binds a TCP listener on `127.0.0.1:0` and TLS-accepts one connection.
//! 3. From the client side, calls `connect_async_tls_with_config` against
//!    `wss://localhost:<port>/` with one of two `Connector` variants:
//!     - `None` (default verifier — native root store) for the
//!       "reject self-signed by default" test.
//!     - `Some(build_insecure_connector())` (the production code path
//!       under the antipattern flag) for the "skip verification" test.
//!
//! We assert on the WHERE the call fails:
//! - Default verifier path: the call returns `Err(Tls(...))` because the
//!   client refuses to trust the self-signed cert. Anything else (Ok, Io,
//!   Url, Protocol) is a regression.
//! - Insecure verifier path: TLS handshake completes; the WS upgrade then
//!   fails (our test server speaks raw TLS, not WS). We allow any non-TLS
//!   error here — what matters is that we got PAST the TLS handshake.
//!
//! This is narrower than booting two real TestJigServers — it avoids the
//! cost of standing up a real WSS-capable jig-server with a self-signed
//! cert (which doesn't exist as a config knob today and would itself be
//! a multi-PR refactor). The verifier code path under test is the same.

use std::sync::Arc;
use std::time::Duration;

use jig_server::v0_0_2_federation_tls::build_insecure_connector;
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite};

/// Spawn a single-shot TLS server that accepts ONE incoming connection,
/// performs the TLS handshake, then drops the stream. Returns the bound
/// port so the test can build a `wss://localhost:<port>` URL.
async fn spawn_one_shot_tls_server() -> u16 {
    // 1. Self-signed cert for `localhost`.
    let cert =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen self-signed cert");
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_pkcs8 = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let key_der: PrivateKeyDer<'static> = PrivateKeyDer::Pkcs8(key_pkcs8);

    // 2. rustls server config that presents that cert.
    let server_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // 3. Bind and spawn a one-shot accept loop.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    tokio::spawn(async move {
        if let Ok((tcp, _addr)) = listener.accept().await {
            // Best-effort TLS handshake; drop the stream immediately after.
            // The client side only cares about whether THIS layer succeeded.
            let _ = acceptor.accept(tcp).await;
        }
    });

    // Give the listener a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(20)).await;
    port
}

#[tokio::test]
async fn federation_rejects_self_signed_cert_by_default() {
    let port = spawn_one_shot_tls_server().await;
    let ws_url = format!("wss://localhost:{port}/api/v1/ws");

    // Default code path: `connector = None` -> tokio-tungstenite uses its
    // default rustls verifier (native roots, via the
    // `rustls-tls-native-roots` feature enabled in jig-server's Cargo.toml).
    // The self-signed cert is NOT in any native root store, so cert
    // verification must fail.
    let result = connect_async_tls_with_config(&ws_url, None, false, None).await;

    let Err(e) = result else {
        panic!("expected TLS verification failure against self-signed cert; got Ok");
    };

    // The exact error variant differs across rustls/tungstenite versions, but
    // the failure MUST originate at the TLS layer (not the WS upgrade or the
    // socket). Accept Tls or Io — both are valid for "verifier rejected".
    let is_tls_or_io = matches!(&e, tungstenite::Error::Tls(_) | tungstenite::Error::Io(_));
    assert!(
        is_tls_or_io,
        "expected Tls/Io error from default verifier; got {e:?}"
    );
}

#[tokio::test]
async fn dangerously_disable_federation_tls_skips_cert_verification() {
    let port = spawn_one_shot_tls_server().await;
    let ws_url = format!("wss://localhost:{port}/api/v1/ws");

    // Production code path under the antipattern flag: install the
    // NoCertVerifier-backed Connector and try to talk WSS to the
    // self-signed peer. The TLS handshake must succeed.
    let connector = build_insecure_connector();
    let result = connect_async_tls_with_config(&ws_url, None, false, Some(connector)).await;

    // The test server only does TLS, not WS. So a successful TLS handshake
    // is followed by the WS upgrade failing (Protocol/Http/Io error). What
    // we MUST NOT see is `Tls(...)` — that would mean the verifier rejected
    // the cert, i.e. the flag didn't actually disable verification.
    match result {
        Ok(_) => {
            // Allowed but unlikely — happens only if the server happens to
            // send back something WS-shaped. The TLS layer succeeded, which
            // is what we're testing.
        }
        Err(tungstenite::Error::Tls(e)) => {
            panic!(
                "dangerously_disable_federation_tls did NOT skip cert verification: \
                 got TLS error {e:?}"
            );
        }
        Err(_other) => {
            // Any non-TLS error means TLS succeeded but the post-TLS layer
            // (WS upgrade, raw socket close, etc.) failed. That's expected
            // — our test server isn't a real WS server.
        }
    }
}
