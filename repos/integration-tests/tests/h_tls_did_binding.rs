//! TLS on by default: a server's own certificate is trusted because its DID
//! vouches for it at `/.well-known/jig` (`jig_client::tls::probe`).
//!
//! Each test stands up a minimal HTTPS server that presents one certificate
//! and serves one `/.well-known/jig` document, so the certificate and the
//! document can disagree the way a man in the middle would make them.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use jig_client::tls::{TlsError, probe};
use jig_core::did::Did;
use jig_core::tls_binding::TlsBinding;
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

struct Cert {
    der: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn cert() -> Cert {
    let made = generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    Cert {
        der: CertificateDer::from(made.cert.der().to_vec()),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(made.signing_key.serialize_der())),
    }
}

fn did(key: &SigningKey) -> String {
    Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
}

/// Serve `well_known` at every path over TLS with `cert`, for as many
/// connections as come. Returns the base URL.
async fn serve(cert: &Cert, well_known: serde_json::Value) -> String {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der.clone()], cert.key.clone_key())
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let body = serde_json::to_vec(&well_known).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, body) = (acceptor.clone(), body.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                     connection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls.write_all(&body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    format!("https://localhost:{port}")
}

fn well_known(server_did: &str, binding: &TlsBinding) -> serde_json::Value {
    serde_json::json!({
        "version": "test",
        "host_id": "test",
        "endpoints": { "http": "" },
        "server_did": server_did,
        "tls_binding": binding,
    })
}

/// GET the base URL with a probed config: does it get past TLS?
async fn reaches(base: &str, config: &Arc<jig_client::tls::TlsConfig>) -> bool {
    reqwest::Client::builder()
        .use_preconfigured_tls(config.as_ref().clone())
        .build()
        .unwrap()
        .get(format!("{base}/.well-known/jig"))
        .send()
        .await
        .is_ok()
}

#[tokio::test]
async fn a_certificate_its_did_vouches_for_is_trusted_and_no_other() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let real = cert();
    let base = serve(
        &real,
        well_known(&did(&key), &TlsBinding::sign(&key, real.der.as_ref())),
    )
    .await;

    // First contact: the server's own DID is taken, and its certificate.
    let probed = probe(&base, None).await.expect("probe");
    assert_eq!(probed.server_did.as_deref(), Some(did(&key).as_str()));
    let config = probed.config.expect("a TLS config");
    assert!(reaches(&base, &config).await);

    // The same DID, pinned, is accepted again.
    probe(&base, Some(&did(&key))).await.expect("pinned probe");

    // That config trusts exactly that certificate: another server on the same
    // host, with a certificate of its own, is refused at the handshake.
    let other = cert();
    let elsewhere = serve(
        &other,
        well_known(&did(&key), &TlsBinding::sign(&key, other.der.as_ref())),
    )
    .await;
    assert!(!reaches(&elsewhere, &config).await);
}

/// A man in the middle presents its own certificate and replays the real
/// server's document: the binding names a certificate it did not present.
#[tokio::test]
async fn a_certificate_the_binding_does_not_name_is_refused() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let (real, mitm) = (cert(), cert());
    let replayed = well_known(&did(&key), &TlsBinding::sign(&key, real.der.as_ref()));
    let base = serve(&mitm, replayed).await;

    for expected in [None, Some(did(&key))] {
        match probe(&base, expected.as_deref()).await {
            Err(TlsError::Unvouched { reason, .. }) => {
                assert!(reason.contains("another certificate"), "{reason}")
            }
            other => panic!("expected Unvouched, got {:?}", other.map(|p| p.server_did)),
        }
    }
}

/// Vouching for a certificate in a server's name takes that server's key.
#[tokio::test]
async fn a_binding_signed_by_another_key_is_refused() {
    let (key, mallory) = (
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
    );
    let mitm = cert();

    // Claims the real DID, signs with its own key.
    let forged = well_known(&did(&key), &TlsBinding::sign(&mallory, mitm.der.as_ref()));
    let base = serve(&mitm, forged).await;
    assert!(matches!(
        probe(&base, Some(&did(&key))).await,
        Err(TlsError::Unvouched { .. })
    ));

    // Or names itself honestly: then it is not the server this client pinned.
    let honest = well_known(
        &did(&mallory),
        &TlsBinding::sign(&mallory, mitm.der.as_ref()),
    );
    let base = serve(&mitm, honest).await;
    assert!(matches!(
        probe(&base, Some(&did(&key))).await,
        Err(TlsError::OtherServer { .. })
    ));
}

#[tokio::test]
async fn a_self_signed_certificate_with_no_binding_is_refused() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let c = cert();
    let base = serve(&c, serde_json::json!({ "server_did": did(&key) })).await;
    match probe(&base, None).await {
        Err(TlsError::Unvouched { reason, .. }) => {
            assert!(reason.contains("tls_binding"), "{reason}")
        }
        other => panic!("expected Unvouched, got {:?}", other.map(|p| p.server_did)),
    }
}

/// The production federation dialer: a peer on its own certificate is
/// reached when its configured `expected_did` vouches for it, and refused
/// when it names another DID.
#[tokio::test]
async fn a_federation_peer_is_held_to_its_expected_did() {
    use jig_config::v0_0_2_server::{FederationPeer, FederationSection};
    use jig_server::v0_0_2_federation_tls::peer_connector;

    let key = SigningKey::from_bytes(&[1; 32]);
    let c = cert();
    let base = serve(
        &c,
        well_known(&did(&key), &TlsBinding::sign(&key, c.der.as_ref())),
    )
    .await;
    let peer = |expected_did: String| FederationPeer {
        url: base.replacen("https://", "wss://", 1),
        expected_did,
        alias: None,
        publish: false,
        quota: None,
        offers: Default::default(),
    };
    let federation = FederationSection::default();

    let connector = peer_connector(&federation, &peer(did(&key)))
        .await
        .expect("vouched for by the expected DID");
    let Some(tokio_tungstenite::Connector::Rustls(config)) = connector else {
        panic!("expected a rustls connector");
    };
    assert!(reaches(&base, &config).await);

    let other = did(&SigningKey::from_bytes(&[2; 32]));
    let err = peer_connector(&federation, &peer(other))
        .await
        .err()
        .expect("a peer naming another DID is refused");
    assert!(err.to_string().contains("not the server"), "{err}");
}

/// A server that changed its key is followed only along a public link its old
/// key signed to the new one (JEP-0012): the probe says where it moved from,
/// and refuses a new DID with no link, or one signed by someone else.
#[tokio::test]
async fn a_pinned_server_is_followed_to_a_new_key_only_along_its_link() {
    use base64::Engine as _;
    use jig_core::key_link::{Audience, SignedKeyLink};
    let (old, new, stranger) = (
        SigningKey::from_bytes(&[3; 32]),
        SigningKey::from_bytes(&[4; 32]),
        SigningKey::from_bytes(&[5; 32]),
    );
    let real = cert();
    let with_link = |link: Option<&SignedKeyLink>| {
        let mut doc = well_known(&did(&new), &TlsBinding::sign(&new, real.der.as_ref()));
        if let Some(link) = link {
            doc["key_link"] = serde_json::json!(
                base64::engine::general_purpose::STANDARD.encode(link.envelope())
            );
        }
        doc
    };

    let link = SignedKeyLink::sign(&old, &new, Audience::Public, 1).unwrap();
    let base = serve(&real, with_link(Some(&link))).await;
    let probed = probe(&base, Some(&did(&old))).await.expect("followed");
    assert_eq!(probed.moved_from.as_deref(), Some(did(&old).as_str()));
    assert_eq!(probed.server_did.as_deref(), Some(did(&new).as_str()));
    assert!(reaches(&base, &probed.config.unwrap()).await);

    let forged = SignedKeyLink::sign(&stranger, &new, Audience::Public, 1).unwrap();
    for doc in [with_link(None), with_link(Some(&forged))] {
        let base = serve(&real, doc).await;
        assert!(matches!(
            probe(&base, Some(&did(&old))).await,
            Err(TlsError::OtherServer { .. })
        ));
    }
}
