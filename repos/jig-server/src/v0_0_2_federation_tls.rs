//! TLS connector for federation peer WSS connections (alpha.1c #4).
//!
//! Default federation peer connects use tokio-tungstenite's built-in
//! verifier (rustls with native roots — see Cargo.toml's
//! `rustls-tls-native-roots` feature). When operators explicitly set
//! `[federation] dangerously_disable_federation_tls = true`, we replace
//! the verifier with `NoCertVerifier` so the WSS handshake accepts
//! self-signed and hostname-mismatched certs.
//!
//! This is intentionally narrow:
//! - The flag is named `dangerously_*` to surface its intent.
//! - It only affects federation peer connects, not any other TLS surface.
//! - The verifier returns `Ok(())` for every chain it's shown; it does
//!   no signature or hostname checks of any kind.
//! - When the flag is on, `v0_0_2_federation.rs::connect_and_relay`
//!   emits a `tracing::warn!` that names the flag at every peer
//!   connection attempt so operators see it during startup logs.
//! - `JigServerConfig::unsafe_options_active` already advertises the flag
//!   in `/.well-known/jig` so federated peers can detect the
//!   misconfiguration.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_tungstenite::Connector;

/// A `rustls::ServerCertVerifier` that accepts any presented certificate
/// without inspection. Installed only when
/// `federation.dangerously_disable_federation_tls` is true.
#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Advertise the full set rustls 0.22's default ring provider supports.
        // The verifier accepts every signature anyway, so this list only
        // affects what schemes rustls negotiates during the handshake.
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Build a tokio-tungstenite `Connector` that disables server cert
/// verification entirely. Returned only when the antipattern flag is set.
pub fn build_insecure_connector() -> Connector {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();
    Connector::Rustls(Arc::new(config))
}

/// Select the `Connector` for a federation peer WSS connect based on the
/// `federation.dangerously_disable_federation_tls` flag.
///
/// - `false` (default) returns `None`, which lets `connect_async` /
///   `connect_async_tls_with_config` use tokio-tungstenite's built-in
///   default verifier (rustls + native roots).
/// - `true` returns `Some(Connector::Rustls(...))` with `NoCertVerifier`
///   installed so the WSS handshake accepts self-signed and
///   hostname-mismatched certs.
pub fn select_connector(
    federation: &jig_config::v0_0_2_server::FederationSection,
) -> Option<Connector> {
    if federation.dangerously_disable_federation_tls {
        Some(build_insecure_connector())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cert_verifier_accepts_any_chain() {
        // Hand the verifier a clearly bogus cert and assert it still returns Ok.
        // verify_server_cert is supposed to fail loudly for invalid chains under
        // the normal WebPkiVerifier — proving here that our impl bypasses that.
        let verifier = NoCertVerifier;
        let bogus_cert = CertificateDer::from(vec![0u8; 32]);
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000));
        let server_name = ServerName::try_from("example.com").unwrap();
        let result = verifier.verify_server_cert(&bogus_cert, &[], &server_name, &[], now);
        assert!(
            result.is_ok(),
            "NoCertVerifier MUST accept any cert; got {result:?}"
        );
    }

    #[test]
    fn build_insecure_connector_returns_rustls_variant() {
        // The connector must be Connector::Rustls — Connector::Plain would
        // mean we silently fell back to no-TLS, which is a different (and
        // worse) failure mode than skipping verification.
        let connector = build_insecure_connector();
        assert!(
            matches!(connector, Connector::Rustls(_)),
            "build_insecure_connector must return Connector::Rustls(_)"
        );
    }

    #[test]
    fn select_connector_returns_none_when_flag_off() {
        // Default config — flag is off. We MUST get None so the federation
        // peer connect uses the standard `connect_async` path with native
        // root verification.
        let federation = jig_config::v0_0_2_server::FederationSection::default();
        assert!(!federation.dangerously_disable_federation_tls);
        assert!(
            select_connector(&federation).is_none(),
            "default config must return no custom connector"
        );
    }

    #[test]
    fn select_connector_returns_insecure_when_flag_on() {
        let federation = jig_config::v0_0_2_server::FederationSection {
            dangerously_disable_federation_tls: true,
            ..Default::default()
        };
        let Some(connector) = select_connector(&federation) else {
            panic!("flag on must produce a custom connector");
        };
        assert!(
            matches!(connector, Connector::Rustls(_)),
            "flag-on connector must be Connector::Rustls(_)"
        );
    }
}
