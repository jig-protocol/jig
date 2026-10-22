//! A listener's `[tls]` section and the rustls config it builds, shared by
//! jig-server and jig-nameserver.

use std::fs;
use std::path::{Path, PathBuf};

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};

/// TLS for the listener. On by default.
///
/// With neither `cert_path` nor `key_path`, the server makes a self-signed
/// certificate on first start, keeps it in `tls/` next to the database, and
/// its DID vouches for it in its well-known document: jig clients trust it
/// through the DID they pinned, not through a CA. Give both paths to serve a
/// certificate a CA issued (`tailscale cert`, certbot); jig clients accept
/// either.
///
/// `enabled = false` serves plaintext HTTP. It is an unsafe option, for
/// loopback or local testing only. A remote client over TLS refuses a server
/// whose welcome is not bound to its TLS session (JEP-0002 rule 4), so
/// anything in front of jig-server must pass TLS through (TCP or SNI
/// passthrough), never terminate it. The server advertises it as `tls.enabled=false`
/// in `unsafe_options_active` and warns at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default = "default_tls_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

fn default_tls_enabled() -> bool {
    true
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cert_path: None,
            key_path: None,
        }
    }
}

impl TlsConfig {
    /// The certificate and key to serve: the configured pair, or the
    /// self-signed pair under `dir/tls/`, made on first use for `names`. One
    /// path without the other is a misconfiguration and fails loudly.
    pub fn material(&self, dir: &Path, names: &[String]) -> Result<(PathBuf, PathBuf), String> {
        match (&self.cert_path, &self.key_path) {
            (Some(cert), Some(key)) => Ok((cert.clone(), key.clone())),
            (None, None) => self_signed(&dir.join("tls"), names),
            _ => Err(
                "[tls] needs both cert_path and key_path, or neither for a self-signed \
                 certificate"
                    .to_string(),
            ),
        }
    }
}

/// The self-signed certificate in `dir`, made now if it is not there yet.
/// The key is written 0600.
fn self_signed(dir: &Path, names: &[String]) -> Result<(PathBuf, PathBuf), String> {
    let (cert, key) = (dir.join("self-signed.crt"), dir.join("self-signed.key"));
    if cert.exists() && key.exists() {
        return Ok((cert, key));
    }
    let made = rcgen::generate_simple_self_signed(names.to_vec())
        .map_err(|e| format!("making a self-signed TLS certificate: {e}"))?;
    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(
        &mut options
            .open(&key)
            .map_err(|e| format!("writing {}: {e}", key.display()))?,
        made.signing_key.serialize_pem().as_bytes(),
    )
    .map_err(|e| format!("writing {}: {e}", key.display()))?;
    fs::write(&cert, made.cert.pem()).map_err(|e| format!("writing {}: {e}", cert.display()))?;
    Ok((cert, key))
}

/// Load a PEM cert chain + private key and build a rustls ServerConfig, with
/// the leaf certificate a DID binding names.
/// ALPN advertises only http/1.1 — it carries everything the edge needs today
/// (Resend's inbound webhook POST plus client/federation WSS, which upgrade
/// over http/1.1), so HTTP/2 is a deferred optimization rather than a
/// requirement. Uses rustls's `ring` provider (same as the federation client
/// config in jig-server's v0_0_2_federation_tls).
pub fn load_rustls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(ServerConfig, CertificateDer<'static>), String> {
    // PEM parsing via rustls-pki-types rather than rustls-pemfile: the latter is
    // unmaintained (RUSTSEC-2025-0134) and was only ever a thin wrapper over
    // these same types. This also drops the manual File/BufReader dance.
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| format!("opening TLS cert {}: {e}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parsing TLS cert: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certificates in {}", cert_path.display()));
    }
    let leaf = certs[0].clone();
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| format!("reading TLS key {}: {e}", key_path.display()))?;
    // TLS 1.3 only (transports.md, "TLS 1.3 Only").
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("building rustls config: {e}"))?;
    // http/1.1 only: it carries the webhook POST and the WSS upgrades, so
    // HTTP/2 multiplexing isn't needed for the MVP edge (deferred).
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((config, leaf))
}
