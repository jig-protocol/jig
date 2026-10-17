//! What this process trusts for a server: the DID this device pinned for it,
//! and the TLS certificate that DID vouches for ([`jig_client::tls`]).
//!
//! The first connection to an `https://` server in a process probes it once:
//! the DID it names must be the pinned one (or is pinned, on first contact),
//! and its certificate must be one that DID vouches for, or one a CA issued.
//! Every later REST and WSS connection in the process gets a config that
//! accepts that certificate and nothing else. A certificate the server rotated
//! is picked up by the next process, as long as the same DID vouches for it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use jig_client::pins::Pins;
use jig_client::secure::server_key;
use jig_client::tls::{TlsError, probe};

type Config = Option<Arc<jig_client::tls::TlsConfig>>;

static PROBED: Mutex<Option<HashMap<String, Config>>> = Mutex::new(None);

/// The TLS config for connections to `server`: `None` over plaintext, which
/// has nothing to bind.
pub async fn server_tls(server: &str) -> Result<Config> {
    let key = server_key(server);
    if let Some(config) = PROBED
        .lock()
        .expect("probe cache lock")
        .get_or_insert_with(HashMap::new)
        .get(&key)
    {
        return Ok(config.clone());
    }
    let plaintext = !jig_client::tls::http_base(server)?.starts_with("https://");
    let config = if plaintext {
        hint_if_tls(server).await?;
        None
    } else {
        let mut pins = Pins::load(&Pins::default_path())?;
        let expected = pins.offer(server).pinned_server_did;
        let probed = probe(server, expected.as_deref())
            .await
            .map_err(|e| refusal(server, e))?;
        if let Some(did) = &probed.server_did {
            pins.check_server_did(server, did)?;
        }
        probed.config
    };
    PROBED
        .lock()
        .expect("probe cache lock")
        .get_or_insert_with(HashMap::new)
        .insert(key, config.clone());
    Ok(config)
}

/// A REST client for `server` that trusts what [`server_tls`] decided.
pub async fn http(server: &str, timeout: std::time::Duration) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(config) = server_tls(server).await? {
        builder = builder.use_preconfigured_tls(config.as_ref().clone());
    }
    builder.build().context("building HTTP client")
}

fn refusal(server: &str, e: TlsError) -> anyhow::Error {
    match e {
        TlsError::OtherServer { .. } => anyhow::anyhow!(
            "{e}. If its key really changed, `jig server forget {server}` drops the pin."
        ),
        e => e.into(),
    }
}

/// A configured `http://` URL for a server that has since turned TLS on
/// (the default) fails with a bare "connection closed". Say what to do.
async fn hint_if_tls(server: &str) -> Result<()> {
    let base = jig_client::tls::http_base(server)?;
    let plain = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .context("building HTTP client")?
        .get(format!("{base}/.well-known/jig"))
        .send()
        .await;
    let Err(e) = plain else {
        return Ok(());
    };
    if e.is_connect() || e.is_timeout() {
        // Down or unreachable: the command reports that in its own terms.
        return Ok(());
    }
    let tls_url = base.replacen("http://", "https://", 1);
    if probe(&tls_url, None).await.is_ok() {
        anyhow::bail!(
            "{server} serves TLS now; run `jig server set {tls_url}` to talk to it over TLS"
        );
    }
    Ok(())
}
