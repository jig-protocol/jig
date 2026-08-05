//! `jig server set` and `jig server info` — Phase F3 of v0.0.2 hello-world.
//!
//! `set <url>` rewrites `[server] base_url` in the active config file
//! (`--config <path>` when given, else `~/.jig/cli.toml`). The URL
//! can be `http://`, `https://`, `ws://`, or `wss://`. v0.0.2 does not try
//! to be clever about scheme rewriting — whatever the operator passes is
//! what gets persisted (validated only for basic URL shape via the `url`
//! crate so we don't end up with garbage strings in config).
//!
//! `info` fetches `GET <server>/.well-known/jig` and pretty-prints the
//! response. The endpoint always serves over HTTP/HTTPS even when the
//! configured `base_url` is a WSS endpoint, so we transpose schemes via
//! `well_known_url` before issuing the request.
//!
//! The response shape is defined by `jig_server::handler::ServerInfoResponse`.
//! We mirror it here as a CLI-local struct (`ServerInfoResponse`) rather
//! than depending on `jig-server` — server is a heavy crate and this CLI
//! has no other reason to pull it in.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::cmd::common::CliContext;

// ============================================================================
// set
// ============================================================================

/// Apply `jig server set <url>` — validates the URL shape, then rewrites
/// `[server] base_url` in the active config file (`--config <path>` when
/// given, otherwise `~/.jig/cli.toml`).
///
/// Writes start from the *on-disk* config, so a one-shot `--server`
/// override never gets persisted as a side effect.
///
/// Synchronous: no network calls happen here. To verify the URL is
/// reachable, the operator should run `jig server info` afterwards.
pub fn set(ctx: &CliContext, url: &str) -> Result<()> {
    let url = url.trim();
    if url.is_empty() {
        anyhow::bail!("server URL must not be empty");
    }

    // Parse via the `url` crate to catch obvious typos (missing scheme,
    // bare hostnames, etc). v0.0.2 doesn't enforce a scheme allowlist —
    // operators on weird transports (e.g. unix sockets via a custom proxy)
    // should be free to wire something nonstandard if they know what
    // they're doing.
    let parsed = url::Url::parse(url)
        .with_context(|| format!("`{url}` is not a valid URL (expected e.g. http://host:port)"))?;
    if parsed.host().is_none() {
        anyhow::bail!("`{url}` has no host component");
    }

    let mut cfg = ctx.file_config().clone();
    cfg.server.base_url = url.to_string();
    ctx.save_file_config(&cfg)?;
    println!("server set: {url}");
    Ok(())
}

// ============================================================================
// info
// ============================================================================

/// Apply `jig server info` — fetch and pretty-print `/.well-known/jig`
/// from the resolved server.
///
/// URL precedence: the subcommand's own `--url` (the diagnostic escape
/// hatch, "does that peer think it's federated with me?") beats the global
/// `--server`, which beats `[server] base_url` in the config file.
pub async fn info(ctx: &CliContext, override_url: Option<&str>) -> Result<()> {
    let base = match override_url {
        Some(u) => u.trim().to_string(),
        None => ctx.server_url()?,
    };
    if base.is_empty() {
        anyhow::bail!("no server base URL configured — run `jig server set <url>` first");
    }

    let endpoint = well_known_url(&base);
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("building HTTP client for /.well-known/jig")?;

    let resp = http
        .get(&endpoint)
        .send()
        .await
        .with_context(|| format!("GET {endpoint}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "GET {endpoint} returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let body: ServerInfoResponse = resp
        .json()
        .await
        .context("decoding /.well-known/jig response")?;
    print_server_info(&base, &body);
    Ok(())
}

/// Transpose `ws://`/`wss://` to `http://`/`https://` so we can hit the
/// `/.well-known/jig` HTTP endpoint regardless of how the operator wrote
/// the configured base URL.
pub(crate) fn well_known_url(base_url: &str) -> String {
    let base = base_url
        .replace("wss://", "https://")
        .replace("ws://", "http://");
    let trimmed = base.trim_end_matches('/');
    format!("{trimmed}/.well-known/jig")
}

/// CLI-local mirror of `jig_server::handler::ServerInfoResponse`. The
/// shape must stay in lockstep with that struct; Phase H integration
/// tests cover the end-to-end round-trip.
///
/// All v0.0.2 fields are `#[serde(default)]` so a v0.0.1 server (which
/// emits only `version` + `host_id` + `endpoints`) still deserializes
/// cleanly and we just show empty rows.
#[derive(Debug, Deserialize)]
pub(crate) struct ServerInfoResponse {
    pub version: String,
    pub host_id: String,
    pub endpoints: ServerEndpoints,
    #[serde(default)]
    pub server_did: Option<String>,
    #[serde(default)]
    pub unsafe_options_active: Vec<String>,
    #[serde(default)]
    pub allowed_block_kinds: Vec<String>,
    #[serde(default)]
    pub peers: Vec<PeerInfo>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ServerEndpoints {
    pub http: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PeerInfo {
    pub url: String,
    #[serde(default)]
    pub alias: Option<String>,
}

/// Render the response as aligned columns. Antipattern flags get an
/// explicit `WARNING:` prefix per the v0.0.2 ROE — misconfiguration
/// should look loud, not blend in with the rest of the output.
fn print_server_info(base_url: &str, info: &ServerInfoResponse) {
    println!("{:<22}{}", "server", base_url);
    println!("{:<22}{}", "version", info.version);
    println!("{:<22}{}", "host_id", info.host_id);
    println!("{:<22}{}", "endpoints.http", info.endpoints.http);
    println!(
        "{:<22}{}",
        "server_did",
        info.server_did
            .as_deref()
            .unwrap_or("[absent — v0.0.1 server?]")
    );

    let kinds = if info.allowed_block_kinds.is_empty() {
        "[empty]".to_string()
    } else {
        info.allowed_block_kinds.join(", ")
    };
    println!("{:<22}{}", "allowed_block_kinds", kinds);

    let peers = if info.peers.is_empty() {
        "[none]".to_string()
    } else {
        info.peers
            .iter()
            .map(|p| match &p.alias {
                Some(a) => format!("{} ({})", p.url, a),
                None => p.url.clone(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!("{:<22}{}", "peers", peers);

    if info.unsafe_options_active.is_empty() {
        println!("{:<22}[empty]", "unsafe_options_active");
    } else {
        // Loud — antipatterns are not to be glossed over.
        println!(
            "WARNING: {:<13}{}",
            "unsafe_options_active",
            info.unsafe_options_active.join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_url_preserves_http() {
        assert_eq!(
            well_known_url("http://127.0.0.1:7117"),
            "http://127.0.0.1:7117/.well-known/jig"
        );
    }

    #[test]
    fn well_known_url_preserves_https() {
        assert_eq!(
            well_known_url("https://jig.onl"),
            "https://jig.onl/.well-known/jig"
        );
    }

    #[test]
    fn well_known_url_transposes_ws_to_http() {
        assert_eq!(
            well_known_url("ws://127.0.0.1:7117"),
            "http://127.0.0.1:7117/.well-known/jig"
        );
    }

    #[test]
    fn well_known_url_transposes_wss_to_https() {
        assert_eq!(
            well_known_url("wss://deji.jig.onl"),
            "https://deji.jig.onl/.well-known/jig"
        );
    }

    #[test]
    fn well_known_url_strips_trailing_slash() {
        // Otherwise we'd end up with `//well-known/jig` and a confusing 404.
        assert_eq!(
            well_known_url("http://host:7117/"),
            "http://host:7117/.well-known/jig"
        );
    }

    #[test]
    fn print_server_info_renders_loud_warning_for_unsafe_options() {
        // Smoke: just exercise the path; we capture nothing here, but
        // make sure non-empty unsafe_options_active doesn't panic.
        let body = ServerInfoResponse {
            version: "0.0.2".into(),
            host_id: "test-host".into(),
            endpoints: ServerEndpoints {
                http: "http://127.0.0.1:7117".into(),
            },
            server_did: Some("did:jig:zABC".into()),
            unsafe_options_active: vec!["naively_unbounded_clock_skew".into()],
            allowed_block_kinds: vec!["text-render".into()],
            peers: vec![PeerInfo {
                url: "wss://deji.jig.onl".into(),
                alias: Some("deji".into()),
            }],
        };
        print_server_info("http://127.0.0.1:7117", &body);
    }

    #[test]
    fn print_server_info_handles_empty_v0_0_1_response() {
        // v0.0.1 server: no server_did, no peers, no allowed_block_kinds,
        // no unsafe_options_active. Must render `[absent]` / `[empty]` /
        // `[none]` placeholders without panicking.
        let body = ServerInfoResponse {
            version: "0.0.1".into(),
            host_id: "legacy".into(),
            endpoints: ServerEndpoints {
                http: "http://127.0.0.1:7117".into(),
            },
            server_did: None,
            unsafe_options_active: vec![],
            allowed_block_kinds: vec![],
            peers: vec![],
        };
        print_server_info("http://127.0.0.1:7117", &body);
    }
}
