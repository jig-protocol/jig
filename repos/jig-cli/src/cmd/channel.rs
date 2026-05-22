//! `jig channel create` / `join` / `list` — Phase F4 of v0.0.2 hello-world.
//!
//! `create #hello [--visibility open|restricted]` builds a signed
//! `channel-create` block via `jig_client::blocks::build_channel_create`,
//! POSTs it to `/_admin_v0_0_2/channels`, and prints the new slug + CID.
//!
//! `join #hello` builds a signed `member-add` block that adds the caller's
//! own DID and POSTs it to `/_admin_v0_0_2/channels/<url-escaped slug>/members`.
//!
//! `list` GETs `/api/v1/channels` and pretty-prints a column-aligned table.
//!
//! ## HLC
//! The CLI has no persistent HLC clock — each invocation uses
//! `HlcTimestamp::now_wall(did)` directly. The server re-bases against its
//! own HLC on ingest (`HlcClock::update_on_receive`), so client-side wall
//! time is sufficient for v0.0.2.
//!
//! ## URL transposition
//! `[server] base_url` may be `http://`, `https://`, `ws://`, or `wss://`.
//! Channel admin endpoints + the channel-list endpoint are HTTP-only, so we
//! rewrite the scheme via [`base_http_url`] before issuing requests.

use anyhow::{Context, Result};
use base64::Engine as _;
use jig_client::{
    Identity,
    blocks::{BuiltBlock, build_channel_create, build_member_add},
};
use jig_core::HlcTimestamp;
use serde::{Deserialize, Serialize};

use crate::config;

// ============================================================================
// Helpers
// ============================================================================

/// Transpose `ws://`/`wss://` to `http://`/`https://` so we can hit REST
/// endpoints regardless of how `[server] base_url` is written. Same shape
/// as `cmd::server::well_known_url` but factored to return the base URL
/// (caller appends the path) rather than a specific endpoint.
pub(crate) fn base_http_url(base_url: &str) -> String {
    base_url
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .trim_end_matches('/')
        .to_string()
}

/// Load the identity referenced by `[user] did` in `~/.jig/cli.toml`.
/// Fails loudly if the config has no DID yet (operator hasn't run
/// `jig init`) or if the keyfile is missing.
fn load_active_identity() -> Result<(Identity, config::Config)> {
    let cfg = config::load_config(None)?;
    let did_str = cfg.user.did.clone();
    if !did_str.starts_with("did:jig:") {
        anyhow::bail!(
            "cli.toml `[user] did = \"{did_str}\"` does not look like a Jig DID. \
             Run `jig init` first."
        );
    }
    let keys_dir = jig_client::identity::default_keys_dir();
    let id = Identity::load_from_dir(&keys_dir, &did_str)
        .with_context(|| format!("loading identity {did_str} from {}", keys_dir.display()))?;
    Ok((id, cfg))
}

/// Wire shape for the admin endpoints. Matches
/// `jig_server::v0_0_2_admin::BundleSubmission`. Kept here as a local mirror
/// to avoid pulling jig-server into the CLI's dep graph.
#[derive(Debug, Serialize)]
struct BundleSubmission {
    bundle_b64: String,
    sig_b64: String,
}

fn submission_for(block: &BuiltBlock) -> BundleSubmission {
    BundleSubmission {
        bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
        sig_b64: base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
    }
}

#[derive(Debug, Deserialize)]
struct AdminResult {
    block_cid: String,
}

// ============================================================================
// create
// ============================================================================

/// Apply `jig channel create <slug> [--visibility ...]`.
///
/// Builds a signed channel-create block, POSTs it to
/// `/_admin_v0_0_2/channels`, and prints the new channel slug + block CID
/// on success.
pub async fn create(slug: String, visibility: String) -> Result<()> {
    let visibility = visibility.trim().to_lowercase();
    if !matches!(visibility.as_str(), "open" | "restricted") {
        anyhow::bail!("--visibility must be `open` or `restricted` (got `{visibility}`)");
    }

    let (id, cfg) = load_active_identity()?;
    let hlc = HlcTimestamp::now_wall(id.did().clone());
    let block = build_channel_create(&id, &slug, &visibility, hlc);

    let base = base_http_url(&cfg.server.base_url);
    let url = format!("{base}/_admin_v0_0_2/channels");
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("building HTTP client for admin endpoint")?;
    let resp = http
        .post(&url)
        .json(&submission_for(&block))
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "POST {url} returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let result: AdminResult = resp
        .json()
        .await
        .context("decoding /_admin_v0_0_2/channels response")?;
    println!("channel created: {slug} ({visibility})");
    println!("  block_cid: {}", result.block_cid);
    Ok(())
}

// ============================================================================
// join
// ============================================================================

/// Apply `jig channel join <slug>`.
///
/// Builds a signed member-add block that adds the caller's own DID, then
/// POSTs it to `/_admin_v0_0_2/channels/<url-escaped slug>/members`.
pub async fn join(slug: String) -> Result<()> {
    let (id, cfg) = load_active_identity()?;
    let hlc = HlcTimestamp::now_wall(id.did().clone());
    let my_did = id.did_string();
    let block = build_member_add(&id, &slug, &my_did, hlc);

    let base = base_http_url(&cfg.server.base_url);
    let escaped = escape_slug_for_url(&slug);
    let url = format!("{base}/_admin_v0_0_2/channels/{escaped}/members");
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("building HTTP client for admin endpoint")?;
    let resp = http
        .post(&url)
        .json(&submission_for(&block))
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "POST {url} returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let result: AdminResult = resp.json().await.context("decoding member-add response")?;
    println!("joined {slug} as {my_did}");
    println!("  block_cid: {}", result.block_cid);
    Ok(())
}

/// URL-escape the channel slug so `#hello` becomes `%23hello` and similar.
/// We do not bring in `percent-encoding` for this — a tiny manual escape of
/// the small set of characters channel slugs can contain (`#`, plus
/// alphanumerics + `-` + `_`) is enough for v0.0.2.
pub(crate) fn escape_slug_for_url(slug: &str) -> String {
    let mut out = String::with_capacity(slug.len() + 2);
    for ch in slug.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(ch),
            _ => {
                // Percent-encode each UTF-8 byte.
                let mut buf = [0u8; 4];
                let bytes = ch.encode_utf8(&mut buf).as_bytes();
                for b in bytes {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
        }
    }
    out
}

// ============================================================================
// list
// ============================================================================

#[derive(Debug, Deserialize)]
struct ChannelView {
    slug: String,
    visibility: String,
    owner_did: String,
    /// Reserved for future column rendering (e.g. `--long`); currently
    /// deserialized but not printed. Kept on the type for wire-shape parity
    /// with the server-side `ChannelView` so a future flag doesn't need a
    /// breaking deserialization change.
    #[serde(default)]
    #[allow(dead_code)]
    created_at: i64,
}

#[derive(Debug, Deserialize)]
struct ChannelsResponse {
    channels: Vec<ChannelView>,
}

/// Apply `jig channel list`. GETs `/api/v1/channels` and renders a table.
pub async fn list() -> Result<()> {
    let cfg = config::load_config(None)?;
    let base = base_http_url(&cfg.server.base_url);
    let url = format!("{base}/api/v1/channels");
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("building HTTP client for /api/v1/channels")?;
    let resp = http
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "GET {url} returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let body: ChannelsResponse = resp
        .json()
        .await
        .context("decoding /api/v1/channels response")?;
    print_channels(&body.channels);
    Ok(())
}

/// Render the channel list as aligned columns:
///
/// ```text
/// #hello       open        did:jig:zAlice...
/// #devops      restricted  did:jig:zBob...
/// ```
///
/// Empty list prints `(no channels yet)` so operators don't see silence and
/// wonder whether their `list` even ran.
fn print_channels(channels: &[ChannelView]) {
    if channels.is_empty() {
        println!("(no channels yet)");
        return;
    }
    // Pad slug + visibility to the widest entry so the DID column lines up.
    let slug_w = channels
        .iter()
        .map(|c| c.slug.len())
        .max()
        .unwrap_or(0)
        .max(8);
    let vis_w = channels
        .iter()
        .map(|c| c.visibility.len())
        .max()
        .unwrap_or(0)
        .max(10);
    for c in channels {
        println!(
            "{:<slug_w$}  {:<vis_w$}  {}",
            c.slug,
            c.visibility,
            c.owner_did,
            slug_w = slug_w,
            vis_w = vis_w,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_http_url_transposes_ws_and_strips_trailing_slash() {
        assert_eq!(
            base_http_url("ws://127.0.0.1:7117/"),
            "http://127.0.0.1:7117"
        );
        assert_eq!(base_http_url("wss://deji.jig.onl"), "https://deji.jig.onl");
        assert_eq!(
            base_http_url("http://localhost:7117"),
            "http://localhost:7117"
        );
        assert_eq!(base_http_url("https://jig.onl/"), "https://jig.onl");
    }

    #[test]
    fn escape_slug_for_url_encodes_hash() {
        // `#` is the single most-common channel-name prefix and MUST be
        // percent-encoded — leaving it unescaped truncates the path at the
        // fragment delimiter on the server side.
        assert_eq!(escape_slug_for_url("#hello"), "%23hello");
        assert_eq!(escape_slug_for_url("#dev-ops"), "%23dev-ops");
        assert_eq!(
            escape_slug_for_url("#with_underscore"),
            "%23with_underscore"
        );
    }

    #[test]
    fn escape_slug_for_url_preserves_unreserved_chars() {
        // Letters, digits, `-`, `_`, `.`, `~` are unreserved per RFC 3986;
        // we must NOT percent-encode them.
        assert_eq!(escape_slug_for_url("abc123-_.~"), "abc123-_.~");
    }

    #[test]
    fn escape_slug_for_url_encodes_multibyte_utf8() {
        // Defence-in-depth: a slug containing a non-ASCII char must round
        // through percent-encoded UTF-8 bytes, not naively `\u{...}`.
        // `é` is 0xC3 0xA9 in UTF-8 → %C3%A9.
        assert_eq!(escape_slug_for_url("#caf\u{00E9}"), "%23caf%C3%A9");
    }

    #[test]
    fn print_channels_does_not_panic_on_empty_or_populated() {
        // Smoke: just exercise the path. Captures nothing; assertion is
        // "doesn't panic and renders something sensible".
        print_channels(&[]);
        print_channels(&[
            ChannelView {
                slug: "#hello".into(),
                visibility: "open".into(),
                owner_did: "did:jig:zAlice".into(),
                created_at: 0,
            },
            ChannelView {
                slug: "#devops".into(),
                visibility: "restricted".into(),
                owner_did: "did:jig:zBob".into(),
                created_at: 0,
            },
        ]);
    }
}
