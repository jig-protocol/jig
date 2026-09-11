//! `jig channel create` / `join` / `delete` / `list` — Phase F4 of v0.0.2
//! hello-world, plus the channel delete that F4 shipped without.
//!
//! `create #hello [--visibility open|restricted]` builds a signed
//! `channel-create` block via `jig_client::blocks::build_channel_create`,
//! POSTs it to `/_admin_v0_0_2/channels`, and prints the new slug + CID.
//!
//! `join #hello` builds a signed `member-add` block that adds the caller's
//! own DID and POSTs it to `/_admin_v0_0_2/channels/<url-escaped slug>/members`.
//!
//! `delete #hello [--yes]` builds a signed `channel-archive` block and POSTs it
//! to `/_admin_v0_0_2/channels/<url-escaped slug>/archive`. Owner-only, and a
//! soft delete: the server retires the channel and keeps its history.
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
use jig_client::blocks::{
    BuiltBlock, build_channel_archive, build_channel_create, build_member_add,
};
use jig_client::read_auth::{ReadProof, signable_path};
use jig_core::HlcTimestamp;
use serde::{Deserialize, Serialize};

use crate::cmd::common::CliContext;

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
pub async fn create(ctx: &CliContext, slug: String, visibility: String) -> Result<()> {
    let visibility = visibility.trim().to_lowercase();
    if !matches!(visibility.as_str(), "open" | "restricted") {
        anyhow::bail!("--visibility must be `open` or `restricted` (got `{visibility}`)");
    }

    let id = ctx.identity()?;
    let hlc = HlcTimestamp::now_wall(id.did().clone());
    let block = build_channel_create(&id, &slug, &visibility, hlc);

    let base = base_http_url(&ctx.server_url()?);
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

    // A freshly created channel is almost always the one the operator wants
    // to talk in next; without this, a bare `jig send hi` still goes to
    // `#general` and the message appears to vanish.
    if let Err(e) = remember_default_channel(ctx, &slug) {
        eprintln!("warning: channel created but default_channel not saved: {e:#}");
    } else {
        println!("  default channel is now {slug}");
    }
    Ok(())
}

/// Persist `slug` as `[user] default_channel`.
///
/// Starts from the on-disk config (not the effective one) so a one-shot
/// `--server` / `--did` override never gets written back to `cli.toml`.
fn remember_default_channel(ctx: &CliContext, slug: &str) -> Result<()> {
    let mut cfg = ctx.file_config().clone();
    cfg.user.default_channel = slug.to_string();
    ctx.save_file_config(&cfg)
}

// ============================================================================
// join
// ============================================================================

/// Apply `jig channel join <slug>`.
///
/// Builds a signed member-add block that adds the caller's own DID, then
/// POSTs it to `/_admin_v0_0_2/channels/<url-escaped slug>/members`.
pub async fn join(ctx: &CliContext, slug: String) -> Result<()> {
    let id = ctx.identity()?;
    let hlc = HlcTimestamp::now_wall(id.did().clone());
    let my_did = id.did_string();
    let block = build_member_add(&id, &slug, &my_did, hlc);

    let base = base_http_url(&ctx.server_url()?);
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

    // Cheap moment to populate the address book: we know the DID and the
    // name it belongs to. Purely local — nothing about the name goes into
    // the member-add block.
    if let Err(e) = remember_joiner(ctx, &my_did) {
        eprintln!("warning: joined but contact name not saved: {e:#}");
    }
    Ok(())
}

/// Record the joining DID under the configured display name.
fn remember_joiner(ctx: &CliContext, did: &str) -> Result<()> {
    let display_name = ctx.effective().user.display_name.clone();
    let mut cfg = ctx.file_config().clone();
    crate::config::remember_contact(&mut cfg, did, &display_name);
    ctx.save_file_config(&cfg)
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
// delete (archive)
// ============================================================================

/// Whether a `channel delete` may proceed without an interactive prompt.
///
/// `--yes` is the only non-interactive way through. When stdin is not a TTY
/// (CI, `ssh host jig ...`, a script) there is nobody to answer the prompt, so
/// refusing is the safe outcome rather than reading EOF as consent.
fn deletion_confirmed(yes: bool, stdin_is_tty: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !stdin_is_tty {
        anyhow::bail!(
            "refusing to delete a channel without confirmation — pass --yes to confirm \
             (stdin is not a terminal, so there is nobody to prompt)"
        );
    }
    Ok(())
}

/// Read a typed confirmation from `reader` and check it against `slug`.
///
/// Typing the slug back, rather than "y", is deliberate: deleting a channel
/// retires shared history for everyone on the server and cannot be undone from
/// the CLI.
fn confirmation_matches(input: &str, slug: &str) -> bool {
    input.trim() == slug
}

/// Apply `jig channel delete <slug> [--yes]`.
///
/// Builds a signed `channel-archive` block and POSTs it to
/// `/_admin_v0_0_2/channels/<url-escaped slug>/archive`. The server accepts it
/// only from the channel's owner DID.
///
/// This is a soft delete: the channel stops appearing in `jig channel list` and
/// stops accepting new blocks, but the server keeps its history. Nothing here
/// erases messages from disk, and copies already federated to peers are
/// unaffected — so this is not a privacy tool.
pub async fn delete(ctx: &CliContext, slug: String, yes: bool) -> Result<()> {
    use std::io::{IsTerminal, Write};

    let stdin = std::io::stdin();
    deletion_confirmed(yes, stdin.is_terminal())?;
    if !yes {
        print!(
            "Delete {slug}? History is kept but the channel is retired. Type the slug to confirm: "
        );
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::BufRead::read_line(&mut stdin.lock(), &mut answer)
            .context("reading confirmation from stdin")?;
        if !confirmation_matches(&answer, &slug) {
            anyhow::bail!("confirmation did not match `{slug}` — nothing was deleted");
        }
    }

    let id = ctx.identity()?;
    let hlc = HlcTimestamp::now_wall(id.did().clone());
    let block = build_channel_archive(&id, &slug, hlc);

    let base = base_http_url(&ctx.server_url()?);
    let escaped = escape_slug_for_url(&slug);
    let url = format!("{base}/_admin_v0_0_2/channels/{escaped}/archive");
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
        .context("decoding channel-archive response")?;
    println!("channel deleted: {slug}");
    println!("  block_cid: {}", result.block_cid);
    println!("  history is retained server-side; the channel is no longer listed");
    Ok(())
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
///
/// Signed as the caller: the server lists open channels plus the restricted
/// ones this identity owns or belongs to, and nothing at all to an unsigned
/// request.
pub async fn list(ctx: &CliContext) -> Result<()> {
    let id = ctx.identity()?;
    let base = base_http_url(&ctx.server_url()?);
    let url = format!("{base}/api/v1/channels");
    let proof = ReadProof::sign(&id, "GET", signable_path(&url));
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("building HTTP client for /api/v1/channels")?;
    let mut req = http.get(&url);
    for (name, value) in proof.headers() {
        req = req.header(name, value);
    }
    let resp = req.send().await.with_context(|| format!("GET {url}"))?;
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

    fn ctx_over(path: &std::path::Path) -> CliContext {
        std::fs::write(
            path,
            "[server]\nbase_url = \"http://127.0.0.1:7117\"\n\n\
             [user]\ndid = \"did:jig:zFile\"\ndisplay_name = \"dj\"\n\
             default_channel = \"#general\"\n",
        )
        .unwrap();
        CliContext::resolve(&crate::cmd::common::GlobalOverrides {
            config: Some(path.to_path_buf()),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn creating_a_channel_makes_it_the_default_for_bare_sends() {
        // Without this, `jig channel create '#hello'` followed by
        // `jig send hi` silently posts to `#general`.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.toml");
        let ctx = ctx_over(&path);

        remember_default_channel(&ctx, "#hello").unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("default_channel = \"#hello\""),
            "create must persist the new default channel: {written}"
        );
    }

    #[test]
    fn joining_a_channel_records_the_joiner_in_the_address_book() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.toml");
        let ctx = ctx_over(&path);

        remember_joiner(&ctx, "did:jig:zJoiner").unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("did:jig:zJoiner") && written.contains("dj"),
            "join must map the joiner's DID to their display name: {written}"
        );
    }

    #[test]
    fn remembering_a_default_channel_does_not_persist_one_shot_overrides() {
        // `--server` is a per-invocation override; it must never be written
        // back to cli.toml as a side effect of `channel create`.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.toml");
        ctx_over(&path);
        let ctx = CliContext::resolve(&crate::cmd::common::GlobalOverrides {
            config: Some(path.clone()),
            server: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        })
        .unwrap();

        remember_default_channel(&ctx, "#hello").unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("http://127.0.0.1:7117"),
            "on-disk base_url must survive: {written}"
        );
        assert!(
            !written.contains("127.0.0.1:1\""),
            "the --server override leaked into the file: {written}"
        );
    }

    #[test]
    fn delete_without_yes_is_refused_when_stdin_is_not_a_terminal() {
        // `ssh box jig channel delete '#x'` or a CI step has no terminal to
        // prompt on; reading EOF must not count as "yes".
        let e = deletion_confirmed(false, false).unwrap_err();
        assert!(
            e.to_string().contains("--yes"),
            "error must point at --yes: {e}"
        );
    }

    #[test]
    fn delete_with_yes_needs_no_terminal() {
        deletion_confirmed(true, false).unwrap();
        deletion_confirmed(true, true).unwrap();
    }

    #[test]
    fn delete_without_yes_proceeds_to_the_prompt_on_a_terminal() {
        deletion_confirmed(false, true).unwrap();
    }

    #[test]
    fn confirmation_must_be_the_slug_not_just_yes() {
        // One keystroke must not retire shared history.
        assert!(confirmation_matches("#scratch\n", "#scratch"));
        assert!(confirmation_matches("  #scratch  ", "#scratch"));
        assert!(!confirmation_matches("y\n", "#scratch"));
        assert!(!confirmation_matches("yes\n", "#scratch"));
        assert!(!confirmation_matches("\n", "#scratch"));
        assert!(!confirmation_matches("#other\n", "#scratch"));
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
