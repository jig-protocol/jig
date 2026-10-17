//! `jig channel create` / `join` / `delete` / `list` — Phase F4 of v0.0.2
//! hello-world, plus the channel delete that F4 shipped without.
//!
//! `create #hello [--visibility open|restricted]` builds a signed
//! `channel-create` block via `jig_client::blocks::build_channel_create`,
//! POSTs it to `/api/v1/channels`, and prints the new slug + CID.
//!
//! `join #hello` builds a signed `member-add` block that adds the caller's
//! own DID and POSTs it to `/api/v1/channels/<url-escaped slug>/members`.
//!
//! `delete #hello [--yes]` builds a signed `channel-archive` block and POSTs it
//! to `/api/v1/channels/<url-escaped slug>/archive`. Owner-only, and a
//! soft delete: the server retires the channel and keeps its history.
//!
//! Servers that predate `/api/v1/channels*` only expose the same handlers
//! under `/_admin_v0_0_2/*` (behind `[debug] admin_endpoints`), so a 404 on the
//! stable path is retried once against the legacy one.
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
    BuiltBlock, build_channel_archive, build_channel_promote, build_member_add,
    build_member_remove, build_with_metadata, merge,
};
use jig_client::read_auth::{ReadProof, signable_path};
use jig_core::{BlockKind, HlcTimestamp};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::cmd::common::CliContext;
use crate::cmd::secure::{ChannelInfo, Refused, Secure, mls_fields, refused};

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

/// A channel-op POST the server answered with a non-2xx status.
#[derive(Debug)]
struct ChannelOpError {
    url: String,
    status: reqwest::StatusCode,
    body: String,
}

impl std::fmt::Display for ChannelOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "POST {} returned {}: {}",
            self.url, self.status, self.body
        )
    }
}

impl std::error::Error for ChannelOpError {}

impl ChannelOpError {
    fn is_channel_exists(&self) -> bool {
        is_channel_exists(self.status, &self.body)
    }
}

/// Whether a channel-create refusal means "that slug is already taken".
/// Servers before the `CHANNEL_EXISTS` code answered with a 500 carrying the
/// SQLite constraint text, so that exact shape counts too.
fn is_channel_exists(status: reqwest::StatusCode, body: &str) -> bool {
    let code = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["code"].as_str().map(str::to_string));
    match status {
        reqwest::StatusCode::CONFLICT => code.as_deref() == Some("CHANNEL_EXISTS"),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
            body.contains("UNIQUE constraint failed: channels.slug")
        }
        _ => false,
    }
}

const CHANNEL_OPS_PREFIX: &str = "/api/v1/channels";
const LEGACY_CHANNEL_OPS_PREFIX: &str = "/_admin_v0_0_2/channels";

/// POST a signed channel-op block to `<base><prefix><suffix>`, where `suffix`
/// is `""`, `/<slug>/members` or `/<slug>/archive`.
async fn post_channel_op(base: &str, suffix: &str, block: &BuiltBlock) -> Result<AdminResult> {
    let http = crate::cmd::trust::http(base, std::time::Duration::from_secs(15)).await?;
    let submission = submission_for(block);

    let mut url = format!("{base}{CHANNEL_OPS_PREFIX}{suffix}");
    let mut resp = http
        .post(&url)
        .json(&submission)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND
        || resp.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
    {
        url = format!("{base}{LEGACY_CHANNEL_OPS_PREFIX}{suffix}");
        resp = http
            .post(&url)
            .json(&submission)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(ChannelOpError { url, status, body }.into());
    }
    resp.json()
        .await
        .with_context(|| format!("decoding {url} response"))
}

// ============================================================================
// create
// ============================================================================

/// Apply `jig channel create <slug> [--visibility ...] [--exist-ok]`.
///
/// Builds a signed channel-create block, POSTs it to
/// `/api/v1/channels`, and prints the new channel slug + block CID
/// on success. A taken slug is an error unless `exist_ok`, in which case it
/// is reported and treated as success (the channel's existing visibility and
/// owner are left as they are).
pub async fn create(
    ctx: &CliContext,
    slug: String,
    visibility: String,
    exist_ok: bool,
    encrypted: bool,
) -> Result<()> {
    create_with(ctx, &slug, &visibility, exist_ok, encrypted, json!({})).await?;

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

/// Create a channel; `extra` is merged into the creation block's metadata.
/// Returns whether this call created it (`false`: it already existed and
/// `exist_ok` was set).
pub(crate) async fn create_with(
    ctx: &CliContext,
    slug: &str,
    visibility: &str,
    exist_ok: bool,
    encrypted: bool,
    extra: serde_json::Value,
) -> Result<bool> {
    let visibility = visibility.trim().to_lowercase();
    if !matches!(visibility.as_str(), "open" | "restricted") {
        anyhow::bail!("--visibility must be `open` or `restricted` (got `{visibility}`)");
    }

    let id = ctx.identity()?;
    let hlc = HlcTimestamp::now_wall(id.did().clone());
    let mut meta = json!({"slug": slug, "visibility": visibility});
    merge(&mut meta, extra);

    // An encrypted channel is one MLS group, started here with the creator
    // alone in it; its epoch-0 public state rides the creation block.
    let (secure, _held) = if encrypted {
        let secure = Secure::open(ctx)?;
        // Held until the create is settled, so a second `create` racing this
        // one cannot discard the group this one is about to publish.
        let held = secure.hold(slug).await?;
        if secure.session.has_group(secure.server(), slug)? {
            if secure.channel(slug).await?.is_some() {
                if exist_ok {
                    println!("channel already exists: {slug}");
                    return Ok(false);
                }
                anyhow::bail!("this device already holds the group for {slug}");
            }
            // Left over from a create the server never answered and never took.
            secure.session.discard_group(secure.server(), slug)?;
        }
        let created = secure.session.create_group(secure.server(), slug)?;
        merge(
            &mut meta,
            json!({
                "suite": "mls",
                "mls_group_info": base64::engine::general_purpose::STANDARD.encode(&created.group_info),
                "mls_ratchet_tree": base64::engine::general_purpose::STANDARD.encode(&created.ratchet_tree),
            }),
        );
        if let Err(e) = secure.ensure_key_packages().await {
            eprintln!("warning: MLS key packages not published: {e:#}");
        }
        (Some(secure), Some(held))
    } else {
        (None, None)
    };
    let block = build_with_metadata(&id, BlockKind::ChannelCreate, hlc, meta);

    let base = base_http_url(&ctx.server_url()?);
    let mut outcome = post_channel_op(&base, "", &block).await;
    if let (Err(e), Some(secure)) = (&outcome, &secure) {
        if e.downcast_ref::<ChannelOpError>()
            .is_some_and(|c| c.status.is_client_error())
        {
            secure.session.discard_group(secure.server(), slug)?;
        } else {
            // No answer, or none to trust: the server may have created it
            // anyway, and then the group is the only copy of the channel's
            // keys. Keep it unless the server says the channel is not ours;
            // if it cannot say, the next create tidies up.
            match member_role(secure, slug, &id.did_string()).await {
                Ok(Some(role)) if role == "owner" => {
                    outcome = Ok(AdminResult {
                        block_cid: block.cid(),
                    })
                }
                Ok(_) => secure.session.discard_group(secure.server(), slug)?,
                Err(_) => {}
            }
        }
    }
    let label = if encrypted {
        format!("{visibility}, end-to-end encrypted")
    } else {
        visibility.clone()
    };
    match outcome {
        Ok(result) => {
            println!("channel created: {slug} ({label})");
            println!("  block_cid: {}", result.block_cid);
            Ok(true)
        }
        Err(e)
            if e.downcast_ref::<ChannelOpError>()
                .is_some_and(ChannelOpError::is_channel_exists) =>
        {
            if !exist_ok {
                anyhow::bail!(
                    "channel {slug} already exists on this server (pass --exist-ok to treat that as success)"
                );
            }
            println!("channel already exists: {slug}");
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Resolve a DID or a `[contacts]` name to a canonical DID.
pub(crate) fn resolve_who(ctx: &CliContext, who: &str) -> Result<String> {
    let who = who.trim();
    if who.starts_with("did:jig:") {
        return canonical_did(who);
    }
    let matches: Vec<&String> = ctx
        .effective()
        .contacts
        .iter()
        .filter(|(_, name)| name.eq_ignore_ascii_case(who))
        .map(|(did, _)| did)
        .collect();
    match matches.as_slice() {
        // A hand-edited `[contacts]` entry may spell the DID differently;
        // everything downstream (DM slugs, membership) compares canonical ones.
        [did] => canonical_did(did).with_context(|| format!("the `[contacts]` entry for `{who}`")),
        [] => anyhow::bail!("`{who}` is neither a did:jig nor a name in [contacts]; pass the DID"),
        _ => anyhow::bail!("more than one contact is called `{who}`; pass the DID"),
    }
}

/// The canonical spelling of a key-derived `did:jig`: the one the server
/// writes into rows and the one DM slugs are derived from.
fn canonical_did(did: &str) -> Result<String> {
    jig_core::Did::from_did_jig_string(did)
        .ok()
        .and_then(|d| d.as_bytes().ok())
        .map(|k| jig_core::Did::from_ed25519_pubkey(&k).to_did_jig_string())
        .ok_or_else(|| anyhow::anyhow!("`{did}` is not a valid did:jig"))
}

// ============================================================================
// add / kick / leave / promote / members
// ============================================================================

/// The channel as the caller sees it, or an error saying why not.
async fn visible_channel(secure: &Secure, slug: &str) -> Result<ChannelInfo> {
    secure
        .channel(slug)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no channel {slug} that you can see on this server"))
}

/// Apply `jig channel add <slug> <who>`. Owner only. On an encrypted channel
/// this fetches one of the member's key packages and commits their addition;
/// the welcome rides the same block.
pub async fn add(ctx: &CliContext, slug: String, who: String) -> Result<()> {
    let did = resolve_who(ctx, &who)?;
    let secure = Secure::open(ctx)?;
    let info = visible_channel(&secure, &slug).await?;
    let id = secure.identity();
    let cid = if info.encrypted() {
        let kp = secure.take_key_package(&did).await.with_context(|| {
            format!(
                "fetching a key package for {did} — they need to have run `jig chat` or \
                 `jig init` against this server at least once"
            )
        })?;
        let server = secure.server().to_string();
        secure
            .commit(
                &slug,
                |s| Ok(s.prepare_add(&server, &slug, &kp, &did)?),
                |c| {
                    let mut meta = json!({"channel": slug, "member_did": did});
                    merge(&mut meta, mls_fields(c));
                    build_with_metadata(id, BlockKind::MemberAdd, now(id), meta)
                },
            )
            .await?
    } else {
        let block = build_member_add(id, &slug, &did, now(id));
        secure.submit(&block).await?
    };
    println!("added {did} to {slug}");
    println!("  block_cid: {cid}");
    Ok(())
}

/// Apply `jig channel kick <slug> <who>`. Owner only.
pub async fn kick(ctx: &CliContext, slug: String, who: String) -> Result<()> {
    let did = resolve_who(ctx, &who)?;
    let secure = Secure::open(ctx)?;
    let info = visible_channel(&secure, &slug).await?;
    let id = secure.identity();
    let cid = if info.encrypted() {
        let server = secure.server().to_string();
        secure
            .commit(
                &slug,
                |s| Ok(s.prepare_remove(&server, &slug, &did)?),
                |c| build_member_remove(id, &slug, &did, mls_fields(c), now(id)),
            )
            .await?
    } else {
        secure
            .submit(&build_member_remove(id, &slug, &did, json!({}), now(id)))
            .await?
    };
    println!("removed {did} from {slug}");
    println!("  block_cid: {cid}");
    Ok(())
}

/// Apply `jig channel leave <slug>`. The owner archives instead.
///
/// On an encrypted channel this device drops its copy of the group at once,
/// and the server stops delivering to it; the next member online commits the
/// leaf out of the tree (a member cannot commit its own removal in MLS).
pub async fn leave(ctx: &CliContext, slug: String) -> Result<()> {
    let secure = Secure::open(ctx)?;
    let id = secure.identity();
    let me = id.did_string();
    let cid = secure
        .submit(&build_member_remove(id, &slug, &me, json!({}), now(id)))
        .await?;
    secure.session.discard_group(secure.server(), &slug)?;
    println!("left {slug}");
    println!("  block_cid: {cid}");
    Ok(())
}

/// Apply `jig channel promote <slug>`: restricted → open. Owner only. On an
/// encrypted channel, newcomers then join by external commit — the content
/// stays end-to-end encrypted, only who may join changes.
pub async fn promote(ctx: &CliContext, slug: String) -> Result<()> {
    let secure = Secure::open(ctx)?;
    let id = secure.identity();
    let cid = secure
        .submit(&build_channel_promote(id, &slug, now(id)))
        .await?;
    println!("{slug} is now open");
    println!("  block_cid: {cid}");
    Ok(())
}

#[derive(Debug, Deserialize)]
struct MemberView {
    did: String,
    role: String,
}

#[derive(Debug, Deserialize)]
struct MembersResponse {
    members: Vec<MemberView>,
}

/// Apply `jig channel members <slug>`.
pub async fn members(ctx: &CliContext, slug: String) -> Result<()> {
    let secure = Secure::open(ctx)?;
    let body: MembersResponse = secure
        .get_json(&format!(
            "/api/v1/channels/{}/members",
            escape_slug_for_url(&slug)
        ))
        .await?;
    let contacts = &ctx.effective().contacts;
    for m in body.members {
        let name = contacts.get(&m.did).map(String::as_str).unwrap_or("");
        println!("{:<6}  {:<16}  {}", m.role, name, m.did);
    }
    Ok(())
}

/// `did`'s role in the channel, as the server has it: `None` when it is not
/// a member, or the channel is not there for the caller to see. An error only
/// when the server could not be asked.
async fn member_role(secure: &Secure, slug: &str, did: &str) -> Result<Option<String>> {
    match secure
        .get_json::<MembersResponse>(&format!(
            "/api/v1/channels/{}/members",
            escape_slug_for_url(slug)
        ))
        .await
    {
        Ok(body) => Ok(body
            .members
            .into_iter()
            .find(|m| m.did == did)
            .map(|m| m.role)),
        Err(e)
            if e.downcast_ref::<Refused>()
                .is_some_and(|r| matches!(r.status, 403 | 404)) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn now(id: &jig_client::Identity) -> HlcTimestamp {
    HlcTimestamp::now_wall(id.did().clone())
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
/// POSTs it to `/api/v1/channels/<url-escaped slug>/members`.
pub async fn join(ctx: &CliContext, slug: String) -> Result<()> {
    // An open encrypted channel is joined by external commit, from the group
    // info its last committer published.
    // Failing to find out is an error, never a plaintext join.
    let secure = Secure::open(ctx)?;
    if secure
        .channel(&slug)
        .await?
        .is_some_and(|info| info.encrypted())
    {
        return join_encrypted(ctx, &secure, &slug).await;
    }
    let id = ctx.identity()?;
    let hlc = HlcTimestamp::now_wall(id.did().clone());
    let my_did = id.did_string();
    let block = build_member_add(&id, &slug, &my_did, hlc);

    let base = base_http_url(&ctx.server_url()?);
    let escaped = escape_slug_for_url(&slug);
    let result = post_channel_op(&base, &format!("/{escaped}/members"), &block).await?;
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

async fn join_encrypted(ctx: &CliContext, secure: &Secure, slug: &str) -> Result<()> {
    let id = secure.identity();
    let me = id.did_string();
    let server = secure.server().to_string();
    let _held = secure.hold(slug).await?;
    // A join whose answer never came may have landed: then the group held
    // here is the one that works, and joining again would replace it.
    if secure.session.has_group(&server, slug)? && member_role(secure, slug, &me).await?.is_some() {
        println!("already in {slug}");
        return Ok(());
    }
    let joined = |cid: &str| {
        println!("joined {slug} as {me} (end-to-end encrypted)");
        println!("  block_cid: {cid}");
        if let Err(e) = remember_joiner(ctx, &me) {
            eprintln!("warning: joined but contact name not saved: {e:#}");
        }
    };
    for attempt in 0..2 {
        let info = secure.group_info(slug).await?;
        let commit = secure.session.prepare_join(&server, slug, &info)?;
        let mut meta = json!({"channel": slug, "member_did": me});
        merge(&mut meta, mls_fields(&commit));
        let block = build_with_metadata(id, BlockKind::MemberAdd, now(id), meta);
        match secure.submit(&block).await {
            Ok(cid) => {
                joined(&cid);
                return Ok(());
            }
            Err(e) if refused(&e) => {
                secure.session.discard_group(&server, slug)?;
                let stale = e
                    .downcast_ref::<Refused>()
                    .is_some_and(|r| r.code == "STALE_EPOCH");
                if !(stale && attempt == 0) {
                    return Err(e);
                }
            }
            // No answer, or none to trust: keep the group unless the server
            // says the join did not land.
            Err(e) => {
                return match member_role(secure, slug, &me).await {
                    Ok(Some(_)) => {
                        joined(&block.cid());
                        Ok(())
                    }
                    Ok(None) => {
                        secure.session.discard_group(&server, slug)?;
                        Err(e)
                    }
                    Err(_) => Err(e.context(format!(
                        "no answer from the server; run `jig channel join {slug}` again to settle it"
                    ))),
                };
            }
        }
    }
    unreachable!("the loop returns on its second attempt")
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
/// `/api/v1/channels/<url-escaped slug>/archive`. The server accepts it
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
    let result = post_channel_op(&base, &format!("/{escaped}/archive"), &block).await?;
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
    /// `none` or `mls`. Absent from servers before v0.2.
    #[serde(default)]
    suite: String,
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
    // Cheap moment to stay reachable for encrypted channels; best effort.
    if let Ok(secure) = Secure::open(ctx) {
        let _ = secure.ensure_key_packages().await;
    }
    let id = ctx.identity()?;
    let base = base_http_url(&ctx.server_url()?);
    let url = format!("{base}/api/v1/channels");
    let proof = ReadProof::sign(&id, "GET", signable_path(&url));
    let http = crate::cmd::trust::http(&base, std::time::Duration::from_secs(10)).await?;
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
        let sealed = if c.suite == "mls" { "🔒" } else { "  " };
        println!(
            "{:<slug_w$}  {:<vis_w$}  {sealed}  {}",
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
    fn a_did_resolves_to_one_spelling_however_it_is_written() {
        let did = jig_core::Did::from_ed25519_pubkey(&[7u8; 32]).to_did_jig_string();
        let shouted = format!("did:jig:z{}", did["did:jig:z".len()..].to_uppercase());
        assert_ne!(shouted, did);
        assert_eq!(canonical_did(&shouted).unwrap(), did);
        assert_eq!(canonical_did(&did).unwrap(), did);
        assert!(canonical_did("did:jig:alice").is_err());
    }

    #[test]
    fn channel_exists_is_recognised_from_new_and_old_servers() {
        use reqwest::StatusCode;
        let new = r##"{"code":"CHANNEL_EXISTS","message":"channel '#hello' already exists"}"##;
        assert!(is_channel_exists(StatusCode::CONFLICT, new));
        let old = r#"{"code":"INGEST_ERROR","message":"UNIQUE constraint failed: channels.slug"}"#;
        assert!(is_channel_exists(StatusCode::INTERNAL_SERVER_ERROR, old));

        let replay = r#"{"code":"DUPLICATE_BLOCK","message":"block `x` was already ingested"}"#;
        assert!(!is_channel_exists(StatusCode::CONFLICT, replay));
        let other_500 = r#"{"code":"PERSIST_ERROR","message":"disk full"}"#;
        assert!(!is_channel_exists(
            StatusCode::INTERNAL_SERVER_ERROR,
            other_500
        ));
        assert!(!is_channel_exists(StatusCode::NOT_FOUND, new));
    }

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
                suite: "none".into(),
            },
            ChannelView {
                slug: "#devops".into(),
                visibility: "restricted".into(),
                owner_did: "did:jig:zBob".into(),
                created_at: 0,
                suite: "mls".into(),
            },
        ]);
    }
}
