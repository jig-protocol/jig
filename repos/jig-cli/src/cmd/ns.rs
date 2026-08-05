//! `jig ns resolve` / `jig ns list` — nameserver lookups from the CLI.
//!
//! Until now the only way to answer "what DID is `dj@dj.jig`?" was curl.
//! Both subcommands are read-only diagnostics against a nameserver's
//! v0.0.2 HTTP surface (`jig-nameserver::v0_0_2_resolve` /
//! `v0_0_2_handles`), and both take pains to explain a 404 rather than
//! reporting a bare status: the two 404s an operator actually hits mean
//! very different things.
//!   * `resolve` 404 → the alias has no valid attestation (body carries
//!     `NOT_FOUND` + a message naming the alias).
//!   * `list` 404 → the route is not mounted at all, because `/v1/handles`
//!     is debug-gated behind `[debug] list_handles`.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::cmd::common::CliContext;

/// Subset of the attestation JSON that `GET /v1/resolve/:alias` returns.
/// The server hands back the stored attestation verbatim, so unknown
/// fields (`sig`, `profile_ttl_seconds`, …) are ignored here.
#[derive(Debug, Deserialize)]
pub struct Resolution {
    pub did: String,
    pub alias: String,
    pub valid_until: i64,
}

/// One row of `GET /v1/handles`. Mirrors
/// `jig_nameserver::v0_0_2_handles::HandleEntry`.
#[derive(Debug, Deserialize)]
pub struct HandleEntry {
    pub alias: String,
    pub did: String,
    pub valid_until: i64,
}

#[derive(Debug, Deserialize)]
pub struct HandlesList {
    pub aliases: Vec<HandleEntry>,
}

/// Structured error body shared by the nameserver's v0.0.2 endpoints.
#[derive(Debug, Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
}

/// Resolve the nameserver base URL: `--nameserver` wins, else
/// `[server] nameserver_url` from `cli.toml`.
pub fn nameserver_base(ctx: &CliContext, flag: Option<&str>) -> Result<String> {
    let raw = flag
        .map(str::to_string)
        .or_else(|| ctx.effective().server.nameserver_url.clone())
        .unwrap_or_default();
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        anyhow::bail!(
            "no nameserver configured — pass `--nameserver <url>` \
             or set `nameserver_url` under `[server]` in cli.toml"
        );
    }
    Ok(trimmed.to_string())
}

/// Reject aliases that would change the shape of the request path.
pub fn validate_alias(alias: &str) -> Result<()> {
    // The alias goes into the request path unescaped: `@` and `.` are legal
    // there, and percent-encoding them would depend on the server decoding
    // the segment. Anything that could reshape the path is rejected here
    // instead, so a typo fails locally rather than as a confusing 404.
    if alias.is_empty() {
        anyhow::bail!("alias must not be empty (e.g. `dj@dj.jig`)");
    }
    if let Some(bad) = alias
        .chars()
        .find(|c| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '%'))
    {
        anyhow::bail!("alias `{alias}` contains an illegal character `{bad}`");
    }
    Ok(())
}

/// Render a unix-seconds expiry as something a human can act on.
pub fn format_expiry(valid_until: i64) -> String {
    match chrono::DateTime::from_timestamp(valid_until, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("unrepresentable timestamp ({valid_until})"),
    }
}

/// One-line rendering of a successful resolution.
pub fn format_resolution(r: &Resolution) -> String {
    format!(
        "{alias} -> {did}\n  valid until: {until}",
        alias = r.alias,
        did = r.did,
        until = format_expiry(r.valid_until),
    )
}

/// Turn a non-success `GET /v1/resolve/:alias` response into an operator
/// message.
pub fn explain_resolve_error(status: u16, body: &str, alias: &str) -> String {
    if let Ok(parsed) = serde_json::from_str::<ErrorBody>(body) {
        // The server's own message distinguishes "alias unregistered or
        // expired" from "route missing"; a bare "not found" would not.
        return format!("{} ({})", parsed.message, parsed.code);
    }
    format!("resolving `{alias}` failed with HTTP {status}: {body}")
}

/// Turn a non-success `GET /v1/handles` response into an operator message.
pub fn explain_list_error(status: u16, body: &str) -> String {
    if status == 404 {
        return "the nameserver did not mount `/v1/handles`. That route is \
                debug-gated: it is only served when the nameserver config \
                sets `[debug] list_handles = true`. This is not a fault of \
                the nameserver."
            .to_string();
    }
    format!("listing handles failed with HTTP {status}: {body}")
}

/// Render the handle table.
pub fn format_handles(entries: &[HandleEntry]) -> String {
    if entries.is_empty() {
        return "(no aliases registered)".to_string();
    }
    let alias_w = entries.iter().map(|e| e.alias.len()).max().unwrap_or(0);
    entries
        .iter()
        .map(|e| {
            format!(
                "{:<alias_w$}  {}  (until {})",
                e.alias,
                e.did,
                format_expiry(e.valid_until),
                alias_w = alias_w,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Shared HTTP client for the two lookups. Short timeout: these are
/// interactive diagnostics, not background jobs.
fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("building HTTP client for the nameserver")
}

/// Apply `jig ns resolve <alias> [--nameserver <url>]`.
pub async fn resolve(ctx: &CliContext, alias: String, nameserver: Option<String>) -> Result<()> {
    validate_alias(&alias)?;
    let base = nameserver_base(ctx, nameserver.as_deref())?;
    let url = format!("{base}/v1/resolve/{alias}");

    let resp = http_client()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .with_context(|| format!("reading body of GET {url}"))?;
    if !status.is_success() {
        anyhow::bail!("{}", explain_resolve_error(status.as_u16(), &body, &alias));
    }

    let resolution: Resolution =
        serde_json::from_str(&body).context("decoding /v1/resolve response")?;
    println!("{}", format_resolution(&resolution));
    Ok(())
}

/// Apply `jig ns list [--nameserver <url>]`.
pub async fn list(ctx: &CliContext, nameserver: Option<String>) -> Result<()> {
    let base = nameserver_base(ctx, nameserver.as_deref())?;
    let url = format!("{base}/v1/handles");

    let resp = http_client()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .with_context(|| format!("reading body of GET {url}"))?;
    if !status.is_success() {
        anyhow::bail!("{}", explain_list_error(status.as_u16(), &body));
    }

    let handles: HandlesList =
        serde_json::from_str(&body).context("decoding /v1/handles response")?;
    println!("{}", format_handles(&handles.aliases));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::common::GlobalOverrides;

    fn ctx_with(nameserver_line: &str) -> (tempfile::TempDir, CliContext) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.toml");
        std::fs::write(
            &path,
            format!(
                "[server]\nbase_url = \"http://127.0.0.1:7117\"\n{nameserver_line}\n\
                 [user]\ndid = \"did:jig:zA\"\ndisplay_name = \"dj\"\n\
                 default_channel = \"#general\"\n"
            ),
        )
        .unwrap();
        let ctx = CliContext::resolve(&GlobalOverrides {
            config: Some(path),
            ..Default::default()
        })
        .unwrap();
        (dir, ctx)
    }

    #[test]
    fn nameserver_flag_wins_over_the_config_file() {
        let (_dir, ctx) = ctx_with("nameserver_url = \"http://127.0.0.1:7118\"");
        assert_eq!(
            nameserver_base(&ctx, Some("http://other:9999")).unwrap(),
            "http://other:9999"
        );
    }

    #[test]
    fn nameserver_falls_back_to_the_config_file() {
        let (_dir, ctx) = ctx_with("nameserver_url = \"http://127.0.0.1:7118/\"");
        assert_eq!(
            nameserver_base(&ctx, None).unwrap(),
            "http://127.0.0.1:7118",
            "trailing slash must be trimmed so paths don't double up"
        );
    }

    #[test]
    fn missing_nameserver_says_how_to_supply_one() {
        let (_dir, ctx) = ctx_with("");
        let msg = format!("{:#}", nameserver_base(&ctx, None).unwrap_err());
        assert!(msg.contains("--nameserver"), "must name the flag: {msg}");
    }

    #[test]
    fn validate_alias_rejects_path_shaped_input() {
        // A `/` would silently address a different route; whitespace makes
        // an invalid URL. Both should fail before any request is sent.
        assert!(validate_alias("dj@dj.jig").is_ok());
        assert!(validate_alias("dj/../handles").is_err());
        assert!(validate_alias("dj dj.jig").is_err());
        assert!(validate_alias("").is_err());
    }

    #[test]
    fn format_resolution_shows_alias_did_and_readable_expiry() {
        let r = Resolution {
            did: "did:jig:zAlice".into(),
            alias: "dj@dj.jig".into(),
            valid_until: 1_781_015_579,
        };
        let line = format_resolution(&r);
        assert!(line.contains("dj@dj.jig -> did:jig:zAlice"), "got {line}");
        assert!(
            !line.contains("1781015579"),
            "raw epoch seconds are not human-readable: {line}"
        );
        assert!(line.contains("2026"), "expiry must show a date: {line}");
    }

    #[test]
    fn resolve_404_reports_the_servers_own_message() {
        // Distinguishes "alias not registered" from "route not mounted",
        // which a bare `not found` would blur.
        let body = r#"{"code":"NOT_FOUND","message":"no valid attestation for `dj@dj.jig`"}"#;
        let msg = explain_resolve_error(404, body, "dj@dj.jig");
        assert!(
            msg.contains("no valid attestation for `dj@dj.jig`"),
            "got {msg}"
        );
    }

    #[test]
    fn resolve_404_without_a_structured_body_still_shows_what_came_back() {
        let msg = explain_resolve_error(404, "<html>nginx</html>", "dj@dj.jig");
        assert!(msg.contains("404"), "status must survive: {msg}");
        assert!(msg.contains("nginx"), "body must survive: {msg}");
    }

    #[test]
    fn list_404_blames_the_debug_gate_not_the_nameserver() {
        let msg = explain_list_error(404, "");
        assert!(
            msg.contains("list_handles"),
            "must name the config key that mounts the route: {msg}"
        );
        assert!(
            !msg.to_lowercase().contains("broken"),
            "must not imply the nameserver is broken: {msg}"
        );
    }

    #[test]
    fn format_handles_reports_an_empty_directory_explicitly() {
        assert!(format_handles(&[]).contains("no aliases"));
    }

    #[test]
    fn format_handles_lists_one_row_per_alias() {
        let rows = vec![
            HandleEntry {
                alias: "dj@dj.jig".into(),
                did: "did:jig:zAlice".into(),
                valid_until: 1_781_015_579,
            },
            HandleEntry {
                alias: "deji@dj.jig".into(),
                did: "did:jig:zBob".into(),
                valid_until: 1_781_015_579,
            },
        ];
        let table = format_handles(&rows);
        assert_eq!(table.lines().count(), 2, "one line per alias: {table}");
        assert!(table.contains("dj@dj.jig") && table.contains("did:jig:zBob"));
    }
}
