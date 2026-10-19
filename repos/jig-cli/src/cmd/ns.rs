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
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jig_core::naming::{self, Attestation, Name, SuffixDelegation};
use serde::Deserialize;

use crate::cmd::common::CliContext;

/// Subset of the JSON that `GET /v1/resolve/:alias` returns: the unsigned
/// `did`, `alias` and `valid_until` hints. Unknown fields are ignored.
/// F1 slice 6b moves this command to verifying the signed attestation.
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

/// Body of GET `/v1/challenge` (only the `challenge` field is read).
#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    challenge: String,
}

/// Body of GET `/.well-known/jig-ns-delegation`.
#[derive(Debug, Deserialize)]
struct DelegationResponse {
    envelopes: Vec<String>,
}

/// The body register, renew and rotate return. Only the signed
/// `attestation` envelope is read: the unsigned `did`, `alias` and
/// `valid_until` beside it are transitional hints this client never trusts.
#[derive(Debug, Deserialize)]
struct BindingResponse {
    attestation: String,
}

/// A nameserver to register, renew or rotate an alias with: its base URL and
/// the suffix delegation it publishes, whose single authority is the DID that
/// proofs of control are bound to.
///
/// The delegation comes from the nameserver itself, so it does not prove the
/// nameserver speaks for the suffix: that is the resolver's job (F1 slice 6b).
/// It does pin what a reply must be: an attestation signed by that authority,
/// for the name asked about, valid now. A proof signed for the wrong
/// `ns_did` is refused by the real nameserver, so a lying delegation cannot
/// turn a proof into one for another nameserver.
pub(crate) struct Nameserver {
    base: String,
    http: reqwest::Client,
    delegation: SuffixDelegation,
}

impl Nameserver {
    /// Fetch and check the nameserver's delegation.
    pub(crate) async fn connect(ns_url: &str) -> Result<Self> {
        let base = ns_url.trim().trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .context("building HTTP client for nameserver")?;
        let url = format!("{base}/.well-known/jig-ns-delegation");
        let body: DelegationResponse = get_json(&http, &url).await?;
        let envelopes = body
            .envelopes
            .iter()
            .map(|e| URL_SAFE_NO_PAD.decode(e))
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("{url}: an envelope is not unpadded base64url"))?;
        let delegation = SuffixDelegation::from_envelopes(&envelopes)
            .with_context(|| format!("{url}: the delegation does not verify"))?;
        if delegation.authorities.len() != 1 {
            anyhow::bail!(
                "{url} lists {} authorities for `{}`; a nameserver publishes itself as the only one",
                delegation.authorities.len(),
                delegation.suffix
            );
        }
        Ok(Self {
            base,
            http,
            delegation,
        })
    }

    /// The nameserver's DID, which every proof of control names.
    pub(crate) fn ns_did(&self) -> &str {
        &self.delegation.authorities[0]
    }

    /// The suffix this nameserver issues aliases under.
    pub(crate) fn suffix(&self) -> &str {
        &self.delegation.suffix
    }

    /// GET `/v1/challenge`.
    pub(crate) async fn challenge(&self) -> Result<String> {
        let url = format!("{}/v1/challenge", self.base);
        let body: ChallengeResponse = get_json(&self.http, &url).await?;
        Ok(body.challenge)
    }

    /// POST `body` to `path` and return the attestation from a 2xx reply.
    /// A transport error or non-2xx status is `Err`. A 2xx is `Ok`, with the
    /// inner `Err` saying why the reply does not verify; the two are kept
    /// apart because after a 2xx the nameserver may already have acted.
    pub(crate) async fn post_binding(
        &self,
        path: &str,
        body: &impl serde::Serialize,
        name: &Name,
        expected_did: &str,
    ) -> Result<Result<Attestation>> {
        let url = format!("{}{path}", self.base);
        let resp = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .with_context(|| format!("reading body of POST {url}"))?;
        if !status.is_success() {
            anyhow::bail!("POST {url} returned {status}: {text}");
        }
        let now = chrono::Utc::now().timestamp();
        Ok(
            verify_binding_reply(&text, &self.delegation, name, expected_did, now)
                .with_context(|| format!("POST {url} succeeded, but its reply does not verify")),
        )
    }
}

/// Check a register, renew or rotate reply: the attestation is signed by the
/// delegation's authority, for `name`, valid at `now`, and binds the name to
/// `expected_did`.
pub(crate) fn verify_binding_reply(
    body: &str,
    delegation: &SuffixDelegation,
    name: &Name,
    expected_did: &str,
    now: i64,
) -> Result<Attestation> {
    let reply: BindingResponse =
        serde_json::from_str(body).context("the reply has no `attestation` envelope")?;
    let envelope = URL_SAFE_NO_PAD
        .decode(&reply.attestation)
        .context("`attestation` is not unpadded base64url")?;
    let att = Attestation::from_envelope(&envelope).context("the attestation does not verify")?;
    naming::verify_binding(&att, delegation, name, now)
        .context("the attestation is not a valid binding for this name")?;
    if att.did != expected_did {
        anyhow::bail!(
            "the attestation binds {} to {}, not to {expected_did}",
            att.alias,
            att.did
        );
    }
    Ok(att)
}

/// Unpadded base64url, the encoding every naming envelope travels in.
pub(crate) fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn get_json<T: serde::de::DeserializeOwned>(http: &reqwest::Client, url: &str) -> Result<T> {
    let resp = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!(
            "GET {url} returned {status}: {}",
            resp.text().await.unwrap_or_default()
        );
    }
    resp.json()
        .await
        .with_context(|| format!("decoding the response to GET {url}"))
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
    use ed25519_dalek::SigningKey;
    use jig_core::naming::{Action, Root};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    // ------------------------------------------------------------------
    // Register, renew and rotate against a stub nameserver speaking the
    // F1 slice 2 wire shape (#210).
    // ------------------------------------------------------------------

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn did_of(key: &SigningKey) -> String {
        jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    fn delegation(ns: &SigningKey) -> SuffixDelegation {
        SuffixDelegation::sign(&[ns], "dj.jig", Root::Dns, "dj.jig", NOW + DAY)
    }

    fn reply(att: &Attestation) -> String {
        serde_json::json!({
            "attestation": b64u(&att.envelope),
            "links": [],
            "reachability": null,
            // Unsigned hints, deliberately wrong: the client must not read them.
            "did": "did:jig:zLiar",
            "alias": "liar@dj.jig",
            "valid_until": 0,
        })
        .to_string()
    }

    fn check(body: &str, name: &str, did: &str, ns: &SigningKey) -> Result<Attestation> {
        verify_binding_reply(body, &delegation(ns), &Name::parse(name).unwrap(), did, NOW)
    }

    #[test]
    fn a_reply_verifies_from_the_signed_attestation_not_the_hints() {
        let ns = key(1);
        let me = did_of(&key(2));
        let att = Attestation::sign(&ns, &me, "dj@dj.jig", NOW - 1, NOW + 90 * DAY);
        let got = check(&reply(&att), "DJ@dj.jig", &me, &ns).expect("verifies");
        assert_eq!(got.did, me);
        assert_eq!(got.alias, "dj@dj.jig");
        assert_eq!(got.ns_did, did_of(&ns));
    }

    #[test]
    fn a_reply_is_refused_unless_it_binds_this_name_to_this_did_from_the_authority() {
        let ns = key(1);
        let me = did_of(&key(2));
        let cases = [
            (
                "another DID",
                Attestation::sign(&ns, &did_of(&key(3)), "dj@dj.jig", NOW - 1, NOW + DAY),
                "not to",
            ),
            (
                "another alias",
                Attestation::sign(&ns, &me, "dk@dj.jig", NOW - 1, NOW + DAY),
                "not a valid binding",
            ),
            (
                "a key that is not the delegation's authority",
                Attestation::sign(&key(9), &me, "dj@dj.jig", NOW - 1, NOW + DAY),
                "not a valid binding",
            ),
            (
                "an expired attestation",
                Attestation::sign(&ns, &me, "dj@dj.jig", NOW - 2 * DAY, NOW - 1),
                "not a valid binding",
            ),
        ];
        for (what, att, why) in cases {
            let err = check(&reply(&att), "dj@dj.jig", &me, &ns).expect_err(what);
            assert!(format!("{err:#}").contains(why), "{what}: {err:#}");
        }
        let err = check(r#"{"did":"did:jig:zLiar"}"#, "dj@dj.jig", &me, &ns)
            .expect_err("a reply carrying only the hints");
        assert!(format!("{err:#}").contains("no `attestation`"), "{err:#}");
    }

    /// One request the stub received: method, path and body.
    type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

    /// A stub nameserver on a loopback port. `post` answers each POST from
    /// its path and body; GETs serve `ns`'s delegation and a fixed challenge.
    async fn stub_nameserver(
        ns: SigningKey,
        post: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
    ) -> (String, Seen) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen: Seen = Arc::default();
        let log = seen.clone();
        let post = Arc::new(post);
        let deleg = serde_json::json!({
            "envelopes": SuffixDelegation::sign(&[&ns], "dj.jig", Root::Dns, "dj.jig",
                chrono::Utc::now().timestamp() + DAY)
                .envelopes
                .iter()
                .map(|e| b64u(e))
                .collect::<Vec<_>>(),
        })
        .to_string();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let (log, post, deleg) = (log.clone(), post.clone(), deleg.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head, body) = loop {
                        let n = sock.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf).to_string();
                        if let Some((head, body)) = text.split_once("\r\n\r\n") {
                            let len = head
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().ok())?
                                })
                                .unwrap_or(0);
                            if body.len() >= len || n == 0 {
                                break (head.to_string(), body.to_string());
                            }
                        }
                    };
                    let mut words = head.split_whitespace();
                    let (method, path) = (words.next().unwrap(), words.next().unwrap());
                    log.lock()
                        .unwrap()
                        .push((method.into(), path.into(), body.clone()));
                    let (status, out) = match (method, path) {
                        ("GET", "/.well-known/jig-ns-delegation") => (200, deleg),
                        ("GET", "/v1/challenge") => (200, r#"{"challenge":"c0ffee"}"#.into()),
                        ("POST", p) => post(p, &body),
                        _ => (404, "{}".into()),
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{out}",
                        out.len()
                    );
                    sock.write_all(resp.as_bytes()).await.unwrap();
                });
            }
        });
        (base, seen)
    }

    /// The stub's `post`: attest whatever DID asked, for `alias`, as `ns`.
    fn attest_as(ns: SigningKey, alias: &'static str) -> impl Fn(&str, &str) -> (u16, String) {
        move |_path, body| {
            let req: serde_json::Value = serde_json::from_str(body).unwrap();
            let did = req["did"]
                .as_str()
                .or(req["new_did"].as_str())
                .unwrap()
                .to_string();
            let now = chrono::Utc::now().timestamp();
            let att = Attestation::sign(&ns, &did, alias, now - 1, now + 90 * DAY);
            (200, reply(&att))
        }
    }

    fn sent_proof(seen: &Seen, path: &str) -> (String, Vec<u8>) {
        let seen = seen.lock().unwrap();
        let (_, _, body) = seen
            .iter()
            .find(|(m, p, _)| m == "POST" && p == path)
            .expect("the client posted");
        let req: serde_json::Value = serde_json::from_str(body).unwrap();
        let proof = URL_SAFE_NO_PAD
            .decode(req["proof_of_control"].as_str().unwrap())
            .unwrap();
        (req["did"].as_str().unwrap().to_string(), proof)
    }

    #[tokio::test]
    async fn register_signs_for_the_delegated_nameserver_and_verifies_the_reply() {
        let ns = key(1);
        let (base, seen) = stub_nameserver(ns.clone(), attest_as(ns.clone(), "dj@dj.jig")).await;
        let dir = tempdir().unwrap();
        let me = jig_client::Identity::generate_and_save(dir.path()).unwrap();

        let att = crate::cmd::init::register_with_nameserver(&me, "DJ", &base)
            .await
            .expect("registers");
        assert_eq!(att.did, me.did_string());
        assert_eq!(att.alias, "dj@dj.jig");

        let (did, proof) = sent_proof(&seen, "/v1/register");
        assert_eq!(did, me.did_string());
        naming::verify_proof(
            &did,
            &proof,
            Action::Register,
            &did_of(&ns),
            "dj@dj.jig",
            "c0ffee",
        )
        .expect("the proof names the delegation's authority and the full lowercased name");
    }

    #[tokio::test]
    async fn renew_signs_a_renew_proof() {
        let ns = key(1);
        let (base, seen) = stub_nameserver(ns.clone(), attest_as(ns.clone(), "dj@dj.jig")).await;
        let dir = tempdir().unwrap();
        let me = jig_client::Identity::generate_and_save(dir.path()).unwrap();

        crate::cmd::keys::renew_with_nameserver(&me, "dj@DJ.jig", &base)
            .await
            .expect("renews");
        let (did, proof) = sent_proof(&seen, "/v1/renew");
        naming::verify_proof(
            &did,
            &proof,
            Action::Renew,
            &did_of(&ns),
            "dj@dj.jig",
            "c0ffee",
        )
        .expect("a renew proof for the delegation's authority");
    }

    #[tokio::test]
    async fn register_refuses_a_reply_for_another_did() {
        let ns = key(1);
        let other = did_of(&key(7));
        let liar = move |_: &str, _: &str| {
            let now = chrono::Utc::now().timestamp();
            let att = Attestation::sign(&key(1), &other, "dj@dj.jig", now - 1, now + DAY);
            (200, reply(&att))
        };
        let (base, _) = stub_nameserver(ns, liar).await;
        let dir = tempdir().unwrap();
        let me = jig_client::Identity::generate_and_save(dir.path()).unwrap();

        let err = crate::cmd::init::register_with_nameserver(&me, "dj", &base)
            .await
            .expect_err("a binding to someone else is not a registration");
        assert!(format!("{err:#}").contains("does not verify"), "{err:#}");
    }

    #[tokio::test]
    async fn rotate_tells_a_refused_rotation_from_an_unverifiable_reply() {
        let ns = key(1);
        let dir = tempdir().unwrap();
        let old = jig_client::Identity::generate_and_save(dir.path()).unwrap();
        let new = jig_client::Identity::generate_and_save(dir.path()).unwrap();

        // Refused: the outer Err, so the caller may delete the new key.
        let (base, _) = stub_nameserver(ns.clone(), |_: &str, _: &str| {
            (401, r#"{"code":"PROOF_FAILED"}"#.into())
        })
        .await;
        let refused =
            crate::cmd::keys::rotate_with_nameserver(&old, &new, "dj@dj.jig", &base).await;
        assert!(refused.is_err(), "a 401 is a refused rotation");

        // Accepted, but the attestation still names the old DID: the inner
        // Err, so the caller keeps both keys.
        let old_did = old.did_string();
        let stale = move |_: &str, _: &str| {
            let now = chrono::Utc::now().timestamp();
            let att = Attestation::sign(&key(1), &old_did, "dj@dj.jig", now - 1, now + DAY);
            (200, reply(&att))
        };
        let (base, _) = stub_nameserver(ns.clone(), stale).await;
        let accepted = crate::cmd::keys::rotate_with_nameserver(&old, &new, "dj@dj.jig", &base)
            .await
            .expect("the nameserver accepted");
        assert!(
            accepted.is_err(),
            "the reply binds the old DID, not the new one"
        );

        // Accepted and verified.
        let (base, _) = stub_nameserver(ns.clone(), attest_as(ns, "dj@dj.jig")).await;
        let att = crate::cmd::keys::rotate_with_nameserver(&old, &new, "dj@dj.jig", &base)
            .await
            .expect("accepted")
            .expect("verifies");
        assert_eq!(att.did, new.did_string());
    }

    #[tokio::test]
    async fn connect_refuses_a_delegation_that_does_not_verify() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let out = r#"{"envelopes":["bm90LWNvc2U"]}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}",
                out.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });
        let err = Nameserver::connect(&base).await.err().expect("refused");
        assert!(format!("{err:#}").contains("does not verify"), "{err:#}");
    }
}
