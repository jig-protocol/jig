//! `jig ns resolve` / `jig ns list` — nameserver lookups from the CLI.
//!
//! `resolve` is verified (JEP-0004): the suffix's delegation comes from
//! `[naming.delegations]` in `cli.toml` (or the built-in `@jig` one), else
//! from `dns` discovery, and only an attestation from one of its authorities
//! is printed, with whether it is pinned. It never prints an unverified DID.
//!
//! `list` is a debug diagnostic: `/v1/handles` is debug-gated behind
//! `[debug] list_handles`, so its 404 means the route is not mounted.
//!
//! This module also holds the client side of register, renew and rotate
//! ([`Nameserver`]), used by `jig init` and `jig keys`.

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jig_client::naming::{
    Delegations, NameEvidence, NameEvidenceBundle, NameKey, NamePin, NamePins, NameResolver,
    ResolveError, Verified,
};
use jig_core::naming::{self, Attestation, Name, SuffixDelegation};
use serde::Deserialize;

use crate::cmd::common::CliContext;
use crate::config::DEFAULT_SUFFIX;

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

/// Render a unix-seconds expiry as something a human can act on.
pub fn format_expiry(valid_until: i64) -> String {
    match chrono::DateTime::from_timestamp(valid_until, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("unrepresentable timestamp ({valid_until})"),
    }
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

/// A challenge for one action, with the work the nameserver asks for it.
pub(crate) struct Challenge {
    pub challenge: String,
    pub offer: Option<jig_core::naming::PowOffer>,
    /// When the offer runs out, by the nameserver's clock (its `Date`).
    pub deadline: Option<std::time::Instant>,
}

/// Body of GET `/v1/challenge`. `pow_offer` is there when the suffix asks
/// for proof-of-work; the unsigned `pow` beside it is never read.
#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    challenge: String,
    #[serde(default)]
    pow_offer: Option<String>,
}

/// A refusal a nameserver answered a register, renew or rotate with, which
/// says it did not act: a 4xx, or `503 REGISTRATION_BUSY` (the pool was full
/// and the challenge was not consumed). Carried in the `anyhow` error so a
/// caller can tell which refusal it was.
#[derive(Debug, thiserror::Error)]
#[error("POST {url} returned {status}: {body}")]
pub(crate) struct Refusal {
    pub url: String,
    pub status: reqwest::StatusCode,
    pub body: String,
    /// `Retry-After`, in seconds, when the nameserver sent one.
    pub retry_after: Option<u64>,
}

impl Refusal {
    /// The `code` of the nameserver's error body, if it has one.
    pub(crate) fn code(&self) -> Option<String> {
        code_of(&self.body)
    }
}

fn code_of(body: &str) -> Option<String> {
    let body: serde_json::Value = serde_json::from_str(body).ok()?;
    Some(body.get("code")?.as_str()?.to_string())
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

/// How long a nameserver request may take. Short in tests, which wait it out.
const REQUEST_TIMEOUT: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_secs(2)
} else {
    std::time::Duration::from_secs(15)
};

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
            .timeout(REQUEST_TIMEOUT)
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

    /// GET `/v1/challenge` for `action` by `did` on `name`, with the
    /// proof-of-work it asks for: an offer this nameserver signed for exactly
    /// this request (JEP-0008 rule 16), or `None` when it asks for none. A
    /// nameserver from before proof-of-work ignores the query and sends no
    /// offer.
    pub(crate) async fn challenge_for(
        &self,
        action: jig_core::pow::Action,
        did: &str,
        name: &Name,
    ) -> Result<Challenge> {
        let label = match action {
            jig_core::pow::Action::NsRegister => "register",
            jig_core::pow::Action::NsRenew => "renew",
            jig_core::pow::Action::NsRotate => "rotate",
            other => anyhow::bail!("{other:?} is not a nameserver action"),
        };
        // A DID and `Name::parse`'s output are legal in a query as they are.
        let alias = name.as_alias();
        let url = format!(
            "{}/v1/challenge?action={label}&did={did}&name={alias}",
            self.base
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        {
            anyhow::bail!(
                "GET {url} returned {status}: the nameserver is not issuing challenges right \
                 now (rate-limited or busy); try again in a minute"
            );
        }
        if !status.is_success() {
            anyhow::bail!(
                "GET {url} returned {status}: {}",
                resp.text().await.unwrap_or_default()
            );
        }
        let received = std::time::Instant::now();
        let server_now = resp
            .headers()
            .get(reqwest::header::DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| chrono::DateTime::parse_from_rfc2822(v).ok())
            .map(|t| t.timestamp());
        let body: ChallengeResponse = resp
            .json()
            .await
            .with_context(|| format!("decoding the response to GET {url}"))?;
        let offer = body
            .pow_offer
            .map(|offer| {
                jig_client::pow::verify_offer(
                    &offer,
                    self.ns_did(),
                    &body.challenge,
                    action,
                    &alias,
                    did,
                )
            })
            .transpose()?;
        let deadline = offer
            .as_ref()
            .and_then(|o| jig_client::pow::deadline(o.expires_at, server_now, received));
        Ok(Challenge {
            challenge: body.challenge,
            offer,
            deadline,
        })
    }

    /// POST `body` to `path` and return the attestation from a 2xx reply.
    ///
    /// The outer `Err` means the nameserver did not act: the request never
    /// reached it, or it answered with a 4xx. The inner `Err` means it may
    /// have: a timeout or dropped connection after the request went out, a
    /// 5xx (a proxy's 502 can follow an applied change), a 2xx whose body
    /// could not be read, or a reply that does not verify. Rotate keeps the
    /// new key in that case, because the name may already point at it.
    pub(crate) async fn post_binding(
        &self,
        path: &str,
        body: &impl serde::Serialize,
        name: &Name,
        expected_did: &str,
    ) -> Result<Result<Attestation>> {
        let url = format!("{}{path}", self.base);
        let resp = match self.http.post(&url).json(body).send().await {
            Ok(resp) => resp,
            // Nothing was sent: no connection, or no request to send.
            Err(e) if e.is_connect() || e.is_builder() => {
                return Err(anyhow::Error::new(e).context(format!("POST {url}")));
            }
            Err(e) => {
                return Ok(Err(anyhow::Error::new(e)
                    .context(format!("POST {url} was sent, but no reply came back"))));
            }
        };
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()?.trim().parse().ok());
        if status.is_client_error() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Refusal {
                url,
                status,
                body,
                retry_after,
            }
            .into());
        }
        let text = match resp.text().await {
            Ok(text) => text,
            Err(e) => {
                return Ok(Err(anyhow::Error::new(e).context(format!(
                    "POST {url} returned {status}, but its body could not be read"
                ))));
            }
        };
        // The one 5xx that says nothing was done: the nameserver's own pool
        // refusal, which it answers before the challenge is consumed. A
        // proxy's 503 carries no such code and stays an unknown outcome.
        if status == reqwest::StatusCode::SERVICE_UNAVAILABLE
            && code_of(&text).as_deref() == Some("REGISTRATION_BUSY")
        {
            return Err(Refusal {
                url,
                status,
                body: text,
                retry_after,
            }
            .into());
        }
        if !status.is_success() {
            return Ok(Err(anyhow::anyhow!("POST {url} returned {status}: {text}")));
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

/// Pins for `jig ns resolve`: none. It is a lookup, not a use of the name,
/// so every answer is [`Verified::New`] and is reported as not pinned; the
/// pinned and rotated cases come with lane L7's name pin store.
struct NoPins;

impl NamePins for NoPins {
    fn name_pin(&self, _key: &NameKey) -> Option<NamePin> {
        None
    }
}

/// Evidence for `jig ns resolve`: nothing is kept, because nothing is acted
/// on. A command that acts on a name (`dm`, `channel add`) records through
/// lane L7's evidence writer.
struct NoEvidence;

impl NameEvidence for NoEvidence {
    fn record(&self, _bundle: &NameEvidenceBundle) -> Result<(), String> {
        Ok(())
    }
}

/// The delegations `jig ns resolve` uses. `--nameserver` replaces the URLs
/// to ask for a `config`-rooted suffix; the authorities stay, so it changes
/// where the client asks, never whose answer counts.
pub(crate) fn resolve_delegations(
    cfg: &crate::config::Config,
    name: &Name,
    nameserver: Option<&str>,
) -> Result<Delegations> {
    // For `@jig` with no cli.toml entry, `--nameserver` is where the built-in
    // delegation asks, as `[server] nameserver_url` would be.
    let mut cfg = cfg.clone();
    if let Some(url) = nameserver
        && name.suffix == DEFAULT_SUFFIX
        && !cfg.naming.delegations.contains_key(DEFAULT_SUFFIX)
    {
        cfg.server.nameserver_url = Some(url.to_string());
    }
    let mut delegations = crate::config::delegations(&cfg);
    if !delegations.config.contains_key(&name.suffix) && name.suffix == DEFAULT_SUFFIX {
        // Say why the built-in delegation is missing (a placeholder authority,
        // or no nameserver) rather than falling through to a dns lookup of a
        // name that is not a domain.
        crate::config::default_jig_delegation(&cfg)?;
    }
    if let Some(url) = nameserver {
        let url = url.trim().trim_end_matches('/').to_string();
        let Some(entry) = delegations.config.get_mut(&name.suffix) else {
            anyhow::bail!(
                "`--nameserver` only applies to a suffix with a [naming.delegations] entry; \
                 `{}` is looked up through its own domain",
                name.suffix
            );
        };
        entry.nameservers = vec![url];
    }
    Ok(delegations)
}

/// Render a verified resolution. Never prints a DID that did not verify.
pub fn format_verified(name: &Name, verified: &Verified) -> String {
    let (binding, state) = match verified {
        Verified::New(b) => (b, "verified, not pinned".to_string()),
        Verified::Pinned(b) => (b, "verified, pinned".to_string()),
        Verified::Rotated { binding, from } => (binding, format!("verified, rotated from {from}")),
    };
    format!(
        "{name} -> {did}\n  {state}\n  vouched for by {ns}\n  valid until: {until}",
        name = name.as_alias(),
        did = binding.did(),
        ns = binding.attestation.ns_did,
        until = format_expiry(binding.attestation.valid_until),
    )
}

/// Apply `jig ns resolve <alias@suffix> [--nameserver <url>]`.
pub async fn resolve(ctx: &CliContext, alias: String, nameserver: Option<String>) -> Result<()> {
    let name = Name::parse(&alias).with_context(|| format!("`{alias}` is not alias@suffix"))?;
    let delegations = resolve_delegations(ctx.effective(), &name, nameserver.as_deref())?;
    let verified = NameResolver::new()
        .resolve(&name.as_alias(), &delegations, &NoPins, &NoEvidence)
        .await
        .map_err(|e| anyhow::anyhow!("{}", explain_resolve_error(&name, &delegations, &e)))?;
    println!("{}", format_verified(&name, &verified));
    Ok(())
}

/// Turn a refused resolution into an operator message: what failed, and for
/// the two an operator can fix, how.
pub fn explain_resolve_error(name: &Name, delegations: &Delegations, e: &ResolveError) -> String {
    let full = name.as_alias();
    match e {
        ResolveError::NoDelegation { .. } => format!(
            "{full}: {e}. Add a [naming.delegations.\"{suffix}\"] entry to cli.toml naming its \
             authorities and nameservers",
            suffix = name.suffix
        ),
        ResolveError::Unreachable(_) => {
            let asked = delegations
                .config
                .get(&name.suffix)
                .map(|d| d.nameservers.join(", "))
                .unwrap_or_else(|| format!("https://{}", name.suffix));
            format!("{full}: {e} (asked {asked})")
        }
        _ => format!("{full}: {e}"),
    }
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
        stub_nameserver_raw(ns, move |p, b| {
            let (status, out) = post(p, b);
            Answer::Full(status, out)
        })
        .await
    }

    /// How the stub answers a request.
    #[derive(Clone)]
    enum Answer {
        /// A complete response.
        Full(u16, String),
        /// No response: the connection stays open past the client's timeout.
        Stall,
        /// The status line and headers, then half the promised body.
        Truncated(u16, String),
    }

    async fn stub_nameserver_raw(
        ns: SigningKey,
        post: impl Fn(&str, &str) -> Answer + Send + Sync + 'static,
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
                    let answer = match (method, path) {
                        ("GET", "/.well-known/jig-ns-delegation") => Answer::Full(200, deleg),
                        ("GET", p) if p.starts_with("/v1/challenge") => {
                            Answer::Full(200, r#"{"challenge":"c0ffee"}"#.into())
                        }
                        ("POST", p) => post(p, &body),
                        ("GET", p) if p.starts_with("/v1/resolve/") => post(p, ""),
                        _ => Answer::Full(404, "{}".into()),
                    };
                    let (status, out, sent) = match answer {
                        Answer::Full(status, out) => {
                            let len = out.len();
                            (status, out, len)
                        }
                        Answer::Truncated(status, out) => {
                            let half = out.len() / 2;
                            (status, out, half)
                        }
                        Answer::Stall => {
                            tokio::time::sleep(REQUEST_TIMEOUT * 2).await;
                            return;
                        }
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{}",
                        out.len(),
                        &out[..sent]
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
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
        let me = jig_client::Identity::generate_for_tests(dir.path());

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
        let me = jig_client::Identity::generate_for_tests(dir.path());

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
        let me = jig_client::Identity::generate_for_tests(dir.path());

        let err = crate::cmd::init::register_with_nameserver(&me, "dj", &base)
            .await
            .expect_err("a binding to someone else is not a registration");
        assert!(format!("{err:#}").contains("does not verify"), "{err:#}");
    }

    #[tokio::test]
    async fn rotate_tells_a_refused_rotation_from_an_unverifiable_reply() {
        let ns = key(1);
        let dir = tempdir().unwrap();
        let old = jig_client::Identity::generate_for_tests(dir.path());
        let new = jig_client::Identity::generate_for_tests(dir.path());

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

    /// Every way a rotation can fail after the request went out leaves its
    /// outcome unknown (the inner `Err`, so rotate keeps the new key); only
    /// a 4xx or a request that never connected is a definite refusal.
    #[tokio::test]
    async fn rotate_counts_only_a_4xx_or_no_connection_as_not_applied() {
        let ns = key(1);
        let dir = tempdir().unwrap();
        let old = jig_client::Identity::generate_for_tests(dir.path());
        let new = jig_client::Identity::generate_for_tests(dir.path());
        let rotate = |base: String| {
            let (old, new) = (&old, &new);
            async move { crate::cmd::keys::rotate_with_nameserver(old, new, "dj@dj.jig", &base).await }
        };
        let now = chrono::Utc::now().timestamp();
        let applied = reply(&Attestation::sign(
            &key(1),
            &new.did_string(),
            "dj@dj.jig",
            now - 1,
            now + DAY,
        ));

        let unknown = [
            ("a stall past the timeout", Answer::Stall),
            (
                "a 2xx with a truncated body",
                Answer::Truncated(200, applied),
            ),
            (
                "a 502 from a proxy",
                Answer::Full(502, "bad gateway".into()),
            ),
            ("a 500", Answer::Full(500, r#"{"code":"INTERNAL"}"#.into())),
        ];
        for (what, answer) in unknown {
            let (base, _) = stub_nameserver_raw(ns.clone(), move |_, _| answer.clone()).await;
            let outcome = rotate(base).await.unwrap_or_else(|e| {
                panic!("{what}: the rotation may have applied, so not a refusal: {e:#}")
            });
            assert!(outcome.is_err(), "{what}: no verified attestation");
        }

        let (base, _) = stub_nameserver_raw(ns.clone(), |_, _| {
            Answer::Full(409, r#"{"code":"DID_HOLDS_NAME"}"#.into())
        })
        .await;
        assert!(rotate(base).await.is_err(), "a 4xx is a refusal");

        // A port nothing listens on: the request never connects.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let (base, _) = stub_nameserver(ns, attest_as(key(1), "dj@dj.jig")).await;
        let ns_conn = Nameserver::connect(&base).await.unwrap();
        let moved = Nameserver {
            base: format!("http://{addr}"),
            ..ns_conn
        };
        let name = Name::parse("dj@dj.jig").unwrap();
        let body = crate::cmd::keys::build_rotate_request(&old, &new, "dj@dj.jig", "c0ffee");
        assert!(
            moved
                .post_binding("/v1/rotate", &body, &name, &new.did_string())
                .await
                .is_err(),
            "nothing was sent, so nothing was applied"
        );
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

    // ------------------------------------------------------------------
    // jig ns resolve
    // ------------------------------------------------------------------

    fn cfg_with_jig(authority: &str, nameserver: &str) -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.naming.delegations.insert(
            DEFAULT_SUFFIX.into(),
            crate::config::DelegationEntry {
                authorities: vec![authority.into()],
                nameservers: vec![nameserver.into()],
            },
        );
        cfg
    }

    async fn resolve_against(
        cfg: &crate::config::Config,
        name: &str,
    ) -> Result<Verified, jig_client::naming::ResolveError> {
        let name = Name::parse(name).unwrap();
        let delegations = resolve_delegations(cfg, &name, None).unwrap();
        NameResolver::new()
            .resolve(&name.as_alias(), &delegations, &NoPins, &NoEvidence)
            .await
    }

    /// The stub's resolve answer: `ns` attests `did` for `dj@jig`.
    fn attests(ns: SigningKey, did: String) -> impl Fn(&str, &str) -> (u16, String) {
        move |_, _| {
            let now = chrono::Utc::now().timestamp();
            let att = Attestation::sign(&ns, &did, "dj@jig", now - 1, now + DAY);
            (200, reply(&att))
        }
    }

    #[tokio::test]
    async fn resolve_reports_a_verified_unpinned_binding_from_the_authority() {
        let ns = key(1);
        let dj = did_of(&key(2));
        let (base, seen) = stub_nameserver(ns.clone(), attests(ns.clone(), dj.clone())).await;
        let cfg = cfg_with_jig(&did_of(&ns), &base);

        let verified = resolve_against(&cfg, "DJ@jig").await.expect("verifies");
        let Verified::New(binding) = &verified else {
            panic!("no pins, so every answer is new: {verified:?}");
        };
        assert_eq!(binding.did(), dj, "the signed DID, not the hint");
        let out = format_verified(&Name::parse("dj@jig").unwrap(), &verified);
        assert!(out.starts_with(&format!("dj@jig -> {dj}")), "{out}");
        assert!(out.contains("verified, not pinned"), "{out}");
        assert!(out.contains(&did_of(&ns)), "names who vouched: {out}");
        assert!(
            seen.lock()
                .unwrap()
                .iter()
                .any(|(_, p, _)| p == "/v1/resolve/dj@jig"),
            "asked for the full lowercased name"
        );
    }

    #[tokio::test]
    async fn resolve_refuses_an_attestation_from_a_key_that_is_not_the_authority() {
        let ns = key(1);
        let impostor = key(9);
        let (base, _) = stub_nameserver(ns.clone(), attests(impostor, did_of(&key(2)))).await;
        let cfg = cfg_with_jig(&did_of(&ns), &base);
        let err = resolve_against(&cfg, "dj@jig").await.expect_err("refused");
        assert!(
            !err.to_string().contains(&did_of(&key(2))),
            "a refusal never prints the unverified DID: {err}"
        );
    }

    #[test]
    fn nameserver_flag_moves_where_to_ask_but_not_whose_answer_counts() {
        let cfg = cfg_with_jig("did:jig:zAuthority", "https://ns.example");
        let name = Name::parse("dj@jig").unwrap();
        let d = resolve_delegations(&cfg, &name, Some("http://127.0.0.1:9/")).unwrap();
        assert_eq!(d.config["jig"].nameservers, ["http://127.0.0.1:9"]);
        assert_eq!(d.config["jig"].authorities, ["did:jig:zAuthority"]);

        let dns = Name::parse("dj@example.org").unwrap();
        let err = resolve_delegations(&cfg, &dns, Some("http://127.0.0.1:9")).unwrap_err();
        assert!(err.to_string().contains("own domain"), "{err}");
    }
}
