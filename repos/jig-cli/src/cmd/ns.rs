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

/// HTTP client for a nameserver at `base`, and the DID its TLS is bound to.
///
/// Over TLS it accepts only the certificate the nameserver's own DID vouches
/// for at `/.well-known/jig-ns`, never a CA's; the caller checks that DID
/// against what it trusts (the suffix's authorities, or nothing, for `jig ns
/// list`). Plaintext, with no DID to check, needs `[naming]
/// dangerously_allow_plaintext_nameservers`.
async fn bound_client(
    base: &str,
    allow_plaintext: bool,
    timeout: std::time::Duration,
) -> Result<(reqwest::Client, Option<String>)> {
    let builder = reqwest::Client::builder().timeout(timeout);
    let (builder, did) = if base.starts_with("http://") {
        if !allow_plaintext {
            anyhow::bail!(
                "{base} is plaintext; a nameserver is reached only over TLS its DID vouches for \
                 (set [naming] dangerously_allow_plaintext_nameservers in cli.toml only for \
                 loopback or local testing)"
            );
        }
        (builder, None)
    } else {
        let probed = jig_client::tls::probe_self_bound(base, "/.well-known/jig-ns")
            .await
            .with_context(|| format!("{base}: the nameserver's TLS"))?;
        let config = probed.config.expect("a bound probe over TLS has a config");
        (
            builder.use_preconfigured_tls(config.as_ref().clone()),
            probed.server_did,
        )
    };
    let http = builder
        .build()
        .context("building HTTP client for the nameserver")?;
    Ok((http, did))
}

/// The DID the replies at `base` speak for, `claimed` by the nameserver
/// (unsigned), checked against the DID its TLS is bound to when there is one.
fn speaking_for(base: &str, claimed: String, bound: Option<&str>) -> Result<String> {
    match bound {
        Some(bound) if bound != claimed => anyhow::bail!(
            "{base} claims to be {claimed}, but its TLS is bound to {bound}; nothing was signed"
        ),
        _ => Ok(claimed),
    }
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

/// A 4xx a nameserver answered a register, renew or rotate with: it did not
/// act. Carried in the `anyhow` error so a caller can tell which refusal it
/// was.
#[derive(Debug, thiserror::Error)]
#[error("POST {url}: {}", explain_nameserver_error(status.as_u16(), body))]
pub(crate) struct Refusal {
    pub url: String,
    pub status: reqwest::StatusCode,
    pub body: String,
}

impl Refusal {
    /// The `code` of the nameserver's error body, if it has one.
    pub(crate) fn code(&self) -> Option<String> {
        let body: serde_json::Value = serde_json::from_str(&self.body).ok()?;
        Some(body.get("code")?.as_str()?.to_string())
    }
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

/// Body of GET `/v1/suffixes`: the nameserver's DID and what it serves.
/// Unsigned: a wrong `ns_did` only makes a proof fail at the nameserver.
#[derive(Debug, Deserialize)]
struct SuffixesResponse {
    ns_did: String,
    suffixes: Vec<SuffixInfo>,
}

#[derive(Debug, Deserialize)]
struct SuffixInfo {
    suffix: String,
    registration: String,
    #[serde(default)]
    dns_delegation: bool,
}

/// Why the CLI is talking to a nameserver: registration is the one action a
/// closed suffix refuses, so it is refused before a challenge is fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Purpose {
    Register,
    Keep,
}

/// Whose signature a reply must carry.
enum Authority {
    /// A `config`-rooted suffix: the authorities `cli.toml` (or this build)
    /// names. The nameserver's own claims add nothing to this list.
    Config(Vec<String>),
    /// A `dns`-rooted suffix: the delegation the nameserver publishes for it,
    /// signed by the suffix's authorities.
    Dns(SuffixDelegation),
}

/// How long a nameserver request may take. Short in tests, which wait it out.
const REQUEST_TIMEOUT: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_secs(2)
} else {
    std::time::Duration::from_secs(15)
};

/// A nameserver to register, renew or rotate one name with: its base URL, its
/// DID (which every proof of control names) and whose signature its replies
/// must carry for that name.
///
/// For a `config`-rooted suffix (any single-label one, `jig` included) the
/// authorities come from `cli.toml` or this build, and the nameserver's DID
/// must be one of them before anything is signed. For a `dns`-rooted one they
/// come from the delegation the nameserver publishes, which proves only that
/// the nameserver is consistent with itself; the resolver checks the suffix's
/// own domain. Either way a proof made for the wrong DID is refused by the
/// real nameserver, so a lying nameserver cannot redirect a proof.
pub(crate) struct Nameserver {
    base: String,
    http: reqwest::Client,
    ns_did: String,
    name: Name,
    authority: Authority,
}

impl Nameserver {
    /// Connect to `ns_url` about `who`: a full `alias@suffix`, or a bare
    /// local part when the nameserver serves exactly one suffix.
    pub(crate) async fn connect(
        ns_url: &str,
        who: &str,
        delegations: &Delegations,
        purpose: Purpose,
    ) -> Result<Self> {
        let base = ns_url.trim().trim_end_matches('/').to_string();
        let (http, bound) = bound_client(
            &base,
            delegations.dangerously_allow_plaintext_nameservers,
            REQUEST_TIMEOUT,
        )
        .await?;
        let url = format!("{base}/v1/suffixes");
        let resp = http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            // A nameserver from before multi-suffix serving: one suffix, named
            // by its own delegation.
            return Self::connect_single_suffix(base, http, bound, who).await;
        }
        let mut served: SuffixesResponse = json_or_explain(resp, &url).await?;
        // Every check below is on this DID: under TLS it is the one the
        // certificate is bound to, so an authority's DID cannot be claimed by
        // a server that does not hold its key.
        served.ns_did = speaking_for(&base, served.ns_did, bound.as_deref())?;

        let name = match who.split_once('@') {
            Some(_) => Name::parse(who).with_context(|| format!("`{who}` is not alias@suffix"))?,
            None => match served.suffixes.as_slice() {
                [only] => Name::parse(&format!("{who}@{}", only.suffix))
                    .with_context(|| format!("`{who}` is not a valid alias"))?,
                many => anyhow::bail!(
                    "{base} serves {}; pass the full alias@suffix",
                    served_list(many)
                ),
            },
        };
        let Some(info) = served
            .suffixes
            .iter()
            .find(|s| s.suffix.eq_ignore_ascii_case(&name.suffix))
        else {
            anyhow::bail!(
                "{base} does not serve `{}`; it serves {}",
                name.suffix,
                served_list(&served.suffixes)
            );
        };
        if purpose == Purpose::Register && info.registration != "open" {
            anyhow::bail!("registration on `{}` is closed at {base}", name.suffix);
        }

        let authority = match delegations.config.get(&name.suffix) {
            Some(config) => {
                if !config.authorities.contains(&served.ns_did) {
                    anyhow::bail!(
                        "{base} is {}, which is not an authority for `{}` (cli.toml names {}); \
                         nothing was signed",
                        served.ns_did,
                        name.suffix,
                        config.authorities.join(", ")
                    );
                }
                Authority::Config(config.authorities.clone())
            }
            None if info.dns_delegation => {
                let url = format!(
                    "{base}/.well-known/jig-ns-delegation?suffix={}",
                    name.suffix
                );
                let delegation = fetch_delegation(&http, &url).await?;
                if delegation.suffix != name.suffix
                    || !delegation.authorities.contains(&served.ns_did)
                {
                    anyhow::bail!(
                        "{url} is not a delegation of `{}` to {}",
                        name.suffix,
                        served.ns_did
                    );
                }
                Authority::Dns(delegation)
            }
            None => {
                if name.suffix == DEFAULT_SUFFIX
                    && let Err(e) = jig_core::naming::default_jig_authority()
                {
                    anyhow::bail!(
                        "{e}; add a [naming.delegations.{DEFAULT_SUFFIX}] entry to cli.toml to \
                         register `@{DEFAULT_SUFFIX}` names"
                    );
                }
                anyhow::bail!(
                    "`{}` has no delegation this client can check: add a \
                     [naming.delegations.\"{}\"] entry to cli.toml naming its authorities",
                    name.suffix,
                    name.suffix
                )
            }
        };
        Ok(Self {
            base,
            http,
            ns_did: served.ns_did,
            name,
            authority,
        })
    }

    /// The path for a nameserver without `/v1/suffixes`: its one suffix and
    /// its DID come from the delegation it publishes.
    async fn connect_single_suffix(
        base: String,
        http: reqwest::Client,
        bound: Option<String>,
        who: &str,
    ) -> Result<Self> {
        let url = format!("{base}/.well-known/jig-ns-delegation");
        let delegation = fetch_delegation(&http, &url).await?;
        if delegation.authorities.len() != 1 {
            anyhow::bail!(
                "{url} lists {} authorities for `{}`; a nameserver publishes itself as the only one",
                delegation.authorities.len(),
                delegation.suffix
            );
        }
        let name = match who.split_once('@') {
            Some(_) => Name::parse(who).with_context(|| format!("`{who}` is not alias@suffix"))?,
            None => Name::parse(&format!("{who}@{}", delegation.suffix))
                .with_context(|| format!("`{who}` is not a valid alias"))?,
        };
        let ns_did = speaking_for(&base, delegation.authorities[0].clone(), bound.as_deref())?;
        Ok(Self {
            base,
            http,
            ns_did,
            name,
            authority: Authority::Dns(delegation),
        })
    }

    /// The nameserver's DID, which every proof of control names.
    pub(crate) fn ns_did(&self) -> &str {
        &self.ns_did
    }

    /// The full, lowercased name this connection is about.
    pub(crate) fn name(&self) -> &Name {
        &self.name
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
        if status.is_client_error() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Refusal { url, status, body }.into());
        }
        let text = match resp.text().await {
            Ok(text) => text,
            Err(e) => {
                return Ok(Err(anyhow::Error::new(e).context(format!(
                    "POST {url} returned {status}, but its body could not be read"
                ))));
            }
        };
        if !status.is_success() {
            return Ok(Err(anyhow::anyhow!(
                "POST {url}: {}",
                explain_nameserver_error(status.as_u16(), &text)
            )));
        }
        let now = chrono::Utc::now().timestamp();
        Ok(self
            .verify_reply(&text, expected_did, now)
            .with_context(|| format!("POST {url} succeeded, but its reply does not verify")))
    }

    fn verify_reply(&self, body: &str, expected_did: &str, now: i64) -> Result<Attestation> {
        match &self.authority {
            Authority::Config(authorities) => {
                verify_config_reply(body, authorities, &self.name, expected_did, now)
            }
            Authority::Dns(delegation) => {
                verify_binding_reply(body, delegation, &self.name, expected_did, now)
            }
        }
    }
}

fn served_list(suffixes: &[SuffixInfo]) -> String {
    if suffixes.is_empty() {
        return "no suffixes".to_string();
    }
    suffixes
        .iter()
        .map(|s| format!("`{}`", s.suffix))
        .collect::<Vec<_>>()
        .join(", ")
}

async fn fetch_delegation(http: &reqwest::Client, url: &str) -> Result<SuffixDelegation> {
    let resp = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let body: DelegationResponse = json_or_explain(resp, url).await?;
    let envelopes = body
        .envelopes
        .iter()
        .map(|e| URL_SAFE_NO_PAD.decode(e))
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("{url}: an envelope is not unpadded base64url"))?;
    SuffixDelegation::from_envelopes(&envelopes)
        .with_context(|| format!("{url}: the delegation does not verify"))
}

/// The JSON of a 2xx response, or an error explaining the nameserver's
/// refusal.
async fn json_or_explain<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
    url: &str,
) -> Result<T> {
    let status = resp.status();
    let text = resp
        .text()
        .await
        .with_context(|| format!("reading body of {url}"))?;
    if !status.is_success() {
        anyhow::bail!(
            "{url}: {}",
            explain_nameserver_error(status.as_u16(), &text)
        );
    }
    serde_json::from_str(&text).with_context(|| format!("decoding the response from {url}"))
}

/// Turn a nameserver's refusal into an operator message: its own message and
/// code, and for the ones a user can act on, what to do.
pub fn explain_nameserver_error(status: u16, body: &str) -> String {
    #[derive(Deserialize)]
    struct ErrorBody {
        code: String,
        message: String,
    }
    let Ok(e) = serde_json::from_str::<ErrorBody>(body) else {
        return format!("HTTP {status}: {body}");
    };
    let hint = match e.code.as_str() {
        "SUFFIX_REQUIRED" => "; pass the full alias@suffix",
        "UNKNOWN_SUFFIX" => "; check the suffix, or ask a nameserver that serves it",
        "REGISTRATION_CLOSED" => "; names already registered there still renew and resolve",
        "ALIAS_RESERVED" | "ALIAS_TOO_SHORT" => "; pick another alias",
        "DID_HOLDS_NAME" => "; this key already holds a name under that suffix",
        _ => "",
    };
    format!("{} ({}){hint}", e.message, e.code)
}

/// Check a reply for a `config`-rooted suffix: the attestation is signed by
/// one of `authorities`, for `name`, valid at `now`, and binds the name to
/// `expected_did`.
pub(crate) fn verify_config_reply(
    body: &str,
    authorities: &[String],
    name: &Name,
    expected_did: &str,
    now: i64,
) -> Result<Attestation> {
    let att = attestation_of(body)?;
    naming::verify_attestation(&att, authorities, name, now)
        .context("the attestation is not a valid binding for this name")?;
    expect_did(att, expected_did)
}

fn attestation_of(body: &str) -> Result<Attestation> {
    let reply: BindingResponse =
        serde_json::from_str(body).context("the reply has no `attestation` envelope")?;
    let envelope = URL_SAFE_NO_PAD
        .decode(&reply.attestation)
        .context("`attestation` is not unpadded base64url")?;
    Attestation::from_envelope(&envelope).context("the attestation does not verify")
}

fn expect_did(att: Attestation, expected_did: &str) -> Result<Attestation> {
    if att.did != expected_did {
        anyhow::bail!(
            "the attestation binds {} to {}, not to {expected_did}",
            att.alias,
            att.did
        );
    }
    Ok(att)
}

/// Check a register, renew or rotate reply for a `dns`-rooted suffix: the
/// attestation is signed by the delegation's authority, for `name`, valid at
/// `now`, and binds the name to `expected_did`.
pub(crate) fn verify_binding_reply(
    body: &str,
    delegation: &SuffixDelegation,
    name: &Name,
    expected_did: &str,
    now: i64,
) -> Result<Attestation> {
    let att = attestation_of(body)?;
    naming::verify_binding(&att, delegation, name, now)
        .context("the attestation is not a valid binding for this name")?;
    expect_did(att, expected_did)
}

/// Unpadded base64url, the encoding every naming envelope travels in.
pub(crate) fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
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
        && !cfg
            .naming
            .delegations
            .keys()
            .any(|k| k.eq_ignore_ascii_case(DEFAULT_SUFFIX))
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

    let plaintext = ctx
        .effective()
        .naming
        .dangerously_allow_plaintext_nameservers;
    let (http, _) = bound_client(&base, plaintext, std::time::Duration::from_secs(10)).await?;
    let resp = http
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
        stub_nameserver_serving(ns, None, post).await
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

    /// [`stub_nameserver`], also serving `suffixes` at `/v1/suffixes` (a
    /// nameserver from before multi-suffix serving 404s there).
    async fn stub_nameserver_serving(
        ns: SigningKey,
        suffixes: Option<serde_json::Value>,
        post: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
    ) -> (String, Seen) {
        stub_nameserver_raw(ns, suffixes, move |p, b| {
            let (status, out) = post(p, b);
            Answer::Full(status, out)
        })
        .await
    }

    /// [`stub_nameserver_serving`], with `post` choosing how to answer.
    async fn stub_nameserver_raw(
        ns: SigningKey,
        suffixes: Option<serde_json::Value>,
        post: impl Fn(&str, &str) -> Answer + Send + Sync + 'static,
    ) -> (String, Seen) {
        let suffixes = suffixes.map(|v| v.to_string());
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
                let (log, post, deleg, suffixes) =
                    (log.clone(), post.clone(), deleg.clone(), suffixes.clone());
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
                        ("GET", p) if p.starts_with("/.well-known/jig-ns-delegation") => {
                            Answer::Full(200, deleg)
                        }
                        ("GET", "/v1/suffixes") => match suffixes {
                            Some(body) => Answer::Full(200, body),
                            None => Answer::Full(404, "{}".into()),
                        },
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

        let att = crate::cmd::init::register_with_nameserver(&me, "DJ", &base, &plaintext())
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
    async fn a_plaintext_nameserver_is_not_asked_without_the_opt_in() {
        let ns = key(1);
        let (base, seen) = stub_nameserver(ns.clone(), attest_as(ns, "dj@dj.jig")).await;
        let dir = tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());
        let err = crate::cmd::keys::renew_with_nameserver(
            &me,
            "dj@dj.jig",
            &base,
            &Delegations::default(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("dangerously_allow_plaintext_nameservers"),
            "{err:#}"
        );
        assert!(paths(&seen).is_empty(), "nothing was asked");
    }

    #[test]
    fn a_nameserver_speaks_only_for_the_did_its_tls_is_bound_to() {
        let (a, b) = (did_of(&key(1)), did_of(&key(2)));
        assert_eq!(speaking_for("https://ns", a.clone(), Some(&a)).unwrap(), a);
        assert_eq!(
            speaking_for("http://ns", a.clone(), None).unwrap(),
            a,
            "plaintext, opted into, has no DID to check"
        );
        let err = speaking_for("https://ns", a, Some(&b))
            .unwrap_err()
            .to_string();
        assert!(err.contains("bound to") && err.contains(&b), "{err}");
    }

    #[tokio::test]
    async fn renew_signs_a_renew_proof() {
        let ns = key(1);
        let (base, seen) = stub_nameserver(ns.clone(), attest_as(ns.clone(), "dj@dj.jig")).await;
        let dir = tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());

        crate::cmd::keys::renew_with_nameserver(&me, "dj@DJ.jig", &base, &plaintext())
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

        let err = crate::cmd::init::register_with_nameserver(&me, "dj", &base, &plaintext())
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
            crate::cmd::keys::rotate_with_nameserver(&old, &new, "dj@dj.jig", &base, &plaintext())
                .await;
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
        let accepted =
            crate::cmd::keys::rotate_with_nameserver(&old, &new, "dj@dj.jig", &base, &plaintext())
                .await
                .expect("the nameserver accepted");
        assert!(
            accepted.is_err(),
            "the reply binds the old DID, not the new one"
        );

        // Accepted and verified.
        let (base, _) = stub_nameserver(ns.clone(), attest_as(ns, "dj@dj.jig")).await;
        let att =
            crate::cmd::keys::rotate_with_nameserver(&old, &new, "dj@dj.jig", &base, &plaintext())
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
            async move {
                crate::cmd::keys::rotate_with_nameserver(old, new, "dj@dj.jig", &base, &plaintext())
                    .await
            }
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
            let (base, _) = stub_nameserver_raw(ns.clone(), None, move |_, _| answer.clone()).await;
            let outcome = rotate(base).await.unwrap_or_else(|e| {
                panic!("{what}: the rotation may have applied, so not a refusal: {e:#}")
            });
            assert!(outcome.is_err(), "{what}: no verified attestation");
        }

        let (base, _) = stub_nameserver_raw(ns.clone(), None, |_, _| {
            Answer::Full(409, r#"{"code":"DID_HOLDS_NAME"}"#.into())
        })
        .await;
        assert!(rotate(base).await.is_err(), "a 4xx is a refusal");

        // A port nothing listens on: the request never connects.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let (base, _) = stub_nameserver(ns, attest_as(key(1), "dj@dj.jig")).await;
        let ns_conn = Nameserver::connect(&base, "dj@dj.jig", &plaintext(), Purpose::Keep)
            .await
            .unwrap();
        let moved = Nameserver {
            base: format!("http://{addr}"),
            ..ns_conn
        };
        let body = crate::cmd::keys::build_rotate_request(&old, &new, "dj@dj.jig", "c0ffee");
        assert!(
            moved
                .post_binding("/v1/rotate", &body, &new.did_string())
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
            // A nameserver from before /v1/suffixes, serving a bad delegation.
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let (status, out) = if head.starts_with("GET /v1/suffixes ") {
                    ("404 Not Found", "{}")
                } else {
                    ("200 OK", r#"{"envelopes":["bm90LWNvc2U"]}"#)
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}",
                    out.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        let err = Nameserver::connect(&base, "dj", &plaintext(), Purpose::Register)
            .await
            .err()
            .expect("refused");
        assert!(format!("{err:#}").contains("does not verify"), "{err:#}");
    }

    // ------------------------------------------------------------------
    // Register, renew and rotate against a nameserver serving several
    // suffixes (#224), with `jig` rooted in config.
    // ------------------------------------------------------------------

    fn served(ns: &SigningKey, list: serde_json::Value) -> Option<serde_json::Value> {
        Some(serde_json::json!({ "ns_did": did_of(ns), "suffixes": list }))
    }

    fn jig_open() -> serde_json::Value {
        serde_json::json!([
            {"suffix": "jig", "registration": "open", "dns_delegation": false},
            {"suffix": "dj.jig", "registration": "open", "dns_delegation": true},
        ])
    }

    /// No delegations of our own, and the stubs' `http://` allowed: they
    /// serve plaintext on loopback.
    fn plaintext() -> Delegations {
        Delegations {
            dangerously_allow_plaintext_nameservers: true,
            ..Delegations::default()
        }
    }

    fn jig_authority(did: &str) -> Delegations {
        let mut d = plaintext();
        d.config.insert(
            "jig".into(),
            jig_client::naming::ConfigDelegation {
                authorities: vec![did.into()],
                nameservers: vec!["http://unused".into()],
            },
        );
        d
    }

    fn paths(seen: &Seen) -> Vec<String> {
        seen.lock()
            .unwrap()
            .iter()
            .map(|(m, p, _)| format!("{m} {p}"))
            .collect()
    }

    #[tokio::test]
    async fn register_under_a_config_rooted_suffix_checks_the_nameserver_is_an_authority() {
        let ns = key(1);
        let (base, seen) = stub_nameserver_serving(
            ns.clone(),
            served(&ns, jig_open()),
            attest_as(ns.clone(), "dj@jig"),
        )
        .await;
        let dir = tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());

        let att = crate::cmd::init::register_with_nameserver(
            &me,
            "DJ@jig",
            &base,
            &jig_authority(&did_of(&ns)),
        )
        .await
        .expect("registers");
        assert_eq!(att.alias, "dj@jig");
        assert_eq!(att.did, me.did_string());

        let (did, proof) = sent_proof(&seen, "/v1/register");
        naming::verify_proof(
            &did,
            &proof,
            Action::Register,
            &did_of(&ns),
            "dj@jig",
            "c0ffee",
        )
        .expect("a register proof for the configured authority");
        let body = seen
            .lock()
            .unwrap()
            .iter()
            .find(|(_, p, _)| p == "/v1/register")
            .map(|(_, _, b)| b.clone())
            .unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["suffix"], "jig", "the suffix is named");
        assert_eq!(body["requested_alias"], "dj");
    }

    #[tokio::test]
    async fn a_nameserver_that_is_not_the_configured_authority_gets_nothing_signed() {
        let ns = key(1);
        let (base, seen) =
            stub_nameserver_serving(ns.clone(), served(&ns, jig_open()), attest_as(ns, "dj@jig"))
                .await;
        let dir = tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());

        let err = crate::cmd::init::register_with_nameserver(
            &me,
            "dj@jig",
            &base,
            &jig_authority(&did_of(&key(9))),
        )
        .await
        .expect_err("refused");
        assert!(format!("{err:#}").contains("nothing was signed"), "{err:#}");
        assert_eq!(paths(&seen), ["GET /v1/suffixes"], "no challenge, no proof");
    }

    #[tokio::test]
    async fn registration_on_a_closed_suffix_is_refused_before_the_challenge() {
        let ns = key(1);
        let closed = serde_json::json!([
            {"suffix": "jig", "registration": "closed", "dns_delegation": false},
        ]);
        let (base, seen) = stub_nameserver_serving(
            ns.clone(),
            served(&ns, closed),
            attest_as(ns.clone(), "dj@jig"),
        )
        .await;
        let dir = tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());

        let err = crate::cmd::init::register_with_nameserver(
            &me,
            "dj",
            &base,
            &jig_authority(&did_of(&ns)),
        )
        .await
        .expect_err("closed");
        assert!(format!("{err:#}").contains("closed"), "{err:#}");
        assert_eq!(paths(&seen), ["GET /v1/suffixes"]);
    }

    #[tokio::test]
    async fn a_bare_alias_needs_its_suffix_when_several_are_served_and_one_must_be_served() {
        let ns = key(1);
        let (base, _) = stub_nameserver_serving(
            ns.clone(),
            served(&ns, jig_open()),
            attest_as(ns.clone(), "dj@jig"),
        )
        .await;
        let dir = tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());
        let d = jig_authority(&did_of(&ns));

        let err = crate::cmd::init::register_with_nameserver(&me, "dj", &base, &d)
            .await
            .expect_err("ambiguous");
        assert!(
            format!("{err:#}").contains("pass the full alias@suffix"),
            "{err:#}"
        );

        let err = crate::cmd::init::register_with_nameserver(&me, "dj@other.example", &base, &d)
            .await
            .expect_err("not served");
        assert!(
            format!("{err:#}").contains("does not serve `other.example`"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn renew_under_a_config_rooted_suffix_verifies_against_the_configured_authority() {
        let ns = key(1);
        let impostor = key(9);
        // The nameserver claims to be `ns`, but signs as someone else.
        let (base, _) = stub_nameserver_serving(
            ns.clone(),
            served(&ns, jig_open()),
            attest_as(impostor, "dj@jig"),
        )
        .await;
        let dir = tempdir().unwrap();
        let me = jig_client::Identity::generate_for_tests(dir.path());

        let err = crate::cmd::keys::renew_with_nameserver(
            &me,
            "dj@jig",
            &base,
            &jig_authority(&did_of(&ns)),
        )
        .await
        .expect_err("an attestation from a non-authority");
        assert!(format!("{err:#}").contains("does not verify"), "{err:#}");
    }

    #[test]
    fn a_nameserver_refusal_says_what_to_do() {
        let body =
            r#"{"code":"SUFFIX_REQUIRED","message":"this nameserver serves several suffixes"}"#;
        let msg = explain_nameserver_error(400, body);
        assert!(msg.contains("(SUFFIX_REQUIRED)"), "{msg}");
        assert!(msg.contains("pass the full alias@suffix"), "{msg}");
        assert_eq!(explain_nameserver_error(502, "<html>"), "HTTP 502: <html>");
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
        // The stubs are plaintext.
        cfg.naming.dangerously_allow_plaintext_nameservers = true;
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
