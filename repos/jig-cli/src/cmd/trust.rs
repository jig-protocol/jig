//! What this process trusts for a server: the DID this device pinned for it,
//! and the TLS certificate that DID vouches for ([`jig_client::tls`]).
//!
//! The first connection to an `https://` server in a process probes it once:
//! the DID it names must be the pinned one (or is pinned, on first contact),
//! and its certificate must be one that DID vouches for, or one a CA issued.
//! Every later REST and WSS connection in the process gets a config that
//! accepts that certificate and nothing else. A certificate the server rotated
//! is picked up by the next process, as long as the same DID vouches for it.
//!
//! Plaintext REST is refused, except to this machine (D11 item 10): nothing
//! ties a plaintext response to the pinned server, and any response may say
//! what a channel's suite is.

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
        refuse_remote_plaintext(server)?;
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

/// What [`check_channel_chain`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainCheck {
    /// Every record continued the pinned chain, gaps filled; the pin moved.
    Verified,
    /// This device has not pinned the channel (or the server sequences
    /// nothing for it), so there is nothing to hold the server to yet.
    Unpinned,
    /// The server would not serve records `from..to`, so what follows them is
    /// unchecked. Not a contradiction: a member removed and re-added may not
    /// read the gap.
    Unfilled { from: u64, to: u64 },
}

/// Hold `records` (from a page of history or a live stream) to the chain
/// this device pinned for `slug` on `server`: each must continue it, signed
/// by the server's pinned DID (JEP-0002 rule 9). Gaps are filled from the
/// records endpoint, signed as `who`. A break is an error naming what the
/// server contradicted; the pin moves forward only over what verified.
pub async fn check_channel_chain(
    who: &jig_client::Identity,
    server: &str,
    slug: &str,
    records: &[jig_client::chain::IngestRecord],
) -> Result<ChainCheck> {
    check_chain_in(&Pins::default_path(), who, server, slug, records).await
}

async fn check_chain_in(
    pins_path: &std::path::Path,
    who: &jig_client::Identity,
    server: &str,
    slug: &str,
    records: &[jig_client::chain::IngestRecord],
) -> Result<ChainCheck> {
    use jig_client::chain::{ChannelChain, Step};
    let mut pins = Pins::load(pins_path)?;
    let (Some(channel), Some(sequencer)) = (
        pins.channel(server, slug).cloned(),
        pins.server(server)
            .map(|p| p.server_did.clone())
            .filter(|d| !d.is_empty()),
    ) else {
        return Ok(ChainCheck::Unpinned);
    };
    // A pin in an older record format hashes other bytes, so nothing can be
    // compared with it. Start the chain again from what the server serves
    // now, and say so: only a pin this build wrote is held to.
    let head = match channel.chain_head {
        Some(head) if !head.is_current() => {
            let format = if head.format.is_empty() {
                "an unnamed older format"
            } else {
                head.format.as_str()
            };
            eprintln!(
                "warning: this device pinned {slug} on {server} in {format}, up to record {}. \
                 The server now signs `{}`, so history up to there is NOT checked against \
                 the old pin; re-pinning at what it serves now.",
                head.seq,
                jig_client::chain::RECORD_FORMAT,
            );
            None
        }
        head => head,
    };
    let mut chain = ChannelChain::new(&channel.create_cid, &sequencer, head);
    let mut sorted: Vec<_> = records.iter().collect();
    sorted.sort_by_key(|r| r.seq);
    let mut outcome = ChainCheck::Verified;
    for record in sorted {
        let broke = |e: jig_client::chain::ChainBreak| {
            anyhow::anyhow!(
                "{server} contradicted the history of {slug} this device verified: {e}. \
                 It signed both; refusing to go on"
            )
        };
        let step = chain
            .accept(record, Some(&record.block_cid))
            .map_err(broke)?;
        if let Step::Gap { from, to } = step {
            match fetch_records(who, server, slug, from, to).await {
                Ok(filler) if filler.len() as u64 == to - from => {
                    for missing in &filler {
                        chain.accept(missing, None).map_err(broke)?;
                    }
                    chain
                        .accept(record, Some(&record.block_cid))
                        .map_err(broke)?;
                }
                // Short, refused or unreachable: what follows stays unchecked.
                _ => {
                    outcome = ChainCheck::Unfilled { from, to };
                    break;
                }
            }
        }
    }
    if let Some(head) = chain.head() {
        pins.advance_chain(server, slug, head)?;
    }
    Ok(outcome)
}

/// Hold a fetched page of `slug`'s history to the pinned chain
/// ([`check_channel_chain`]) before any of it is shown. A break is an error;
/// a gap the server will not fill is a warning on stderr.
pub async fn check_history(
    who: &jig_client::Identity,
    server: &str,
    slug: &str,
    blocks: &[jig_client::DeliveredBlock],
) -> Result<()> {
    let records: Vec<_> = blocks.iter().filter_map(|b| b.ingest.clone()).collect();
    if records.is_empty() {
        return Ok(());
    }
    if let ChainCheck::Unfilled { from, to } =
        check_channel_chain(who, server, slug, &records).await?
    {
        eprintln!(
            "warning: {server} did not serve records {from}..{to} of {slug}; \
             history after them is not checked against this device's pin."
        );
    }
    Ok(())
}

/// Why a live connection to `server` ended, when the server contradicted
/// itself on it (a forked or foreign record, a second welcome): the reason
/// the reader closed with, in place of a bare "connection lost".
pub fn live_contradiction(client: &jig_client::Client, server: &str) -> Option<anyhow::Error> {
    client.contradiction().map(|c| {
        anyhow::anyhow!(
            "{server} contradicted what it signed: {}. The connection was closed",
            c.reason
        )
    })
}

/// Records `from..to` of `slug`, signed as `who`.
async fn fetch_records(
    who: &jig_client::Identity,
    server: &str,
    slug: &str,
    from: u64,
    to: u64,
) -> Result<Vec<jig_client::chain::IngestRecord>> {
    let base = crate::cmd::channel::base_http_url(server);
    let mut out = Vec::new();
    let mut next = from;
    while next < to {
        let url = format!(
            "{base}/api/v1/channels/{}/records?from={next}&limit={}",
            crate::cmd::channel::escape_slug_for_url(slug),
            to - next
        );
        let proof = jig_client::read_auth::ReadProof::sign(
            who,
            "GET",
            jig_client::read_auth::signable_path(&url),
        );
        let mut req = http(server, std::time::Duration::from_secs(10))
            .await?
            .get(&url);
        for (name, value) in proof.headers() {
            req = req.header(name, value);
        }
        let resp = req.send().await.with_context(|| format!("GET {url}"))?;
        if !resp.status().is_success() {
            anyhow::bail!("GET {url} returned {}", resp.status());
        }
        let page: Vec<jig_client::chain::IngestRecord> = resp
            .json()
            .await
            .with_context(|| format!("decoding {url}"))?;
        let Some(last) = page.last() else { break };
        next = last.seq + 1;
        out.extend(page.into_iter().filter(|r| r.seq < to));
    }
    Ok(out)
}

/// Refuse a plaintext server that is not on this machine. Loopback stays
/// allowed for local development; nothing on the wire leaves the host.
fn refuse_remote_plaintext(server: &str) -> Result<()> {
    let base = jig_client::tls::http_base(server)?;
    let host = url::Url::parse(&base)
        .ok()
        .and_then(|url| url.host().map(|host| host.to_owned()));
    let loopback = match host {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if loopback {
        return Ok(());
    }
    let tls_url = base.replacen("http://", "https://", 1);
    anyhow::bail!(
        "refusing plaintext {server}: over plaintext nothing ties an answer to the server this \
         device pinned. Use TLS: `jig server set {tls_url}`"
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use jig_client::chain::{GENESIS_PREV, IngestRecord, RecordSigner, label_cid};
    use jig_client::pins::ChannelPin;

    // Port 1 refuses at once, so a gap fill fails fast and offline.
    const SERVER: &str = "http://127.0.0.1:1";

    fn sign(
        key: &ed25519_dalek::SigningKey,
        seq: u64,
        block: &str,
        prev: [u8; 32],
    ) -> IngestRecord {
        RecordSigner {
            channel_id: label_cid("bafyCreate"),
            key,
            ingest_wall_ms: 1_000 + seq,
            ingest_logical: 0,
        }
        .sign(seq, &label_cid(block), prev)
        .unwrap()
    }

    /// A pin store holding `#ops` on [`SERVER`], sequenced by `key`, verified
    /// up to `head`.
    fn pinned(
        dir: &std::path::Path,
        key: &ed25519_dalek::SigningKey,
        head: Option<&IngestRecord>,
    ) -> std::path::PathBuf {
        let path = dir.join("pins.json");
        let mut pins = Pins::load(&path).unwrap();
        let did =
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string();
        pins.check_server_did(SERVER, &did).unwrap();
        pins.check_channel(
            SERVER,
            "#ops",
            ChannelPin {
                create_cid: label_cid("bafyCreate"),
                suite: "none".into(),
                owner_did: did,
                chain_head: None,
            },
        )
        .unwrap();
        if let Some(r) = head {
            pins.advance_chain(SERVER, "#ops", &jig_client::chain::ChainHead::of(r))
                .unwrap();
        }
        path
    }

    fn head_seq(path: &std::path::Path) -> Option<u64> {
        Pins::load(path)
            .unwrap()
            .channel(SERVER, "#ops")
            .and_then(|c| c.chain_head.as_ref())
            .map(|h| h.seq)
    }

    #[tokio::test]
    async fn history_that_continues_the_pin_moves_it() {
        let dir = tempfile::tempdir().unwrap();
        let who = jig_client::Identity::generate_for_tests(dir.path());
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let r0 = sign(&key, 0, "bafyCreate", GENESIS_PREV);
        let r1 = sign(&key, 1, "bafyA", r0.hash());
        let r2 = sign(&key, 2, "bafyB", r1.hash());
        let path = pinned(dir.path(), &key, Some(&r0));
        // Out of order, with a re-delivery of the pinned head: a page of history.
        let got = check_chain_in(&path, &who, SERVER, "#ops", &[r2, r0, r1])
            .await
            .unwrap();
        assert_eq!(got, ChainCheck::Verified);
        assert_eq!(head_seq(&path), Some(2));
    }

    #[tokio::test]
    async fn history_that_forks_from_the_pin_is_refused_and_the_pin_holds() {
        let dir = tempfile::tempdir().unwrap();
        let who = jig_client::Identity::generate_for_tests(dir.path());
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let r0 = sign(&key, 0, "bafyCreate", GENESIS_PREV);
        let r1 = sign(&key, 1, "bafyA", r0.hash());
        let path = pinned(dir.path(), &key, Some(&r1));
        // The server signs another entry 1 and builds on it.
        let other = sign(&key, 1, "bafyOther", r0.hash());
        let e = check_chain_in(&path, &who, SERVER, "#ops", &[other])
            .await
            .unwrap_err();
        assert!(e.to_string().contains("contradicted"), "{e}");
        assert_eq!(head_seq(&path), Some(1), "a break never moves the pin");
    }

    #[tokio::test]
    async fn a_gap_the_server_does_not_fill_is_reported_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let who = jig_client::Identity::generate_for_tests(dir.path());
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let r0 = sign(&key, 0, "bafyCreate", GENESIS_PREV);
        let r1 = sign(&key, 1, "bafyA", r0.hash());
        let r2 = sign(&key, 2, "bafyB", r1.hash());
        let path = pinned(dir.path(), &key, Some(&r0));
        let got = check_chain_in(&path, &who, SERVER, "#ops", &[r2])
            .await
            .unwrap();
        assert_eq!(got, ChainCheck::Unfilled { from: 1, to: 2 });
        assert_eq!(head_seq(&path), Some(0));
    }

    #[tokio::test]
    async fn a_pin_in_an_older_format_is_re_pinned_not_called_a_fork() {
        let dir = tempfile::tempdir().unwrap();
        let who = jig_client::Identity::generate_for_tests(dir.path());
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let r0 = sign(&key, 0, "bafyCreate", GENESIS_PREV);
        let r1 = sign(&key, 1, "bafyA", r0.hash());
        let path = pinned(dir.path(), &key, None);
        // What a build before named formats pinned: another hash at seq 3.
        let mut pins = Pins::load(&path).unwrap();
        pins.advance_chain(
            SERVER,
            "#ops",
            &jig_client::chain::ChainHead {
                format: String::new(),
                seq: 3,
                hash: "00".repeat(32),
                ingest_wall_ms: 0,
                ingest_logical: 0,
            },
        )
        .unwrap();
        let got = check_chain_in(&path, &who, SERVER, "#ops", &[r0, r1])
            .await
            .unwrap();
        assert_eq!(got, ChainCheck::Verified);
        assert_eq!(
            head_seq(&path),
            Some(1),
            "re-pinned at what the server serves"
        );
    }

    #[tokio::test]
    async fn a_current_format_pin_is_never_re_pinned() {
        // The guard is gated on the format: a server cannot use it to escape
        // a pin this build wrote.
        let dir = tempfile::tempdir().unwrap();
        let who = jig_client::Identity::generate_for_tests(dir.path());
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let r0 = sign(&key, 0, "bafyCreate", GENESIS_PREV);
        let r1 = sign(&key, 1, "bafyA", r0.hash());
        let path = pinned(dir.path(), &key, Some(&r1));
        let rewritten = sign(&key, 1, "bafyOther", r0.hash());
        assert!(
            check_chain_in(&path, &who, SERVER, "#ops", &[r0, rewritten])
                .await
                .is_err()
        );
        assert_eq!(head_seq(&path), Some(1));
    }

    #[tokio::test]
    async fn an_unpinned_channel_has_nothing_to_hold_the_server_to() {
        let dir = tempfile::tempdir().unwrap();
        let who = jig_client::Identity::generate_for_tests(dir.path());
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let r0 = sign(&key, 0, "bafyCreate", GENESIS_PREV);
        let path = dir.path().join("pins.json");
        let got = check_chain_in(&path, &who, SERVER, "#ops", &[r0])
            .await
            .unwrap();
        assert_eq!(got, ChainCheck::Unpinned);
    }

    #[test]
    fn plaintext_is_refused_except_on_this_machine() {
        for local in [
            "http://127.0.0.1:7117",
            "http://127.0.0.2:1",
            "http://localhost:7117",
            "http://[::1]:7117",
            "ws://127.0.0.1:7117",
        ] {
            assert!(refuse_remote_plaintext(local).is_ok(), "{local}");
        }
        for remote in [
            "http://example.com:7117",
            "http://10.0.0.5:7117",
            "ws://example.com",
        ] {
            let err = refuse_remote_plaintext(remote).unwrap_err().to_string();
            assert!(err.contains("jig server set https://"), "{remote}: {err}");
        }
    }
}

/// A name's delegation as given on the command line: the nameservers to ask
/// and the authorities whose attestations count. Without any, the suffix's
/// delegation is discovered over `dns`.
pub fn delegations_for(
    name: &str,
    nameservers: Vec<String>,
    authorities: Vec<String>,
) -> Result<jig_client::naming::Delegations> {
    let mut delegations = jig_client::naming::Delegations::default();
    if nameservers.is_empty() && authorities.is_empty() {
        return Ok(delegations);
    }
    anyhow::ensure!(
        !nameservers.is_empty() && !authorities.is_empty(),
        "a delegation needs both --nameserver and --authority"
    );
    let suffix = jig_core::naming::Name::parse(name)?.suffix;
    delegations.config.insert(
        suffix,
        jig_client::naming::ConfigDelegation {
            authorities,
            nameservers,
        },
    );
    Ok(delegations)
}

/// Resolve `name` and hold it to this device's pin (JEP-0004 rule 17): a new
/// name is pinned, a pinned one must still match, and a change is refused
/// with the reason, both DIDs and the `jig trust accept-name` command that
/// moves the pin. Everything the resolution acted on is kept as evidence; a
/// failure to keep it fails the resolution. Warns when the pinned
/// attestation is close to expiring. Returns the resolver's verdict, after
/// pinning, so a caller can say "first contact" only on [`Verified::New`].
///
/// [`Verified::New`]: jig_client::naming::Verified::New
pub async fn verify_name(
    name: &str,
    delegations: &jig_client::naming::Delegations,
) -> Result<jig_client::naming::Verified> {
    use jig_client::naming::{NameResolver, ResolveError, Verified};
    let mut pins = Pins::load(&Pins::default_path())?;
    let evidence = jig_client::evidence::NameEvidenceDir::new(
        &jig_client::evidence::NameEvidenceDir::default_path(),
    );
    let verified = match NameResolver::new()
        .resolve(name, delegations, &pins, &evidence)
        .await
    {
        Ok(verified) => verified,
        Err(e) => {
            let hint = match &e {
                ResolveError::PinMismatch { new, .. } => Some(format!(
                    "if its holder confirms the change, `jig trust accept-name {name} --did {new}` \
                     moves the pin"
                )),
                _ => None,
            };
            let e = anyhow::Error::new(e);
            return Err(match hint {
                Some(hint) => e.context(hint),
                None => e,
            });
        }
    };
    let binding = match &verified {
        Verified::New(binding) | Verified::Pinned(binding) => {
            pins.pin_name(binding)?;
            binding
        }
        Verified::Rotated { binding, from } => {
            pins.accept_name(binding, binding.did())?;
            eprintln!(
                "note: {name} moved from {from} to {} along rotation links its old key signed.",
                binding.did()
            );
            binding
        }
    };
    warn_if_expiring(name, binding, chrono::Utc::now().timestamp());
    Ok(verified)
}

/// Move `name`'s pin to `confirmed`, the DID its holder confirmed out of
/// band (rule 9). The name is resolved afresh and must attest exactly that
/// DID. Returns the DID it was pinned to before.
pub async fn accept_name(
    name: &str,
    confirmed: &str,
    delegations: &jig_client::naming::Delegations,
) -> Result<Option<String>> {
    use jig_client::naming::{NameResolver, Verified};
    // Resolve as if nothing were pinned: the point is to replace the pin.
    struct Unpinned;
    impl jig_client::naming::NamePins for Unpinned {
        fn name_pin(&self, _: &jig_client::naming::NameKey) -> Option<jig_client::naming::NamePin> {
            None
        }
    }
    let evidence = jig_client::evidence::NameEvidenceDir::new(
        &jig_client::evidence::NameEvidenceDir::default_path(),
    );
    let binding = match NameResolver::new()
        .resolve(name, delegations, &Unpinned, &evidence)
        .await?
    {
        Verified::New(b) | Verified::Pinned(b) | Verified::Rotated { binding: b, .. } => b,
    };
    let mut pins = Pins::load(&Pins::default_path())?;
    let old = pins.accept_name(&binding, confirmed)?;
    warn_if_expiring(name, &binding, chrono::Utc::now().timestamp());
    Ok(old)
}

/// How long before an attestation expires the CLI starts saying so.
const EXPIRY_WARNING_SECS: i64 = 7 * 24 * 3600;

fn warn_if_expiring(name: &str, binding: &jig_client::naming::Binding, now: i64) {
    if let Some(message) = expiry_warning(name, binding.attestation.valid_until, now) {
        eprintln!("warning: {message}");
    }
}

fn expiry_warning(name: &str, valid_until: i64, now: i64) -> Option<String> {
    let left = valid_until - now;
    (left < EXPIRY_WARNING_SECS).then(|| {
        format!(
            "{name}'s attestation expires in {} day(s); its holder should renew it, or it stops \
             resolving",
            left.max(0) / (24 * 3600)
        )
    })
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn an_attestation_near_expiry_is_warned_about() {
        let day = 24 * 3600;
        assert!(expiry_warning("alice@example.org", 30 * day, 0).is_none());
        let soon = expiry_warning("alice@example.org", 3 * day, 0).unwrap();
        assert!(soon.contains("3 day"), "{soon}");
    }

    #[test]
    fn a_delegation_needs_both_halves() {
        assert!(
            delegations_for("alice@example.org", vec![], vec![])
                .unwrap()
                .config
                .is_empty()
        );
        assert!(delegations_for("alice@example.org", vec!["https://ns".into()], vec![]).is_err());
        let d = delegations_for(
            "alice@example.org",
            vec!["https://ns".into()],
            vec!["did:jig:zNs".into()],
        )
        .unwrap();
        assert_eq!(d.config["example.org"].authorities, ["did:jig:zNs"]);
    }
}
