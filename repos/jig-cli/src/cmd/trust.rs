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
//!
//! A contradiction the server signs is kept as an evidence bundle
//! ([`jig_client::evidence`]). One whose bundle carries a proof that holds
//! makes the refusal sticky: every later connection to the server, REST or
//! WebSocket, stops in [`server_tls`] until `jig trust accept` (D11 item 9).

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
    refuse_if_sticky(&Pins::load(&Pins::default_path())?, server)?;
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
        let probed = match probe(server, expected.as_deref()).await {
            Ok(probed) => probed,
            Err(e) => {
                return Err(
                    link_fork_in(&Pins::default_path(), server, &e)?.unwrap_or(refusal(server, e))
                );
            }
        };
        match (&probed.server_did, &probed.moved_from, &probed.key_link) {
            (Some(did), Some(from), Some(link)) => {
                pins.move_server(server, from, did, link)?;
                eprintln!(
                    "note: {server} moved its key from {from} to {did}, and both keys signed the \
                     move (JEP-0012); this device's pin follows it."
                );
            }
            (Some(did), _, _) => pins.check_server_did(server, did)?,
            _ => {}
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

/// `jig trust evidence list`.
pub fn evidence_list() -> Result<()> {
    let store = jig_client::evidence::EvidenceStore::new(&evidence_dir(&Pins::default_path()));
    let bundles = store.list()?;
    if bundles.is_empty() {
        println!("No evidence kept.");
    }
    for (id, bundle) in bundles {
        println!("{id}\t{}\t{}", status_of(&bundle), bundle.reason);
    }
    Ok(())
}

/// `jig trust evidence show <id>`.
pub fn evidence_show(id: &str) -> Result<()> {
    let store = jig_client::evidence::EvidenceStore::new(&evidence_dir(&Pins::default_path()));
    print!("{}", describe(&store.get(id)?));
    Ok(())
}

/// `jig trust evidence export <id> [--out <file>]`.
pub fn evidence_export(id: &str, out: Option<&std::path::Path>) -> Result<()> {
    let store = jig_client::evidence::EvidenceStore::new(&evidence_dir(&Pins::default_path()));
    let json = serde_json::to_string_pretty(&store.get(id)?)?;
    match out {
        Some(path) => std::fs::write(path, json + "\n")
            .with_context(|| format!("writing {}", path.display()))?,
        None => println!("{json}"),
    }
    Ok(())
}

/// `jig trust evidence import <file>`: check and show, nothing else. Someone
/// else's evidence never refuses a server here (design D11 item 9, rule 4),
/// or one shared report could turn every client against it.
pub fn evidence_import(file: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let bundle: jig_client::evidence::Bundle = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a bundle", file.display()))?;
    print!("{}", describe(&bundle));
    println!("Imported evidence is only shown: nothing was refused or pinned.");
    Ok(())
}

/// `jig trust accept <server>`.
pub fn accept_server(server: &str) -> Result<()> {
    match Pins::load(&Pins::default_path())?.accept_server(server)? {
        Some(lifted) => println!(
            "{server} is no longer refused (it was for: {}; evidence {} is kept). It is still \
             held to what this device pinned.",
            lifted.reason, lifted.bundle
        ),
        None => println!("{server} was not refused."),
    }
    Ok(())
}

fn status_of(bundle: &jig_client::evidence::Bundle) -> &'static str {
    match jig_client::evidence::verify(bundle) {
        Ok(checked) if checked.proven.is_some() => "proven",
        Ok(_) => "unproven",
        Err(_) => "INVALID",
    }
}

/// A bundle for a person: what it claims, and what checking it found.
fn describe(bundle: &jig_client::evidence::Bundle) -> String {
    let check = match jig_client::evidence::verify(bundle) {
        Ok(checked) => match checked.proven {
            Some(what) => format!("proven from what the server signed: {what}"),
            None => "unproven: it records what this client saw, but nothing in it proves \
                     the server signed a contradiction"
                .to_string(),
        },
        Err(e) => format!("INVALID: {e}"),
    };
    format!(
        "server:   {} ({})\ncode:     {} (class {})\nreason:   {}\nseen at:  {} ms (the \
         observer's clock, unsigned)\nitems:    {} frame(s){}\ncheck:    {check}\n",
        bundle.server,
        bundle.server_did,
        bundle.code,
        bundle.class,
        bundle.reason,
        bundle.observed_at_ms,
        bundle.items.len(),
        if bundle.welcome.is_some() {
            ", and the connection's welcome"
        } else {
            ""
        },
    )
}

/// Refuse `server` if it signed a contradiction this device has not accepted.
pub fn refuse_if_sticky(pins: &Pins, server: &str) -> Result<()> {
    if let Some(refused) = pins.refusal(server) {
        anyhow::bail!(
            "refusing {server}: it signed a contradiction ({}). The evidence is \
             `jig trust evidence show {}`. Every connection to it is refused until you run \
             `jig trust accept {server}`; if the server is honest and this is a bug, that \
             bundle is what to report",
            refused.reason,
            refused.bundle
        );
    }
    Ok(())
}

/// The hook a connection to `server` calls when it contradicts itself: keep
/// the evidence and, when it proves the contradiction, refuse the server.
pub fn evidence_hook(server: &str) -> jig_client::connection::ContradictionHook {
    let server = server.to_string();
    Arc::new(move |c: &jig_client::connection::Contradiction| {
        if let Err(e) = keep_evidence_in(&Pins::default_path(), &server, c) {
            eprintln!("warning: could not keep the evidence of {server}'s contradiction: {e:#}");
        }
    })
}

/// What [`keep_evidence_in`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// The bundle's id in the evidence store.
    pub id: String,
    /// Whether the server is now refused.
    pub sticky: bool,
}

/// Keep `c` as a bundle against `server`, and refuse `server` from now on
/// when the bundle proves it. A downgrade proof is completed here from the
/// welcome the pin kept, which the connection does not hold.
fn keep_evidence_in(
    pins_path: &std::path::Path,
    server: &str,
    c: &jig_client::connection::Contradiction,
) -> Result<Kept> {
    let server_did = Pins::load(pins_path)?
        .server(server)
        .map(|p| p.server_did.clone())
        .unwrap_or_default();
    keep_bundle_in(pins_path, server, &server_did, c)
}

/// [`keep_evidence_in`], against `server_did`: the DID that signed the
/// evidence, which a key-link fork shows is one the pin has left.
fn keep_bundle_in(
    pins_path: &std::path::Path,
    server: &str,
    server_did: &str,
    c: &jig_client::connection::Contradiction,
) -> Result<Kept> {
    use jig_client::evidence::{BUNDLE_FORMAT, Bundle, EvidenceStore, verify};
    let mut pins = Pins::load(pins_path)?;
    let pin = pins.server(server).cloned().unwrap_or_default();
    let mut proof = c.proof.clone().map(|p| *p);
    if proof.is_none()
        && c.code == "refusal-downgrade"
        && let (Some(pinned_welcome), Some(refusal)) = (&pin.welcome, c.evidence.first())
    {
        proof = jig_client::evidence::downgrade_proof(
            pinned_welcome,
            &pin.suites,
            refusal,
            &pin.server_did,
        );
    }
    let bundle = Bundle {
        format: BUNDLE_FORMAT.to_string(),
        class: 3,
        code: c.code.to_string(),
        reason: c.reason.clone(),
        server: server.to_string(),
        server_did: server_did.to_string(),
        observed_at_ms: now_ms(),
        welcome: c.welcome.clone(),
        items: c.evidence.clone(),
        proof,
    };
    // Only a proof that holds here, from the bundle alone, makes it sticky.
    let proven = verify(&bundle).ok().and_then(|checked| checked.proven);
    let id = EvidenceStore::new(&evidence_dir(pins_path)).keep(&bundle)?;
    let sticky = proven.is_some();
    if sticky {
        pins.refuse(
            server,
            jig_client::pins::StickyRefusal {
                bundle: id.clone(),
                reason: c.reason.clone(),
                at_ms: bundle.observed_at_ms,
            },
        )?;
    }
    Ok(Kept { id, sticky })
}

/// A probe refused because `server` named another DID, when the key link it
/// served forks one this pin moved along: the key that signed both is held by
/// someone else, and neither link is to be trusted (JEP-0012). Kept as a
/// bundle, and `server` is refused until its user accepts it again. `None`
/// for any other refusal.
fn link_fork_in(
    pins_path: &std::path::Path,
    server: &str,
    e: &TlsError,
) -> Result<Option<anyhow::Error>> {
    let TlsError::OtherServer {
        key_link: Some(presented),
        ..
    } = e
    else {
        return Ok(None);
    };
    let kept = Pins::load(pins_path)?
        .server(server)
        .map(|p| p.links.clone())
        .unwrap_or_default();
    let Some((signer, proof)) = jig_client::evidence::key_link_fork(&kept, presented) else {
        return Ok(None);
    };
    let reason = format!(
        "{signer}, a key {server} moved away from, signed a second key link to another DID; \
         someone other than the server holds that key"
    );
    let c = jig_client::connection::Contradiction {
        code: "key-link-fork",
        reason: reason.clone(),
        welcome: None,
        evidence: vec![presented.clone()],
        proof: Some(Box::new(proof)),
    };
    let kept = keep_bundle_in(pins_path, server, &signer, &c)?;
    if !kept.sticky {
        return Ok(None);
    }
    Ok(Some(anyhow::anyhow!(
        "refusing {server}: {reason}. The evidence is `jig trust evidence show {}`. Every \
         connection to it is refused until you run `jig trust accept {server}`",
        kept.id
    )))
}

/// The evidence store beside the pin store `pins_path`: `~/.jig/evidence`
/// for the default `~/.jig/pins.json`.
fn evidence_dir(pins_path: &std::path::Path) -> std::path::PathBuf {
    pins_path.with_file_name("evidence")
}

/// A contradiction found over REST, kept like one on a connection, as the
/// error to stop on.
fn chain_contradiction(
    pins_path: &std::path::Path,
    server: &str,
    slug: &str,
    chain: &jig_client::chain::ChannelChain,
    record: &jig_client::chain::IngestRecord,
    broke: &jig_client::chain::ChainBreak,
) -> anyhow::Error {
    let reason = format!("the history of {slug} broke: {broke}");
    let c = jig_client::connection::Contradiction {
        code: broke.code(),
        reason: reason.clone(),
        welcome: None,
        evidence: vec![serde_json::to_string(record).unwrap_or_default()],
        proof: chain
            .proof(record, broke)
            .map(|p| Box::new(jig_client::evidence::Proof::Chain(Box::new(p)))),
    };
    let kept = match keep_evidence_in(pins_path, server, &c) {
        Ok(kept) => format!(
            " Kept as `jig trust evidence show {}`{}.",
            kept.id,
            if kept.sticky {
                format!("; {server} is refused until `jig trust accept {server}`")
            } else {
                String::new()
            }
        ),
        Err(e) => format!(" The evidence could not be kept: {e:#}."),
    };
    anyhow::anyhow!(
        "{server} contradicted the history of {slug} this device verified: {broke}. \
         Refusing to go on.{kept}"
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
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
        let accept = |chain: &mut ChannelChain,
                      record: &jig_client::chain::IngestRecord,
                      block: Option<&str>| {
            let before = chain.clone();
            chain
                .accept(record, block)
                .map_err(|e| chain_contradiction(pins_path, server, slug, &before, record, &e))
        };
        let step = accept(&mut chain, record, Some(&record.block_cid))?;
        if let Step::Gap { from, to } = step {
            match fetch_records(who, server, slug, from, to).await {
                Ok(filler) if filler.len() as u64 == to - from => {
                    for missing in &filler {
                        accept(&mut chain, missing, None)?;
                    }
                    accept(&mut chain, record, Some(&record.block_cid))?;
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
        let refused = Pins::load(&Pins::default_path())
            .ok()
            .and_then(|pins| pins.refusal(server).cloned())
            .map_or(String::new(), |r| {
                format!(
                    ". It is refused until `jig trust accept {server}`; the evidence is \
                     `jig trust evidence show {}`",
                    r.bundle
                )
            });
        anyhow::anyhow!(
            "{server} contradicted what it signed: {}. The connection was closed{refused}",
            c.reason
        )
    })
}

/// Hold `welcome` to the `server-manifest` it cites (JEP-0002 rule 12): fetch
/// the block and its record, check that they are the server's and say what
/// the welcome says ([`jig_client::manifest::check_cited`]), and hold the
/// manifest log's chain to this device's pin of it. A manifest already
/// checked is not fetched again. A welcome that cites none is let through
/// with a warning: a server from before manifest logs has none.
pub async fn check_manifest(
    who: &jig_client::Identity,
    server: &str,
    welcome: &jig_client::manifest::VerifiedWelcome,
) -> Result<()> {
    check_manifest_in(&Pins::default_path(), who, server, welcome).await
}

async fn check_manifest_in(
    pins_path: &std::path::Path,
    who: &jig_client::Identity,
    server: &str,
    welcome: &jig_client::manifest::VerifiedWelcome,
) -> Result<()> {
    use jig_client::manifest::{LOG_SLUG, check_cited};
    let Some(cited) = &welcome.manifest else {
        eprintln!(
            "warning: {server}'s welcome cites no manifest log entry, so its claims are not \
             checked against one."
        );
        return Ok(());
    };
    let mut pins = Pins::load(pins_path)?;
    if pins.server(server).and_then(|p| p.manifest.as_ref()) == Some(cited) {
        return Ok(());
    }
    #[derive(serde::Deserialize)]
    struct Served {
        bundle_b64: String,
        sig_b64: Option<String>,
    }
    let base = crate::cmd::channel::base_http_url(server);
    let url = format!("{base}/api/v1/blocks/{}", cited.cid);
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
    anyhow::ensure!(
        resp.status().is_success(),
        "{server} did not serve the manifest its welcome cites: GET {url} returned {}",
        resp.status()
    );
    let served: Served = resp
        .json()
        .await
        .with_context(|| format!("decoding {url}"))?;
    let record = fetch_records(who, server, LOG_SLUG, cited.seq, cited.seq + 1)
        .await?
        .into_iter()
        .next()
        .with_context(|| {
            format!(
                "{server} did not serve record {} of its manifest log",
                cited.seq
            )
        })?;
    check_cited(
        welcome,
        cited,
        &served.bundle_b64,
        served.sig_b64.as_deref().unwrap_or_default(),
        &record,
    )
    .map_err(|e| anyhow::anyhow!("{server}: {e}. Refusing to go on"))?;

    // The log is a channel like any other: pinned at first sight, and held
    // to its chain from then on.
    pins.check_channel(
        server,
        LOG_SLUG,
        jig_client::pins::ChannelPin {
            create_cid: record.channel_id.clone(),
            suite: "none".into(),
            owner_did: welcome.server_did.clone(),
            chain_head: None,
        },
    )?;
    if let ChainCheck::Unfilled { from, to } =
        check_chain_in(pins_path, who, server, LOG_SLUG, &[record]).await?
    {
        eprintln!(
            "warning: {server} did not serve records {from}..{to} of its manifest log; the \
             entries in between are not checked."
        );
    }
    Pins::load(pins_path)?.set_manifest(server, cited)?;
    Ok(())
}

/// `jig trust show <server>`: what this device pinned for `server`, and its
/// manifest log, oldest entry first, each checked as the server's and the
/// chain held to the pin.
pub async fn show(who: &jig_client::Identity, server: &str) -> Result<()> {
    use jig_client::manifest::{LOG_SLUG, read_entry};
    let pins = Pins::load(&Pins::default_path())?;
    let Some(pin) = pins.server(server).cloned() else {
        println!("{server}: nothing pinned yet. Connect once to pin it.");
        return Ok(());
    };
    println!("server:    {server}");
    println!("DID:       {}", pin.server_did);
    println!(
        "suites:    {}",
        pin.suites.iter().cloned().collect::<Vec<_>>().join(", ")
    );
    if let Some(m) = &pin.manifest {
        println!(
            "manifest:  {} (entry {} of its log, last checked)",
            m.cid, m.seq
        );
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        bundle_b64: String,
        sig_b64: Option<String>,
        ingest: Option<jig_client::chain::IngestRecord>,
    }
    let base = crate::cmd::channel::base_http_url(server);
    let url = format!(
        "{base}/api/v1/channels/{}/blocks?limit=200",
        crate::cmd::channel::escape_slug_for_url(LOG_SLUG)
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
    anyhow::ensure!(
        resp.status().is_success(),
        "GET {url} returned {}",
        resp.status()
    );
    let entries: Vec<Entry> = resp
        .json()
        .await
        .with_context(|| format!("decoding {url}"))?;
    let records: Vec<_> = entries.iter().filter_map(|e| e.ingest.clone()).collect();
    if !records.is_empty() {
        check_channel_chain(who, server, LOG_SLUG, &records).await?;
    }
    println!("manifest log ({LOG_SLUG}):");
    for entry in &entries {
        let seq = entry
            .ingest
            .as_ref()
            .map_or("-".to_string(), |r| r.seq.to_string());
        match read_entry(
            &pin.server_did,
            &entry.bundle_b64,
            entry.sig_b64.as_deref().unwrap_or_default(),
        ) {
            Ok(Some((cid, doc))) => {
                let caps = &doc.capabilities;
                println!(
                    "  {seq:>4}  {cid}\n        versions {:?}, suites {}, kinds {}, execution {}, \
                     federation {}, skew bound {} ms, {} published peer(s)",
                    doc.versions,
                    doc.suites.join(", "),
                    caps.block_kinds.join(", "),
                    caps.execution,
                    caps.federation,
                    caps.max_future_skew_ms,
                    doc.peer_policy.peers.len()
                );
            }
            Ok(None) => println!("  {seq:>4}  (the log's creation)"),
            Err(e) => println!("  {seq:>4}  NOT THE SERVER'S: {e}"),
        }
    }
    Ok(())
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

    #[test]
    fn a_link_forking_one_the_pin_followed_refuses_the_server() {
        use base64::Engine as _;
        use jig_core::key_link::{Audience, SignedKeyLink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let server = "https://host:7117";
        let new_key = jig_core::crypto::ed25519::generate_signing_key;
        let did = |k: &ed25519_dalek::SigningKey| {
            jig_core::Did::from_ed25519_pubkey(k.verifying_key().as_bytes()).to_did_jig_string()
        };
        let link = |a, b| {
            base64::engine::general_purpose::STANDARD.encode(
                SignedKeyLink::sign(a, b, Audience::Public, 1)
                    .unwrap()
                    .envelope(),
            )
        };
        let (old, new, thief) = (new_key(), new_key(), new_key());
        let mut pins = Pins::load(&path).unwrap();
        pins.check_server_did(server, &did(&old)).unwrap();
        pins.move_server(server, &did(&old), &did(&new), &link(&old, &new))
            .unwrap();
        let other = |key_link: Option<String>| TlsError::OtherServer {
            server: server.into(),
            expected: did(&new),
            presented: did(&thief),
            key_link,
        };

        // No link, or one that forks nothing followed: an ordinary refusal.
        for e in [other(None), other(Some(link(&thief, &new)))] {
            assert!(link_fork_in(&path, server, &e).unwrap().is_none());
        }
        assert!(Pins::load(&path).unwrap().refusal(server).is_none());

        // The key the pin left, linked again to another DID.
        let refused = link_fork_in(&path, server, &other(Some(link(&old, &thief))))
            .unwrap()
            .unwrap();
        let sticky = Pins::load(&path).unwrap().refusal(server).cloned().unwrap();
        assert!(refused.to_string().contains(&sticky.bundle), "{refused}");
        let bundle = jig_client::evidence::EvidenceStore::new(&evidence_dir(&path))
            .get(&sticky.bundle)
            .unwrap();
        assert_eq!(
            (bundle.code.as_str(), bundle.server_did.clone()),
            ("key-link-fork", did(&old))
        );
        assert!(
            jig_client::evidence::verify(&bundle)
                .unwrap()
                .proven
                .is_some()
        );
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

        // Both records are kept, they prove the fork, and the server is
        // refused until accepted.
        let store = jig_client::evidence::EvidenceStore::new(&evidence_dir(&path));
        let [(id, bundle)] = store.list().unwrap().try_into().unwrap();
        assert_eq!(bundle.code, "chain-rewritten");
        assert!(
            jig_client::evidence::verify(&bundle)
                .unwrap()
                .proven
                .is_some()
        );
        assert!(e.to_string().contains(&id), "{e}");
        let pins = Pins::load(&path).unwrap();
        let refused = refuse_if_sticky(&pins, SERVER).unwrap_err().to_string();
        assert!(refused.contains("jig trust accept"), "{refused}");
        assert!(refused.contains(&id), "{refused}");
        let mut pins = pins;
        pins.accept_server(SERVER).unwrap();
        refuse_if_sticky(&pins, SERVER).unwrap();
    }

    #[tokio::test]
    async fn a_break_that_proves_nothing_is_kept_but_not_sticky() {
        let dir = tempfile::tempdir().unwrap();
        let who = jig_client::Identity::generate_for_tests(dir.path());
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let r0 = sign(&key, 0, "bafyCreate", GENESIS_PREV);
        let r1 = sign(&key, 1, "bafyA", r0.hash());
        let path = pinned(dir.path(), &key, Some(&r0));
        // Signed by someone else: anyone can do that.
        let stranger = jig_core::crypto::ed25519::generate_signing_key();
        let forged = sign(&stranger, 1, "bafyA", r0.hash());
        assert!(
            check_chain_in(&path, &who, SERVER, "#ops", &[forged])
                .await
                .is_err()
        );

        // A fork against a head pinned without its record cannot be shown.
        let mut pins = Pins::load(&path).unwrap();
        let mut bare = jig_client::chain::ChainHead::of(&r1);
        bare.record = None;
        pins.advance_chain(SERVER, "#ops", &bare).unwrap();
        let other = sign(&key, 1, "bafyOther", r0.hash());
        assert!(
            check_chain_in(&path, &who, SERVER, "#ops", &[other])
                .await
                .is_err()
        );

        let store = jig_client::evidence::EvidenceStore::new(&evidence_dir(&path));
        let codes: Vec<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|(_, b)| b.code)
            .collect();
        assert_eq!(codes, ["chain-unsigned", "chain-rewritten"]);
        for (_, bundle) in store.list().unwrap() {
            assert_eq!(jig_client::evidence::verify(&bundle).unwrap().proven, None);
        }
        refuse_if_sticky(&Pins::load(&path).unwrap(), SERVER).unwrap();
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
                record: None,
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

/// The delegations for resolving `name`. A `--nameserver`/`--authority` pair
/// given on the command line replaces the suffix's entry: the nameservers to
/// ask and the authorities whose attestations count. Without one, it is
/// `cli.toml`'s `[naming.delegations]` (or the built-in `@jig` one), and any
/// other suffix is discovered over `dns`, as for `jig ns resolve`.
pub fn delegations_for(
    cfg: &crate::config::Config,
    name: &str,
    nameservers: Vec<String>,
    authorities: Vec<String>,
) -> Result<jig_client::naming::Delegations> {
    let parsed = jig_core::naming::Name::parse(name)?;
    if nameservers.is_empty() && authorities.is_empty() {
        return crate::cmd::ns::resolve_delegations(cfg, &parsed, None);
    }
    anyhow::ensure!(
        !nameservers.is_empty() && !authorities.is_empty(),
        "a delegation needs both --nameserver and --authority"
    );
    let mut delegations = crate::config::delegations(cfg);
    delegations.config.insert(
        parsed.suffix,
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
        let cfg = crate::config::Config::default();
        assert!(
            !delegations_for(&cfg, "alice@example.org", vec![], vec![])
                .unwrap()
                .config
                .contains_key("example.org"),
            "a dns suffix with no flags is discovered, not configured"
        );
        assert!(
            delegations_for(&cfg, "alice@example.org", vec!["https://ns".into()], vec![]).is_err()
        );
        let d = delegations_for(
            &cfg,
            "alice@example.org",
            vec!["https://ns".into()],
            vec!["did:jig:zNs".into()],
        )
        .unwrap();
        assert_eq!(d.config["example.org"].authorities, ["did:jig:zNs"]);
    }

    #[test]
    fn without_flags_the_configured_delegation_counts() {
        let mut cfg = crate::config::Config::default();
        cfg.naming.delegations.insert(
            "example.org".into(),
            crate::config::DelegationEntry {
                authorities: vec!["did:jig:zCfg".into()],
                nameservers: vec!["https://ns.example.org".into()],
            },
        );
        let d = delegations_for(&cfg, "alice@example.org", vec![], vec![]).unwrap();
        assert_eq!(d.config["example.org"].authorities, ["did:jig:zCfg"]);
        let d = delegations_for(
            &cfg,
            "alice@example.org",
            vec!["https://other".into()],
            vec!["did:jig:zFlag".into()],
        )
        .unwrap();
        assert_eq!(
            d.config["example.org"].authorities,
            ["did:jig:zFlag"],
            "flags replace the entry"
        );
    }
}
