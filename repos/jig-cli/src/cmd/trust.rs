//! What this process trusts for a server: the DID this device pinned for it,
//! and the TLS certificate that DID vouches for ([`jig_client::tls`]).
//!
//! The first connection to an `https://` server in a process probes it once:
//! the DID it names must be the pinned one (or is pinned, on first contact),
//! and its certificate must be one that DID vouches for, or one a CA issued.
//! Every later REST and WSS connection in the process gets a config that
//! accepts that certificate and nothing else. A certificate the server rotated
//! is picked up by the next process, as long as the same DID vouches for it.

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
    let mut chain = ChannelChain::new(&channel.create_cid, &sequencer, channel.chain_head);
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
    use jig_client::chain::{GENESIS_PREV, IngestRecord, RecordSigner};
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
            channel_id: "bafyCreate".into(),
            key,
            ingest_wall_ms: 1_000 + seq,
            ingest_logical: 0,
        }
        .sign(seq, block, prev)
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
                create_cid: "bafyCreate".into(),
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
        let who = jig_client::Identity::generate_and_save(dir.path()).unwrap();
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
        let who = jig_client::Identity::generate_and_save(dir.path()).unwrap();
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
        let who = jig_client::Identity::generate_and_save(dir.path()).unwrap();
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
    async fn an_unpinned_channel_has_nothing_to_hold_the_server_to() {
        let dir = tempfile::tempdir().unwrap();
        let who = jig_client::Identity::generate_and_save(dir.path()).unwrap();
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let r0 = sign(&key, 0, "bafyCreate", GENESIS_PREV);
        let path = dir.path().join("pins.json");
        let got = check_chain_in(&path, &who, SERVER, "#ops", &[r0])
            .await
            .unwrap();
        assert_eq!(got, ChainCheck::Unpinned);
    }
}
