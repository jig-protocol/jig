//! A server that changes its key keeps its channels, its manifest log and
//! its clients (JEP-0012).
//!
//! A real server with an open channel, an encrypted one and its manifest log
//! changes its key twice (`jig-server keys rotate`, then a restart each
//! time). Clients pinned before either change reconnect on their old pins,
//! read every channel's history across both changes with the chain checked,
//! post into the channels that were there before, and see the manifest log
//! go on in the channel they pinned. A record the first key signs after the
//! change is refused as a break.

use std::path::{Path, PathBuf};

use integration_tests::harness::*;
use jig_client::Identity;
use jig_client::chain::{ChainBreak, ChannelChain, IngestRecord, RecordSigner, Step};
use jig_client::connection::{Client, ConnectOptions};
use jig_client::pins::{ChannelPin, Pins};
use jig_client::read_auth::{ReadProof, signable_path};
use jig_client::secure::{Seen, Session};
use jig_pipeline::server_manifest::LOG_SLUG;

/// What the devices pin the server as. The harness gives a restarted server
/// a new port, so pins and MLS state are kept under one name for it, as they
/// would be for a server at one address.
const SERVER: &str = "ws://rotating.example";

const OPEN: &str = "#general";
const SECRET: &str = "#secret";

/// One person on one device: their key, their pins, their MLS state.
struct Device {
    id: Identity,
    keys: PathBuf,
    pins: PathBuf,
    session: Session,
}

impl Device {
    fn new(root: &Path, name: &str) -> Self {
        let (id, keys) = test_identity_with_dir();
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let session = Session::open(&dir.join("mls"), load_identity(&keys, &id.did_string()))
            .expect("MLS session");
        Self {
            id,
            keys,
            pins: dir.join("pins.json"),
            session,
        }
    }

    fn identity(&self) -> Identity {
        load_identity(&self.keys, &self.id.did_string())
    }

    fn pinned(&self) -> jig_client::pins::ServerPin {
        Pins::load(&self.pins)
            .unwrap()
            .server(SERVER)
            .cloned()
            .expect("pinned")
    }

    /// Connect the way `jig` does: the pin's offer and key links, then the
    /// welcome checked against the pin (and pinned on first sight).
    async fn connect(&self, server: &TestJigServer) -> Client {
        let mut pins = Pins::load(&self.pins).unwrap();
        let options = ConnectOptions {
            offer: pins.offer(SERVER),
            key_links: pins
                .server(SERVER)
                .map(|p| p.links.clone())
                .unwrap_or_default(),
            ..ConnectOptions::default()
        };
        let client = Client::connect_with_options(&server.ws_url(), self.identity(), options)
            .await
            .expect("the server proves it is the one pinned");
        pins.check_welcome(SERVER, client.welcome().unwrap())
            .expect("the welcome fits the pin");
        client
    }

    /// Every record of `slug`, held to the chain this device pinned for it
    /// and moving the pin, as `jig` checks a page of history. Returns them,
    /// oldest first.
    async fn verify_history(&self, server: &TestJigServer, slug: &str) -> Vec<IngestRecord> {
        let records = records(server, &self.id, slug).await;
        assert!(!records.is_empty(), "{slug} has history");
        let mut pins = Pins::load(&self.pins).unwrap();
        // The channel is the one first pinned under this name: the same
        // creation block, whoever signs its records now.
        let pin = pins
            .check_channel(
                SERVER,
                slug,
                ChannelPin {
                    create_cid: records[0].channel_id.clone(),
                    suite: "none".into(),
                    owner_did: String::new(),
                    chain_head: None,
                    sequencer: None,
                },
            )
            .expect("the channel this device pinned");
        let mut chain = ChannelChain::across(
            &pin.create_cid,
            pins.server(SERVER).unwrap().sequencers(),
            pin.chain_head,
        );
        for record in &records {
            let step = chain
                .accept(record, Some(&record.block_cid))
                .unwrap_or_else(|e| panic!("{slug} record {}: {e}", record.seq));
            assert!(matches!(step, Step::Next | Step::Behind), "{step:?}");
        }
        pins.advance_chain(SERVER, slug, chain.head().unwrap())
            .unwrap();
        records
    }
}

fn enc(slug: &str) -> String {
    slug.replace('#', "%23").replace('/', "%2F")
}

/// Boot as `jig-server` does before it serves anything: the manifest log
/// first, which the harness leaves out.
async fn booted(server: TestJigServer) -> TestJigServer {
    jig_server::v0_0_2_manifest_log::publish(&server.state)
        .await
        .expect("the manifest log");
    server
}

async fn get(who: &Identity, url: &str) -> serde_json::Value {
    let proof = ReadProof::sign(who, "GET", signable_path(url));
    let mut req = reqwest::Client::new().get(url);
    for (name, value) in proof.headers() {
        req = req.header(name, value);
    }
    let resp = req.send().await.expect("GET");
    assert!(resp.status().is_success(), "GET {url}: {}", resp.status());
    resp.json().await.unwrap()
}

async fn records(server: &TestJigServer, who: &Identity, slug: &str) -> Vec<IngestRecord> {
    let url = format!(
        "{}/api/v1/channels/{}/records?from=0&limit=500",
        server.http_url(),
        enc(slug)
    );
    serde_json::from_value(get(who, &url).await).unwrap()
}

/// Change the server's key the way `jig-server keys rotate` does, and boot
/// it again. Returns the server, and the key it signed with before.
async fn rotate(server: TestJigServer, now: i64) -> (TestJigServer, ed25519_dalek::SigningKey) {
    let before = server.state.ingest_ctx.server_key.clone();
    let dir = server.data_dir().to_path_buf();
    // The harness opens the key with this credential on every boot, so the
    // new key is sealed with it too.
    let credential = jig_client::server_key::credential_for_tests(&dir);
    let rotated = jig_client::server_key::rotate(
        &dir.join("server.key"),
        std::slice::from_ref(&credential),
        false,
        &jig_server::v0_0_2::key_options(&server.state.config.keys),
        now,
    )
    .expect("keys rotate");
    assert_eq!(rotated.old_did, server.server_did_string);
    let server = booted(server.restart().await.expect("restart")).await;
    assert_eq!(server.server_did_string, rotated.new_did);
    (server, before)
}

async fn say(server: &TestJigServer, mls_server: &str, who: &Device, text: &str) {
    let (msg, epoch) = who.session.encrypt(mls_server, SECRET, text).unwrap();
    let block = jig_client::blocks::build_sealed_text(
        &who.id,
        SECRET,
        &msg,
        epoch,
        jig_core::HlcTimestamp::now_wall(who.id.did().clone()),
    );
    who.session
        .remember(&block.cid(), &who.id.did_string(), text)
        .unwrap();
    server.submit_block(&block).await.expect("sealed text");
}

/// What `who` reads of the encrypted channel's history, decrypted.
async fn read_secret(server: &TestJigServer, mls_server: &str, who: &Device) -> Vec<String> {
    let url = format!(
        "{}/api/v1/channels/{}/blocks",
        server.http_url(),
        enc(SECRET)
    );
    let blocks: Vec<jig_client::DeliveredBlock> =
        serde_json::from_value(get(&who.id, &url).await).unwrap();
    let opened: Vec<_> = blocks
        .iter()
        .map(|b| jig_client::open::open(b).unwrap())
        .collect();
    jig_client::secure::replay_order(opened)
        .iter()
        .map(|o| who.session.observe(mls_server, o))
        .filter_map(|s| match s {
            Seen::Text { text, .. } => Some(text),
            _ => None,
        })
        .collect()
}

/// The welcome's manifest entry, checked as `jig` checks it.
async fn check_manifest(server: &TestJigServer, who: &Device, client: &Client) -> u64 {
    let welcome = client.welcome().unwrap();
    let cited = welcome.manifest.clone().expect("the welcome cites the log");
    let block = get(
        &who.id,
        &format!("{}/api/v1/blocks/{}", server.http_url(), cited.cid),
    )
    .await;
    let record = records(server, &who.id, LOG_SLUG)
        .await
        .into_iter()
        .find(|r| r.seq == cited.seq)
        .expect("the cited record");
    jig_client::manifest::check_cited(
        welcome,
        &cited,
        block["bundle_b64"].as_str().unwrap(),
        block["sig_b64"].as_str().unwrap_or_default(),
        &record,
    )
    .expect("the welcome's own DID wrote the entry it cites");
    cited.seq
}

#[tokio::test]
async fn a_server_that_changes_its_key_twice_keeps_its_channels_log_and_clients() {
    let root = tempfile::tempdir().unwrap();
    let server = booted(TestJigServer::start().await.expect("start")).await;
    // The MLS groups were made at this address; a restart changes the port,
    // not the server, so the groups stay under it.
    let mls_server = server.http_url();
    let alice = Device::new(root.path(), "alice");
    let bob = Device::new(root.path(), "bob");
    let first = server.server_did_string.clone();

    // ---- before: both devices pin the server and its channels ----------
    drop(alice.connect(&server).await);
    drop(bob.connect(&server).await);
    server
        .create_channel(&alice.id, OPEN, "open")
        .await
        .unwrap();
    server
        .send_text_render(&alice.id, OPEN, "before any change")
        .await
        .unwrap();
    server
        .create_restricted_channel(&alice.id, &alice.session, SECRET)
        .await
        .unwrap();
    server
        .add_restricted_member(&alice.id, &alice.session, SECRET, &bob.session)
        .await
        .unwrap();
    // Bob joins the group from the welcome in the history.
    read_secret(&server, &mls_server, &bob).await;
    say(&server, &mls_server, &bob, "sealed before").await;
    for d in [&alice, &bob] {
        for slug in [OPEN, SECRET, LOG_SLUG] {
            d.verify_history(&server, slug).await;
        }
    }
    let log_before = records(&server, &alice.id, LOG_SLUG).await;
    let log_id = log_before[0].channel_id.clone();

    // ---- the first change; Alice reconnects in between, Bob does not ----
    let (server, first_key) = rotate(server, 1).await;
    let second = server.server_did_string.clone();
    let client = alice.connect(&server).await;
    assert_eq!(alice.pinned().server_did, second, "the pin followed");
    check_manifest(&server, &alice, &client).await;
    drop(client);
    server
        .send_text_render(&alice.id, OPEN, "after one change")
        .await
        .expect("an existing channel still takes posts");
    say(&server, &mls_server, &alice, "sealed after one").await;
    alice.verify_history(&server, OPEN).await;

    // ---- the second change --------------------------------------------------
    let (server, second_key) = rotate(server, 2).await;
    let third = server.server_did_string.clone();
    let dids = vec![first.clone(), second.clone(), third.clone()];

    // Both reconnect on the pins they hold, two hops back for Bob, one for
    // Alice: nobody re-pins.
    let mut clients = Vec::new();
    for d in [&alice, &bob] {
        let client = d.connect(&server).await;
        let pin = d.pinned();
        assert_eq!(pin.server_did, third);
        assert_eq!(pin.sequencers(), dids, "the chain of DIDs it followed");
        clients.push(client);
    }

    // Each posts into the channels that were there before.
    let mut live = clients[0].subscribe_channel(OPEN).await.unwrap();
    let posted = server
        .send_text_render(&bob.id, OPEN, "after two changes")
        .await
        .expect("an existing channel still takes posts");
    say(&server, &mls_server, &bob, "sealed after two").await;
    server
        .add_member(&alice.id, OPEN, &bob.id.did_string())
        .await
        .expect("and changes");
    let record = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let delivered = live.next().await.expect("a block");
            if let Some(record) = delivered.ingest
                && record.block_cid == posted
            {
                return record;
            }
        }
    })
    .await
    .expect("delivered live");
    record.verify(&third).unwrap();
    assert!(
        clients[0].contradiction().is_none(),
        "the session's chain took it"
    );

    // History across both changes verifies, every DID in its stretch.
    for d in [&alice, &bob] {
        for slug in [OPEN, SECRET] {
            let records = d.verify_history(&server, slug).await;
            let signers: Vec<&str> = records.iter().map(|r| r.sequencer.as_str()).collect();
            assert_eq!(signers.first(), Some(&first.as_str()), "{slug}");
            assert_eq!(signers.last(), Some(&third.as_str()), "{slug}");
        }
    }
    let decrypted = read_secret(&server, &mls_server, &alice).await;
    for text in ["sealed before", "sealed after one", "sealed after two"] {
        // Only the expected text is named, never what was decrypted.
        assert!(
            decrypted.iter().any(|t| t == text),
            "{text} does not decrypt"
        );
    }

    // The manifest log goes on in the channel both devices pinned, each
    // stretch written by the DID of its time, and the welcome cites the
    // newest DID's entry.
    for (d, client) in [&alice, &bob].into_iter().zip(&clients) {
        let log = d.verify_history(&server, LOG_SLUG).await;
        assert_eq!(log[0].channel_id, log_id, "the same log");
        assert!(log.len() > log_before.len(), "it went on");
        let cited = check_manifest(&server, d, client).await;
        assert_eq!(log.last().unwrap().seq, cited);
        let signers: std::collections::BTreeSet<&str> =
            log.iter().map(|r| r.sequencer.as_str()).collect();
        assert_eq!(signers.len(), 3, "{signers:?}");
    }

    // ---- an earlier key signs on after the change ---------------------------
    let open = alice.verify_history(&server, OPEN).await;
    let head = open.last().unwrap();
    let pins = Pins::load(&alice.pins).unwrap();
    let pinned = pins.channel(SERVER, OPEN).unwrap().clone();
    for (key, did) in [(&first_key, &first), (&second_key, &second)] {
        let forged = RecordSigner {
            channel_id: head.channel_id.clone(),
            key,
            ingest_wall_ms: head.ingest_wall_ms + 1,
            ingest_logical: 0,
        }
        .sign(
            head.seq + 1,
            &jig_pipeline::ingest_record::label_cid("forged by an old key"),
            head.hash(),
        )
        .unwrap();
        let mut chain = ChannelChain::across(
            &pinned.create_cid,
            pins.server(SERVER).unwrap().sequencers(),
            pinned.chain_head.clone(),
        );
        let broke = chain.accept(&forged, None).unwrap_err();
        assert!(
            matches!(&broke, ChainBreak::RetiredKey { signer, newer, .. }
                if signer == did && *newer == third),
            "{broke}"
        );
        assert_eq!(broke.code(), "chain-retired-key");
    }
    // And a DID outside the chain, as before.
    let stranger = jig_core::crypto::ed25519::generate_signing_key();
    let forged = RecordSigner {
        channel_id: head.channel_id.clone(),
        key: &stranger,
        ingest_wall_ms: head.ingest_wall_ms + 1,
        ingest_logical: 0,
    }
    .sign(head.seq + 1, &head.block_cid, head.hash())
    .unwrap();
    let mut chain = ChannelChain::across(
        &pinned.create_cid,
        pins.server(SERVER).unwrap().sequencers(),
        pinned.chain_head,
    );
    assert!(matches!(
        chain.accept(&forged, None),
        Err(ChainBreak::Unsigned(_))
    ));

    // A device pinned to a DID the chain does not lead from is refused at
    // the handshake, and its pin left as it was.
    let carol = Device::new(root.path(), "carol");
    let elsewhere =
        jig_core::Did::from_ed25519_pubkey(stranger.verifying_key().as_bytes()).to_did_jig_string();
    Pins::load(&carol.pins)
        .unwrap()
        .check_server_did(SERVER, &elsewhere)
        .unwrap();
    let pins = Pins::load(&carol.pins).unwrap();
    let refused = Client::connect_with_options(
        &server.ws_url(),
        carol.identity(),
        ConnectOptions {
            offer: pins.offer(SERVER),
            ..ConnectOptions::default()
        },
    )
    .await;
    assert!(
        refused.is_err(),
        "the welcome does not move a pin it does not chain from"
    );
    assert_eq!(carol.pinned().server_did, elsewhere);
    assert!(carol.pinned().links.is_empty());

    // No channel was left behind under an earlier DID.
    let store = &server.state.ingest_ctx.store;
    for c in store.list_channels_including_archived().unwrap() {
        assert_eq!(c.sequencer_did, third, "{}", c.slug);
    }
}
