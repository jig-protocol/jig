//! H12: end-to-end encrypted channels against a real server.
//!
//! Every surface a client uses — channel creation, key packages, the signed
//! read routes, REST submit, live WSS delivery — driven the way `jig` drives
//! it, with each member's MLS state in its own `jig_client::secure::Session`.
//! The headline assertion is the one the feature exists for: after a
//! conversation, the server's files on disk contain none of what was said.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures_util::{SinkExt, StreamExt};
use integration_tests::harness::*;
use jig_client::blocks::{BuiltBlock, build_member_remove, build_sealed_text, build_with_metadata};
use jig_client::open::open;
use jig_client::read_auth::{ReadProof, signable_path};
use jig_client::secure::{Seen, Session, history_reaches, replay_order};
use jig_client::{DeliveredBlock, Identity};
use jig_core::{BlockKind, HlcTimestamp};
use jig_mls::member::Commit;
use jig_pipeline::envelope::{Envelope, Frame, Scope};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

/// A person: an identity to sign with and a session holding their MLS state.
struct Person {
    id: Identity,
    session: Session,
    keys: PathBuf,
}

impl Person {
    fn new(mls_root: &Path) -> Self {
        let (id, keys) = test_identity_with_dir();
        let session = Session::open(mls_root, load_identity(&keys, &id.did_string())).unwrap();
        Self { id, session, keys }
    }
    fn did(&self) -> String {
        self.id.did_string()
    }
    fn hlc(&self) -> HlcTimestamp {
        HlcTimestamp::now_wall(self.id.did().clone())
    }
}

struct Api<'a> {
    server: &'a TestJigServer,
}

impl Api<'_> {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server.http_url())
    }

    async fn get(&self, who: &Identity, path: &str) -> (u16, Value) {
        let url = self.url(path);
        let proof = ReadProof::sign(who, "GET", signable_path(&url));
        let mut req = reqwest::Client::new().get(&url);
        for (name, value) in proof.headers() {
            req = req.header(name, value);
        }
        let resp = req.send().await.expect("GET");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn post(&self, path: &str, body: &Value) -> (u16, Value) {
        let resp = reqwest::Client::new()
            .post(self.url(path))
            .json(body)
            .send()
            .await
            .expect("POST");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn submit(&self, block: &BuiltBlock) -> (u16, Value) {
        self.post(
            "/api/v1/blocks",
            &json!({
                "bundle_b64": STANDARD.encode(block.canonical_bytes()),
                "sig_b64": STANDARD.encode(&block.sender_sig),
            }),
        )
        .await
    }

    async fn publish_key_packages(&self, p: &Person) {
        let mut kps = p.session.key_packages(3, false).unwrap();
        kps.extend(p.session.key_packages(1, true).unwrap());
        let (status, body) = self
            .post(
                "/api/v1/mls/key-packages",
                &json!({"key_packages_b64": kps.iter().map(|k| STANDARD.encode(k)).collect::<Vec<_>>()}),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["available"], 3);
        assert_eq!(body["last_resort"], true);
    }

    async fn key_package(&self, asker: &Identity, did: &str) -> Vec<u8> {
        let (status, body) = self
            .get(asker, &format!("/api/v1/mls/key-packages/{did}"))
            .await;
        assert_eq!(status, 200, "{body}");
        STANDARD
            .decode(body["key_package_b64"].as_str().unwrap())
            .unwrap()
    }

    async fn history(&self, who: &Identity, slug: &str) -> (u16, Vec<DeliveredBlock>) {
        let (status, body) = self
            .get(who, &format!("/api/v1/channels/{}/blocks", enc(slug)))
            .await;
        let blocks = if status == 200 {
            serde_json::from_value(body).unwrap()
        } else {
            Vec::new()
        };
        (status, blocks)
    }

    /// One page of history: the newest `limit` blocks, or those just older
    /// than the block `before`.
    async fn history_page(
        &self,
        who: &Identity,
        slug: &str,
        limit: usize,
        before: Option<&str>,
    ) -> (u16, Vec<DeliveredBlock>) {
        let mut path = format!("/api/v1/channels/{}/blocks?limit={limit}", enc(slug));
        if let Some(cid) = before {
            path.push_str(&format!("&before={cid}"));
        }
        let (status, body) = self.get(who, &path).await;
        assert_eq!(status, 200, "{body}");
        (status, serde_json::from_value(body).unwrap())
    }
}

fn enc(slug: &str) -> String {
    slug.replace('#', "%23").replace('/', "%2F")
}

fn mls_meta(c: &Commit) -> Value {
    let mut v = json!({"mls_commit": STANDARD.encode(&c.commit), "mls_epoch": c.epoch});
    if let Some(w) = &c.welcome {
        v["mls_welcome"] = STANDARD.encode(w).into();
    }
    if let Some(i) = &c.group_info {
        v["mls_group_info"] = STANDARD.encode(i).into();
    }
    v
}

fn with(mut base: Value, extra: Value) -> Value {
    if let (Value::Object(b), Value::Object(e)) = (&mut base, extra) {
        b.extend(e);
    }
    base
}

async fn create_encrypted(api: &Api<'_>, owner: &Person, slug: &str, visibility: &str) {
    let (status, body) = try_create(api, owner, slug, json!({"visibility": visibility})).await;
    assert_eq!(status, 200, "{body}");
}

async fn try_create(api: &Api<'_>, owner: &Person, slug: &str, meta: Value) -> (u16, Value) {
    let server = api.server.http_url();
    let created = owner.session.create_group(&server, slug).unwrap();
    let block = build_with_metadata(
        &owner.id,
        BlockKind::ChannelCreate,
        owner.hlc(),
        with(
            json!({"slug": slug, "suite": "mls",
                   "mls_group_info": STANDARD.encode(&created.group_info),
                   "mls_ratchet_tree": STANDARD.encode(&created.ratchet_tree)}),
            meta,
        ),
    );
    api.post(
        "/api/v1/channels",
        &json!({
            "bundle_b64": STANDARD.encode(block.canonical_bytes()),
            "sig_b64": STANDARD.encode(&block.sender_sig),
        }),
    )
    .await
}

async fn add(api: &Api<'_>, owner: &Person, slug: &str, who: &Person) {
    let server = api.server.http_url();
    let kp = api.key_package(&owner.id, &who.did()).await;
    let c = owner
        .session
        .prepare_add(&server, slug, &kp, &who.did())
        .unwrap();
    let block = build_with_metadata(
        &owner.id,
        BlockKind::MemberAdd,
        owner.hlc(),
        with(
            json!({"channel": slug, "member_did": who.did()}),
            mls_meta(&c),
        ),
    );
    let (status, body) = api.submit(&block).await;
    assert_eq!(status, 200, "{body}");
    owner.session.confirm(&server, slug).unwrap();
}

/// Replay a member's view of the channel from the server's history.
async fn catch_up(api: &Api<'_>, p: &Person, slug: &str) -> Vec<Seen> {
    let (status, blocks) = api.history(&p.id, slug).await;
    assert_eq!(status, 200);
    let opened: Vec<_> = blocks.iter().map(|b| open(b).unwrap()).collect();
    jig_client::secure::replay_order(opened)
        .iter()
        .map(|o| p.session.observe(&api.server.http_url(), o))
        .collect()
}

async fn say(api: &Api<'_>, p: &Person, slug: &str, text: &str) -> String {
    let (msg, epoch) = p
        .session
        .encrypt(&api.server.http_url(), slug, text)
        .unwrap();
    let block = build_sealed_text(&p.id, slug, &msg, epoch, p.hlc());
    p.session.remember(&block.cid(), &p.did(), text).unwrap();
    let (status, body) = api.submit(&block).await;
    assert_eq!(status, 200, "{body}");
    body["block_cid"].as_str().unwrap().to_string()
}

fn texts(seen: &[Seen]) -> Vec<String> {
    seen.iter()
        .filter_map(|s| match s {
            Seen::Text { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

/// Every byte the server has on disk, for a plaintext scan.
fn disk_bytes(dir: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            all.extend(std::fs::read(path).unwrap());
        }
    }
    all
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[tokio::test]
async fn an_encrypted_channel_round_trip_leaves_no_plaintext_on_the_server() {
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let api = Api { server: &server };
    let root = tempfile::tempdir().unwrap();
    let alice = Person::new(root.path());
    let bob = Person::new(root.path());
    let carol = Person::new(root.path());
    let slug = "#ops";
    let host = server.http_url();

    for p in [&alice, &bob, &carol] {
        api.publish_key_packages(p).await;
    }
    create_encrypted(&api, &alice, slug, "restricted").await;
    add(&api, &alice, slug, &bob).await;

    // Bob is subscribed live when Alice speaks.
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("{}/api/v1/ws", server.ws_url()))
        .await
        .unwrap();
    jig_server::v0_0_2_federation::complete_client_handshake(&mut ws, None)
        .await
        .unwrap();
    let sub = signed_subscribe(&bob.id, Scope::Channel { slug: slug.into() });
    ws.send(Message::Text(serde_json::to_string(&sub).unwrap().into()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        catch_up(&api, &bob, slug).await.first(),
        Some(&Seen::Control)
    );
    assert!(
        bob.session.has_group(&host, slug).unwrap(),
        "joined from the welcome"
    );

    let before = "the launch code is 0451";
    say(&api, &alice, slug, before).await;
    let live = loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("live delivery")
            .unwrap()
            .unwrap();
        let Message::Text(text) = msg else { continue };
        let Ok(env) = serde_json::from_str::<Envelope>(&text) else {
            continue;
        };
        if let Frame::Block {
            bundle_b64,
            sig_b64,
            receipts,
            delivery_cid,
            ingest,
        } = env.frame
        {
            break DeliveredBlock {
                bundle_b64,
                sig_b64,
                receipts,
                delivery_cid,
                ingest,
            };
        }
    };
    let opened = open(&live).unwrap();
    assert_eq!(
        bob.session.observe(&host, &opened),
        Seen::Text {
            sender: alice.did(),
            text: before.to_string()
        }
    );
    assert!(
        live.receipts[0].render_hash.is_none(),
        "the server executed nothing over ciphertext"
    );

    // Carol was never added: she cannot read the channel at all, and could
    // not decrypt it if she could.
    let (status, _) = api.history(&carol.id, slug).await;
    assert_eq!(status, 403);
    assert!(matches!(
        carol.session.observe(&host, &opened),
        Seen::Sealed { .. }
    ));

    // Plaintext into the encrypted channel is refused, not stored.
    let leak =
        jig_client::blocks::build_text_render(&alice.id, slug, "oops, plaintext", alice.hlc());
    let (status, body) = api.submit(&leak).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("SUITE_MISMATCH")),
        "{body}"
    );

    // Alice removes Bob. What she says next, Bob cannot read — even handed
    // the ciphertext directly.
    let c = alice
        .session
        .prepare_remove(&host, slug, &bob.did())
        .unwrap();
    let kick = build_member_remove(&alice.id, slug, &bob.did(), mls_meta(&c), alice.hlc());
    let (status, body) = api.submit(&kick).await;
    assert_eq!(status, 200, "{body}");
    alice.session.confirm(&host, slug).unwrap();
    let after = "bob must not read this";
    let cid = say(&api, &alice, slug, after).await;
    let (status, _) = api.history(&bob.id, slug).await;
    assert_eq!(status, 403, "a removed member loses read access");
    let stored = server.block_for(&cid).unwrap().unwrap();
    let handed = DeliveredBlock {
        bundle_b64: STANDARD.encode(&stored.bundle_bytes),
        sig_b64: Some(STANDARD.encode(&stored.sender_sig)),
        receipts: vec![],
        delivery_cid: cid.clone(),
        ingest: None,
    };
    let seen_kick = bob
        .session
        .observe(&host, &open(&build_delivered(&kick)).unwrap());
    assert_eq!(seen_kick, Seen::Gone);
    assert!(matches!(
        bob.session.observe(&host, &open(&handed).unwrap()),
        Seen::Sealed { .. }
    ));

    // Alice's own history replays from her plaintext cache.
    assert_eq!(
        texts(&catch_up(&api, &alice, slug).await),
        vec![before, after]
    );

    // The point of all this.
    let disk = disk_bytes(server.data_dir());
    for said in [before, after] {
        assert!(!contains(&disk, said), "`{said}` is on the server's disk");
    }
    let _ = &carol.keys;
}

fn build_delivered(b: &BuiltBlock) -> DeliveredBlock {
    DeliveredBlock {
        bundle_b64: STANDARD.encode(b.canonical_bytes()),
        sig_b64: Some(STANDARD.encode(&b.sender_sig)),
        receipts: vec![],
        delivery_cid: b.cid(),
        ingest: None,
    }
}

#[tokio::test]
async fn an_open_encrypted_channel_is_joined_by_external_commit_and_tidied_on_leave() {
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let api = Api { server: &server };
    let root = tempfile::tempdir().unwrap();
    let alice = Person::new(root.path());
    let dave = Person::new(root.path());
    let slug = "#town-square";
    let host = server.http_url();
    create_encrypted(&api, &alice, slug, "open").await;
    say(&api, &alice, slug, "before dave").await;

    // Dave joins on his own, from the group info the server holds.
    let (status, body) = api
        .get(
            &dave.id,
            &format!("/api/v1/channels/{}/mls/group-info", enc(slug)),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let info = STANDARD
        .decode(body["group_info_b64"].as_str().unwrap())
        .unwrap();
    let c = dave.session.prepare_join(&host, slug, &info).unwrap();
    let join = build_with_metadata(
        &dave.id,
        BlockKind::MemberAdd,
        dave.hlc(),
        with(
            json!({"channel": slug, "member_did": dave.did()}),
            mls_meta(&c),
        ),
    );
    let (status, body) = api.submit(&join).await;
    assert_eq!(status, 200, "{body}");

    // Alice follows the join, then they talk.
    let seen = catch_up(&api, &alice, slug).await;
    assert!(
        seen.contains(&Seen::Added { member: dave.did() }),
        "{seen:?}"
    );
    say(&api, &alice, slug, "hi dave").await;
    let dave_view = catch_up(&api, &dave, slug).await;
    assert_eq!(
        texts(&dave_view),
        vec!["hi dave"],
        "nothing from before they joined"
    );
    assert!(dave_view.iter().any(|s| matches!(s, Seen::Sealed { .. })));

    // Dave leaves: no commit from him, and Alice — online next — tidies his
    // leaf out of the tree.
    let leave = build_member_remove(&dave.id, slug, &dave.did(), json!({}), dave.hlc());
    let (status, body) = api.submit(&leave).await;
    assert_eq!(status, 200, "{body}");
    let seen = catch_up(&api, &alice, slug).await;
    assert!(
        seen.contains(&Seen::Left {
            member: dave.did(),
            tidy: true
        }),
        "{seen:?}"
    );
    let c = alice
        .session
        .prepare_remove(&host, slug, &dave.did())
        .unwrap();
    let tidy = build_member_remove(&alice.id, slug, &dave.did(), mls_meta(&c), alice.hlc());
    let (status, body) = api.submit(&tidy).await;
    assert_eq!(status, 200, "{body}");
    alice.session.confirm(&host, slug).unwrap();
    assert_eq!(
        alice.session.group_members(&host, slug).unwrap(),
        vec![alice.did()]
    );

    // The membership list says the same as the tree.
    let (status, body) = api
        .get(
            &alice.id,
            &format!("/api/v1/channels/{}/members", enc(slug)),
        )
        .await;
    assert_eq!(status, 200);
    let dids: Vec<&str> = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["did"].as_str().unwrap())
        .collect();
    assert_eq!(dids, vec![alice.did()]);
}

#[tokio::test]
async fn racing_commits_land_one_at_a_time() {
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let api = Api { server: &server };
    let root = tempfile::tempdir().unwrap();
    let alice = Person::new(root.path());
    let bob = Person::new(root.path());
    let carol = Person::new(root.path());
    let slug = "#race";
    let host = server.http_url();
    for p in [&bob, &carol] {
        api.publish_key_packages(p).await;
    }
    create_encrypted(&api, &alice, slug, "restricted").await;

    // Two commits built on epoch 0. The first to land wins; the second is
    // refused as stale and changes nothing.
    let kp_b = api.key_package(&alice.id, &bob.did()).await;
    let first = alice
        .session
        .prepare_add(&host, slug, &kp_b, &bob.did())
        .unwrap();
    alice.session.abandon(&host, slug).unwrap();
    let kp_c = api.key_package(&alice.id, &carol.did()).await;
    let second = alice
        .session
        .prepare_add(&host, slug, &kp_c, &carol.did())
        .unwrap();
    let block = |c: &Commit, who: &Person| {
        build_with_metadata(
            &alice.id,
            BlockKind::MemberAdd,
            alice.hlc(),
            with(
                json!({"channel": slug, "member_did": who.did()}),
                mls_meta(c),
            ),
        )
    };
    let (s1, _) = api.submit(&block(&first, &bob)).await;
    let (s2, body) = api.submit(&block(&second, &carol)).await;
    assert_eq!(s1, 200);
    assert_eq!(
        (s2, body["code"].as_str()),
        (409, Some("STALE_EPOCH")),
        "{body}"
    );
    let (status, members) = api
        .get(
            &alice.id,
            &format!("/api/v1/channels/{}/members", enc(slug)),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        members["members"].as_array().unwrap().len(),
        2,
        "owner + bob only"
    );
}

#[tokio::test]
async fn a_member_away_for_more_than_a_page_catches_up_by_paging_back() {
    const PAGE: usize = 100;
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let api = Api { server: &server };
    let root = tempfile::tempdir().unwrap();
    let alice = Person::new(root.path());
    let bob = Person::new(root.path());
    let carol = Person::new(root.path());
    let slug = "#away";
    let host = server.http_url();
    for p in [&bob, &carol] {
        api.publish_key_packages(p).await;
    }
    create_encrypted(&api, &alice, slug, "restricted").await;
    add(&api, &alice, slug, &bob).await;
    catch_up(&api, &bob, slug).await;
    let bobs_epoch = bob.session.epoch(&host, slug).unwrap();
    assert!(bobs_epoch.is_some(), "bob joined");

    // While bob is away, carol is added — a commit bob must follow — and then
    // more than a page of messages pushes that commit out of the newest page.
    add(&api, &alice, slug, &carol).await;
    for i in 0..PAGE + 5 {
        say(&api, &alice, slug, &format!("m{i}")).await;
    }
    let opened =
        |blocks: &[DeliveredBlock]| -> Vec<_> { blocks.iter().map(|b| open(b).unwrap()).collect() };

    let (_, newest) = api.history_page(&bob.id, slug, PAGE, None).await;
    assert!(
        !history_reaches(&opened(&newest), bobs_epoch, &bob.did()),
        "the newest page alone misses the commit that added carol"
    );

    let before = open(&newest[0]).unwrap().cid;
    let (_, mut history) = api.history_page(&bob.id, slug, 200, Some(&before)).await;
    history.extend(newest);
    let history = opened(&history);
    assert!(history_reaches(&history, bobs_epoch, &bob.did()));

    let seen: Vec<Seen> = replay_order(history)
        .iter()
        .map(|o| bob.session.observe(&host, o))
        .collect();
    let read = texts(&seen);
    assert_eq!(read.len(), PAGE + 5, "every message decrypts");
    assert_eq!(read.last().map(String::as_str), Some("m104"));
}

#[tokio::test]
async fn a_commit_stamped_by_a_slow_clock_is_still_found() {
    const PAGE: usize = 100;
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let api = Api { server: &server };
    let root = tempfile::tempdir().unwrap();
    let alice = Person::new(root.path());
    let bob = Person::new(root.path());
    let carol = Person::new(root.path());
    let slug = "#skew";
    let host = server.http_url();
    for p in [&bob, &carol] {
        api.publish_key_packages(p).await;
    }
    create_encrypted(&api, &alice, slug, "restricted").await;
    add(&api, &alice, slug, &bob).await;
    catch_up(&api, &bob, slug).await;
    let bobs_epoch = bob.session.epoch(&host, slug).unwrap();

    // A page of messages in bob's epoch, then carol's addition from a clock an
    // hour slow — so it sorts behind all of them — then a few messages after.
    for i in 0..PAGE {
        say(&api, &alice, slug, &format!("before {i}")).await;
    }
    let kp = api.key_package(&alice.id, &carol.did()).await;
    let c = alice
        .session
        .prepare_add(&host, slug, &kp, &carol.did())
        .unwrap();
    let mut slow = alice.hlc();
    slow.wall_ms -= 3_600_000;
    let block = build_with_metadata(
        &alice.id,
        BlockKind::MemberAdd,
        slow,
        with(
            json!({"channel": slug, "member_did": carol.did()}),
            mls_meta(&c),
        ),
    );
    let (status, body) = api.submit(&block).await;
    assert_eq!(status, 200, "{body}");
    alice.session.confirm(&host, slug).unwrap();
    for i in 0..5 {
        say(&api, &alice, slug, &format!("after {i}")).await;
    }

    // History is in the order the server sequenced blocks (JEP-0002 rule 9),
    // not the order their authors' clocks claim: the slow commit sits where it
    // arrived, after the page before it, so the newest page already holds it
    // and the five messages that followed it.
    let opened =
        |blocks: &[DeliveredBlock]| -> Vec<_> { blocks.iter().map(|b| open(b).unwrap()).collect() };
    let (_, newest) = api.history_page(&bob.id, slug, PAGE, None).await;
    let history = opened(&newest);
    assert!(history_reaches(&history, bobs_epoch, &bob.did()));
    let seen: Vec<Seen> = replay_order(history)
        .iter()
        .map(|o| bob.session.observe(&host, o))
        .collect();
    assert_eq!(
        texts(&seen).last().map(String::as_str),
        Some("after 4"),
        "bob follows the slow commit and reads what came after it"
    );
}

/// Anyone can derive a pair's DM slug. If anyone could also create it,
/// Mallory could open Alice and Bob's DM first, add them both, and read it.
/// Only one of the pair may create it (and `jig dm` separately refuses a DM
/// with anyone else in its MLS tree).
#[tokio::test]
async fn only_the_pair_can_open_their_dm() {
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let api = Api { server: &server };
    let root = tempfile::tempdir().unwrap();
    let alice = Person::new(root.path());
    let bob = Person::new(root.path());
    let mallory = Person::new(root.path());
    let slug = jig_core::dm::dm_slug(&alice.did(), &bob.did());
    let dm = |peer: &Person| json!({"visibility": "restricted", "dm": true, "dm_peer": peer.did()});

    for peer in [&alice, &bob] {
        let (status, body) = try_create(&api, &mallory, &slug, dm(peer)).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.to_string().contains("direct-message"), "{body}");
    }
    // Nor plaintext, naming nobody: the client refuses an unencrypted DM, so
    // that squat alone would keep the pair from ever DMing here.
    let plain = json!({"visibility": "restricted", "suite": "none"});
    let (status, body) = try_create(&api, &mallory, &slug, plain).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.to_string().contains("dm_peer"), "{body}");

    let (status, body) = try_create(&api, &alice, &slug, dm(&bob)).await;
    assert_eq!(status, 200, "{body}");
}

fn submission(block: &BuiltBlock) -> Value {
    json!({
        "bundle_b64": STANDARD.encode(block.canonical_bytes()),
        "sig_b64": STANDARD.encode(&block.sender_sig),
    })
}

/// D25: a restricted channel is always `mls`. However a plaintext restricted
/// channel is asked for, through either door, the server refuses it and keeps
/// nothing; an open channel may still be plaintext.
#[tokio::test]
async fn a_restricted_channel_cannot_be_plaintext() {
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let api = Api { server: &server };
    let root = tempfile::tempdir().unwrap();
    let alice = Person::new(root.path());

    let asks = [
        json!({"slug": "#quiet", "visibility": "restricted"}),
        json!({"slug": "#quiet", "visibility": "restricted", "suite": "none"}),
        json!({"slug": "#quiet", "visibility": "members-only"}),
    ];
    for meta in asks {
        let block = build_with_metadata(
            &alice.id,
            BlockKind::ChannelCreate,
            alice.hlc(),
            meta.clone(),
        );
        for path in ["/api/v1/channels", "/api/v1/blocks"] {
            let (status, body) = api.post(path, &submission(&block)).await;
            assert_eq!(
                (status, body["code"].as_str()),
                (400, Some("RESTRICTED_REQUIRES_MLS")),
                "{path} {meta}: {body}"
            );
        }
    }
    let (status, listed) = api.get(&alice.id, "/api/v1/channels").await;
    assert_eq!(status, 200, "{listed}");
    assert!(
        !listed.to_string().contains("#quiet"),
        "a refused create left a channel behind: {listed}"
    );

    // The same slug, restricted and `mls`, is fine.
    create_encrypted(&api, &alice, "#quiet", "restricted").await;
    // And plaintext is what open channels are for.
    let open = build_with_metadata(
        &alice.id,
        BlockKind::ChannelCreate,
        alice.hlc(),
        json!({"slug": "#lobby", "visibility": "open", "tier": "public"}),
    );
    let (status, body) = api.post("/api/v1/channels", &submission(&open)).await;
    assert_eq!(status, 200, "{body}");
}

/// A restricted channel created plaintext before D25 cannot become `mls`, so
/// it is frozen: its members still read its history, and it takes nothing new.
#[tokio::test]
async fn a_plaintext_restricted_channel_from_before_d25_is_frozen() {
    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let api = Api { server: &server };
    let root = tempfile::tempdir().unwrap();
    let alice = Person::new(root.path());
    let slug = "#legacy";
    server
        .seed_plaintext_restricted_channel(&alice.id, slug)
        .unwrap();

    let post = jig_client::blocks::build_text_render(&alice.id, slug, "still here?", alice.hlc());
    let (status, body) = api.submit(&post).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (409, Some("CHANNEL_FROZEN")),
        "{body}"
    );
    let (status, blocks) = api.history(&alice.id, slug).await;
    assert_eq!(status, 200, "members still read a frozen channel");
    assert!(blocks.is_empty(), "the refused post was stored: {blocks:?}");
}

/// OP-03 for a device that holds no group for a channel: the server can
/// relabel the channel in its own store, but not the block its owner signed.
/// The listing names the creation block; that block, served with its
/// signature, still proves `mls`.
#[tokio::test]
async fn a_relabelled_channel_is_still_what_its_owner_signed() {
    use jig_client::pins::prove_channel;

    let server = TestJigServer::start_with_full_kinds().await.unwrap();
    let api = Api { server: &server };
    let root = tempfile::tempdir().unwrap();
    let alice = Person::new(root.path());
    let carol = Person::new(root.path());
    create_encrypted(&api, &alice, "#town", "open").await;

    // The operator rewrites its own row.
    rusqlite::Connection::open(server.data_dir().join("server.db"))
        .unwrap()
        .execute(
            "UPDATE channels SET suite = 'none' WHERE slug = '#town'",
            [],
        )
        .unwrap();

    let (status, listing) = api.get(&carol.id, "/api/v1/channels").await;
    assert_eq!(status, 200, "{listing}");
    let town = listing["channels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["slug"] == "#town")
        .unwrap()
        .clone();
    assert_eq!(
        town["suite"], "none",
        "the listing says what the server says"
    );

    let id = town["id"].as_str().unwrap();
    let (status, block) = api.get(&carol.id, &format!("/api/v1/blocks/{id}")).await;
    assert_eq!(status, 200, "{block}");
    let proven = prove_channel(
        "#town",
        id,
        block["bundle_b64"].as_str().unwrap(),
        block["sig_b64"].as_str().unwrap(),
    )
    .unwrap();
    assert!(proven.encrypted(), "the owner created #town `mls`");
    assert_eq!(proven.owner_did, alice.did());
}
