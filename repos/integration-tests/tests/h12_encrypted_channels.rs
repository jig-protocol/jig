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
use jig_client::secure::{Seen, Session};
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
    let server = api.server.http_url();
    let created = owner.session.create_group(&server, slug).unwrap();
    let block = build_with_metadata(
        &owner.id,
        BlockKind::ChannelCreate,
        owner.hlc(),
        json!({"slug": slug, "visibility": visibility, "suite": "mls",
               "mls_group_info": STANDARD.encode(&created.group_info),
               "mls_ratchet_tree": STANDARD.encode(&created.ratchet_tree)}),
    );
    let (status, body) = api
        .post(
            "/api/v1/channels",
            &json!({
                "bundle_b64": STANDARD.encode(block.canonical_bytes()),
                "sig_b64": STANDARD.encode(&block.sender_sig),
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
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
    jig_server::v0_0_2_federation::complete_client_handshake(&mut ws)
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
        } = env.frame
        {
            break DeliveredBlock {
                bundle_b64,
                sig_b64,
                receipts,
                delivery_cid,
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
