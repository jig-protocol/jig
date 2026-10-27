//! An encrypted channel's history is read once, in order, however far a
//! device falls behind.
//!
//! MLS lets a sender's messages be decrypted only a few generations out of
//! order (openmls keeps 5 behind the newest one read). A device that caught
//! up by reading just the newest page of history could never decrypt the
//! messages before it. This runs the real `jig` binary as the device, against
//! a real server, with an owner posting in-process.
//!
//! `HOME` points at a tempdir, so the pin store and MLS state are this test's.

use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use integration_tests::harness::{TestJigServer, load_identity, test_identity_with_dir};
use jig_client::Identity;
use jig_client::blocks::{BuiltBlock, build_sealed_text, build_with_metadata};
use jig_client::read_auth::{ReadProof, signable_path};
use jig_client::secure::Session;
use jig_core::{BlockKind, HlcTimestamp};
use serde_json::{Value, json};

/// More than two pages of the newest-page catch-up this replaces (100), and
/// past what a 200-block page holds.
const AWAY: usize = 250;

fn jig(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_jig"));
    cmd.env("HOME", home)
        // Never the developer's real keychain; seal test keys with a fixed secret.
        .env("JIG_KEYCHAIN", "none")
        .env("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")
        .env(
            "JIG_TEST_KEY_SECRET",
            "jig cli tests: a fixed, public secret",
        )
        .env("JIG_NONINTERACTIVE", "1")
        .env("RUST_BACKTRACE", "0");
    cmd
}

/// A member who posts in-process, through its own MLS session, the way
/// `jig` does: a fresh `jig send` per message replays the channel's history
/// first, which makes a burst of them take minutes.
struct Member {
    id: Identity,
    session: Session,
    _home: tempfile::TempDir,
}

impl Member {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let (id, keys) = test_identity_with_dir();
        let session = Session::open(home.path(), load_identity(&keys, &id.did_string())).unwrap();
        Self {
            id,
            session,
            _home: home,
        }
    }

    fn hlc(&self) -> HlcTimestamp {
        HlcTimestamp::now_wall(self.id.did().clone())
    }
}

async fn post(server: &TestJigServer, path: &str, block: &BuiltBlock) {
    let resp = reqwest::Client::new()
        .post(format!("{}{path}", server.http_url()))
        .json(&json!({
            "bundle_b64": STANDARD.encode(block.canonical_bytes()),
            "sig_b64": STANDARD.encode(&block.sender_sig),
        }))
        .send()
        .await
        .expect("POST");
    let status = resp.status();
    assert!(
        status.is_success(),
        "{path}: {status} {}",
        resp.text().await.unwrap_or_default()
    );
}

/// `owner` adds `did` to `slug`: an MLS commit, posted as a member-add.
async fn add(server: &TestJigServer, owner: &Member, slug: &str, did: &str) {
    let url = format!("{}/api/v1/mls/key-packages/{did}", server.http_url());
    let proof = ReadProof::sign(&owner.id, "GET", signable_path(&url));
    let mut req = reqwest::Client::new().get(&url);
    for (name, value) in proof.headers() {
        req = req.header(name, value);
    }
    let body: Value = req.send().await.unwrap().json().await.unwrap();
    let kp = STANDARD
        .decode(body["key_package_b64"].as_str().expect("a key package"))
        .unwrap();
    let base = server.http_url();
    let c = owner.session.prepare_add(&base, slug, &kp, did).unwrap();
    let mut meta = json!({
        "channel": slug,
        "member_did": did,
        "mls_commit": STANDARD.encode(&c.commit),
        "mls_epoch": c.epoch,
    });
    if let Some(w) = &c.welcome {
        meta["mls_welcome"] = STANDARD.encode(w).into();
    }
    if let Some(i) = &c.group_info {
        meta["mls_group_info"] = STANDARD.encode(i).into();
    }
    let block = build_with_metadata(&owner.id, BlockKind::MemberAdd, owner.hlc(), meta);
    post(server, "/api/v1/blocks", &block).await;
    owner.session.confirm(&base, slug).unwrap();
}

async fn say(server: &TestJigServer, m: &Member, slug: &str, text: &str) {
    let (msg, epoch) = m.session.encrypt(&server.http_url(), slug, text).unwrap();
    let block = build_sealed_text(&m.id, slug, &msg, epoch, m.hlc());
    post(server, "/api/v1/blocks", &block).await;
}

/// `jig read` as the device, and its output.
fn read(home: &Path, limit: usize) -> String {
    let out = jig(home)
        .args(["read", "#sec", "--limit", &limit.to_string()])
        .output()
        .unwrap();
    assert!(out.status.success(), "jig read: {out:?}");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_away_for_more_than_a_page_reads_every_message() {
    let server = TestJigServer::start().await.expect("start");
    let owner = Member::new();

    let device = tempfile::tempdir().unwrap();
    let out = jig(device.path()).args(["init", "me"]).output().unwrap();
    assert!(out.status.success(), "jig init: {out:?}");
    let out = jig(device.path())
        .args(["server", "set", &server.http_url()])
        .output()
        .unwrap();
    assert!(out.status.success(), "jig server set: {out:?}");
    let cfg: toml::Table = toml::from_str(
        &std::fs::read_to_string(device.path().join(".jig").join("cli.toml")).unwrap(),
    )
    .unwrap();
    let did = cfg["user"]["did"].as_str().unwrap().to_string();

    let created = owner
        .session
        .create_group(&server.http_url(), "#sec")
        .unwrap();
    let create = build_with_metadata(
        &owner.id,
        BlockKind::ChannelCreate,
        owner.hlc(),
        json!({"slug": "#sec", "suite": "mls", "visibility": "open",
               "mls_group_info": STANDARD.encode(&created.group_info),
               "mls_ratchet_tree": STANDARD.encode(&created.ratchet_tree)}),
    );
    post(&server, "/api/v1/channels", &create).await;
    add(&server, &owner, "#sec", &did).await;
    say(&server, &owner, "#sec", "before").await;

    // The device joins and reads what there is.
    assert!(read(device.path(), 10).contains("before"));

    // It is away while the owner says more than a page's worth, with no
    // commit among it: nothing makes it page back to its epoch.
    for i in 0..AWAY {
        say(&server, &owner, "#sec", &format!("away-{i:04}")).await;
    }

    // Back: the next read catches up, and scrolling back shows every message.
    let shown = read(device.path(), AWAY + 10);
    let missing: Vec<String> = (0..AWAY)
        .map(|i| format!("away-{i:04}"))
        .filter(|m| !shown.contains(m.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "{} of {AWAY} messages unreadable, from {:?}; output:\n{}",
        missing.len(),
        missing.first(),
        shown.lines().take(5).collect::<Vec<_>>().join("\n")
    );
    assert!(!shown.contains("cannot decrypt"), "{shown}");
}
