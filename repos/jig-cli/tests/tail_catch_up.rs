//! `jig tail` that falls behind a busy channel catches up by itself.
//!
//! Runs the real `jig` binary against a real server, and stops reading its
//! stdout while a burst is posted. The pipe fills, the tail blocks on its
//! next line, the client's subscription queue fills behind it, and the
//! stream ends lagged. Once stdout is read again, every message of the burst
//! must be there exactly once, and the tail must still be live.
//!
//! `HOME` points at a tempdir, so the pin store is this test's own.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use integration_tests::harness::{
    TestJigServer, load_identity, test_identity, test_identity_with_dir,
};
use jig_client::Identity;
use jig_client::blocks::{BuiltBlock, build_sealed_text, build_with_metadata};
use jig_client::read_auth::{ReadProof, signable_path};
use jig_client::secure::Session;
use jig_core::{BlockKind, HlcTimestamp};
use serde_json::{Value, json};

/// More than a full pipe of lines (64 KiB at about 1 KiB a line) plus a
/// full subscription queue (`SUBSCRIPTION_QUEUE`, 64), with room to spare.
const BURST: usize = 300;

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

/// Lines from `out`, read on a thread so the test can wait with a timeout.
fn lines<R: BufRead + Send + 'static>(out: R) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in out.lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// Read `out` up to the line starting with `prefix`, then hand it back
/// unread past that, so the pipe behind it can fill.
fn read_until<R: BufRead + Send + 'static>(mut out: R, prefix: &'static str) -> R {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            if out.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if line.starts_with(prefix) {
                let _ = tx.send(out);
                return;
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(60))
        .unwrap_or_else(|_| panic!("no line starting {prefix:?}"))
}

/// How long a tail may go with no line shown and no sign of work before the
/// test calls it stalled.
const STALL: Duration = Duration::from_secs(60);

/// The most a whole catch-up may take, however busy the tail stays: a tail
/// that spins forever shows work and nothing else.
const CATCH_UP: Duration = Duration::from_secs(600);

/// The tail's next line. The catch-up shows nothing while it works, and
/// under a loaded test run it can take longer than any fixed wait, so this
/// waits as long as `progress` (a count that grows while the tail works)
/// keeps changing. `None` once neither a line nor progress has come for
/// [`STALL`], once `started` is [`CATCH_UP`] ago, or when the tail is gone.
fn next_line(
    stdout: &mpsc::Receiver<String>,
    started: Instant,
    progress: impl Fn() -> u64,
) -> Option<String> {
    let mut seen = progress();
    let mut since = Instant::now();
    loop {
        match stdout.recv_timeout(Duration::from_secs(1)) {
            Ok(line) => return Some(line),
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let now = progress();
                if started.elapsed() > CATCH_UP {
                    return None;
                }
                if now != seen {
                    seen = now;
                    since = Instant::now();
                } else if since.elapsed() > STALL {
                    return None;
                }
            }
        }
    }
}

/// CPU time `pid` has used, in clock ticks: it grows while the process
/// works, and stops when it blocks or hangs. 0 where `/proc` is missing,
/// so the wait falls back to [`STALL`] from the last line.
fn cpu_ticks(pid: u32) -> u64 {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0;
    };
    // utime and stime, the 14th and 15th fields: the 12th and 13th after
    // the command name, which is in parentheses and may hold spaces.
    let fields: Vec<&str> = stat
        .rsplit_once(')')
        .map_or("", |(_, rest)| rest)
        .split_whitespace()
        .collect();
    let at = |i: usize| {
        fields
            .get(i)
            .and_then(|f| f.parse::<u64>().ok())
            .unwrap_or(0)
    };
    at(11) + at(12)
}

/// The reader's plaintext store (`jig_client::secure`): one sealed record
/// per message it has decrypted.
fn plaintext_store(home: &Path, did: &str) -> PathBuf {
    home.join(".jig")
        .join("mls")
        .join(did)
        .join("plaintext.jsonl")
}

/// The burst message a line shows, if it shows one.
fn message(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|w| w.starts_with("burst-") || *w == "after")
        .map(str::to_string)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tail_that_falls_behind_catches_up_with_nothing_missed_or_repeated() {
    let server = TestJigServer::start().await.expect("start");
    let owner = test_identity();
    server
        .create_channel(&owner, "#busy", "open")
        .await
        .expect("create");

    let home = tempfile::tempdir().unwrap();
    let out = jig(home.path()).args(["init", "me"]).output().unwrap();
    assert!(out.status.success(), "jig init: {out:?}");
    let path = home.path().join(".jig").join("cli.toml");
    let mut cfg: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    cfg["server"]["base_url"] = toml::Value::String(server.http_url());
    std::fs::write(&path, toml::to_string(&cfg).unwrap()).unwrap();

    let mut tail = jig(home.path())
        .args(["tail", "#busy"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = lines(BufReader::new(tail.stderr.take().unwrap()));
    let stdout = read_until(BufReader::new(tail.stdout.take().unwrap()), "Tailing #busy");

    // Nothing reads stdout now. The burst fills the pipe, the tail blocks
    // writing, and its subscription queue fills behind it.
    let pad = "x".repeat(1000);
    for i in 0..BURST {
        server
            .send_text_render(&owner, "#busy", &format!("burst-{i:04} {pad}"))
            .await
            .expect("send");
    }
    // Let the server's deliveries reach the client and overflow its queue.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Read again, until the last of the burst, then post once more: the tail
    // must still be live after catching up.
    let stdout = lines(stdout);
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let last = format!("burst-{:04}", BURST - 1);
    let mut posted_after = false;
    let pid = tail.id();
    let started = Instant::now();
    loop {
        let line = next_line(&stdout, started, || cpu_ticks(pid)).unwrap_or_else(|| {
            panic!(
                "stalled: nothing shown and no work done for {STALL:?}; shown so far: {}",
                seen.len()
            )
        });
        let Some(m) = message(&line) else { continue };
        *seen.entry(m.clone()).or_default() += 1;
        if m == last && !posted_after {
            posted_after = true;
            server
                .send_text_render(&owner, "#busy", "after")
                .await
                .expect("send");
        }
        if m == "after" {
            break;
        }
    }
    // Give a late duplicate the chance to show.
    while let Ok(line) = stdout.recv_timeout(Duration::from_secs(2)) {
        if let Some(m) = message(&line) {
            *seen.entry(m).or_default() += 1;
        }
    }
    tail.kill().unwrap();
    let _ = tail.wait();
    let errors: Vec<String> = stderr.try_iter().collect();

    let missing: Vec<String> = (0..BURST)
        .map(|i| format!("burst-{i:04}"))
        .filter(|m| !seen.contains_key(m))
        .collect();
    let repeated: Vec<(&String, &usize)> = seen.iter().filter(|(_, n)| **n > 1).collect();
    assert!(
        missing.is_empty(),
        "missing {missing:?}; stderr: {errors:?}"
    );
    assert!(repeated.is_empty(), "shown twice {repeated:?}");
    assert_eq!(seen.get("after"), Some(&1), "live after catching up");
    assert!(
        errors.iter().any(|e| e.contains("caught up")),
        "the burst must actually have overflowed the queue, or this test \
         proves nothing; stderr: {errors:?}"
    );
}
/// The encrypted burst, and the message the member-add goes before. 16 KiB
/// lines fill the pipe in about four, so the stream lags about 70 messages
/// in, well before the add.
const ENCRYPTED_BURST: usize = 110;
const ADD_BEFORE: usize = 85;
const ENCRYPTED_PAD: usize = 16 * 1024;

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

async fn publish_key_packages(server: &TestJigServer, m: &Member) {
    let mut kps = m.session.key_packages(3, false).unwrap();
    kps.extend(m.session.key_packages(1, true).unwrap());
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/mls/key-packages", server.http_url()))
        .json(&json!({"key_packages_b64": kps.iter().map(|k| STANDARD.encode(k)).collect::<Vec<_>>()}))
        .send()
        .await
        .expect("POST key packages");
    assert!(resp.status().is_success());
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

/// The same burst on an encrypted channel, with a member added (an MLS
/// commit) in the part the tail never read live. Every message after the
/// commit is in the new epoch, so it decrypts only if the catch-up applied
/// the commit first.
#[tokio::test(flavor = "multi_thread")]
async fn an_encrypted_tail_that_falls_behind_catches_up_across_a_commit() {
    let server = TestJigServer::start().await.expect("start");
    let owner = Member::new();
    let late = Member::new();
    publish_key_packages(&server, &late).await;

    // The reader is `jig` itself; `jig server set` publishes its key packages.
    let reader = tempfile::tempdir().unwrap();
    let out = jig(reader.path()).args(["init", "me"]).output().unwrap();
    assert!(out.status.success(), "jig init: {out:?}");
    let out = jig(reader.path())
        .args(["server", "set", &server.http_url()])
        .output()
        .unwrap();
    assert!(out.status.success(), "jig server set: {out:?}");
    let cfg: toml::Table = toml::from_str(
        &std::fs::read_to_string(reader.path().join(".jig").join("cli.toml")).unwrap(),
    )
    .unwrap();
    let reader_did = cfg["user"]["did"].as_str().unwrap().to_string();

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
    add(&server, &owner, "#sec", &reader_did).await;

    let mut tail = jig(reader.path())
        .args(["tail", "#sec"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = lines(BufReader::new(tail.stderr.take().unwrap()));
    let stdout = read_until(BufReader::new(tail.stdout.take().unwrap()), "Tailing #sec");

    // Nothing reads stdout now. Past the pipe and the subscription queue,
    // the owner adds a member, then carries on.
    let pad = "x".repeat(ENCRYPTED_PAD);
    for i in 0..ENCRYPTED_BURST {
        if i == ADD_BEFORE {
            add(&server, &owner, "#sec", &late.id.did_string()).await;
        }
        say(&server, &owner, "#sec", &format!("burst-{i:04} {pad}")).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    let stdout = lines(stdout);
    let store = plaintext_store(reader.path(), &reader_did);
    let pid = tail.id();
    let started = Instant::now();
    let mut shown: Vec<String> = Vec::new();
    let last = format!("burst-{:04}", ENCRYPTED_BURST - 1);
    loop {
        // Work is a decrypted message recorded, or CPU time spent.
        let line = next_line(&stdout, started, || {
            std::fs::metadata(&store).map_or(0, |m| m.len()) + cpu_ticks(pid)
        })
        .unwrap_or_else(|| {
            panic!("stalled: nothing shown or read for {STALL:?}; shown so far: {shown:?}")
        });
        if line.contains(" was added") {
            shown.push("added".to_string());
            continue;
        }
        let Some(m) = message(&line) else { continue };
        let done = m == last;
        shown.push(m);
        if done {
            break;
        }
    }
    while let Ok(line) = stdout.recv_timeout(Duration::from_secs(2)) {
        if let Some(m) = message(&line) {
            shown.push(m);
        }
    }
    tail.kill().unwrap();
    let _ = tail.wait();
    let errors: Vec<String> = stderr.try_iter().collect();

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for m in &shown {
        *counts.entry(m).or_default() += 1;
    }
    let missing: Vec<String> = (0..ENCRYPTED_BURST)
        .map(|i| format!("burst-{i:04}"))
        .filter(|m| !counts.contains_key(m.as_str()))
        .collect();
    let repeated: Vec<_> = counts.iter().filter(|(_, n)| **n > 1).collect();
    assert!(
        missing.is_empty(),
        "missing {missing:?}; stderr: {errors:?}"
    );
    assert!(repeated.is_empty(), "shown twice {repeated:?}");
    // The commit was applied in its place: after the last message of the
    // old epoch, before the first of the new.
    let at = |m: &str| shown.iter().position(|s| s == m).unwrap();
    let added = at("added");
    assert!(
        at(&format!("burst-{:04}", ADD_BEFORE - 1)) < added
            && added < at(&format!("burst-{ADD_BEFORE:04}")),
        "the member-add is out of place: {shown:?}"
    );
    // And the catch-up took it from history: what was caught up reaches back
    // past the member-add (the catch-up runs once the burst is over, so it
    // covers everything from the first block dropped to the end).
    let caught_up: usize = errors
        .iter()
        // Each line shown rings a bell on stderr, ahead of this one.
        .filter_map(|e| e.split("[fell behind; caught up ").nth(1))
        .filter_map(|e| e.split(' ').next()?.parse::<usize>().ok())
        .sum();
    assert!(
        caught_up > ENCRYPTED_BURST - ADD_BEFORE,
        "the member-add was read live, not caught up ({caught_up} blocks); stderr: {errors:?}"
    );
}
