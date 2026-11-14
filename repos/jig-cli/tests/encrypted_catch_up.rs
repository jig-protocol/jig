//! An encrypted channel's history is read once, in order, however far a
//! device falls behind.
//!
//! MLS lets a sender's messages be decrypted only a few generations out of
//! order (openmls keeps 5 behind the newest one read). A device that caught
//! up by reading just the newest page of history could never decrypt the
//! messages before it. This runs the real `jig` binary as the device, against
//! a real server, with an owner posting in-process.
//!
//! It runs three ways: against a server that pages history forward
//! (`after=`) and says so; through a proxy that drops `after` and hides that
//! it can, as a server from before it does; and through one that says it can
//! but drops `after`, as a broken or lying server might.
//!
//! `HOME` points at a tempdir, so the pin store and MLS state are this test's.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
        .header("jig-capabilities", "tiers")
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

/// How [`proxy`] stands in for a server.
#[derive(Clone, Copy, PartialEq)]
enum Serves {
    /// Passes everything through: a server that pages forward.
    Forward,
    /// Drops `after=` and the `history_after` advertisement: a server from
    /// before `after`.
    Old,
    /// Drops `after=` but keeps the advertisement: it says it pages forward
    /// and sends the newest page instead.
    Lying,
    /// Pages forward, but leaves a block out of the middle of the first
    /// forward page: a hole the device must not keep.
    Skipping,
}

/// A proxy in front of `server`, serving as `serves` says, that counts the
/// requests paging history forward (`after` without `before`). Read proofs
/// sign the path, not the query, so dropping a parameter breaks nothing
/// else.
///
/// It works on the bytes: each request head is read and its target
/// rewritten, responses are copied back (with the advertisement renamed,
/// keeping its length, for [`Serves::Old`]), and a WebSocket upgrade (the
/// client's handshake) is passed through untouched from then on.
async fn proxy(server: &TestJigServer, serves: Serves) -> (String, Arc<AtomicUsize>) {
    let upstream = server.http_url().trim_start_matches("http://").to_string();
    let forward_pages = Arc::new(AtomicUsize::new(0));
    let counted = forward_pages.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let (upstream, counted) = (upstream.clone(), counted.clone());
            tokio::spawn(async move {
                let _ = relay(client, &upstream, serves, &counted).await;
            });
        }
    });
    (url, forward_pages)
}

/// One client connection through [`proxy`].
async fn relay(
    client: tokio::net::TcpStream,
    upstream: &str,
    serves: Serves,
    counted: &AtomicUsize,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let up = tokio::net::TcpStream::connect(upstream).await?;
    let (mut from_client, to_client) = client.into_split();
    let (mut from_up, mut to_up) = up.into_split();
    let to_client = Arc::new(tokio::sync::Mutex::new(to_client));
    let responses = to_client.clone();
    tokio::spawn(async move {
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let n = from_up.read(&mut chunk).await?;
            if n == 0 {
                return Ok::<_, std::io::Error>(());
            }
            let mut out = chunk[..n].to_vec();
            if serves == Serves::Old {
                const FROM: &[u8] = b"\"history_after\":true";
                const TO: &[u8] = b"\"history_gone_\":true";
                while let Some(at) = out.windows(FROM.len()).position(|w| w == FROM) {
                    out[at..at + FROM.len()].copy_from_slice(TO);
                }
            }
            responses.lock().await.write_all(&out).await?;
        }
    });
    let ignore_after = matches!(serves, Serves::Old | Serves::Lying);
    let mut skipped = false;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let n = from_client.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let lower = head.to_ascii_lowercase();
        let body_len = lower
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while buf.len() < head_end + body_len {
            let n = from_client.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let (line, rest) = head.split_once("\r\n").unwrap_or((&head, ""));
        let mut parts = line.splitn(3, ' ');
        let (method, target, version) = (
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
        );
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let params: Vec<&str> = query.split('&').filter(|p| !p.is_empty()).collect();
        let after = params.iter().any(|p| p.starts_with("after="));
        let before = params.iter().any(|p| p.starts_with("before="));
        if after && !before {
            counted.fetch_add(1, Ordering::SeqCst);
        }
        let kept: Vec<&str> = params
            .into_iter()
            .filter(|p| !(ignore_after && p.starts_with("after=")))
            .collect();
        let target = if kept.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{}", kept.join("&"))
        };
        if serves == Serves::Skipping && after && !before && !skipped {
            // Asked on a connection of its own, so the answer can be cut
            // before the client sees it.
            let request = format!("{method} {target} {version}\r\nconnection: close\r\n{rest}");
            let page = skip_one(
                upstream,
                request.as_bytes(),
                &buf[head_end..head_end + body_len],
            )
            .await?;
            skipped = page.1;
            to_client.lock().await.write_all(&page.0).await?;
            buf.drain(..head_end + body_len);
            continue;
        }
        to_up
            .write_all(format!("{method} {target} {version}\r\n{rest}").as_bytes())
            .await?;
        to_up.write_all(&buf[head_end..head_end + body_len]).await?;
        buf.drain(..head_end + body_len);
        if lower.contains("upgrade: websocket") {
            to_up.write_all(&buf).await?;
            tokio::io::copy(&mut from_client, &mut to_up).await?;
            return Ok(());
        }
    }
}

/// Sends `request` (a head with `connection: close`) and `body` upstream,
/// and returns the answer with the middle entry of its JSON array left out,
/// and whether one was: the page a server that skips a block would send.
async fn skip_one(upstream: &str, request: &[u8], body: &[u8]) -> std::io::Result<(Vec<u8>, bool)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut up = tokio::net::TcpStream::connect(upstream).await?;
    up.write_all(request).await?;
    up.write_all(body).await?;
    let mut answer = Vec::new();
    up.read_to_end(&mut answer).await?;
    let Some(split) = answer.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok((answer, false));
    };
    let head = String::from_utf8_lossy(&answer[..split]).into_owned();
    let Ok(Value::Array(mut page)) = serde_json::from_slice::<Value>(&answer[split + 4..]) else {
        return Ok((answer, false));
    };
    if page.len() < 3 {
        return Ok((answer, false));
    }
    page.remove(page.len() / 2);
    let body = serde_json::to_vec(&page).unwrap();
    let head: Vec<String> = head
        .split("\r\n")
        .map(|l| {
            if l.to_ascii_lowercase().starts_with("content-length:") {
                format!("content-length: {}", body.len())
            } else {
                l.to_string()
            }
        })
        .collect();
    let mut out = format!("{}\r\n\r\n", head.join("\r\n")).into_bytes();
    out.extend_from_slice(&body);
    Ok((out, true))
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
    let forward_pages = away_and_back(Serves::Forward).await;
    assert!(
        forward_pages > 0,
        "the catch-up must page forward from the head on a server that can"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn on_a_server_without_after_the_device_pages_back_and_reads_every_message() {
    let forward_pages = away_and_back(Serves::Old).await;
    assert_eq!(
        forward_pages, 0,
        "a server that does not advertise `after` must be paged back, never forward"
    );
}

/// The advertisement is unsigned: a server that makes it and then sends the
/// newest page breaks the chain on the first page, and the device pages back
/// instead, missing nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_advertises_after_but_ignores_it_costs_time_not_messages() {
    let forward_pages = away_and_back(Serves::Lying).await;
    assert_eq!(
        forward_pages, 1,
        "one forward page, refused for breaking the chain, then back"
    );
}

/// A server that pages forward but leaves a block out of a page would leave
/// a hole in the device's history. The page's records skip one, so the
/// device refuses the page, reads back from its head instead, and misses
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_forward_page_that_skips_a_block_is_refused_and_the_block_is_still_read() {
    let forward_pages = away_and_back(Serves::Skipping).await;
    assert_eq!(
        forward_pages, 1,
        "one forward page, refused for its gap, then back"
    );
}

/// The device joins, reads, is away for [`AWAY`] messages, and reads again:
/// every message must show, and none fail to decrypt. Returns how many
/// history requests paged forward.
async fn away_and_back(serves: Serves) -> usize {
    let server = TestJigServer::start().await.expect("start");
    let (url, forward_pages) = proxy(&server, serves).await;
    let owner = Member::new();

    let device = tempfile::tempdir().unwrap();
    let out = jig(device.path()).args(["init", "me"]).output().unwrap();
    assert!(out.status.success(), "jig init: {out:?}");
    let out = jig(device.path())
        .args(["server", "set", &url])
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
               "sequencer": server.server_did_string,
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
    forward_pages.load(Ordering::SeqCst)
}
