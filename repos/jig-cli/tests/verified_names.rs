//! `alias@suffix` names in `jig dm` and `jig channel add` (F1 slice 6b).
//!
//! Runs the real `jig` binary against a stub nameserver that signs with a
//! test key `cli.toml` names as the `@jig` authority, and a stub server that
//! only counts connections. A name is verified and pinned before anything
//! is sent; a name whose DID changed is refused before the server is
//! contacted at all.
//!
//! Every invocation points `HOME` at a tempdir, so the pin store and the
//! evidence directory are this test's own.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use jig_core::naming::Attestation;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DAY: i64 = 86_400;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn did_of(key: &SigningKey) -> String {
    jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
}

/// A nameserver that attests `dj@jig` to whatever DID `attested` holds now,
/// signed by `ns`.
async fn stub_nameserver(ns: SigningKey, attested: Arc<Mutex<String>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let (ns, attested) = (ns.clone(), attested.clone());
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                let (status, body) = if path == "/v1/resolve/dj@jig" {
                    let now = chrono::Utc::now().timestamp();
                    let did = attested.lock().unwrap().clone();
                    let att = Attestation::sign(&ns, &did, "dj@jig", now - 1, now + 30 * DAY);
                    let body = serde_json::json!({
                        "attestation": URL_SAFE_NO_PAD.encode(&att.envelope),
                        "links": [],
                        "reachability": null,
                    });
                    (200, body.to_string())
                } else {
                    (404, r#"{"code":"NOT_FOUND","message":"no"}"#.to_string())
                };
                let resp = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    base
}

/// Every request line a [`recording_server`] received.
type Requests = Arc<Mutex<Vec<String>>>;

/// A "server" that records each request line and answers 404, as one that
/// predates admission would.
async fn recording_server() -> (String, Requests) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Requests = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                if let Some(line) = head.lines().next().filter(|l| !l.is_empty()) {
                    log.lock().unwrap().push(line.to_string());
                }
                let _ = sock
                    .write_all(b"HTTP/1.1 404 X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    (base, seen)
}

/// What the server saw beyond the admission check every server command runs
/// first (`GET /.well-known/jig`), which carries nothing about the peer.
fn beyond_admission(seen: &Requests) -> Vec<String> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|l| !l.starts_with("GET /.well-known/jig "))
        .cloned()
        .collect()
}

/// `jig init` into `home`, then point it at `server` and delegate `@jig` to
/// `authority` at `nameserver`.
fn set_up(home: &Path, server: &str, authority: &str, nameserver: &str) {
    let (ok, out) = run(home, &["init", "me"]);
    assert!(ok, "jig init: {out}");
    let path = home.join(".jig").join("cli.toml");
    let cfg = std::fs::read_to_string(&path).unwrap();
    let mut cfg: toml::Table = toml::from_str(&cfg).unwrap();
    cfg["server"]["base_url"] = toml::Value::String(server.into());
    let mut jig = toml::Table::new();
    jig.insert("authorities".into(), vec![authority.to_string()].into());
    jig.insert("nameservers".into(), vec![nameserver.to_string()].into());
    let mut delegations = toml::Table::new();
    delegations.insert("jig".into(), jig.into());
    let mut naming = toml::Table::new();
    naming.insert("delegations".into(), delegations.into());
    cfg.insert("naming".into(), naming.into());
    std::fs::write(&path, toml::to_string(&cfg).unwrap()).unwrap();
}

fn run(home: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(args)
        .env("HOME", home)
        .env("JIG_NONINTERACTIVE", "1")
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// `jig dm` runs the blocking CLI; keep the stubs' runtime free while it does.
async fn run_async(home: &Path, args: &[&str]) -> (bool, String) {
    let home = home.to_path_buf();
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run(&home, &args)
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_name_is_pinned_a_pinned_one_is_used_and_a_changed_one_is_refused() {
    let ns = key(1);
    let dj = did_of(&key(2));
    let attested = Arc::new(Mutex::new(dj.clone()));
    let nameserver = stub_nameserver(ns.clone(), attested.clone()).await;
    let (server, seen) = recording_server().await;
    let home = tempfile::tempdir().unwrap();
    set_up(home.path(), &server, &did_of(&ns), &nameserver);

    // New: verified, pinned, and printed with who vouched. The DM itself
    // then fails against the stub server, which is fine: only the name is
    // under test.
    let (_, out) = run_async(home.path(), &["dm", "DJ@jig", "hi"]).await;
    assert!(
        out.contains(&format!("dj@jig is {dj} (vouched for by {})", did_of(&ns))),
        "{out}"
    );
    let pins = std::fs::read_to_string(home.path().join(".jig").join("pins.json")).unwrap();
    assert!(pins.contains(&dj), "the name is pinned: {pins}");

    // Pinned: the same DID resolves again.
    let (_, out) = run_async(home.path(), &["dm", "dj@jig", "hi"]).await;
    assert!(out.contains(&format!("dj@jig is {dj}")), "{out}");

    // Changed: refused before anything reaches the server.
    let other = did_of(&key(3));
    *attested.lock().unwrap() = other.clone();
    seen.lock().unwrap().clear();
    let (ok, out) = run_async(home.path(), &["dm", "dj@jig", "hi"]).await;
    assert!(!ok, "a changed DID is refused: {out}");
    assert!(out.contains("nothing was sent to dj@jig"), "{out}");
    assert!(
        out.contains(&format!("jig trust accept-name dj@jig {other}")),
        "says how to accept it: {out}"
    );
    assert_eq!(
        beyond_admission(&seen),
        Vec::<String>::new(),
        "nothing reached the server"
    );
    let (ok, out) = run_async(home.path(), &["channel", "add", "#general", "dj@jig"]).await;
    assert!(!ok, "channel add refuses it too: {out}");
    assert_eq!(beyond_admission(&seen), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_name_signed_by_anyone_but_the_authority_is_refused_and_not_pinned() {
    let impostor = key(9);
    let attested = Arc::new(Mutex::new(did_of(&key(2))));
    let nameserver = stub_nameserver(impostor, attested).await;
    let (server, seen) = recording_server().await;
    let home = tempfile::tempdir().unwrap();
    set_up(home.path(), &server, &did_of(&key(1)), &nameserver);

    let (ok, out) = run_async(home.path(), &["dm", "dj@jig", "hi"]).await;
    assert!(!ok, "{out}");
    assert!(!out.contains(&did_of(&key(2))), "never prints it: {out}");
    assert_eq!(
        beyond_admission(&seen),
        Vec::<String>::new(),
        "nothing was sent"
    );
    let pins = home.path().join(".jig").join("pins.json");
    assert!(
        !pins.exists()
            || !std::fs::read_to_string(pins)
                .unwrap()
                .contains(&did_of(&key(2))),
        "nothing was pinned"
    );
}

#[test]
fn a_bare_word_that_is_not_a_contact_still_says_to_pass_the_did() {
    let home = tempfile::tempdir().unwrap();
    let (ok, out) = run(home.path(), &["init", "me"]);
    assert!(ok, "{out}");
    let (ok, out) = run(home.path(), &["dm", "nobody", "hi"]);
    assert!(!ok, "{out}");
    assert!(out.contains("pass the DID"), "{out}");
}
