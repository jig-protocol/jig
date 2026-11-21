//! Ending a server's custody of one's key packages (JEP-0017 R1), across two
//! servers and two devices.
//!
//! The member uses server B. The owner, on server A, adds them through B as
//! custodian. After `jig server custody off`, B releases nothing more to A,
//! while members of B still add them; another device of the member learns of
//! the withdrawal from B and does not undo it; `custody on` restores it.
//!
//! The real `jig` binary plays everyone, each with `HOME` in a tempdir.

use std::path::Path;
use std::process::{Command, Output};

use integration_tests::harness::{TestJigServer, test_identity};
use jig_client::Identity;
use jig_client::read_auth::{ReadProof, signable_path};
use serde_json::Value;

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

fn run(home: &Path, args: &[&str]) -> Output {
    jig(home).args(args).output().unwrap()
}

fn ok(home: &Path, args: &[&str]) -> String {
    let out = run(home, args);
    assert!(
        out.status.success(),
        "jig {}: {}\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A person with an identity, using `server`. Returns their DID.
fn person(home: &Path, server: &TestJigServer) -> String {
    ok(home, &["init", "me"]);
    ok(home, &["server", "set", &server.http_url()]);
    let cfg: toml::Table =
        toml::from_str(&std::fs::read_to_string(home.join(".jig").join("cli.toml")).unwrap())
            .unwrap();
    cfg["user"]["did"].as_str().unwrap().to_string()
}

async fn get(server: &TestJigServer, who: &Identity, path: &str) -> (u16, Value) {
    let url = format!("{}{path}", server.http_url());
    let proof = ReadProof::sign(who, "GET", signable_path(&url));
    let mut req = reqwest::Client::new().get(&url);
    for (name, value) in proof.headers() {
        req = req.header(name, value);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn stock(server: &TestJigServer, did: &str) -> (u64, bool) {
    let (status, body) = get(
        server,
        &test_identity(),
        &format!("/api/v1/mls/key-packages/{did}/stock"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    (
        body["available"].as_u64().unwrap(),
        body["last_resort"].as_bool().unwrap(),
    )
}

/// Copy one device's identity and settings to a fresh home: a second device
/// of the same DID, with none of the first one's MLS state or server state.
fn second_device(first: &Path) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let to = home.path().join(".jig");
    copy_except(&first.join(".jig"), &to, &["mls", "servers"]);
    home
}

fn copy_except(from: &Path, to: &Path, skip: &[&str]) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if skip.iter().any(|s| name == *s) {
            continue;
        }
        if entry.file_type().unwrap().is_dir() {
            copy_except(&entry.path(), &to.join(&name), &[]);
        } else {
            std::fs::copy(entry.path(), to.join(&name)).unwrap();
        }
    }
}

fn add_via(owner: &Path, channel: &str, member: &str, via: &TestJigServer) -> Output {
    run(
        owner,
        &["channel", "add", channel, member, "--via", &via.http_url()],
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_who_ends_custody_is_added_only_locally_until_they_restore_it() {
    let (a, b) = (
        TestJigServer::start().await.unwrap(),
        TestJigServer::start().await.unwrap(),
    );
    let member_home = tempfile::tempdir().unwrap();
    let member = person(member_home.path(), &b);
    let owner_home = tempfile::tempdir().unwrap();
    person(owner_home.path(), &a);
    let local_home = tempfile::tempdir().unwrap();
    person(local_home.path(), &b);

    // Before: added from A through B, which releases one ordinary package.
    // The member does not read through A, which would stock A too.
    ok(owner_home.path(), &["channel", "create", "#one"]);
    let out = add_via(owner_home.path(), "#one", &member, &b);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(stock(&a, &member).await, (0, false));

    // Ending custody deletes this device's keys for that package and for the
    // last-resort one others may hold, and stocks a fresh last-resort one.
    let ended = ok(member_home.path(), &["server", "custody", "off"]);
    assert!(ended.contains("no longer releases"), "{ended}");
    assert!(
        ended.contains("deleted this device's keys for 2 package(s)"),
        "{ended}"
    );
    assert!(stock(&b, &member).await.1);

    // A gets nothing from B now, and commits nothing.
    ok(owner_home.path(), &["channel", "create", "#two"]);
    let out = add_via(owner_home.path(), "#two", &member, &b);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("NO_CUSTODY"), "{stderr}");
    let members = ok(owner_home.path(), &["channel", "members", "#two"]);
    assert!(!members.contains(&member), "{members}");
    let (status, _) = get(&b, &test_identity(), &format!("/api/v1/reach/{member}")).await;
    assert_eq!(status, 404, "others see no record");

    // A member of B still adds them.
    ok(local_home.path(), &["channel", "create", "#local"]);
    let added = ok(local_home.path(), &["channel", "add", "#local", &member]);
    assert!(added.contains(&format!("added {member}")), "{added}");

    // Another device, which never saw the withdrawal, stocks B and does not
    // list B again: it learns of the withdrawal from B.
    let other = second_device(member_home.path());
    let out = run(other.path(), &["server", "set", &b.http_url()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let note = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        note.contains("was withdrawn, from another device"),
        "{note}"
    );
    ok(owner_home.path(), &["channel", "create", "#three"]);
    let out = add_via(owner_home.path(), "#three", &member, &b);
    assert!(!out.status.success(), "the other device did not undo R1");

    // Restored: added through B again, and the member joins.
    let restored = ok(member_home.path(), &["server", "custody", "on"]);
    assert!(restored.contains("again a custodian"), "{restored}");
    let out = add_via(owner_home.path(), "#three", &member, &b);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    ok(owner_home.path(), &["send", "--channel", "#three", "after"]);
    let read = ok(
        member_home.path(),
        &["--server", &a.http_url(), "read", "#three"],
    );
    assert!(read.contains("after"), "{read}");
}
