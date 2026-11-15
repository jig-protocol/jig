//! Adding a member whose client has only ever talked to another server to an
//! encrypted channel (JEP-0005 rule 21).
//!
//! The member runs `jig` against server B alone, which stocks their key
//! packages there and a reachability record listing B. The owner, on server
//! A, adds them with `--via` B: A has nothing of the member's, so the owner's
//! client asks B, as the member's custodian, with a signed request. The
//! member then reads, through A, what the owner sent after the add.
//!
//! The real `jig` binary plays both people, each with `HOME` in a tempdir.

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

#[tokio::test(flavor = "multi_thread")]
async fn a_member_who_never_contacted_the_owner_s_server_is_added_through_their_own() {
    let (a, b) = (
        TestJigServer::start().await.unwrap(),
        TestJigServer::start().await.unwrap(),
    );
    let member_home = tempfile::tempdir().unwrap();
    let member = person(member_home.path(), &b);
    let owner_home = tempfile::tempdir().unwrap();
    person(owner_home.path(), &a);

    // The member stocked B, and listed B in a record B keeps; A has nothing.
    let (on_b, _) = stock(&b, &member).await;
    assert!(on_b > 0);
    assert_eq!(stock(&a, &member).await, (0, false));
    let (status, body) = get(&b, &test_identity(), &format!("/api/v1/reach/{member}")).await;
    assert_eq!(status, 200, "{body}");

    ok(owner_home.path(), &["channel", "create", "#sec"]);

    // A bare DID with nothing saying where else to ask is refused, and says
    // how to fix it.
    let out = run(owner_home.path(), &["channel", "add", "#sec", &member]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--via"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(stock(&b, &member).await.0, on_b, "nothing was asked of B");

    let added = ok(
        owner_home.path(),
        &["channel", "add", "#sec", &member, "--via", &b.http_url()],
    );
    assert!(
        added.contains(&format!("added {member} to #sec")),
        "{added}"
    );
    assert_eq!(
        stock(&b, &member).await.0,
        on_b - 1,
        "B released one package"
    );
    assert_eq!(stock(&a, &member).await, (0, false));

    ok(
        owner_home.path(),
        &["send", "--channel", "#sec", "hello across servers"],
    );
    // The member joins from the welcome in the add and decrypts what came
    // after it, reading through the channel's server.
    let read = ok(
        member_home.path(),
        &["--server", &a.http_url(), "read", "#sec"],
    );
    assert!(read.contains("hello across servers"), "{read}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_the_member_does_not_list_is_no_custodian_and_nothing_is_committed() {
    let (a, b, c) = (
        TestJigServer::start().await.unwrap(),
        TestJigServer::start().await.unwrap(),
        TestJigServer::start().await.unwrap(),
    );
    let member_home = tempfile::tempdir().unwrap();
    let member = person(member_home.path(), &b);
    let owner_home = tempfile::tempdir().unwrap();
    person(owner_home.path(), &a);
    ok(owner_home.path(), &["channel", "create", "#sec"]);

    // C holds nothing of the member's and is in no record of theirs.
    let out = run(
        owner_home.path(),
        &["channel", "add", "#sec", &member, "--via", &c.http_url()],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("NO_CUSTODY"), "{stderr}");
    assert!(stderr.contains("nothing was changed"), "{stderr}");
    let members = ok(owner_home.path(), &["channel", "members", "#sec"]);
    assert!(!members.contains(&member), "{members}");
}
