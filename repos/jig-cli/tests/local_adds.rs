//! Ending local adds at a server (JEP-0017 R2), through the real `jig`
//! binary: `jig server local-adds end` stops others adding the member to
//! channels that server sequences, whatever server the key package would
//! come from, and `allow` undoes it.
//!
//! Each person runs with `HOME` in a tempdir.

use std::path::Path;
use std::process::{Command, Output};

use integration_tests::harness::{TestJigServer, test_identity};
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

/// `jig` run to a refusal; its stderr.
fn refused(home: &Path, args: &[&str]) -> String {
    let out = run(home, args);
    assert!(
        !out.status.success(),
        "jig {} succeeded: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
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

async fn available(server: &TestJigServer, did: &str) -> u64 {
    let url = format!("{}/api/v1/mls/key-packages/{did}/stock", server.http_url());
    let proof = ReadProof::sign(&test_identity(), "GET", signable_path(&url));
    let mut req = reqwest::Client::new().get(&url);
    for (name, value) in proof.headers() {
        req = req.header(name, value);
    }
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    body["available"].as_u64().unwrap()
}

/// What the member's device recorded for its servers.
fn server_states(home: &Path, did: &str) -> Value {
    let path = home
        .join(".jig")
        .join("servers")
        .join(format!("{}.json", did.replace(':', "_")));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_who_ended_local_adds_cannot_be_added_until_they_allow_it_again() {
    let a = TestJigServer::start().await.unwrap();
    let member_home = tempfile::tempdir().unwrap();
    let member = person(member_home.path(), &a);
    let owner_home = tempfile::tempdir().unwrap();
    person(owner_home.path(), &a);
    ok(owner_home.path(), &["channel", "create", "#sec"]);

    let said = ok(member_home.path(), &["server", "local-adds", "end"]);
    assert!(said.contains("no longer add you"), "{said}");
    let states = server_states(member_home.path(), &member);
    let state = states["servers"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(state["local_adds"]["allow"], false, "{states}");
    let ended_at = state["local_adds"]["seq"].as_u64().unwrap();

    // The stock stays for custody (rule 19); the local take is refused.
    let stocked = available(&a, &member).await;
    assert!(stocked > 0);
    let err = refused(owner_home.path(), &["channel", "add", "#sec", &member]);
    assert!(err.contains("LOCAL_ADDS_ENDED"), "{err}");
    assert!(err.contains("ended local adds"), "{err}");
    assert_eq!(
        available(&a, &member).await,
        stocked,
        "nothing was released"
    );

    // A plaintext channel takes no package: its member-add is refused.
    ok(
        owner_home.path(),
        &["channel", "create", "#pub", "--tier", "public", "--yes"],
    );
    let err = refused(owner_home.path(), &["channel", "add", "#pub", &member]);
    assert!(err.contains("MEMBER_DECLINED"), "{err}");
    let members = ok(owner_home.path(), &["channel", "members", "#pub"]);
    assert!(!members.contains(&member), "{members}");

    // The member can still join a channel by their own act.
    ok(member_home.path(), &["channel", "join", "#pub"]);

    let said = ok(member_home.path(), &["server", "local-adds", "allow"]);
    assert!(said.contains("can add you"), "{said}");
    let states = server_states(member_home.path(), &member);
    let state = states["servers"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(state["local_adds"]["allow"], true, "{states}");
    assert!(state["local_adds"]["seq"].as_u64().unwrap() > ended_at);

    let added = ok(owner_home.path(), &["channel", "add", "#sec", &member]);
    assert!(
        added.contains(&format!("added {member} to #sec")),
        "{added}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ended_local_adds_are_not_routed_around_through_another_custodian() {
    let (a, b) = (
        TestJigServer::start().await.unwrap(),
        TestJigServer::start().await.unwrap(),
    );
    // The member stocks B, then A, and ends local adds at A only.
    let member_home = tempfile::tempdir().unwrap();
    let member = person(member_home.path(), &b);
    ok(member_home.path(), &["server", "set", &a.http_url()]);
    ok(member_home.path(), &["server", "local-adds", "end"]);
    let on_b = available(&b, &member).await;
    assert!(on_b > 0);

    let owner_home = tempfile::tempdir().unwrap();
    person(owner_home.path(), &a);
    ok(owner_home.path(), &["channel", "create", "#sec"]);

    // A sequences #sec, and would refuse the member-add whatever server the
    // package came from: B is not asked (rule 18).
    let err = refused(
        owner_home.path(),
        &["channel", "add", "#sec", &member, "--via", &b.http_url()],
    );
    assert!(err.contains("LOCAL_ADDS_ENDED"), "{err}");
    assert_eq!(available(&b, &member).await, on_b, "B released nothing");
}
