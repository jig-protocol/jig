//! `jig init --request-alias`, `jig keys renew` and `jig keys rotate` against
//! a real `jig-nameserver`.
//!
//! The CLI and the nameserver sign and check each other's proofs and
//! attestations (JEP-0004), and nothing else in CI runs one against the
//! other: their unit tests each use a stub of the other side. This runs the
//! real `jig` binary against the nameserver's real router, as `jig-nameserver
//! serve` builds it, and checks every binding through the nameserver's own
//! resolve route, verifying the signed attestation independently of the CLI.
//!
//! Every invocation points `HOME` at a tempdir, so keys and `cli.toml` are
//! this test's own.

use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use integration_tests::harness::TestNameserver;
use jig_core::naming::Attestation;

fn run(home: &Path, args: Vec<String>) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(&args)
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

/// Run `jig` off the runtime the nameserver is served from.
async fn jig(home: &Path, args: &[&str]) -> (bool, String) {
    let home = home.to_path_buf();
    let args = args.iter().map(|a| a.to_string()).collect();
    tokio::task::spawn_blocking(move || run(&home, args))
        .await
        .unwrap()
}

/// The `[user] did` the CLI's config names.
fn configured_did(home: &Path) -> String {
    let cfg = std::fs::read_to_string(home.join(".jig").join("cli.toml")).unwrap();
    let cfg: toml::Table = toml::from_str(&cfg).unwrap();
    cfg["user"]["did"].as_str().unwrap().to_string()
}

/// What the nameserver now attests for `name`, verified here: the envelope
/// must be the nameserver's own signature over exactly this name.
async fn resolved(ns: &TestNameserver, name: &str) -> Attestation {
    let body: serde_json::Value = reqwest::get(format!("{}/v1/resolve/{name}", ns.http_url()))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let envelope = URL_SAFE_NO_PAD
        .decode(body["attestation"].as_str().expect("a signed attestation"))
        .unwrap();
    let att = Attestation::from_envelope(&envelope).expect("the attestation verifies");
    assert_eq!(
        att.ns_did,
        ns.state.ns_did_string(),
        "signed by this nameserver"
    );
    assert_eq!(att.alias, name);
    let now = chrono::Utc::now().timestamp();
    assert!(att.valid_from <= now && now < att.valid_until, "valid now");
    att
}

#[tokio::test(flavor = "multi_thread")]
async fn register_renew_and_rotate_against_the_real_nameserver() {
    let ns = TestNameserver::start().await.unwrap();
    let url = ns.http_url();
    let name = format!("dj@{}", ns.alias_suffix);
    let home = tempfile::tempdir().unwrap();

    // Register. Mixed case on purpose: the proof is over the lowercased name.
    let (ok, out) = jig(
        home.path(),
        &["init", "dj", "--request-alias", "DJ", "--nameserver", &url],
    )
    .await;
    assert!(ok, "jig init --request-alias: {out}");
    assert!(
        out.contains(&format!("alias attestation verified: {name}")),
        "{out}"
    );
    let first = configured_did(home.path());
    assert_eq!(resolved(&ns, &name).await.did, first);

    // Renew: the same DID, attested afresh.
    let (ok, out) = jig(home.path(), &["keys", "renew", &name, "--nameserver", &url]).await;
    assert!(ok, "jig keys renew: {out}");
    assert!(
        out.contains(&format!("alias attestation renewed: {name}")),
        "{out}"
    );
    assert_eq!(resolved(&ns, &name).await.did, first);

    // Rotate: the alias now resolves to the new key, and the config names it.
    let (ok, out) = jig(
        home.path(),
        &["keys", "rotate", &name, "--nameserver", &url],
    )
    .await;
    assert!(ok, "jig keys rotate: {out}");
    let second = configured_did(home.path());
    assert_ne!(second, first, "rotate moves [user] did to a new key");
    assert_eq!(
        resolved(&ns, &name).await.did,
        second,
        "the old key's alias resolves to the new DID"
    );
    let keys = home.path().join(".jig").join("keys");
    assert!(keys.join(format!("{second}.key")).exists());
    assert!(keys.join(format!("{first}.key.rotated")).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn renewing_an_alias_held_by_another_key_is_refused() {
    let ns = TestNameserver::start().await.unwrap();
    let url = ns.http_url();
    let holder = ns.register("dj").await.unwrap();
    let name = format!("dj@{}", ns.alias_suffix);
    let home = tempfile::tempdir().unwrap();
    let (ok, out) = jig(home.path(), &["init", "me"]).await;
    assert!(ok, "{out}");

    let (ok, out) = jig(home.path(), &["keys", "renew", &name, "--nameserver", &url]).await;
    assert!(!ok, "someone else's alias is not ours to renew: {out}");
    assert_eq!(
        resolved(&ns, &name).await.did,
        holder.did_string(),
        "the holder's binding is untouched"
    );
}
