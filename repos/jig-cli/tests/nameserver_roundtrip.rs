//! `jig init --request-alias`, `jig keys register`, `renew` and `rotate` against
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
//! this test's own. The nameservers run as `jig-nameserver serve` does by
//! default, over TLS with a self-signed certificate their DID vouches for,
//! which `jig` takes on that DID's word and no CA's.

use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use integration_tests::harness::TestNameserver;
use jig_core::naming::Attestation;

/// `jig`, with `HOME` at `home` and the environment every test here runs it in.
fn jig_command(home: &Path) -> Command {
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

fn run(home: &Path, args: Vec<String>) -> (bool, String) {
    let out = jig_command(home).args(&args).output().unwrap();
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
    let body: serde_json::Value = ns
        .client()
        .get(format!("{}/v1/resolve/{name}", ns.http_url()))
        .send()
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
    let ns = TestNameserver::start_tls_with_suffix("dj.jig")
        .await
        .unwrap();
    let url = ns.http_url();
    let name = format!("deji@{}", ns.alias_suffix);
    let home = tempfile::tempdir().unwrap();

    // Register. Mixed case on purpose: the proof is over the lowercased name.
    // Four letters: a nameserver may set a minimum alias length (#224).
    let (ok, out) = jig(
        home.path(),
        &[
            "init",
            "dj",
            "--request-alias",
            "DeJi",
            "--nameserver",
            &url,
        ],
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
    assert!(keys.join(format!("{second}.jigkey")).exists());
    assert!(keys.join(format!("{first}.jigkey.rotated")).exists());
}

/// `jig keys register` registers the identity `jig init` already made, not a
/// new one: the way a DID a closed suffix's allowlist names gets its name.
#[tokio::test(flavor = "multi_thread")]
async fn keys_register_names_the_existing_identity() {
    let ns = TestNameserver::start_tls_with_suffix("dj.jig")
        .await
        .unwrap();
    let url = ns.http_url();
    let name = format!("deji@{}", ns.alias_suffix);
    let home = tempfile::tempdir().unwrap();
    let (ok, out) = jig(home.path(), &["init", "dj"]).await;
    assert!(ok, "{out}");
    let did = configured_did(home.path());

    let (ok, out) = jig(
        home.path(),
        &["keys", "register", &name, "--nameserver", &url],
    )
    .await;
    assert!(ok, "jig keys register: {out}");
    assert!(
        out.contains(&format!("alias attestation verified: {name}")),
        "{out}"
    );
    assert_eq!(resolved(&ns, &name).await.did, did, "the existing DID");
    assert_eq!(configured_did(home.path()), did, "no new identity");
}

#[tokio::test(flavor = "multi_thread")]
async fn renewing_an_alias_held_by_another_key_is_refused() {
    let ns = TestNameserver::start_tls_with_suffix("dj.jig")
        .await
        .unwrap();
    let url = ns.http_url();
    let holder = ns.register("deji").await.unwrap();
    let name = format!("deji@{}", ns.alias_suffix);
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

/// The default user's path: no `[naming]` in cli.toml, a nameserver serving
/// the single-label `jig` (no DNS delegation), and the built-in `@jig`
/// authority. Test builds accept the placeholder authority, so the
/// nameserver here runs under its public test seed.
#[tokio::test(flavor = "multi_thread")]
async fn register_renew_and_rotate_an_at_jig_name_under_the_built_in_authority() {
    let ns = TestNameserver::start_tls_with_key("jig", [0x4a; 32])
        .await
        .unwrap();
    assert_eq!(
        ns.state.ns_did_string(),
        jig_core::naming::PLACEHOLDER_JIG_AUTHORITY
    );
    let url = ns.http_url();
    let home = tempfile::tempdir().unwrap();

    let (ok, out) = jig(
        home.path(),
        &[
            "init",
            "dj",
            "--request-alias",
            "DeJi@jig",
            "--nameserver",
            &url,
        ],
    )
    .await;
    assert!(ok, "jig init --request-alias DeJi@jig: {out}");
    assert!(
        out.contains("alias attestation verified: deji@jig"),
        "{out}"
    );
    let first = configured_did(home.path());
    assert_eq!(resolved(&ns, "deji@jig").await.did, first);

    let (ok, out) = jig(
        home.path(),
        &["keys", "renew", "deji@jig", "--nameserver", &url],
    )
    .await;
    assert!(ok, "jig keys renew: {out}");
    assert_eq!(resolved(&ns, "deji@jig").await.did, first);

    let (ok, out) = jig(
        home.path(),
        &["keys", "rotate", "deji@jig", "--nameserver", &url],
    )
    .await;
    assert!(ok, "jig keys rotate: {out}");
    let second = configured_did(home.path());
    assert_ne!(second, first);
    assert_eq!(resolved(&ns, "deji@jig").await.did, second);
}

/// A nameserver for `jig` that is not the `@jig` authority gets nothing
/// signed, and the name stays unregistered.
#[tokio::test(flavor = "multi_thread")]
async fn a_jig_nameserver_that_is_not_the_authority_is_refused_before_signing() {
    let ns = TestNameserver::start_tls_with_suffix("jig").await.unwrap();
    let url = ns.http_url();
    let home = tempfile::tempdir().unwrap();

    let (ok, out) = jig(
        home.path(),
        &[
            "init",
            "dj",
            "--request-alias",
            "deji@jig",
            "--nameserver",
            &url,
        ],
    )
    .await;
    assert!(!ok, "{out}");
    assert!(out.contains("nothing was signed"), "{out}");
    let status = ns
        .client()
        .get(format!("{url}/v1/resolve/deji@jig"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_FOUND,
        "deji@jig was never registered"
    );
}

/// A plaintext nameserver is not asked at all unless cli.toml opts in.
#[tokio::test(flavor = "multi_thread")]
async fn a_plaintext_nameserver_is_refused_without_the_opt_in() {
    let ns = TestNameserver::start().await.unwrap();
    let url = ns.http_url();
    let home = tempfile::tempdir().unwrap();

    let (ok, out) = jig(
        home.path(),
        &[
            "init",
            "dj",
            "--request-alias",
            "deji",
            "--nameserver",
            &url,
        ],
    )
    .await;
    assert!(!ok, "{out}");
    assert!(
        out.contains("dangerously_allow_plaintext_nameservers"),
        "{out}"
    );
    let status = reqwest::get(format!("{url}/v1/resolve/deji@dj.jig"))
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND, "nothing registered");
}

/// The same CLI against a nameserver that asks for proof-of-work (JEP-0008):
/// each command fetches a challenge for its action, solves the effort the
/// nameserver signed, and the nameserver checks the work before anything
/// else.
#[tokio::test(flavor = "multi_thread")]
async fn register_renew_and_rotate_solve_the_nameservers_proof_of_work() {
    let pow = integration_tests::harness::PowPolicy {
        min_effort: 1 << 12,
        max_effort: 1 << 16,
        renew_effort: 1 << 8,
        ..integration_tests::harness::PowPolicy::default()
    };
    let ns = TestNameserver::start_tls_with_pow("dj.jig", pow)
        .await
        .unwrap();
    let url = ns.http_url();
    let name = "deji@dj.jig";
    let home = tempfile::tempdir().unwrap();

    let (ok, out) = jig(
        home.path(),
        &[
            "init",
            "dj",
            "--request-alias",
            "deji",
            "--nameserver",
            &url,
        ],
    )
    .await;
    assert!(ok, "jig init --request-alias with proof-of-work: {out}");
    let first = configured_did(home.path());
    assert_eq!(resolved(&ns, name).await.did, first);

    let (ok, out) = jig(home.path(), &["keys", "renew", name, "--nameserver", &url]).await;
    assert!(ok, "jig keys renew with proof-of-work: {out}");

    let (ok, out) = jig(home.path(), &["keys", "rotate", name, "--nameserver", &url]).await;
    assert!(ok, "jig keys rotate with proof-of-work: {out}");
    let second = configured_did(home.path());
    assert_ne!(second, first);
    assert_eq!(resolved(&ns, name).await.did, second);
}

/// A nameserver whose registration pool is full answers `503
/// REGISTRATION_BUSY` with `Retry-After` (JEP-0008 rules 22–24). `jig` waits
/// that long, says so, and registers on a fresh challenge.
///
/// Independent of timing: the test holds the pool so it never refills, so
/// `jig`'s first attempt is refused however long it takes to arrive. Its
/// `Retry-After` is the 5 s one token takes at 720 an hour. The test releases
/// the pool only once `jig` says it is waiting, so the retry can succeed only
/// by waiting and trying again.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_pool_is_waited_out_and_the_registration_retried() {
    use integration_tests::harness::{PoolPolicy, PowPolicy};
    use std::io::{BufRead, Read};
    let pool = PoolPolicy {
        strangers_per_hour: 720,
        burst: 1,
        queue_wait_secs: 0,
        ..PoolPolicy::recommended()
    };
    let ns = TestNameserver::start_tls_with_policies("dj.jig", PowPolicy::off(), pool)
        .await
        .unwrap();
    ns.hold_pool(true);
    ns.register("first").await.expect("takes the one token");
    let ns = std::sync::Arc::new(ns);
    let home = tempfile::tempdir().unwrap();

    let (ok, out) = {
        let (ns, home) = (ns.clone(), home.path().to_path_buf());
        tokio::task::spawn_blocking(move || {
            let mut child = jig_command(&home)
                .args(["init", "dj", "--request-alias", "deji", "--nameserver"])
                .arg(ns.http_url())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdout = child.stdout.take().unwrap();
            let stdout = std::thread::spawn(move || {
                let mut s = String::new();
                stdout.read_to_string(&mut s).unwrap();
                s
            });
            let mut out = String::new();
            for line in std::io::BufReader::new(child.stderr.take().unwrap()).lines() {
                let line = line.unwrap();
                if line.contains("taking no more new names for now; waiting") {
                    // jig has seen the busy pool and is sleeping out its
                    // Retry-After: let its retry through.
                    ns.hold_pool(false);
                }
                out.push_str(&line);
                out.push('\n');
            }
            let ok = child.wait().unwrap().success();
            (ok, stdout.join().unwrap() + &out)
        })
        .await
        .unwrap()
    };
    assert!(ok, "jig init after a busy pool: {out}");
    let waited: u64 = out
        .split("taking no more new names for now; waiting ")
        .nth(1)
        .and_then(|rest| rest.split('s').next())
        .and_then(|secs| secs.parse().ok())
        .unwrap_or_else(|| panic!("no busy refusal was waited out: {out}"));
    assert_eq!(waited, 5, "jig waits exactly its Retry-After: {out}");
    assert_eq!(
        out.matches("taking no more new names for now").count(),
        1,
        "one busy refusal, then the retry got through: {out}"
    );
    assert_eq!(
        resolved(&ns, "deji@dj.jig").await.did,
        configured_did(home.path())
    );
}

/// When the pool's next token is further off than the client will wait, it
/// says when to try again instead of waiting.
#[tokio::test(flavor = "multi_thread")]
async fn a_pool_full_for_long_is_reported_not_waited_for() {
    use integration_tests::harness::PoolPolicy;
    let pool = PoolPolicy {
        strangers_per_hour: 1,
        burst: 1,
        queue_wait_secs: 0,
        ..PoolPolicy::recommended()
    };
    let ns = TestNameserver::start_tls_with_policies("dj.jig", TestNameserver::test_pow(), pool)
        .await
        .unwrap();
    ns.register("first").await.expect("takes the one token");
    let home = tempfile::tempdir().unwrap();

    let started = std::time::Instant::now();
    let (ok, out) = jig(
        home.path(),
        &[
            "init",
            "dj",
            "--request-alias",
            "deji",
            "--nameserver",
            &ns.http_url(),
        ],
    )
    .await;
    assert!(!ok, "{out}");
    assert!(
        out.contains("taking no more new names for now; try again in about"),
        "{out}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "did not wait an hour"
    );
}
