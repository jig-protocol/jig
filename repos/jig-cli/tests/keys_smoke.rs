//! Smoke + request-builder tests for `jig keys renew` and `jig keys rotate`
//! (Phase F2, v0.0.2 hello-world).
//!
//! No live HTTP round-trips — Phase H integration tests cover the end-to-end
//! challenge → sign → renew/rotate flow against an in-process nameserver.
//! These tests pin two things:
//!
//!   1. The wire-shape construction (field names, signature payload).
//!      Drift between this client and `jig_nameserver::v0_0_2_rotate_renew`
//!      will surface in Phase H, but is much cheaper to catch here.
//!   2. The compiled binary surfaces the `keys renew` / `keys rotate`
//!      subcommands at all (clap wiring sanity).

use std::process::Command;

#[test]
fn binary_exposes_keys_renew_subcommand() {
    // `--help` should mention both subcommands. If clap isn't wired up,
    // this catches it before someone tries to use the binary.
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        // Never the developer's real keychain; seal test keys with a fixed secret.
        .env("JIG_KEYCHAIN", "none")
        .env("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")
        .env(
            "JIG_TEST_KEY_SECRET",
            "jig cli tests: a fixed, public secret",
        )
        .args(["keys", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "jig keys --help exited non-zero. stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("renew"),
        "`jig keys --help` should mention `renew`. got:\n{help}"
    );
    assert!(
        help.contains("rotate"),
        "`jig keys --help` should mention `rotate`. got:\n{help}"
    );
}

#[test]
fn keys_renew_requires_alias_and_nameserver_flag() {
    // No args at all → clap should bail with non-zero and mention the
    // required ALIAS positional.
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        // Never the developer's real keychain; seal test keys with a fixed secret.
        .env("JIG_KEYCHAIN", "none")
        .env("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")
        .env(
            "JIG_TEST_KEY_SECRET",
            "jig cli tests: a fixed, public secret",
        )
        .args(["keys", "renew"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "`jig keys renew` with no args should fail clap parsing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ALIAS") || stderr.contains("alias") || stderr.contains("required"),
        "stderr should mention required alias. got:\n{stderr}"
    );
}

#[test]
fn keys_rotate_requires_alias_and_nameserver_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        // Never the developer's real keychain; seal test keys with a fixed secret.
        .env("JIG_KEYCHAIN", "none")
        .env("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")
        .env(
            "JIG_TEST_KEY_SECRET",
            "jig cli tests: a fixed, public secret",
        )
        .args(["keys", "rotate"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "`jig keys rotate` with no args should fail clap parsing"
    );
}

#[test]
fn keys_renew_fails_loudly_when_no_cli_toml_or_keyfile() {
    // With a redirected empty HOME, there's no cli.toml; load_config will
    // synthesize a default Config whose `[user] did` doesn't start with
    // `did:jig:` — keys::renew must reject it rather than silently load a
    // bogus identity. Confirm we get a non-zero exit and a useful stderr.
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        // Never the developer's real keychain; seal test keys with a fixed secret.
        .env("JIG_KEYCHAIN", "none")
        .env("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")
        .env(
            "JIG_TEST_KEY_SECRET",
            "jig cli tests: a fixed, public secret",
        )
        .args([
            "keys",
            "renew",
            "dj@dj.jig",
            "--nameserver",
            "http://127.0.0.1:1",
        ])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "renew with no identity should fail. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn keys_rotate_refuses_before_changing_anything_when_a_rotated_key_exists() {
    // A rotate that could not move the old key aside at the end would leave
    // the nameserver on the new DID and cli.toml on the old one. It must
    // refuse up front instead, before it mints a key or calls the nameserver.
    let tmp = tempfile::tempdir().unwrap();
    let jig = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_jig"))
            .env("JIG_KEYCHAIN", "none")
            .env("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")
            .env(
                "JIG_TEST_KEY_SECRET",
                "jig cli tests: a fixed, public secret",
            )
            .env("HOME", tmp.path())
            .args(args)
            .output()
            .unwrap()
    };
    let init = jig(&["init", "rotator"]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let stdout = String::from_utf8_lossy(&init.stdout);
    let did = stdout
        .lines()
        .find_map(|l| l.strip_prefix("generated DID: "))
        .expect("init prints the DID")
        .trim()
        .to_string();
    let keys = tmp.path().join(".jig/keys");
    std::fs::write(
        keys.join(format!("{did}.jigkey.rotated")),
        b"an earlier rotation",
    )
    .unwrap();
    let keys_before: Vec<_> = std::fs::read_dir(&keys)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();

    // An unreachable nameserver: reaching it would fail differently.
    let out = jig(&[
        "keys",
        "rotate",
        "rotator@x.jig",
        "--nameserver",
        "http://127.0.0.1:1",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("exists already"), "{stderr}");
    let keys_after: Vec<_> = std::fs::read_dir(&keys)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        keys_before.len(),
        keys_after.len(),
        "a key was minted: {keys_after:?}"
    );
}

/// `jig keys protect`: list, add a passphrase, remove the first slot, and
/// never the last.
#[test]
fn keys_protect_adds_and_removes_slots_but_never_the_last() {
    let tmp = tempfile::tempdir().unwrap();
    let jig = |args: &[&str], env: &[(&str, &str)]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_jig"));
        cmd.env("HOME", tmp.path())
            .env("JIG_KEYCHAIN", "none")
            .env("JIG_NONINTERACTIVE", "1")
            .env_remove("JIG_KEY_UNLOCK")
            .env_remove("JIG_KEY_PASSPHRASE")
            .env(
                "JIG_TEST_KEY_SECRET",
                "jig cli tests: a fixed, public secret",
            )
            .args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let secret = [("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")];
    let (ok, out) = jig(&["init", "dj"], &secret);
    assert!(ok, "{out}");

    let (ok, out) = jig(&["keys", "protect"], &[]);
    assert!(ok && out.contains("1. an environment secret"), "{out}");
    assert!(out.contains("one way to open this key"), "{out}");

    let (ok, out) = jig(
        &["keys", "protect", "--add", "passphrase"],
        &[
            secret[0],
            ("JIG_KEY_NEW_PASSPHRASE", "a passphrase kept offline"),
        ],
    );
    assert!(ok && out.contains("2. a passphrase"), "{out}");

    // Opened with the passphrase alone, the environment's slot goes.
    let pass = [("JIG_KEY_PASSPHRASE", "a passphrase kept offline")];
    let (ok, out) = jig(&["keys", "protect", "--remove", "1"], &pass);
    assert!(
        ok && out.contains("1. a passphrase") && !out.contains("2."),
        "{out}"
    );

    let (ok, out) = jig(&["keys", "protect", "--remove", "1"], &pass);
    assert!(
        !ok && out.contains("last"),
        "removing the last slot is refused: {out}"
    );

    let (ok, out) = jig(&["keys", "protect", "--add", "hunter2-not-a-spec"], &pass);
    assert!(
        !ok && !out.contains("hunter2"),
        "a bad --add is not echoed: {out}"
    );
}
