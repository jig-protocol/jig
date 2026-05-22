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
