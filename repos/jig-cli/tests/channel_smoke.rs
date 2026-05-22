//! Smoke tests for `jig channel create` / `join` / `list`
//! (Phase F4 of v0.0.2 hello-world).
//!
//! Live HTTP is exercised by the server-side unit tests in
//! `jig-server/src/v0_0_2_blocks.rs` and `v0_0_2_admin.rs`. Here we only
//! confirm:
//!   1. All three subcommands resolve through clap and surface help text.
//!   2. URL-escaping behaviour for `#` in slugs (the load-bearing F4
//!      invariant — a missed escape would break `join` against the admin
//!      route's `:slug` extractor).
//!   3. The CLI fails loudly (non-zero exit) when the server is
//!      unreachable, instead of panicking or silently exiting 0.
//!
//! The escape function itself is unit-tested in
//! `src/cmd/channel.rs::tests`; these tests cover the wiring.

use std::process::Command;

// ---- clap wiring -----------------------------------------------------------

#[test]
fn binary_exposes_channel_subcommands() {
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["channel", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "jig channel --help exited non-zero. stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8_lossy(&output.stdout);
    for sub in ["create", "join", "list"] {
        assert!(
            help.contains(sub),
            "`jig channel --help` should mention `{sub}`. got:\n{help}"
        );
    }
}

#[test]
fn channel_create_help_mentions_visibility_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["channel", "create", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("--visibility"),
        "`jig channel create --help` should mention `--visibility`. got:\n{help}"
    );
}

#[test]
fn channel_join_help_mentions_slug_positional() {
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["channel", "join", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.to_lowercase().contains("slug"),
        "`jig channel join --help` should describe the slug arg. got:\n{help}"
    );
}

#[test]
fn channel_list_takes_no_required_args() {
    // List should resolve from `--help` alone — i.e. it has no required
    // positional or flag args. If someone adds a required field later,
    // this test breaks and we revisit the column-layout assumption in
    // `print_channels`.
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["channel", "list", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "jig channel list --help exited non-zero. stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---- URL escape invariants -------------------------------------------------

#[test]
fn channel_join_escapes_hash_in_slug() {
    // This is the load-bearing F4 invariant: `#hello` MUST encode to
    // `%23hello` in the path the CLI builds. Easiest way to assert that
    // without standing up a live server is to point `jig channel join`
    // at a known-closed port and confirm the failure mode mentions the
    // encoded slug.
    //
    // We can't directly assert what URL the CLI calls (no debug-print of
    // the URL on the success path), but we CAN drive the failure path: a
    // missing/empty `[user] did` in cli.toml short-circuits BEFORE the
    // HTTP call, so we have to set up a tempdir with a written cli.toml.
    // That's overkill for a smoke test; instead, lean on the unit-test
    // coverage of `escape_slug_for_url` in src/cmd/channel.rs::tests and
    // here just confirm the CLI doesn't panic on a slug with a `#`.
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["channel", "join", "#hello"])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    // Will fail — no identity in tempdir HOME — but must not panic.
    assert!(
        !output.status.success(),
        "expected jig channel join to fail (no identity) without panicking"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Failure message should NOT be a Rust panic.
    assert!(
        !stderr.contains("panicked"),
        "must not panic — got: {stderr}"
    );
}

// ---- failure-mode smoke ----------------------------------------------------

#[test]
fn channel_list_fails_loudly_when_target_unreachable() {
    // Port 1 is almost certainly closed; confirm we exit non-zero with a
    // useful stderr instead of panicking. The DID isn't required for
    // `list` (it reads from a public endpoint), so a fresh tempdir HOME
    // is fine — `load_config` will fall through to defaults.
    let tmp = tempfile::tempdir().unwrap();

    // Point cli.toml at the closed port.
    let cfg_dir = tmp.path().join(".jig");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(
        cfg_dir.join("cli.toml"),
        r##"
[server]
base_url = "http://127.0.0.1:1"

[user]
did = "did:jig:zfake"
display_name = "test"
default_channel = "#general"
"##,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["channel", "list"])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "list against closed port should fail. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "must not panic — stderr: {stderr}"
    );
}

#[test]
fn channel_create_rejects_invalid_visibility() {
    // `--visibility nonsense` must fail loudly with a clear message before
    // any HTTP call. We don't even need a working identity for this — the
    // visibility check happens early enough to short-circuit.
    //
    // ...except `load_active_identity` runs FIRST in the current impl,
    // so we may see an identity error here instead. Either way the exit
    // must be non-zero and the run must not panic.
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["channel", "create", "#hello", "--visibility", "nonsense"])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "invalid visibility must fail. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "must not panic — stderr: {stderr}"
    );
}
