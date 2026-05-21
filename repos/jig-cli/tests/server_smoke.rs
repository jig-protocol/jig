//! Smoke tests for `jig server set` / `jig server info`
//! (Phase F3 of v0.0.2 hello-world).
//!
//! Live HTTP is exercised in Phase H integration tests against a real
//! jig-server. Here we only confirm:
//!   1. `jig server set` writes `[server] base_url` to `~/.jig/cli.toml`.
//!   2. Invalid URLs (empty, malformed) are rejected with a non-zero exit
//!      so the user notices instead of silently saving garbage.
//!   3. `jig server info` is wired into clap and surfaces the `--url`
//!      override flag.
//!
//! The `well_known_url` transposition and pretty-printer are unit-tested
//! in `src/cmd/server.rs::tests`.

use std::process::Command;

#[test]
fn server_set_writes_base_url_to_cli_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["server", "set", "http://example.com:9090"])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "jig server set exited non-zero. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let cli_toml = tmp.path().join(".jig").join("cli.toml");
    assert!(
        cli_toml.exists(),
        "expected cli.toml at {}",
        cli_toml.display()
    );
    let body = std::fs::read_to_string(&cli_toml).unwrap();
    assert!(
        body.contains("base_url = \"http://example.com:9090\""),
        "cli.toml missing base_url binding. body=\n{body}"
    );
}

#[test]
fn server_set_accepts_wss_scheme() {
    // wss:// is valid in v0.0.2; the well_known transposition handles it
    // at info-fetch time, so we should store it verbatim here.
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["server", "set", "wss://deji.jig.onl"])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "jig server set wss:// should succeed. stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body = std::fs::read_to_string(tmp.path().join(".jig").join("cli.toml")).unwrap();
    assert!(
        body.contains("base_url = \"wss://deji.jig.onl\""),
        "wss URL must be persisted verbatim. body=\n{body}"
    );
}

#[test]
fn server_set_rejects_empty_url() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["server", "set", ""])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "empty URL must fail. stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("empty") || stderr.contains("URL"),
        "stderr should mention empty/URL. got: {stderr}"
    );
}

#[test]
fn server_set_rejects_garbage_url() {
    // `not-a-url` parses to a relative reference with no scheme; the
    // `url` crate should reject it. Same for `://` and similar nonsense.
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["server", "set", "not a url at all"])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "garbage URL must fail. stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn binary_exposes_server_subcommands() {
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["server", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "jig server --help exited non-zero. stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("set"),
        "`jig server --help` should mention `set`. got:\n{help}"
    );
    assert!(
        help.contains("info"),
        "`jig server --help` should mention `info`. got:\n{help}"
    );
}

#[test]
fn server_info_help_mentions_url_override_flag() {
    // The `--url` override is the diagnostic escape hatch — check that
    // it shows up so operators don't have to grep for it.
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["server", "info", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("--url"),
        "`jig server info --help` should mention `--url`. got:\n{help}"
    );
}

#[test]
fn server_info_fails_loudly_when_target_unreachable() {
    // No mock HTTP server — just point at a port nothing is listening
    // on and confirm we get a non-zero exit with a useful stderr (not a
    // panic or silent success).
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        // Port 1 is privileged and almost certainly closed; the connect
        // attempt should fail fast.
        .args(["server", "info", "--url", "http://127.0.0.1:1"])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "info against a closed port should fail. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
