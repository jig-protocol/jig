//! Smoke tests for `jig ns resolve` / `jig ns list`.
//!
//! The response formatting and 404 explanations are unit-tested in
//! `src/cmd/ns.rs`; this suite covers the wiring that unit tests cannot
//! see: that clap exposes the subcommands at all, and that a lookup with
//! nowhere to look fails loudly (non-zero) with an actionable message
//! rather than silently succeeding.
//!
//! Every invocation redirects `HOME` at a tempdir so nothing here can read
//! or write the developer's real `~/.jig`.

use std::path::Path;
use std::process::Command;

/// Port nothing listens on — a lookup against it must fail fast.
const CLOSED_PORT_URL: &str = "http://127.0.0.1:1";

fn write_cli_toml(home: &Path) {
    let cfg_dir = home.join(".jig");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(
        cfg_dir.join("cli.toml"),
        "[server]\nbase_url = \"http://127.0.0.1:7999\"\n\n\
         [user]\ndid = \"did:jig:zTest\"\ndisplay_name = \"test\"\n\
         default_channel = \"#general\"\n",
    )
    .unwrap();
}

fn run_jig(home: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(args)
        .env("HOME", home)
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

#[test]
fn binary_exposes_ns_subcommands() {
    let out = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["ns", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "jig ns --help exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    for sub in ["resolve", "list"] {
        assert!(
            help.contains(sub),
            "`jig ns --help` must mention `{sub}`:\n{help}"
        );
    }
}

#[test]
fn resolve_without_a_nameserver_fails_with_an_actionable_message() {
    let home = tempfile::tempdir().unwrap();
    write_cli_toml(home.path());

    let (ok, output) = run_jig(home.path(), &["ns", "resolve", "dj@dj.jig"]);
    assert!(
        !ok,
        "must exit non-zero when there is no nameserver: {output}"
    );
    assert!(
        output.contains("--nameserver"),
        "error must say how to supply one: {output}"
    );
}

#[test]
fn resolve_against_a_dead_nameserver_exits_non_zero() {
    let home = tempfile::tempdir().unwrap();
    write_cli_toml(home.path());

    let (ok, output) = run_jig(
        home.path(),
        &[
            "ns",
            "resolve",
            "dj@dj.jig",
            "--nameserver",
            CLOSED_PORT_URL,
        ],
    );
    assert!(!ok, "unreachable nameserver must not exit 0: {output}");
    assert!(
        output.contains("127.0.0.1:1"),
        "error must name the URL it tried: {output}"
    );
}

#[test]
fn list_against_a_dead_nameserver_exits_non_zero() {
    let home = tempfile::tempdir().unwrap();
    write_cli_toml(home.path());

    let (ok, output) = run_jig(
        home.path(),
        &["ns", "list", "--nameserver", CLOSED_PORT_URL],
    );
    assert!(!ok, "unreachable nameserver must not exit 0: {output}");
}
