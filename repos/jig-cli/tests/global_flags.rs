//! Global-flag plumbing: `--server`, `--config`, `--did`.
//!
//! Before this suite existed, all three flags were parsed by clap and then
//! silently discarded by every subcommand that mattered: `cmd/common.rs`
//! re-read `~/.jig/cli.toml` from scratch, and `main.rs` only applied
//! `cli.server` *after* Init/Keys/Server/Channel had already dispatched and
//! returned. A teammate running
//! `jig --server http://100.x.y.z:7117 channel list` got results from their
//! own local config instead — no error, wrong server.
//!
//! Every assertion here works the same way: point the override at
//! **port 1** (nothing listens there, and it's privileged so nothing ever
//! will) and point the config file at a *different* port. The resulting
//! connection error names exactly one of them, which is a direct read-out
//! of which URL the command actually used.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Port nothing listens on — the override target.
const CLOSED_PORT_URL: &str = "http://127.0.0.1:1";
/// Port the *config file* points at, so a stale-config read is visible.
const CONFIG_PORT: &str = "7999";

/// Write a `<home>/.jig/cli.toml` with a known server port and DID.
fn write_cli_toml(home: &Path, base_url: &str, did: &str) {
    let cfg_dir = home.join(".jig");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(
        cfg_dir.join("cli.toml"),
        format!(
            "[server]\nbase_url = \"{base_url}\"\n\n\
             [user]\ndid = \"{did}\"\ndisplay_name = \"test\"\n\
             default_channel = \"#general\"\n"
        ),
    )
    .unwrap();
}

/// Run `jig` with a redirected HOME, killing it if it outlives `timeout`.
///
/// `tail` blocks forever once connected, so a regression that made it
/// reach a *live* server would hang the suite rather than fail it. The
/// kill-and-report path turns that into a normal assertion failure.
fn run_jig(home: &Path, args: &[&str], timeout: Duration) -> (bool, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(args)
        .env("HOME", home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let started = Instant::now();
    let status = loop {
        match child.try_wait().unwrap() {
            Some(status) => break Some(status),
            None if started.elapsed() >= timeout => {
                let _ = child.kill();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }
    let _ = child.wait();

    let success = status.map(|s| s.success()).unwrap_or_else(|| {
        panic!("`jig {}` did not exit within {timeout:?}", args.join(" "));
    });
    (success, stdout, stderr)
}

fn short() -> Duration {
    Duration::from_secs(20)
}

/// Assert the command failed against the override URL, not the config URL.
fn assert_used_override(args: &[&str], success: bool, stdout: &str, stderr: &str) {
    let combined = format!("{stdout}{stderr}");
    assert!(
        !success,
        "`jig {}` should fail against a closed port. output=\n{combined}",
        args.join(" ")
    );
    assert!(
        !combined.contains("panicked"),
        "`jig {}` must not panic. output=\n{combined}",
        args.join(" ")
    );
    assert!(
        combined.contains("127.0.0.1:1"),
        "`jig {}` must report the --server override (port 1). output=\n{combined}",
        args.join(" ")
    );
    assert!(
        !combined.contains(CONFIG_PORT),
        "`jig {}` used cli.toml's port {CONFIG_PORT} — the --server override was ignored. \
         output=\n{combined}",
        args.join(" ")
    );
}

/// `jig init` with a redirected HOME, so later commands have a real keyfile.
fn init_identity(home: &Path) {
    let (ok, stdout, stderr) = run_jig(home, &["init", "tester"], short());
    assert!(ok, "jig init failed. stdout={stdout} stderr={stderr}");
}

/// The DID `jig init` bound in `~/.jig/cli.toml`.
fn initialized_did(home: &Path) -> String {
    let body = std::fs::read_to_string(home.join(".jig").join("cli.toml")).unwrap();
    body.lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("did = \"")?
                .strip_suffix('"')
                .map(str::to_owned)
        })
        .expect("cli.toml binds a did")
}

// ---- --server ---------------------------------------------------------------

#[test]
fn server_flag_overrides_config_for_channel_list() {
    // `channel list` signs its request, so like `send` it loads the identity
    // before it dials and needs a real keyfile to get as far as the URL.
    let tmp = tempfile::tempdir().unwrap();
    init_identity(tmp.path());
    let (ok, out, err) = run_jig(
        tmp.path(),
        &["server", "set", &format!("http://127.0.0.1:{CONFIG_PORT}")],
        short(),
    );
    assert!(ok, "server set failed. stdout={out} stderr={err}");

    let args = ["--server", CLOSED_PORT_URL, "channel", "list"];
    let (ok, out, err) = run_jig(tmp.path(), &args, short());
    assert_used_override(&args, ok, &out, &err);
}

#[test]
fn server_flag_overrides_config_for_server_info() {
    let tmp = tempfile::tempdir().unwrap();
    write_cli_toml(
        tmp.path(),
        &format!("http://127.0.0.1:{CONFIG_PORT}"),
        "did:jig:zfake",
    );

    let args = ["--server", CLOSED_PORT_URL, "server", "info"];
    let (ok, out, err) = run_jig(tmp.path(), &args, short());
    assert_used_override(&args, ok, &out, &err);
}

#[test]
fn server_flag_overrides_config_for_send() {
    // `send` loads the identity before it dials, so this needs a real
    // keyfile — otherwise the run dies at identity-load and never reveals
    // which URL it would have used.
    let tmp = tempfile::tempdir().unwrap();
    init_identity(tmp.path());
    let (ok, out, err) = run_jig(
        tmp.path(),
        &["server", "set", &format!("http://127.0.0.1:{CONFIG_PORT}")],
        short(),
    );
    assert!(ok, "server set failed. stdout={out} stderr={err}");

    let args = ["--server", CLOSED_PORT_URL, "send", "hi"];
    let (ok, out, err) = run_jig(tmp.path(), &args, short());
    assert_used_override(&args, ok, &out, &err);
}

#[test]
fn server_flag_overrides_config_for_tail() {
    let tmp = tempfile::tempdir().unwrap();
    init_identity(tmp.path());
    let (ok, out, err) = run_jig(
        tmp.path(),
        &["server", "set", &format!("http://127.0.0.1:{CONFIG_PORT}")],
        short(),
    );
    assert!(ok, "server set failed. stdout={out} stderr={err}");

    let args = ["--server", CLOSED_PORT_URL, "tail", "--channel", "#hello"];
    let (ok, out, err) = run_jig(tmp.path(), &args, Duration::from_secs(20));
    assert_used_override(&args, ok, &out, &err);
}

#[test]
fn global_server_flag_does_not_leak_into_saved_config() {
    // `--server` is a per-invocation override, not a config edit. If it
    // leaked into `save_config`, `jig --server <peer> server set <url>`
    // would silently rewrite the operator's base_url to the peer.
    let tmp = tempfile::tempdir().unwrap();
    let (ok, out, err) = run_jig(
        tmp.path(),
        &[
            "--server",
            CLOSED_PORT_URL,
            "server",
            "set",
            "http://b.example:5678",
        ],
        short(),
    );
    assert!(ok, "server set failed. stdout={out} stderr={err}");

    let body = std::fs::read_to_string(tmp.path().join(".jig").join("cli.toml")).unwrap();
    assert!(
        body.contains("base_url = \"http://b.example:5678\""),
        "server set must persist its own argument. body=\n{body}"
    );
    assert!(
        !body.contains("127.0.0.1:1"),
        "the --server override must not be written to cli.toml. body=\n{body}"
    );
}

// ---- --did ------------------------------------------------------------------

#[test]
fn did_flag_overrides_config_for_channel_join() {
    // `cmd/channel.rs` used to carry its own private copy of
    // `load_active_identity()` that read cli.toml directly, so `--did` was
    // invisible to it. The identity-load error names the DID it tried, which
    // is how we observe which one won.
    let tmp = tempfile::tempdir().unwrap();
    write_cli_toml(
        tmp.path(),
        &format!("http://127.0.0.1:{CONFIG_PORT}"),
        "did:jig:zConfigDid",
    );

    let (ok, out, err) = run_jig(
        tmp.path(),
        &["--did", "did:jig:zOverrideDid", "channel", "join", "#hello"],
        short(),
    );
    let combined = format!("{out}{err}");
    assert!(
        !ok,
        "join with a bogus DID should fail. output=\n{combined}"
    );
    assert!(
        combined.contains("zOverrideDid"),
        "--did override must be the DID channel.rs tries to load. output=\n{combined}"
    );
    assert!(
        !combined.contains("zConfigDid"),
        "channel.rs used cli.toml's DID — the --did override was ignored. output=\n{combined}"
    );
}

// ---- --config ---------------------------------------------------------------

#[test]
fn explicit_config_path_that_does_not_exist_is_a_hard_error() {
    // `config::load_config` silently falls back to `Config::default()` when
    // the path is missing. That's correct for the implicit `~/.jig/cli.toml`
    // (a first run legitimately has none) but is a silent-wrong-server trap
    // when the operator typed the path themselves.
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nope").join("typo.toml");
    let missing_str = missing.to_str().unwrap();

    let (ok, out, err) = run_jig(
        tmp.path(),
        &["--config", missing_str, "send", "hi"],
        short(),
    );
    let combined = format!("{out}{err}");
    assert!(
        !ok,
        "a missing --config path must fail loudly. output=\n{combined}"
    );
    assert!(
        combined.contains("typo.toml"),
        "the error must name the config path the operator typed. output=\n{combined}"
    );
}

#[test]
fn explicit_config_path_is_actually_read() {
    // Positive half of the pair above: a real `--config` file must win over
    // `~/.jig/cli.toml`. `channel list` signs as the configured DID, so the
    // alt config names the identity `init` minted rather than a fake one.
    let tmp = tempfile::tempdir().unwrap();
    init_identity(tmp.path());
    let (ok, out, err) = run_jig(
        tmp.path(),
        &["server", "set", &format!("http://127.0.0.1:{CONFIG_PORT}")],
        short(),
    );
    assert!(ok, "server set failed. stdout={out} stderr={err}");
    let did = initialized_did(tmp.path());

    let alt = tmp.path().join("alt.toml");
    std::fs::write(
        &alt,
        format!(
            "[server]\nbase_url = \"http://127.0.0.1:1\"\n\n\
             [user]\ndid = \"{did}\"\ndisplay_name = \"alt\"\n\
             default_channel = \"#general\"\n"
        ),
    )
    .unwrap();

    let alt_str = alt.to_str().unwrap();
    let args = ["--config", alt_str, "channel", "list"];
    let (ok, out, err) = run_jig(tmp.path(), &args, short());
    assert_used_override(&args, ok, &out, &err);
}

#[test]
fn init_writes_the_explicit_config_path_and_records_the_server_override() {
    // `init` is the one command exempt from the "--config must exist" rule:
    // it CREATES the file. It must create the file the operator NAMED,
    // though — writing to `~/.jig/cli.toml` while reporting success would
    // strand every later `--config` invocation on a missing file.
    let tmp = tempfile::tempdir().unwrap();
    let alt = tmp.path().join("nested").join("alt.toml");
    let alt_str = alt.to_str().unwrap();

    let (ok, out, err) = run_jig(
        tmp.path(),
        &[
            "--config",
            alt_str,
            "--server",
            "http://chosen.example:7117",
            "init",
            "tester",
        ],
        short(),
    );
    assert!(ok, "jig init failed. stdout={out} stderr={err}");

    let body = std::fs::read_to_string(&alt)
        .unwrap_or_else(|e| panic!("init did not write {}: {e}", alt.display()));
    assert!(
        body.contains("base_url = \"http://chosen.example:7117\""),
        "init must record the --server override. body=\n{body}"
    );
    assert!(
        body.contains("did = \"did:jig:z"),
        "init must bind the generated DID. body=\n{body}"
    );
    assert!(
        !tmp.path().join(".jig").join("cli.toml").exists(),
        "init must not also write the default ~/.jig/cli.toml when --config was given"
    );
}

#[test]
fn missing_implicit_config_still_falls_back_to_defaults() {
    // The flip side of the hard error: a first run with no `~/.jig/cli.toml`
    // must still work off `Config::default()` (base_url 127.0.0.1:7117),
    // not refuse to start. `server info` dials without an identity, so it
    // reaches the URL with no keyfile in the way.
    let tmp = tempfile::tempdir().unwrap();
    let (ok, out, err) = run_jig(tmp.path(), &["server", "info"], short());
    let combined = format!("{out}{err}");
    assert!(
        !ok,
        "nothing is listening on the default port, so this should fail. output=\n{combined}"
    );
    assert!(
        combined.contains("7117"),
        "an absent implicit config must fall back to the built-in default \
         (127.0.0.1:7117), not error out. output=\n{combined}"
    );
}
