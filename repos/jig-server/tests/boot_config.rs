//! Boot-time config handling, driven through the REAL `jig-server` binary.
//!
//! These live at process level because the property under test is an exit
//! code, not a return value: an operator who passes `--config` and typos a key
//! must get a dead server, not a running one that silently discarded their
//! whole file (and, with `server_did_keyfile` reverted to the default, minted
//! a brand-new server DID that breaks TOFU pinning for every pinned client).
//!
//! Every child process is given an isolated HOME + cwd so nothing here can
//! read or write the developer's real `~/.jig`.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_jig-server")
}

/// Spawn jig-server with an isolated HOME/cwd and an ephemeral port.
fn spawn(home: &Path, args: &[&str]) -> Child {
    Command::new(server_bin())
        .args(args)
        .args(["--bind", "127.0.0.1", "--port", "0"])
        .current_dir(home)
        .env("HOME", home)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn jig-server")
}

fn drain_stderr(child: &mut Child) -> String {
    let mut buf = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut buf);
    }
    buf
}

/// Config file that parses cleanly as BOTH halves of the hybrid shape.
fn valid_hybrid_config(home: &Path) -> String {
    format!(
        r#"
database_path = "{db}"
bind_address = "127.0.0.1"
port = 0

[server]
listen = "127.0.0.1:0"
server_did_keyfile = "{key}"
allowed_block_kinds = ["text-render", "channel-create", "member-add"]

[identity]
mode = "tofu"
trusted_nameservers = []
cache_ttl_seconds = 300

[debug]
admin_endpoints = true
"#,
        db = home.join("jig.db").display(),
        key = home.join("server.key").display(),
    )
}

#[test]
fn explicit_config_with_a_typo_is_fatal_and_names_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    // Root keys are valid ServerConfig, so the ONLY thing that can fail here
    // is the v0.0.2 half — `toffu` is not an IdentityMode.
    std::fs::write(
        &cfg,
        format!(
            "database_path = \"{db}\"\nbind_address = \"127.0.0.1\"\nport = 0\n\n[identity]\nmode = \"toffu\"\n",
            db = dir.path().join("jig.db").display()
        ),
    )
    .unwrap();

    let mut child = spawn(dir.path(), &["--config", cfg.to_str().unwrap()]);
    // Bounded wait, NOT `child.wait()`: before this was fixed the server booted
    // happily on the typo'd file and the blocking wait hung the whole test run
    // (816s to SIGTERM) instead of failing.
    let Some(status) = wait_bounded(&mut child, Duration::from_secs(15)) else {
        // Kill BEFORE draining: reading stderr to EOF on a live child hangs too.
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "a malformed --config must be fatal, but the server was still running\nstderr:\n{}",
            drain_stderr(&mut child)
        );
    };
    let stderr = drain_stderr(&mut child);

    assert!(
        !status.success(),
        "a malformed --config must exit non-zero, got {status:?}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains(cfg.to_str().unwrap()),
        "the failure must name the offending file; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("toffu") || stderr.contains("identity"),
        "the failure must surface the underlying parse error; stderr was:\n{stderr}"
    );
}

#[test]
fn valid_explicit_config_still_boots() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(&cfg, valid_hybrid_config(dir.path())).unwrap();

    let mut child = spawn(dir.path(), &["--config", cfg.to_str().unwrap()]);
    assert_still_running(&mut child, "a valid --config must boot");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn no_config_flag_still_uses_defaults() {
    // Defaults are legitimate when the operator never passed --config; only an
    // EXPLICIT path that fails to load is fatal.
    let dir = tempfile::tempdir().unwrap();
    let mut child = spawn(dir.path(), &[]);
    assert_still_running(&mut child, "no --config must fall back to defaults");
    let _ = child.kill();
    let _ = child.wait();
}

/// Wait up to `limit` for the child to exit. `None` means it outlived the
/// deadline — the caller is responsible for killing it.
fn wait_bounded(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Poll for up to 3s; fail if the child exits in that window.
fn assert_still_running(child: &mut Child, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                let stderr = drain_stderr(child);
                panic!("{what}, but it exited with {status:?}\nstderr:\n{stderr}");
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}
