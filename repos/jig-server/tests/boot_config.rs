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
/// A fixed, public secret: test servers seal their keys with an env slot.
const TEST_SECRET: &str = "jig-server boot tests: a fixed, public secret";

fn server(home: &Path) -> Command {
    let mut cmd = Command::new(server_bin());
    cmd.current_dir(home)
        .env("HOME", home)
        .env("RUST_LOG", "info")
        .env_remove("JIG_KEY_PASSPHRASE")
        .env("JIG_KEY_UNLOCK", "env:JIG_TEST_SERVER_SECRET")
        .env("JIG_TEST_SERVER_SECRET", TEST_SECRET)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn spawn(home: &Path, args: &[&str]) -> Child {
    server(home)
        .args(args)
        .args(["--bind", "127.0.0.1", "--port", "0"])
        .spawn()
        .expect("spawn jig-server")
}

/// Run to exit, failing if it outlives a bound; returns (success, stdout+stderr).
fn run_to_exit(mut child: Child) -> (bool, String) {
    let Some(status) = wait_bounded(&mut child, Duration::from_secs(15)) else {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "expected jig-server to exit\nstderr:\n{}",
            drain_stderr(&mut child)
        );
    };
    let mut out = String::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_string(&mut out);
    }
    out.push_str(&drain_stderr(&mut child));
    (status.success(), out)
}

fn drain_stderr(child: &mut Child) -> String {
    let mut buf = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut buf);
    }
    buf
}

/// A config file with the socket keys and the pipeline sections.
fn valid_config(home: &Path) -> String {
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
"#,
        db = home.join("jig.db").display(),
        key = home.join("server.key").display(),
    )
}

#[test]
fn explicit_config_with_a_typo_is_fatal_and_names_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    // The root keys are valid, so the ONLY thing that can fail here is
    // `[identity]` — `toffu` is not an IdentityMode.
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
    std::fs::write(&cfg, valid_config(dir.path())).unwrap();

    let mut child = spawn(dir.path(), &["--config", cfg.to_str().unwrap()]);
    assert_still_running(&mut child, "a valid --config must boot");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn a_v0_0_2_module_that_cannot_start_is_fatal() {
    // A server without the v0.0.2 module serves only /.well-known/jig,
    // /healthz and /metrics: it passes every health check while accepting and
    // serving nothing. So a module that cannot start must stop the boot.
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(&cfg, valid_config(dir.path())).unwrap();
    // The configured server_did_keyfile exists but holds no key.
    std::fs::write(dir.path().join("server.key"), b"not a key").unwrap();

    let mut child = spawn(dir.path(), &["--config", cfg.to_str().unwrap()]);
    let Some(status) = wait_bounded(&mut child, Duration::from_secs(15)) else {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "a v0.0.2 module that cannot start must be fatal, but the server was still \
             running\nstderr:\n{}",
            drain_stderr(&mut child)
        );
    };
    let stderr = drain_stderr(&mut child);
    assert!(
        !status.success(),
        "expected a non-zero exit, got {status:?}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("v0.0.2 module failed to initialize"),
        "the failure must say what failed; stderr was:\n{stderr}"
    );
}

#[test]
fn a_first_boot_seals_its_key_and_writes_nothing_in_clear() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(&cfg, valid_config(dir.path())).unwrap();
    let mut child = spawn(dir.path(), &["--config", cfg.to_str().unwrap()]);
    assert_still_running(&mut child, "a valid --config must boot");
    let _ = child.kill();
    let _ = child.wait();
    assert!(dir.path().join("server.jigkey").exists());
    assert!(
        !dir.path().join("server.key").exists(),
        "no raw key on disk"
    );
}

#[test]
fn a_new_key_with_nothing_to_seal_it_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(&cfg, valid_config(dir.path())).unwrap();
    let child = server(dir.path())
        .env_remove("JIG_KEY_UNLOCK")
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
        ])
        .spawn()
        .unwrap();
    let (ok, out) = run_to_exit(child);
    assert!(!ok, "{out}");
    assert!(
        out.contains("[keys] unlock"),
        "the refusal says what to set: {out}"
    );
    assert!(!dir.path().join("server.key").exists() && !dir.path().join("server.jigkey").exists());
}

#[cfg(unix)]
#[test]
fn a_raw_key_is_refused_until_sealed_and_keeps_its_did_after() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(&cfg, valid_config(dir.path())).unwrap();
    let raw = dir.path().join("server.key");
    std::fs::write(&raw, [9u8; 32]).unwrap();
    std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (ok, out) = run_to_exit(spawn(dir.path(), &["--config", cfg.to_str().unwrap()]));
    assert!(!ok, "a raw key must not boot: {out}");
    assert!(out.contains("jig-server keys seal"), "{out}");

    let (ok, out) = run_to_exit(
        server(dir.path())
            .args(["--config", cfg.to_str().unwrap(), "keys", "seal"])
            .args(["--slot", "env:JIG_TEST_SERVER_SECRET"])
            .spawn()
            .unwrap(),
    );
    assert!(ok, "{out}");
    let did = jig_core::Did::from_ed25519_pubkey(
        ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .as_bytes(),
    )
    .to_did_jig_string();
    assert!(out.contains(&did), "seal keeps the DID: {out}");
    assert!(!raw.exists(), "the raw key is removed");

    let (ok, out) = run_to_exit(
        server(dir.path())
            .args(["--config", cfg.to_str().unwrap(), "keys", "show"])
            .spawn()
            .unwrap(),
    );
    assert!(
        ok && out.contains(&did) && out.contains("an env slot"),
        "{out}"
    );

    let mut child = spawn(dir.path(), &["--config", cfg.to_str().unwrap()]);
    assert_still_running(&mut child, "the sealed key boots");
    let _ = child.kill();
    let _ = child.wait();
}

/// Under a unit with credentials, `[keys] unlock` must name one of them: a
/// `credential:` file elsewhere is a secret on disk, likely beside the key.
#[test]
fn under_a_unit_with_credentials_a_plain_secret_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(&cfg, valid_config(dir.path())).unwrap();
    let creds = dir.path().join("credentials");
    std::fs::create_dir(&creds).unwrap();
    let outside = dir.path().join("beside-the-key");
    std::fs::write(&outside, TEST_SECRET).unwrap();
    let child = server(dir.path())
        .env(
            "JIG_KEY_UNLOCK",
            format!("credential:{}", outside.display()),
        )
        .env("CREDENTIALS_DIRECTORY", &creds)
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
        ])
        .spawn()
        .unwrap();
    let (ok, out) = run_to_exit(child);
    assert!(!ok, "{out}");
    assert!(out.contains("CREDENTIALS_DIRECTORY"), "{out}");

    // One that systemd handed over is accepted.
    let inside = creds.join("jig-server-key");
    std::fs::write(&inside, TEST_SECRET).unwrap();
    let mut child = server(dir.path())
        .env("JIG_KEY_UNLOCK", format!("credential:{}", inside.display()))
        .env("CREDENTIALS_DIRECTORY", &creds)
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
        ])
        .spawn()
        .unwrap();
    assert_still_running(&mut child, "a credential from $CREDENTIALS_DIRECTORY boots");
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
