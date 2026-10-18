//! Smoke test for `jig init` (Phase F1, v0.0.2 hello-world).
//!
//! Drives the compiled binary with a redirected `HOME` and asserts:
//!   * exactly one keyfile lands under `<HOME>/.jig/keys/`
//!   * its filename starts with `did:jig:z` (canonical DID form)
//!   * on Unix, its permissions are mode 0600
//!   * `<HOME>/.jig/cli.toml` is written with the supplied nickname
//!     and the canonical DID from the keyfile
//!
//! Note: on macOS, `dirs::home_dir()` reads from the `HOME` environment
//! variable, so overriding `HOME` for a child process is sufficient to
//! redirect both `default_keys_dir()` and `default_config_path()` into
//! the tempdir. If you see the test scribble in your real `~/.jig/`,
//! something is off — bail out and investigate before re-running.

use std::process::Command;

#[test]
fn init_generates_keypair_under_jig_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        // Never the developer's real keychain; seal test keys with a fixed secret.
        .env("JIG_KEYCHAIN", "none")
        .env("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")
        .env(
            "JIG_TEST_KEY_SECRET",
            "jig cli tests: a fixed, public secret",
        )
        .args(["init", "dj"])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "jig init exited non-zero. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let keys_dir = tmp.path().join(".jig").join("keys");
    let entries: Vec<_> = std::fs::read_dir(&keys_dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", keys_dir.display()))
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one keyfile under {}",
        keys_dir.display()
    );
    let keyfile = entries[0].path();
    let filename = keyfile.file_name().unwrap().to_str().unwrap();
    assert!(
        filename.starts_with("did:jig:z"),
        "keyfile name must be canonical DID: got {filename}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&keyfile).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "keyfile must be mode 0600, got {mode:o}");
    }
}

#[test]
fn init_writes_cli_toml_with_nickname_and_did() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        // Never the developer's real keychain; seal test keys with a fixed secret.
        .env("JIG_KEYCHAIN", "none")
        .env("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")
        .env(
            "JIG_TEST_KEY_SECRET",
            "jig cli tests: a fixed, public secret",
        )
        .args(["init", "dj"])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "jig init exited non-zero. stderr={}",
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
        body.contains("display_name = \"dj\""),
        "cli.toml missing nickname binding. body=\n{body}"
    );
    assert!(
        body.contains("did = \"did:jig:z"),
        "cli.toml must bind a canonical DID. body=\n{body}"
    );
}

#[test]
fn init_refuses_to_clobber_existing_config_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    // First init succeeds.
    let first = Command::new(env!("CARGO_BIN_EXE_jig"))
        // Never the developer's real keychain; seal test keys with a fixed secret.
        .env("JIG_KEYCHAIN", "none")
        .env("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")
        .env(
            "JIG_TEST_KEY_SECRET",
            "jig cli tests: a fixed, public secret",
        )
        .args(["init", "dj"])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(first.status.success());

    // Second init without --force must fail.
    let second = Command::new(env!("CARGO_BIN_EXE_jig"))
        // Never the developer's real keychain; seal test keys with a fixed secret.
        .env("JIG_KEYCHAIN", "none")
        .env("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")
        .env(
            "JIG_TEST_KEY_SECRET",
            "jig cli tests: a fixed, public secret",
        )
        .args(["init", "dj"])
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    assert!(
        !second.status.success(),
        "second init without --force should fail, but exited 0. stdout={}",
        String::from_utf8_lossy(&second.stdout)
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("--force") || stderr.contains("already exists"),
        "stderr should mention --force or existing config. got: {stderr}"
    );
}

/// With no keychain, no terminal and nothing in the environment to seal a key
/// with, `jig init` refuses, with the exit status `install.sh` matches (78),
/// and leaves no key behind.
#[test]
fn init_with_no_way_to_seal_exits_78_and_writes_no_key() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jig"))
        .env("HOME", tmp.path())
        .env("JIG_KEYCHAIN", "none")
        .env("JIG_NONINTERACTIVE", "1")
        .env_remove("JIG_KEY_PASSPHRASE")
        .env_remove("JIG_KEY_UNLOCK")
        .env_remove("JIG_KEYS_STORAGE")
        .args(["init", "tester"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(78), "{output:?}");
    let keys = tmp.path().join(".jig/keys");
    let left = std::fs::read_dir(&keys).map(|d| d.count()).unwrap_or(0);
    assert_eq!(left, 0, "no key file may be left behind");
}
