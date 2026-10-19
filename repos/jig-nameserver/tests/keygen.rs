//! `jig-nameserver keygen` as an operator runs it: stdout is the DID alone,
//! the key file is owner-only, and an existing file is never overwritten.

use std::process::Command;

fn keygen(out: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_jig-nameserver"))
        .args(["keygen", "--out"])
        .arg(out)
        .env("RUST_LOG", "trace")
        .output()
        .expect("runs")
}

#[test]
fn keygen_prints_only_the_did_writes_0600_and_never_overwrites() {
    let dir = std::env::temp_dir().join(format!("jig-ns-keygen-bin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = dir.join("ceremony").join("ns.key");

    let first = keygen(&key);
    assert!(first.status.success(), "{first:?}");
    let stdout = String::from_utf8(first.stdout).unwrap();
    let did = stdout.strip_suffix('\n').expect("one line");
    assert!(did.starts_with("did:jig:z"), "{stdout:?}");
    assert!(
        did.chars()
            .skip("did:jig:z".len())
            .all(|c| c.is_ascii_alphanumeric()),
        "stdout must be the DID and nothing else: {stdout:?}"
    );
    let bytes = std::fs::read(&key).unwrap();
    assert_eq!(bytes.len(), 32);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let second = keygen(&key);
    assert!(
        !second.status.success(),
        "an existing key must not be overwritten"
    );
    assert!(second.stdout.is_empty(), "nothing on stdout on failure");
    assert_eq!(
        std::fs::read(&key).unwrap(),
        bytes,
        "the existing key is untouched"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
