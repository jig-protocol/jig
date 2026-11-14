//! A nameserver that cannot open its key says why and what to run, not only
//! "loading nameserver signing key": the whole cause chain reaches stderr.
//! (Before, an upgraded nameserver with a raw key exited with that line alone.)

use std::path::{Path, PathBuf};
use std::process::Command;

/// A fresh directory for one test, as `config_required.rs` makes one.
fn fresh_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("jig-ns-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn serve(dir: &Path) -> String {
    std::fs::write(
        dir.join("ns.toml"),
        "[[v0_0_2.nameserver.alias_suffixes]]\nsuffix = \"key-errors.example.org\"\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_jig-nameserver"))
        .args(["serve", "--config"])
        .arg(dir.join("ns.toml"))
        .env("JIG_NS_DB_PATH", dir.join("ns.db"))
        .env("JIG_NS_BIND", "127.0.0.1")
        .env("JIG_NS_PORT", "0")
        .env_remove("JIG_KEY_UNLOCK")
        .env_remove("JIG_KEY_PASSPHRASE")
        .env_remove("JIG_NS_CONFIG")
        .output()
        .expect("runs");
    assert!(!out.status.success(), "{out:?}");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn no_key_and_nothing_to_seal_one_with_names_the_ways_to_give_one() {
    let dir = fresh_dir("no-key");
    let stderr = serve(&dir);
    assert!(
        stderr.contains("loading nameserver signing key: no nameserver key at"),
        "{stderr}"
    );
    assert!(
        stderr.contains("JIG_KEY_UNLOCK or JIG_KEY_PASSPHRASE"),
        "{stderr}"
    );
    // Its own table: a `[keys]` table stops a nameserver from starting.
    assert!(stderr.contains("set [v0_0_2.keys] unlock"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_raw_key_from_an_older_release_names_the_command_that_seals_it() {
    let dir = fresh_dir("raw-key");
    std::fs::write(dir.join("ns_v002.key"), [7u8; 32]).unwrap();
    let stderr = serve(&dir);
    assert!(stderr.contains("is a raw nameserver key"), "{stderr}");
    assert!(stderr.contains("jig-nameserver keys seal"), "{stderr}");
    assert!(stderr.contains("set [v0_0_2.keys] unlock"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
