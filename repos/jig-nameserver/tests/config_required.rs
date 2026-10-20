//! The nameserver has no default config path: `serve` without `--config` or
//! `JIG_NS_CONFIG` exits non-zero with an error naming both, even when a
//! legacy `~/.jig/config.toml` with a `[nameserver]` table is present.

use std::process::Command;

#[test]
fn serve_without_a_config_names_both_ways_to_give_one() {
    let home = std::env::temp_dir().join(format!("jig-ns-no-config-{}", std::process::id()));
    std::fs::create_dir_all(home.join(".jig")).unwrap();
    std::fs::write(
        home.join(".jig/config.toml"),
        "[nameserver]\nprofile = \"legacy\"\n",
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_jig-nameserver"))
        .arg("serve")
        .env_remove("JIG_NS_CONFIG")
        .env_remove("JIG_CONFIG")
        .env("HOME", &home)
        .current_dir(&home)
        .output()
        .expect("runs");
    assert!(!out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--config") && stderr.contains("JIG_NS_CONFIG"),
        "{stderr}"
    );

    let _ = std::fs::remove_dir_all(&home);
}
