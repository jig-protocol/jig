//! `jig block run` runs components only. A core module, which used to run on the legacy ABI,
//! is refused before any config is read, and the message says how to make a component.

#![cfg(feature = "local-runtime")]

use std::process::Command;

#[test]
fn a_core_module_is_refused_with_how_to_make_a_component() {
    let dir = tempfile::tempdir().unwrap();
    let wasm = dir.path().join("core.wasm");
    // The smallest core module: the magic number and version 1, no sections.
    std::fs::write(&wasm, b"\0asm\x01\0\0\0").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_jig"))
        .args(["block", "run"])
        .arg(&wasm)
        // No cli.toml: the refusal must not depend on one.
        .env("HOME", dir.path())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("is a core module; `jig block build` makes a component"),
        "{stderr}"
    );
}

#[test]
fn the_core_module_only_flags_are_gone() {
    for flag in ["--seed", "--memory", "--cap", "--receipt", "--pricing"] {
        let out = Command::new(env!("CARGO_BIN_EXE_jig"))
            .args(["block", "run", ".", flag])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{flag}: {stderr}");
        assert!(stderr.contains("unexpected argument"), "{flag}: {stderr}");
    }
}
