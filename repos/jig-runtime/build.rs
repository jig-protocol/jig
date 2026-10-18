//! Records the wasmtime version this crate is built against, for
//! `jig_runtime::WASMTIME_VERSION`.
//!
//! Read from the workspace `Cargo.lock`, so it is the resolved version rather
//! than a second hand-maintained string that could drift from it. Cargo gives a
//! build script no direct way to see a dependency's resolved version.

use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let lock = find_lockfile(&manifest_dir).unwrap_or_else(|| {
        panic!(
            "no Cargo.lock above {}: jig-runtime needs it to record the wasmtime version",
            manifest_dir.display()
        )
    });
    println!("cargo:rerun-if-changed={}", lock.display());

    let content = std::fs::read_to_string(&lock).expect("read Cargo.lock");
    let versions = locked_versions(&content, "wasmtime");
    match versions.as_slice() {
        [version] => println!("cargo:rustc-env=JIG_WASMTIME_VERSION={version}"),
        [] => panic!("{} has no wasmtime package", lock.display()),
        many => panic!(
            "{} locks several wasmtime versions ({}); the engine identity would be ambiguous",
            lock.display(),
            many.join(", ")
        ),
    }
}

fn find_lockfile(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|dir| dir.join("Cargo.lock"))
        .find(|candidate| candidate.is_file())
}

/// Versions of every `[[package]]` named `name`, in lockfile order.
fn locked_versions(lock: &str, name: &str) -> Vec<String> {
    let wanted = format!("name = \"{name}\"");
    let mut versions = Vec::new();
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() == wanted
            && let Some(version) = lines.next().and_then(|l| {
                l.trim()
                    .strip_prefix("version = \"")
                    .and_then(|v| v.strip_suffix('"'))
            })
        {
            versions.push(version.to_string());
        }
    }
    versions
}
