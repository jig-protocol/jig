//! `jig block build`: compile a block project into a `jig:block` component.
//!
//! Three steps:
//!
//! 1. `cargo build --release` for `wasm32-unknown-unknown`, with the project's own
//!    `.cargo/config.toml`;
//! 2. wrap the core module as a component with `wit-component`, in this process, so an author
//!    needs no `wasm-tools`;
//! 3. lint the component against `jig-det-1` (see [`super::block_lint`]).
//!
//! The component is written to `target/jig/<name>.wasm` even when the lint fails, so it can be
//! inspected, and the build then fails.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};

use crate::cmd::block_lint::{Lint, lint};
use crate::cmd::block_project::{Project, WorldName};

/// The only target a block builds for.
pub const TARGET: &str = "wasm32-unknown-unknown";

/// What a successful build produced.
#[derive(Debug)]
pub struct Built {
    pub component: PathBuf,
    /// `blake3:<hex>` of the component bytes, as receipts name it.
    pub component_hash: String,
    pub lint: Lint,
}

/// Build the project in `dir`.
pub fn build(dir: &Path) -> Result<Built> {
    let project = Project::load(dir)?;
    if project.file.block.world == WorldName::Bot {
        bail!("bot blocks cannot be built yet; they need the jig:host interfaces (JEP-0007)");
    }
    check_target_installed()?;

    let module = cargo_build(&project.dir)?;
    let module_bytes =
        std::fs::read(&module).with_context(|| format!("reading {}", module.display()))?;
    let component = componentize(&module_bytes)?;

    let out = project.component_path();
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p).with_context(|| format!("creating {}", p.display()))?;
    }
    std::fs::write(&out, &component).with_context(|| format!("writing {}", out.display()))?;

    let lint = lint(
        &component,
        project.file.block.world.block_world(),
        project.file.limits.memory_max_pages,
    )?;
    Ok(Built {
        component: out,
        component_hash: format!("blake3:{}", blake3::hash(&component).to_hex()),
        lint,
    })
}

/// Wrap a core module, carrying `wit-bindgen`'s component-type metadata, as a component.
pub fn componentize(module: &[u8]) -> Result<Vec<u8>> {
    wit_component::ComponentEncoder::default()
        .validate(true)
        .module(module)
        .and_then(|e| e.encode())
        .map_err(|e| {
            anyhow!(
                "could not turn the module into a component: {e:#}\n  hint: the crate must call \
                 `wit_bindgen::generate!` and `export!`"
            )
        })
}

/// Fail early, with the fix, when the target is missing. Skipped when `rustup` is not the
/// toolchain manager; cargo then reports the problem itself.
fn check_target_installed() -> Result<()> {
    let Ok(out) = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .stderr(Stdio::null())
        .output()
    else {
        return Ok(());
    };
    if !out.status.success() {
        return Ok(());
    }
    let installed = String::from_utf8_lossy(&out.stdout);
    if !installed.lines().any(|l| l.trim() == TARGET) {
        bail!("the {TARGET} target is not installed; run: rustup target add {TARGET}");
    }
    Ok(())
}

/// Run cargo and return the path of the `cdylib` it produced.
fn cargo_build(dir: &Path) -> Result<PathBuf> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(dir)
        .args([
            "build",
            "--release",
            "--target",
            TARGET,
            "--message-format=json-render-diagnostics",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    // A parent cargo (`cargo run -p jig-cli`) exports variables that would point this build at
    // the parent's workspace and target directory.
    for var in ["CARGO_TARGET_DIR", "CARGO_MANIFEST_DIR", "CARGO_PKG_NAME"] {
        cmd.env_remove(var);
    }
    let out = cmd.output().context("running cargo; is Rust installed?")?;
    let artifact = find_cdylib(&String::from_utf8_lossy(&out.stdout));
    if !out.status.success() {
        bail!("cargo build failed (its errors are above)");
    }
    artifact.ok_or_else(|| {
        anyhow!("cargo built no .wasm; Cargo.toml needs `[lib] crate-type = [\"cdylib\"]`")
    })
}

/// The last `.wasm` file in cargo's JSON messages for a `cdylib` target.
fn find_cdylib(messages: &str) -> Option<PathBuf> {
    let mut found = None;
    for line in messages.lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if msg["reason"] != "compiler-artifact" {
            continue;
        }
        let is_cdylib = msg["target"]["kind"]
            .as_array()
            .is_some_and(|k| k.iter().any(|v| v == "cdylib"));
        if !is_cdylib {
            continue;
        }
        if let Some(files) = msg["filenames"].as_array() {
            for f in files.iter().filter_map(|f| f.as_str()) {
                if f.ends_with(".wasm") {
                    found = Some(PathBuf::from(f));
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cdylib_is_found_among_cargo_messages() {
        let messages = [
            r#"{"reason":"compiler-artifact","target":{"kind":["lib"]},"filenames":["/t/libdep.rlib"]}"#,
            "not json",
            r#"{"reason":"compiler-artifact","target":{"kind":["cdylib"]},"filenames":["/t/hello.wasm"]}"#,
            r#"{"reason":"build-finished","success":true}"#,
        ]
        .join("\n");
        assert_eq!(find_cdylib(&messages), Some(PathBuf::from("/t/hello.wasm")));
        assert_eq!(find_cdylib(r#"{"reason":"build-finished"}"#), None);
    }

    #[test]
    fn a_module_without_component_metadata_is_refused_with_a_hint() {
        let module = wat::parse_str("(module (memory 1 1))").unwrap();
        // A module with no wit-bindgen metadata componentizes to a component that exports
        // nothing; either way it must not pass as a renderer.
        match componentize(&module) {
            Err(e) => assert!(e.to_string().contains("wit_bindgen"), "{e}"),
            Ok(component) => {
                let l = lint(
                    &component,
                    jig_core::component_validation::BlockWorld::Renderer,
                    1,
                )
                .unwrap();
                assert!(!l.passes());
            }
        }
    }
}
