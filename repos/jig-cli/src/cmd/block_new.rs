//! `jig block new`: write a block project from a template.
//!
//! The project builds for `wasm32-unknown-unknown` with `wit-bindgen`, and is set up to pass the
//! determinism profile `jig-det-1` as written: no WASI, a declared memory maximum, no floats in
//! the template code. The `jig:block` WIT is copied out of this binary, so a project always
//! targets the ABI version this `jig` runs.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::cmd::block_project::{DEFAULT_MEMORY_PAGES, PROJECT_FILE, check_name};

/// The `jig:block` package this binary runs (JEP-0006).
pub const BLOCK_WIT: &str = include_str!("../../../jig-spec/wit/jig-block/block.wit");

/// The `wit-bindgen` version templates pin: the one this workspace builds `text-block` with.
pub const WIT_BINDGEN_VERSION: &str = "0.51.0";

const RENDERER_CARGO: &str = include_str!("../../templates/renderer/Cargo.toml.tmpl");
const RENDERER_CARGO_CONFIG: &str = include_str!("../../templates/renderer/cargo-config.toml");
const RENDERER_PROJECT: &str = include_str!("../../templates/renderer/jig-block.toml.tmpl");
const RENDERER_LIB: &str = include_str!("../../templates/renderer/lib.rs.tmpl");
const GITIGNORE: &str = include_str!("../../templates/renderer/gitignore");
const RENDERER_VECTOR: &str = include_str!("../../templates/renderer/vector.toml");

/// The templates `jig block new` offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Template {
    /// A pure renderer: message in, rendered payload out.
    Renderer,
}

/// Write a new project named `name` into `parent/name`, or into `dir` if given. Returns the
/// project directory.
pub fn new_block(
    name: &str,
    template: Template,
    parent: &Path,
    dir: Option<&Path>,
) -> Result<PathBuf> {
    check_name(name)?;
    let root = match dir {
        Some(d) => d.to_path_buf(),
        None => parent.join(name),
    };
    if root.exists()
        && root
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(true)
    {
        bail!(
            "{} already exists and is not empty; choose another name or --dir",
            root.display()
        );
    }

    let files = match template {
        Template::Renderer => renderer_files(name),
    };
    for (rel, contents) in &files {
        let path = root.join(rel);
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).with_context(|| format!("creating {}", p.display()))?;
        }
        std::fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(root)
}

/// The renderer template's files, relative to the project root.
fn renderer_files(name: &str) -> Vec<(&'static str, String)> {
    let pages = DEFAULT_MEMORY_PAGES;
    let bytes = u64::from(pages) * 64 * 1024;
    let fill = |t: &str| {
        t.replace("{{name}}", name)
            .replace("{{crate}}", name)
            .replace("{{wit_bindgen}}", WIT_BINDGEN_VERSION)
            .replace("{{memory_pages}}", &pages.to_string())
            .replace("{{memory_bytes}}", &bytes.to_string())
    };
    vec![
        ("Cargo.toml", fill(RENDERER_CARGO)),
        (".cargo/config.toml", fill(RENDERER_CARGO_CONFIG)),
        (PROJECT_FILE, fill(RENDERER_PROJECT)),
        ("src/lib.rs", fill(RENDERER_LIB)),
        ("wit/block.wit", BLOCK_WIT.to_string()),
        (".gitignore", GITIGNORE.to_string()),
        ("tests/vectors/hello.toml", RENDERER_VECTOR.to_string()),
    ]
}

/// What to print after `new`.
pub fn next_steps(root: &Path) -> String {
    format!(
        "Created {}\n\nNext:\n  cd {}\n  # edit src/lib.rs\n  jig block build\n",
        root.display(),
        root.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::block_project::{Project, WorldName};

    #[test]
    fn a_new_renderer_project_loads_and_has_no_placeholders_left() {
        let tmp = tempfile::tempdir().unwrap();
        let root = new_block("hello", Template::Renderer, tmp.path(), None).unwrap();
        assert_eq!(root, tmp.path().join("hello"));

        let project = Project::load(&root).unwrap();
        assert_eq!(project.file.block.name, "hello");
        assert_eq!(project.file.block.world, WorldName::Renderer);
        assert_eq!(project.file.limits.memory_max_pages, DEFAULT_MEMORY_PAGES);
        assert_eq!(project.component_path(), root.join("target/jig/hello.wasm"));

        for (rel, _) in renderer_files("hello") {
            let text = std::fs::read_to_string(root.join(rel)).unwrap();
            assert!(!text.contains("{{"), "{rel} still has a placeholder");
        }
        let config = std::fs::read_to_string(root.join(".cargo/config.toml")).unwrap();
        assert!(config.contains("--max-memory=16777216"), "{config}");
        assert!(config.contains("wasm32-unknown-unknown"), "{config}");
        let cargo = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert!(cargo.contains("wit-bindgen = \"=0.51.0\""), "{cargo}");
    }

    #[test]
    fn the_copied_wit_is_the_block_package() {
        assert!(BLOCK_WIT.contains("package jig:block@0.1.0;"));
        assert!(BLOCK_WIT.contains("world renderer"));
    }

    #[test]
    fn new_refuses_a_non_empty_directory_and_a_bad_name() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("taken")).unwrap();
        std::fs::write(tmp.path().join("taken/file"), "x").unwrap();
        assert!(new_block("taken", Template::Renderer, tmp.path(), None).is_err());
        assert!(new_block("Bad_Name", Template::Renderer, tmp.path(), None).is_err());
    }
}
