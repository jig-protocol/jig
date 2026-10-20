//! A block project on disk: the directory `jig block new` writes and `jig block build` and
//! `jig block lint` read.
//!
//! The project's `jig-block.toml` names the block and its limits. The built component lands in
//! `target/jig/<name>.wasm`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use jig_core::component_validation::BlockWorld;
use serde::Deserialize;

/// The project file's name.
pub const PROJECT_FILE: &str = "jig-block.toml";

/// The memory limit a new project starts with: 256 pages of 64 KiB, 16 MiB.
pub const DEFAULT_MEMORY_PAGES: u32 = 256;

/// `jig-block.toml`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectFile {
    pub block: BlockSection,
    pub limits: LimitsSection,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BlockSection {
    pub name: String,
    pub version: String,
    pub world: WorldName,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    pub memory_max_pages: u32,
}

/// The worlds a project may declare. Only `renderer` can be built in v0.3; `bot` waits for
/// lane C's host interfaces.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WorldName {
    Renderer,
    Bot,
}

impl WorldName {
    pub fn block_world(self) -> BlockWorld {
        match self {
            WorldName::Renderer => BlockWorld::Renderer,
            WorldName::Bot => BlockWorld::Bot,
        }
    }
}

/// A loaded project.
#[derive(Debug, Clone)]
pub struct Project {
    pub dir: PathBuf,
    pub file: ProjectFile,
}

impl Project {
    /// Load the project in `dir`, which must contain `jig-block.toml`.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(PROJECT_FILE);
        let text = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "no {PROJECT_FILE} in {}; run this in a block project, or create one with \
                 `jig block new <name>`",
                dir.display()
            )
        })?;
        let file: ProjectFile =
            toml::from_str(&text).with_context(|| format!("reading {}", path.display()))?;
        if file.limits.memory_max_pages == 0 {
            bail!("{}: memory_max_pages must be at least 1", path.display());
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            file,
        })
    }

    /// Where `jig block build` writes the component.
    pub fn component_path(&self) -> PathBuf {
        self.dir
            .join("target")
            .join("jig")
            .join(format!("{}.wasm", self.file.block.name))
    }
}

/// A block name: lowercase ASCII letters, digits and `-`, starting with a letter. It is also
/// the Cargo package name, so it must be one Cargo accepts.
pub fn check_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let starts_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !starts_ok || !rest_ok || name.ends_with('-') || name.len() > 64 {
        bail!(
            "`{name}` is not a block name: use lowercase letters, digits and `-`, starting with a \
             letter, at most 64 characters"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["hello", "hello-block", "a1"] {
            check_name(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in ["", "Hello", "1abc", "hello_block", "hello-", "héllo", "a b"] {
            assert!(check_name(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn a_project_file_parses_and_refuses_unknown_keys() {
        let ok = "[block]\nname = \"x\"\nversion = \"0.1.0\"\nworld = \"renderer\"\n\
                  [limits]\nmemory_max_pages = 16\n";
        let file: ProjectFile = toml::from_str(ok).unwrap();
        assert_eq!(file.block.world, WorldName::Renderer);
        assert_eq!(file.limits.memory_max_pages, 16);

        let extra = format!("{ok}fuel = 3\n");
        assert!(toml::from_str::<ProjectFile>(&extra).is_err());
    }
}
