use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// Phase 0: Foundation & Types (2025-11-04)
pub mod execution;
pub mod profiles;

// Phase 2: Storage Tier Separation (2025-11-04)
pub mod storage;

// Phase 3: Receipt & Canonicalization Configuration (2025-11-04)
pub mod receipt;

// Phase 4: Pricing & Fuel Band Configuration (2025-11-04)
pub mod pricing;

// Phase 5: Nameserver & Federation Configuration (2025-11-05)
pub mod nameserver;

// Phase 6: Analytics & Telemetry Configuration (2025-11-05)
pub mod analytics;

// Phase 7: Audit & Compliance Logging (2025-11-04)
pub mod audit;

// Phase 8: Export & Interoperability (2025-11-04)
pub mod interop;

// Phase 9: Bridge-Specific Configuration (2025-11-04)
pub mod bridges;

// Phase 10: Template Generation & Validation (2025-11-05)
pub mod templates;
pub mod validation;

// v0.0.2 hello-world server config (jig-server boot path)
pub mod v0_0_2_server;
pub use v0_0_2_server::{
    DebugSection, FederationPeer, FederationSection, IdentityMode, IdentitySection,
    JigServerConfig, ServerSection,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    Wasmtime,
    Podman,
    Docker,
    Local,
}

impl std::str::FromStr for EngineKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "wasmtime" => Ok(Self::Wasmtime),
            "podman" => Ok(Self::Podman),
            "docker" => Ok(Self::Docker),
            "local" => Ok(Self::Local),
            _ => Err(format!("unknown engine kind: {s}")),
        }
    }
}

impl EngineKind {
    /// Parse an engine kind from a string (convenience wrapper for FromStr).
    pub fn parse(s: &str) -> Option<Self> {
        s.parse().ok()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeCommon {
    pub engine: Option<String>,
    pub target: Option<String>,
    #[serde(default)]
    pub inherit_stdio: bool,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WasmtimePreopen {
    pub host: String,
    pub guest: String,
    pub directory_permissions: Option<String>,
    pub file_permissions: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WasmtimeOptions {
    pub fuel: Option<u64>,
    #[serde(default)]
    pub preopened: Vec<WasmtimePreopen>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PodmanOptions {
    pub network: Option<String>,
    #[serde(default)]
    pub mounts: Vec<ContainerMount>,
    #[serde(rename = "dangerously-run_as_root")]
    pub dangerously_run_as_root: Option<bool>,
    #[serde(rename = "shamefully-disable_userns_remap")]
    pub shamefully_disable_userns_remap: Option<bool>,
    pub pull_policy: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DockerOptions {
    pub network: Option<String>,
    #[serde(default)]
    pub mounts: Vec<ContainerMount>,
    pub dangerously_run_as_root: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerMount {
    pub host: String,
    pub container: String,
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub runtime: RuntimeSection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeSection {
    #[serde(flatten)]
    pub common: RuntimeCommon,
    #[serde(default)]
    pub wasmtime: WasmtimeOptions,
    #[serde(default)]
    pub podman: PodmanOptions,
    #[serde(default)]
    pub docker: DockerOptions,
}

impl RuntimeConfig {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let s = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.as_ref().display()))?;
        let cfg: Self = toml::from_str(&s).context("parsing jig-config TOML")?;
        Ok(cfg)
    }

    pub fn load_default() -> Result<Self> {
        let path = default_config_path();
        Self::load_from_path(path)
    }
}

pub fn default_config_path() -> PathBuf {
    // Reuse CLI path convention: ~/.jig/config.toml
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".jig").join("config.toml")
}
