//! Configuration handling for the Jig server.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::runtime::ExecutionConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub database_path: PathBuf,
    pub bind_address: String,
    pub port: u16,
    #[serde(default = "default_host_id")]
    pub host_id: String,
    #[serde(default)]
    pub execution: ExecutionSection,
    #[serde(default)]
    pub tls: TlsConfig,
}

/// Opt-in TLS for the public HTTPS edge. Absent / `enabled = false` keeps the
/// server on plaintext HTTP (the localhost dev default). The operator supplies
/// a static cert + key (e.g. from certbot or a Cloudflare origin cert).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

impl TlsConfig {
    /// `(cert_path, key_path)` when both are present; an error otherwise. The
    /// server calls this only when `enabled`, so a missing path is a
    /// misconfiguration that must fail loudly at startup.
    pub fn resolved_paths(&self) -> Result<(&PathBuf, &PathBuf), String> {
        match (&self.cert_path, &self.key_path) {
            (Some(cert), Some(key)) => Ok((cert, key)),
            _ => Err("[tls] enabled = true requires both cert_path and key_path".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSection {
    #[serde(default = "default_fuel_max")]
    pub fuel_max: u64,
    #[serde(default = "default_memory_max_mb")]
    pub memory_max_mb: u32,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub pricing_enabled: bool,
    #[serde(default)]
    pub cost_per_fuel: Option<f64>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let jig_dir = PathBuf::from(home).join(".jig");
        Self {
            database_path: jig_dir.join("jig.db"),
            bind_address: "127.0.0.1".into(),
            port: 7117,
            host_id: default_host_id(),
            execution: ExecutionSection::default(),
            tls: TlsConfig::default(),
        }
    }
}

impl ServerConfig {
    /// Attempt to construct a ServerConfig from a `jig-config` TOML file.
    /// Maps a minimal subset needed by jig-server:
    /// - storage.truth.connection_string -> database_path (when backend = sqlite)
    pub fn load_from_jig_config_path(path: &Path) -> std::io::Result<Self> {
        #[derive(serde::Deserialize, Default)]
        struct JigConfigDoc {
            #[serde(default)]
            storage: Option<jig_config::storage::MultiTierStorageConfig>,
        }

        let s = fs::read_to_string(path)?;
        let doc: JigConfigDoc = toml::from_str(&s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut cfg = ServerConfig::default();

        // Map storage.truth -> database_path (sqlite path)
        if let Some(storage) = &doc.storage
            && let Some(truth) = &storage.truth
        {
            use jig_config::storage::Backend;
            if matches!(truth.backend, Backend::Sqlite)
                && let Some(path) = &truth.connection_string
            {
                cfg.database_path = PathBuf::from(path);
            }
        }

        Ok(cfg)
    }

    /// Try to load jig-config from common locations (cwd ./jig-config.toml or ~/.jig/config.toml).
    pub fn try_load_jig_config_from_well_known() -> Option<Self> {
        let cwd = std::env::current_dir().ok();
        if let Some(mut p) = cwd.clone() {
            p.push("jig-config.toml");
            if p.exists()
                && let Ok(cfg) = Self::load_from_jig_config_path(&p)
            {
                return Some(cfg);
            }
        }
        let home_default = jig_config::default_config_path();
        if home_default.exists()
            && let Ok(cfg) = Self::load_from_jig_config_path(&home_default)
        {
            return Some(cfg);
        }
        None
    }

    /// Pure helper for tests: try to load from exactly these two potential files in order.
    pub fn try_load_jig_config_from_paths(cwd_config: &Path, home_config: &Path) -> Option<Self> {
        if cwd_config.exists()
            && let Ok(cfg) = Self::load_from_jig_config_path(cwd_config)
        {
            return Some(cfg);
        }
        if home_config.exists()
            && let Ok(cfg) = Self::load_from_jig_config_path(home_config)
        {
            return Some(cfg);
        }
        None
    }
}

impl Default for ExecutionSection {
    fn default() -> Self {
        Self {
            fuel_max: default_fuel_max(),
            memory_max_mb: default_memory_max_mb(),
            timeout_ms: default_timeout_ms(),
            pricing_enabled: false,
            cost_per_fuel: None,
        }
    }
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config = toml::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    pub fn write_template(path: impl AsRef<Path>) -> std::io::Result<()> {
        let template = toml::to_string_pretty(&Self::default()).map_err(std::io::Error::other)?;
        fs::write(path, template)
    }

    pub fn execution_config(&self) -> ExecutionConfig {
        ExecutionConfig {
            fuel_max: self.execution.fuel_max,
            memory_max_mb: self.execution.memory_max_mb,
            timeout_ms: self.execution.timeout_ms,
            host_id: self.host_id.clone(),
            pricing_enabled: self.execution.pricing_enabled,
            cost_per_fuel: self.execution.cost_per_fuel,
        }
    }

    /// Apply explicit overrides with precedence: CLI > ENV > existing (jig-config/defaults)
    pub fn apply_overrides_explicit(
        &mut self,
        cli_db: Option<PathBuf>,
        env_db: Option<PathBuf>,
        cli_bind: Option<String>,
        cli_port: Option<u16>,
    ) {
        if let Some(db) = cli_db.or(env_db) {
            self.database_path = db;
        }
        if let Some(bind) = cli_bind {
            self.bind_address = bind;
        }
        if let Some(port) = cli_port {
            self.port = port;
        }
    }
}

fn default_host_id() -> String {
    "did:jig:server:local".into()
}

fn default_fuel_max() -> u64 {
    5_000_000
}

fn default_memory_max_mb() -> u32 {
    64
}

fn default_timeout_ms() -> u64 {
    250
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_defaults_disabled() {
        let cfg = ServerConfig::default();
        assert!(!cfg.tls.enabled);
        assert!(cfg.tls.resolved_paths().is_err());
    }

    #[test]
    fn tls_section_parses() {
        let toml_str = r#"
            database_path = "/tmp/x.db"
            bind_address = "0.0.0.0"
            port = 443
            [tls]
            enabled = true
            cert_path = "/etc/jig/tls/fullchain.pem"
            key_path = "/etc/jig/tls/privkey.pem"
        "#;
        let cfg: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.tls.enabled);
        let (cert, key) = cfg.tls.resolved_paths().unwrap();
        assert_eq!(cert.to_str().unwrap(), "/etc/jig/tls/fullchain.pem");
        assert_eq!(key.to_str().unwrap(), "/etc/jig/tls/privkey.pem");
    }

    #[test]
    fn tls_enabled_without_paths_is_error() {
        let toml_str = r#"
            database_path = "/tmp/x.db"
            bind_address = "0.0.0.0"
            port = 443
            [tls]
            enabled = true
        "#;
        let cfg: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.tls.resolved_paths().is_err());
    }
}

#[cfg(test)]
mod jig_config_bridge_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn maps_sqlite_path_from_jig_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jig-config.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"[storage.truth]
backend = "sqlite"
connection_string = "{db}"
"#,
            db = dir.path().join("test.db").display()
        )
        .unwrap();

        let cfg = ServerConfig::load_from_jig_config_path(&path).unwrap();
        assert_eq!(cfg.database_path, dir.path().join("test.db"));
    }

    #[test]
    fn apply_overrides_explicit_precedence() {
        let mut cfg = ServerConfig::default();
        let env_db = Some(PathBuf::from("/tmp/env.db"));
        cfg.apply_overrides_explicit(None, env_db.clone(), None, None);
        assert_eq!(cfg.database_path, PathBuf::from("/tmp/env.db"));
        let cli_db = Some(PathBuf::from("/tmp/cli.db"));
        cfg.apply_overrides_explicit(cli_db.clone(), None, Some("0.0.0.0".into()), Some(8123));
        assert_eq!(cfg.database_path, PathBuf::from("/tmp/cli.db"));
        assert_eq!(cfg.bind_address, "0.0.0.0");
        assert_eq!(cfg.port, 8123);
    }

    #[test]
    fn write_template_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server-config.toml");
        ServerConfig::write_template(&path).unwrap();
        let loaded = ServerConfig::load(&path).unwrap();
        assert!(!loaded.bind_address.is_empty());
        let exec = loaded.execution_config();
        assert_eq!(exec.fuel_max, loaded.execution.fuel_max);
        assert_eq!(exec.timeout_ms, loaded.execution.timeout_ms);
    }

    #[test]
    fn jig_config_paths_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let cwd_cfg = dir.path().join("cwd.toml");
        let home_cfg = dir.path().join("home.toml");

        {
            let mut f = std::fs::File::create(&cwd_cfg).unwrap();
            writeln!(
                f,
                r#"[storage.truth]
backend = "sqlite"
connection_string = "{db}"
"#,
                db = dir.path().join("cwd.db").display()
            )
            .unwrap();
        }

        {
            let mut f = std::fs::File::create(&home_cfg).unwrap();
            writeln!(
                f,
                r#"[storage.truth]
backend = "sqlite"
connection_string = "{db}"
"#,
                db = dir.path().join("home.db").display()
            )
            .unwrap();
        }

        let cfg1 = ServerConfig::try_load_jig_config_from_paths(&cwd_cfg, &home_cfg).unwrap();
        assert_eq!(cfg1.database_path, dir.path().join("cwd.db"));

        std::fs::remove_file(&cwd_cfg).unwrap();
        let cfg2 = ServerConfig::try_load_jig_config_from_paths(&cwd_cfg, &home_cfg).unwrap();
        assert_eq!(cfg2.database_path, dir.path().join("home.db"));
    }
}
