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
    pub analytics: AnalyticsSection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClickHouseSettings {
    pub url: String,
    pub database: String,
    pub table: String,
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClickHouseSection {
    pub url: Option<String>,
    pub database: Option<String>,
    pub table: Option<String>,
}

impl ServerConfig {
    /// Resolve ClickHouse settings from environment and config with precedence: env > config.
    pub fn clickhouse_settings(&self) -> Option<ClickHouseSettings> {
        let env_url = std::env::var("JIG_CLICKHOUSE_URL").ok();
        let env_db = std::env::var("JIG_CLICKHOUSE_DB").ok();
        let env_table = std::env::var("JIG_CLICKHOUSE_TABLE").ok();
        resolve_clickhouse_settings(
            env_url,
            env_db,
            env_table,
            self.analytics.clickhouse.as_ref(),
            &self.analytics.dispatcher,
        )
    }
}

fn resolve_clickhouse_settings(
    env_url: Option<String>,
    env_db: Option<String>,
    env_table: Option<String>,
    cfg: Option<&ClickHouseSection>,
    dispatcher: &DispatcherSection,
) -> Option<ClickHouseSettings> {
    let cfg_url = cfg.and_then(|c| c.url.clone());
    let cfg_db = cfg.and_then(|c| c.database.clone());
    let cfg_table = cfg.and_then(|c| c.table.clone());

    let url = env_url.or(cfg_url)?; // require URL from either env or config; otherwise disabled
    let database = env_db.or(cfg_db).unwrap_or_else(|| "default".into());
    let table = env_table.or(cfg_table).unwrap_or_else(|| "receipts".into());

    Some(ClickHouseSettings {
        url,
        database,
        table,
        queue_capacity: dispatcher.queue_capacity,
        batch_size: dispatcher.batch_size,
        flush_interval_ms: dispatcher.flush_interval_ms,
    })
}

fn map_clickhouse_dsn_to_http(
    dsn: &str,
    database_fallback: &str,
) -> (Option<String>, Option<String>) {
    // Accept forms like:
    //  - tcp://host:9000/db
    //  - clickhouse://host:9000/db
    //  - http(s)://host:port/db
    // Return (http_url, database)
    let mut parts = dsn.splitn(2, "://");
    let scheme = parts.next().unwrap_or("");
    let mut rest = parts.next().unwrap_or(dsn);
    rest = rest.trim_start_matches('/');
    let (host_port, path_db) = match rest.split_once('/') {
        Some((hp, db)) => (hp, Some(db)),
        None => (rest, None),
    };
    let (host, port_opt) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (host_port, None),
    };
    let mut port = port_opt.unwrap_or(match scheme {
        "http" => 80,
        "https" => 443,
        _ => 9000,
    });
    let mut http_scheme = match scheme {
        "https" => "https",
        _ => "http",
    };
    // If tcp/clickhouse default port, prefer HTTP interface on 8123
    if (scheme == "tcp" || scheme == "clickhouse") && port == 9000 {
        port = 8123;
        http_scheme = "http";
    }
    let url = format!("{http_scheme}://{host}:{port}");
    let db = path_db
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| database_fallback.to_string());
    (Some(url), Some(db))
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
            analytics: AnalyticsSection::default(),
        }
    }
}

impl ServerConfig {
    /// Attempt to construct a ServerConfig from a `jig-config` TOML file.
    /// Maps a minimal subset needed by jig-server:
    /// - storage.truth.connection_string -> database_path (when backend = sqlite)
    /// - analytics.clickhouse.{batch_size, flush_interval_secs} -> dispatcher knobs (if present)
    pub fn load_from_jig_config_path(path: &Path) -> std::io::Result<Self> {
        #[derive(serde::Deserialize, Default)]
        struct JigConfigDoc {
            #[serde(default)]
            storage: Option<jig_config::storage::MultiTierStorageConfig>,
            #[serde(default)]
            analytics: Option<jig_config::analytics::AnalyticsConfig>,
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

        // Map analytics dispatcher knobs from clickhouse settings if present
        if let Some(analytics) = &doc.analytics
            && let Some(ch) = &analytics.clickhouse
        {
            // Prefer explicit clickhouse batch/flush if provided
            cfg.analytics.dispatcher.batch_size = ch.batch_size as usize;
            cfg.analytics.dispatcher.flush_interval_ms = (ch.flush_interval_secs as u64) * 1000;
            // Also map clickhouse connection into config for server wiring
            let (url_opt, db_opt) = map_clickhouse_dsn_to_http(&ch.dsn, &ch.database);
            cfg.analytics.clickhouse = Some(ClickHouseSection {
                url: url_opt,
                database: db_opt,
                table: None,
            });
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

#[cfg(test)]
mod jig_config_bridge_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn maps_sqlite_path_and_clickhouse_dispatcher_knobs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jig-config.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"[storage.truth]
backend = "sqlite"
connection_string = "{db}"

[analytics]
backend = "clickhouse"

[analytics.clickhouse]
dsn = "tcp://localhost:9000"
database = "jig_analytics"
batch_size = 512
flush_interval_secs = 2
"#,
            db = dir.path().join("test.db").display()
        )
        .unwrap();

        let cfg = ServerConfig::load_from_jig_config_path(&path).unwrap();
        assert_eq!(cfg.database_path, dir.path().join("test.db"));
        assert_eq!(cfg.analytics.dispatcher.batch_size, 512);
        assert_eq!(cfg.analytics.dispatcher.flush_interval_ms, 2000);
    }

    #[test]
    fn resolves_clickhouse_settings_precedence_and_defaults() {
        let dispatcher = DispatcherSection {
            queue_capacity: 42,
            batch_size: 7,
            flush_interval_ms: 99,
        };
        let cfg_ch = ClickHouseSection {
            url: Some("http://cfg-host:8123".into()),
            database: Some("cfg_db".into()),
            table: None,
        };
        let s1 = resolve_clickhouse_settings(None, None, None, Some(&cfg_ch), &dispatcher).unwrap();
        assert_eq!(s1.url, "http://cfg-host:8123");
        assert_eq!(s1.database, "cfg_db");
        assert_eq!(s1.table, "receipts");
        assert_eq!(s1.queue_capacity, 42);
        assert_eq!(s1.batch_size, 7);
        assert_eq!(s1.flush_interval_ms, 99);

        let s2 = resolve_clickhouse_settings(
            Some("http://env-host:8123".into()),
            Some("env_db".into()),
            Some("env_table".into()),
            Some(&cfg_ch),
            &dispatcher,
        )
        .unwrap();
        assert_eq!(s2.url, "http://env-host:8123");
        assert_eq!(s2.database, "env_db");
        assert_eq!(s2.table, "env_table");
    }

    #[test]
    fn resolves_clickhouse_settings_none_without_url() {
        let dispatcher = DispatcherSection::default();
        let cfg_ch = ClickHouseSection {
            url: None,
            database: None,
            table: None,
        };
        let s = resolve_clickhouse_settings(None, None, None, Some(&cfg_ch), &dispatcher);
        assert!(s.is_none());
        let s2 = resolve_clickhouse_settings(None, None, None, None, &dispatcher);
        assert!(s2.is_none());
    }

    #[test]
    fn maps_clickhouse_dsn_variants() {
        let (u1, d1) = map_clickhouse_dsn_to_http("tcp://ch.local:9000/db", "fallback");
        assert_eq!(u1.unwrap(), "http://ch.local:8123");
        assert_eq!(d1.unwrap(), "db");

        let (u2, d2) = map_clickhouse_dsn_to_http("clickhouse://ch.local:9000", "jig");
        assert_eq!(u2.unwrap(), "http://ch.local:8123");
        assert_eq!(d2.unwrap(), "jig");

        let (u3, d3) = map_clickhouse_dsn_to_http("https://secure.host:8443/prod", "x");
        assert_eq!(u3.unwrap(), "https://secure.host:8443");
        assert_eq!(d3.unwrap(), "prod");

        let (u4, d4) = map_clickhouse_dsn_to_http("http://plain.host/dbname", "y");
        assert_eq!(u4.unwrap(), "http://plain.host:80");
        assert_eq!(d4.unwrap(), "dbname");
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

[analytics]
backend = "clickhouse"

[analytics.clickhouse]
dsn = "tcp://localhost:9000"
database = "jig_cwd"
batch_size = 128
flush_interval_secs = 1
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalyticsSection {
    #[serde(default)]
    pub dispatcher: DispatcherSection,
    #[serde(default)]
    pub clickhouse: Option<ClickHouseSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatcherSection {
    #[serde(default = "default_dispatcher_capacity")]
    pub queue_capacity: usize,
    #[serde(default = "default_dispatcher_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_dispatcher_flush_ms")]
    pub flush_interval_ms: u64,
}

impl Default for DispatcherSection {
    fn default() -> Self {
        Self {
            queue_capacity: default_dispatcher_capacity(),
            batch_size: default_dispatcher_batch_size(),
            flush_interval_ms: default_dispatcher_flush_ms(),
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

fn default_dispatcher_capacity() -> usize {
    1024
}
fn default_dispatcher_batch_size() -> usize {
    256
}
fn default_dispatcher_flush_ms() -> u64 {
    10
}
