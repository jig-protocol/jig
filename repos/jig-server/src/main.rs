//! Jig server binary.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use jig_server::{JigServer, ServerConfig};

#[derive(Debug, Subcommand)]
enum AnalyticsCmd {
    /// Export receipts in a time range to a Parquet file (feature: analytics_parquet)
    #[cfg(feature = "analytics_parquet")]
    ExportParquet {
        /// Output Parquet file path
        #[arg(long)]
        out: PathBuf,
        /// Time range: last_hour | last_day | last_week | last_month | custom
        #[arg(long)]
        range: Option<String>,
        /// Start timestamp (unix seconds), required if range=custom
        #[arg(long)]
        start_ts: Option<i64>,
        /// End timestamp (unix seconds), required if range=custom
        #[arg(long)]
        end_ts: Option<i64>,
        /// Compression: zstd | snappy | gzip | lz4 | uncompressed
        #[arg(long, default_value = "zstd")]
        compression: String,
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Jig executable internet server")]
struct Args {
    /// Optional path to a TOML configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Write a configuration template to the given path and exit.
    #[arg(long)]
    init_config: Option<PathBuf>,

    /// Override the database path.
    #[arg(long)]
    db_path: Option<PathBuf>,

    /// Override bind address.
    #[arg(long)]
    bind: Option<String>,

    /// Override port.
    #[arg(long)]
    port: Option<u16>,

    /// Analytics commands (feature-gated behaviors)
    #[command(subcommand)]
    command: Option<AnalyticsCmd>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    if let Some(target) = args.init_config {
        ServerConfig::write_template(&target)?;
        println!("Wrote config template to {}", target.display());
        return Ok(());
    }

    let mut config = if let Some(path) = args.config {
        ServerConfig::load(path)?
    } else {
        // Precedence: jig-config in CWD or ~/.jig/config.toml, then defaults
        ServerConfig::try_load_jig_config_from_well_known().unwrap_or_default()
    };

    let env_db = std::env::var("JIG_DB_PATH").ok().map(PathBuf::from);
    config.apply_overrides_explicit(args.db_path, env_db, args.bind, args.port);

    if let Some(cmd) = args.command {
        return cli_handle_command(cmd, &config);
    }

    tracing::info!("Starting Jig server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Database: {}", config.database_path.display());

    // Build the v0.0.2 pipeline AppState alongside the existing ServerConfig.
    // Uses JigServerConfig::default() for D2 — full config loading arrives in
    // later D tasks. The important thing here is proving the wiring works: when
    // this succeeds, the /.well-known/jig response includes server_did, etc.
    let v0_0_2_state = {
        use jig_config::v0_0_2_server::JigServerConfig;
        let v002_config = JigServerConfig::default();
        let db_path = config.database_path.with_file_name(
            config
                .database_path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
                + "_v002.db",
        );
        match jig_server::v0_0_2::AppState::new(v002_config, db_path) {
            Ok(state) => {
                let state = std::sync::Arc::new(state);
                tracing::info!(
                    "v0.0.2 module active: server_did = {}",
                    state.server_did.to_did_jig_string()
                );
                for opt in state.config.unsafe_options_active() {
                    tracing::warn!("v0.0.2 unsafe option active: {}", opt);
                }
                Some(state)
            }
            Err(e) => {
                tracing::warn!("v0.0.2 module failed to initialize, running without it: {e}");
                None
            }
        }
    };

    // Spawn one long-running federation task per configured [[federation.peers]] entry.
    // Done before handing state to JigServer so we hold a clone while the Arc is still
    // available. Tasks are fire-and-forget (reconnect internally on disconnect).
    if let Some(ref state) = v0_0_2_state {
        jig_server::v0_0_2_federation::spawn_federation_peers(state.clone());
    }

    let server = JigServer::new_with_v0_0_2(config, v0_0_2_state)?;
    server.start().await?;

    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_time_range_cli(
    range: Option<String>,
    start_ts: Option<i64>,
    end_ts: Option<i64>,
) -> Result<jig_server::TimeRange, Box<dyn std::error::Error>> {
    let r = range
        .unwrap_or_else(|| "last_day".to_string())
        .to_ascii_lowercase();
    Ok(match r.as_str() {
        "last_hour" => jig_server::TimeRange::LastHour,
        "last_day" => jig_server::TimeRange::LastDay,
        "last_week" => jig_server::TimeRange::LastWeek,
        "last_month" => jig_server::TimeRange::LastMonth,
        "custom" => {
            let s = start_ts.ok_or("custom range requires --start-ts")?;
            let e = end_ts.ok_or("custom range requires --end-ts")?;
            jig_server::TimeRange::Custom {
                start_ts: s,
                end_ts: e,
            }
        }
        _ => return Err("invalid range value".into()),
    })
}

#[cfg(feature = "analytics_parquet")]
fn cli_handle_command(
    cmd: AnalyticsCmd,
    config: &ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        AnalyticsCmd::ExportParquet {
            out,
            range,
            start_ts,
            end_ts,
            compression,
        } => handle_export_parquet(config, out, range, start_ts, end_ts, compression),
    }
}

#[cfg(not(feature = "analytics_parquet"))]
fn cli_handle_command(
    _cmd: AnalyticsCmd,
    _config: &ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("no analytics subcommands available without features".into())
}

#[cfg_attr(not(test), allow(dead_code))]
#[cfg(feature = "analytics_parquet")]
fn handle_export_parquet(
    config: &ServerConfig,
    out: PathBuf,
    range: Option<String>,
    start_ts: Option<i64>,
    end_ts: Option<i64>,
    compression: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use jig_server::SqliteBlockStore;
    use jig_server::analytics::parquet::ParquetExporter;

    let store = SqliteBlockStore::new(&config.database_path)?;
    let tr = parse_time_range_cli(range, start_ts, end_ts)?;
    let exporter = ParquetExporter::new(&out, Some(&compression))?;
    exporter.write_receipts_from_store(&store, tr)?;
    println!("Wrote Parquet to {}", out.display());
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
#[cfg(not(feature = "analytics_parquet"))]
fn handle_export_parquet(
    _config: &ServerConfig,
    _out: PathBuf,
    _range: Option<String>,
    _start_ts: Option<i64>,
    _end_ts: Option<i64>,
    _compression: String,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("analytics_parquet feature is required for export-parquet".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_time_range_defaults_last_day() {
        let tr = parse_time_range_cli(None, None, None).unwrap();
        assert!(matches!(tr, jig_server::TimeRange::LastDay));
    }

    #[test]
    fn parse_time_range_custom_requires_bounds() {
        let e1 = parse_time_range_cli(Some("custom".into()), None, Some(10)).unwrap_err();
        assert!(e1.to_string().contains("start"));
        let e2 = parse_time_range_cli(Some("custom".into()), Some(0), None).unwrap_err();
        assert!(e2.to_string().contains("end"));
    }

    #[cfg(not(feature = "analytics_parquet"))]
    #[test]
    fn parquet_export_requires_feature() {
        let cfg = ServerConfig::default();
        let res = handle_export_parquet(
            &cfg,
            PathBuf::from("/tmp/out.parquet"),
            None,
            None,
            None,
            "zstd".into(),
        );
        assert!(res.is_err());
        assert!(res.err().unwrap().to_string().contains("feature"));
    }

    #[cfg(feature = "analytics_parquet")]
    #[test]
    fn parquet_export_writes_file() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let mut cfg = ServerConfig::default();
        cfg.database_path = dir.path().join("test.db");
        let out = dir.path().join("out.parquet");
        handle_export_parquet(&cfg, out.clone(), None, None, None, "zstd".into()).unwrap();
        let meta = std::fs::metadata(out).unwrap();
        assert!(meta.is_file());
    }
}
