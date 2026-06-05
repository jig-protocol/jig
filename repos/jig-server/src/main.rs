//! Jig server binary.

use std::path::PathBuf;

use clap::Parser;
use jig_server::{JigServer, ServerConfig};

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
        // Start config-permitted bridges before the router is built (they mount
        // their HTTP routes into bridge_router_mount, which build_v0_0_2_router
        // drains). A bridge that fails to start is logged and skipped inside.
        if let Err(e) = jig_server::v0_0_2_bridges::start_configured_bridges(state).await {
            tracing::warn!("error starting configured bridges: {e}");
        }
    }

    let server = JigServer::new_with_v0_0_2(config, v0_0_2_state)?;
    server.start().await?;

    Ok(())
}
