//! Jig server binary.

use std::path::{Path, PathBuf};

use clap::Parser;
use jig_config::v0_0_2_server::JigServerConfig;
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

/// Load the v0.0.2 half of the config (`[server]`, `[identity]`,
/// `[federation]`, `[bridges]`, `[debug]`) from the same file `ServerConfig`
/// was read from.
///
/// An EXPLICIT `--config` that fails to parse is an error, never a silent
/// fall back to defaults. Swallowing it discards the operator's entire file:
/// `server_did_keyfile` reverts to the default path, the server mints a FRESH
/// ed25519 identity, and it comes up under a NEW server DID — which breaks
/// TOFU pinning for every already-connected client. The same swallow silently
/// reverts `[bridges]`, federation peers, and `debug.admin_endpoints`.
///
/// `None` (no `--config` given) legitimately means defaults.
fn load_v0_0_2_config(config_path: Option<&Path>) -> Result<JigServerConfig, String> {
    match config_path {
        Some(path) => JigServerConfig::load(path)
            .map_err(|e| format!("v0.0.2 config load from {} failed: {e}", path.display())),
        None => Ok(JigServerConfig::default()),
    }
}

/// `[server] listen` is DECORATIVE: it only builds the `ws://` origin-tag
/// string stamped onto blocks. The socket binds the root-level
/// `bind_address`/`port`. An operator who sets `listen = "0.0.0.0:7117"` and
/// expects a reachable server still gets a loopback-only one, so say so out
/// loud at startup.
///
/// Deliberately a textual comparison — `listen` is a free-form origin tag, and
/// "close enough" spellings (`localhost` vs `127.0.0.1`) still hand clients a
/// URL that differs from what the server advertises elsewhere.
fn listen_disagreement_warning(listen: &str, bind_address: &str, port: u16) -> Option<String> {
    let effective = format!("{bind_address}:{port}");
    if listen == effective {
        return None;
    }
    Some(format!(
        "[server] listen = \"{listen}\" disagrees with the effective bind address {effective}. \
         `listen` is decorative — it only builds the ws:// origin tag; the socket binds \
         bind_address/port. Clients handed ws://{listen} may not reach this server."
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Default to `info` when RUST_LOG is unset: `from_default_env()` alone
    // yields an empty filter, which silences every startup diagnostic below
    // (including the fatal-config and decorative-`listen` warnings).
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let args = Args::parse();

    if let Some(target) = args.init_config {
        ServerConfig::write_template(&target)?;
        println!("Wrote config template to {}", target.display());
        return Ok(());
    }

    let config_path = args.config.clone();
    let mut config = if let Some(path) = &config_path {
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
    // Both halves come from the same --config file: root-level keys drive
    // ServerConfig (which opens the socket), and [server]/[identity]/
    // [federation]/[bridges]/[debug] drive JigServerConfig. Neither type uses
    // deny_unknown_fields, which is what makes one file legal for both.
    let v0_0_2_state = {
        let v002_config = match load_v0_0_2_config(config_path.as_deref()) {
            Ok(cfg) => cfg,
            Err(msg) => {
                // Both sinks on purpose: RUST_LOG can filter tracing away
                // entirely, and an operator who typo'd a key must still be
                // told why the server refused to start.
                tracing::error!("{msg}");
                eprintln!("[jig-server] FATAL: {msg}");
                std::process::exit(1);
            }
        };

        if let Some(warning) = listen_disagreement_warning(
            &v002_config.server.listen,
            &config.bind_address,
            config.port,
        ) {
            tracing::warn!("{warning}");
            eprintln!("[jig-server] WARN: {warning}");
        }

        let db_path = config.database_path.with_file_name(
            config
                .database_path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
                + "_v002.db",
        );
        // The operator's `[execution]` limits live on `ServerConfig`, so they are
        // handed over explicitly — this is what makes the ingest render path honour
        // configured fuel, memory, timeout and concurrency.
        match jig_server::v0_0_2::AppState::new(v002_config, db_path, config.execution_config()) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &tempfile::TempDir, name: &str, body: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn explicit_config_that_fails_to_parse_is_an_error_naming_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "bad.toml", "[identity]\nmode = \"toffu\"\n");

        let err = load_v0_0_2_config(Some(&path)).unwrap_err();
        assert!(
            err.contains(path.to_str().unwrap()),
            "error must name the offending file, got: {err}"
        );
        assert!(
            err.contains("toffu"),
            "error must carry the underlying serde message, got: {err}"
        );
    }

    #[test]
    fn explicit_config_that_parses_is_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            "good.toml",
            "[server]\nserver_did_keyfile = \"/srv/keep-me.key\"\n\n[debug]\nadmin_endpoints = true\n",
        );

        let cfg = load_v0_0_2_config(Some(&path)).unwrap();
        // The whole point: the operator's keyfile must survive. Falling back to
        // defaults here mints a new server DID and breaks TOFU pinning.
        assert_eq!(cfg.server.server_did_keyfile, "/srv/keep-me.key");
        assert!(cfg.debug.admin_endpoints);
    }

    #[test]
    fn missing_config_flag_uses_defaults() {
        let cfg = load_v0_0_2_config(None).unwrap();
        assert_eq!(cfg, JigServerConfig::default());
    }

    #[test]
    fn absent_explicit_config_file_is_still_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.toml");
        // A --config pointing at nothing is a typo'd path, not a request for
        // defaults.
        assert!(load_v0_0_2_config(Some(&path)).is_err());
    }

    #[test]
    fn listen_matching_the_bind_address_is_silent() {
        assert!(listen_disagreement_warning("127.0.0.1:7117", "127.0.0.1", 7117).is_none());
    }

    #[test]
    fn listen_disagreeing_with_the_bind_address_warns() {
        let warning = listen_disagreement_warning("0.0.0.0:7117", "127.0.0.1", 7117)
            .expect("a listen/bind mismatch must warn");
        assert!(warning.contains("0.0.0.0:7117"));
        assert!(warning.contains("127.0.0.1:7117"));
        assert!(warning.contains("decorative"));

        // Port-only drift is the same trap.
        assert!(listen_disagreement_warning("127.0.0.1:7118", "127.0.0.1", 7117).is_some());
    }
}
