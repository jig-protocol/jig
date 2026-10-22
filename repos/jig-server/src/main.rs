//! Jig server binary.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
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

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// The server's own signing key.
    Keys {
        #[command(subcommand)]
        keys: KeysCommand,
    },
}

#[derive(Subcommand, Debug)]
enum KeysCommand {
    /// Seal a raw 32-byte keyfile, written by an older jig-server, into a
    /// .jigkey beside it, then remove the raw file. The DID does not change.
    Seal {
        /// The raw keyfile. Defaults to `[server] server_did_keyfile`.
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// A slot to seal it with: credential:PATH, env:NAME, or passphrase
        /// (read from JIG_KEY_PASSPHRASE). Repeat for more than one, for
        /// example a credential to boot with and a passphrase kept offline to
        /// restore with on another machine.
        #[arg(long = "slot", required = true)]
        slots: Vec<String>,
    },
    /// Add a slot to the sealed key, opening it with `[keys] unlock`,
    /// JIG_KEY_UNLOCK or JIG_KEY_PASSPHRASE.
    AddSlot {
        /// The keyfile. Defaults to `[server] server_did_keyfile`.
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// The slot to add: credential:PATH, env:NAME or passphrase.
        #[arg(long)]
        slot: String,
    },
    /// Print the DID of the sealed key and which slots open it.
    Show {
        /// The keyfile. Defaults to `[server] server_did_keyfile`.
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    /// Check that one secret opens the key, trying nothing configured: for
    /// an offline passphrase or a new machine's credential, before relying
    /// on it.
    Verify {
        /// The keyfile. Defaults to `[server] server_did_keyfile`.
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// The slot to try: credential:PATH, env:NAME or passphrase.
        #[arg(long)]
        slot: String,
    },
    /// Make a new key, sealed with every slot named, where there is none. It
    /// is never written in clear and never overwrites a key. Prints the DID.
    Generate {
        /// The keyfile. Defaults to `[server] server_did_keyfile`.
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// A slot to seal it with: credential:PATH, env:NAME, or passphrase
        /// (read from JIG_KEY_PASSPHRASE). Repeatable.
        #[arg(long = "slot", required = true)]
        slots: Vec<String>,
    },
}

/// `jig-server keys ...`: works on the key file only, never starts the server.
fn run_keys(keys: KeysCommand, config: &ServerConfig) -> Result<String, String> {
    use jig_client::server_key::KeysAction;
    let or_configured = |keyfile: Option<PathBuf>| {
        keyfile.unwrap_or_else(|| {
            PathBuf::from(shellexpand::tilde(&config.server.server_did_keyfile).into_owned())
        })
    };
    let action = match keys {
        KeysCommand::Seal { keyfile, slots } => KeysAction::Seal {
            keyfile: or_configured(keyfile),
            slots,
        },
        KeysCommand::AddSlot { keyfile, slot } => KeysAction::AddSlot {
            keyfile: or_configured(keyfile),
            slot,
        },
        KeysCommand::Show { keyfile } => KeysAction::Show {
            keyfile: or_configured(keyfile),
        },
        KeysCommand::Verify { keyfile, slot } => KeysAction::Verify {
            keyfile: or_configured(keyfile),
            slot,
        },
        KeysCommand::Generate { keyfile, slots } => KeysAction::Generate {
            keyfile: or_configured(keyfile),
            slots,
        },
    };
    jig_client::server_key::run(action, &jig_server::v0_0_2::key_options(&config.keys))
        .map_err(|e| e.to_string())
}

/// Load the `--config` file.
///
/// An EXPLICIT `--config` that fails to parse is an error, never a silent
/// fall back to defaults. Swallowing it discards the operator's entire file:
/// `server_did_keyfile` reverts to the default path, the server mints a FRESH
/// ed25519 identity, and it comes up under a NEW server DID — which breaks
/// TOFU pinning for every already-connected client. The same swallow silently
/// reverts `[bridges]`, federation peers, and `[debug]`.
///
/// `None` (no `--config` given) legitimately means defaults.
fn load_config(config_path: Option<&Path>) -> Result<ServerConfig, String> {
    match config_path {
        Some(path) => ServerConfig::load(path)
            .map_err(|e| format!("config load from {} failed: {e}", path.display())),
        None => {
            warn_on_ignored_legacy_config_files();
            Ok(ServerConfig::default())
        }
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

/// Without `--config` the server used to read `[storage.truth]` from
/// `./jig-config.toml` or `~/.jig/config.toml` to pick its database path. It no
/// longer does; a server that relied on that would now open a fresh database
/// at the default path, so say so when one of those files is present.
fn warn_on_ignored_legacy_config_files() {
    let candidates = [
        std::env::current_dir()
            .ok()
            .map(|d| d.join("jig-config.toml")),
        Some(jig_config::default_config_path()),
    ];
    for path in candidates.into_iter().flatten().filter(|p| p.exists()) {
        let msg = format!(
            "ignoring {}: jig-server reads only --config; pass --config (or --db-path / \
             JIG_DB_PATH) to choose the database",
            path.display()
        );
        tracing::warn!("{msg}");
        eprintln!("[jig-server] WARN: {msg}");
    }
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

    let mut config = match load_config(args.config.as_deref()) {
        Ok(cfg) => cfg,
        Err(msg) => {
            // Both sinks on purpose: RUST_LOG can filter tracing away
            // entirely, and an operator who typo'd a key must still be told
            // why the server refused to start.
            tracing::error!("{msg}");
            eprintln!("[jig-server] FATAL: {msg}");
            std::process::exit(1);
        }
    };

    if let Some(Command::Keys { keys }) = args.command {
        match run_keys(keys, &config) {
            Ok(out) => println!("{out}"),
            Err(msg) => {
                eprintln!("[jig-server] {msg}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    let env_db = std::env::var("JIG_DB_PATH").ok().map(PathBuf::from);
    config.apply_overrides_explicit(args.db_path, env_db, args.bind, args.port);

    tracing::info!("Starting Jig server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Database: {}", config.database_path.display());
    for opt in config.unsafe_options_active() {
        tracing::warn!("unsafe option active: {opt} (loopback or local testing only)");
    }

    // Build the v0.0.2 pipeline AppState from the config's pipeline sections.
    let v0_0_2_state = {
        let v002_config = config.v0_0_2();

        // A plaintext federation peer nobody opted into stops the boot, loudly,
        // rather than surfacing only as "v0.0.2 module failed to initialize".
        if let Err(e) =
            jig_server::v0_0_2_federation::check_federation_transport(&v002_config.federation)
        {
            let msg = format!("federation config rejected: {e}");
            tracing::error!("{msg}");
            eprintln!("[jig-server] FATAL: {msg}");
            std::process::exit(1);
        }

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
                // Before serving: write the receipt of every text-render block
                // that landed without one because the server stopped between
                // landing it and rendering it.
                match jig_pipeline::ingest::backfill_render_receipts(&state.ingest_ctx).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!("wrote {n} receipt(s) owed from before the restart"),
                    Err(e) => tracing::warn!("receipt backfill failed: {e}"),
                }
                for opt in state.config.unsafe_options_active() {
                    tracing::warn!("v0.0.2 unsafe option active: {}", opt);
                }
                Some(state)
            }
            Err(e) => {
                // Fatal: without the v0.0.2 module the server would serve only
                // /.well-known/jig, /healthz and /metrics, which reads as "up"
                // to every health check while accepting and serving nothing.
                let msg = format!("v0.0.2 module failed to initialize: {e:#}");
                tracing::error!("{msg}");
                eprintln!("[jig-server] FATAL: {msg}");
                std::process::exit(1);
            }
        }
    };

    // Spawn one long-running federation task per configured [[federation.peers]] entry.
    // Done before handing state to JigServer so we hold a clone while the Arc is still
    // available. Tasks are fire-and-forget (reconnect internally on disconnect).
    if let Some(ref state) = v0_0_2_state {
        // Before anything is served: every welcome cites the current manifest
        // (JEP-0002 rule 12), and a server that cannot keep its log must not
        // pretend to.
        if let Err(e) = jig_server::v0_0_2_manifest_log::publish(state).await {
            let msg = format!("manifest log: {e:#}");
            tracing::error!("{msg}");
            eprintln!("[jig-server] FATAL: {msg}");
            std::process::exit(1);
        }
        // The contract's frames are handled from the first connection on.
        jig_server::v0_0_2_contract::start(state);
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
        let path = write(
            &dir,
            "bad.toml",
            "database_path = \"/tmp/x.db\"\nbind_address = \"127.0.0.1\"\nport = 7117\n\n[identity]\nmode = \"toffu\"\n",
        );

        let err = load_config(Some(&path)).unwrap_err();
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
            "database_path = \"/tmp/x.db\"\nbind_address = \"127.0.0.1\"\nport = 7117\n\n[server]\nserver_did_keyfile = \"/srv/keep-me.key\"\n\n[debug]\nlist_handles = true\n",
        );

        let cfg = load_config(Some(&path)).unwrap();
        // The whole point: the operator's keyfile must survive. Falling back to
        // defaults here mints a new server DID and breaks TOFU pinning.
        assert_eq!(cfg.server.server_did_keyfile, "/srv/keep-me.key");
        assert!(cfg.debug.list_handles);
    }

    #[test]
    fn missing_config_flag_uses_defaults() {
        let cfg = load_config(None).unwrap();
        assert_eq!(cfg.v0_0_2(), ServerConfig::default().v0_0_2());
    }

    #[test]
    fn absent_explicit_config_file_is_still_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.toml");
        // A --config pointing at nothing is a typo'd path, not a request for
        // defaults.
        assert!(load_config(Some(&path)).is_err());
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
