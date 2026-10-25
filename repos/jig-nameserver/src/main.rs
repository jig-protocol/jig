//! Jig Nameserver binary

use clap::{Parser, Subcommand};
use jig_nameserver::config::NameServerConfig;
use jig_nameserver::server::run_http_server;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Config file (env JIG_NS_CONFIG). Required to serve; there is no
    /// default path.
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the nameserver HTTP server (default)
    Serve {
        /// Bind address (env JIG_NS_BIND)
        #[arg(long)]
        bind: Option<String>,

        /// Port (env JIG_NS_PORT)
        #[arg(long)]
        port: Option<u16>,
    },

    /// Write a new nameserver signing key and print only its DID. For a key
    /// ceremony: run it offline and record the DID before any server exists.
    /// Never overwrites an existing file.
    Keygen {
        /// Where to write the key (created 0600): a `.jigkey`, or a path
        /// whose `.jigkey` sibling is meant
        #[arg(long)]
        out: std::path::PathBuf,
        /// A slot to seal it with: passphrase (read from JIG_KEY_PASSPHRASE),
        /// credential:PATH or env:NAME. Repeatable. For a ceremony, a
        /// passphrase; add the server's credential on the server with
        /// `keys add-slot`.
        #[arg(long = "slot", required = true)]
        slots: Vec<String>,
    },

    /// The nameserver's own signing key
    Keys {
        #[command(subcommand)]
        keys: KeysCommand,
    },
}

#[derive(Subcommand, Debug)]
enum KeysCommand {
    /// Seal a raw 32-byte keyfile, written by an older jig-nameserver, into
    /// a .jigkey beside it, then remove the raw file. The DID does not change.
    Seal {
        /// The raw keyfile. Defaults to the configured one.
        #[arg(long)]
        keyfile: Option<std::path::PathBuf>,
        /// A slot to seal it with: credential:PATH, env:NAME, or passphrase
        /// (read from JIG_KEY_PASSPHRASE). Repeatable.
        #[arg(long = "slot", required = true)]
        slots: Vec<String>,
    },
    /// Add a slot to the sealed key, opening it with `[v0_0_2.keys] unlock`,
    /// JIG_KEY_UNLOCK or JIG_KEY_PASSPHRASE.
    AddSlot {
        /// The keyfile. Defaults to the configured one.
        #[arg(long)]
        keyfile: Option<std::path::PathBuf>,
        /// The slot to add: credential:PATH, env:NAME or passphrase.
        #[arg(long)]
        slot: String,
    },
    /// Print the DID of the sealed key and which slots open it.
    Show {
        /// The keyfile. Defaults to the configured one.
        #[arg(long)]
        keyfile: Option<std::path::PathBuf>,
    },
    /// Check that one secret opens the key, trying nothing configured: for
    /// an offline passphrase or a new machine's credential, before relying
    /// on it.
    Verify {
        /// The keyfile. Defaults to the configured one.
        #[arg(long)]
        keyfile: Option<std::path::PathBuf>,
        /// The slot to try: credential:PATH, env:NAME or passphrase.
        #[arg(long)]
        slot: String,
    },
    /// Make a new key, sealed with every slot named, at the configured path
    /// (`keygen` takes any path). Never written in clear; never overwrites.
    Generate {
        /// The keyfile. Defaults to the configured one.
        #[arg(long)]
        keyfile: Option<std::path::PathBuf>,
        /// A slot to seal it with: credential:PATH, env:NAME, or passphrase
        /// (read from JIG_KEY_PASSPHRASE). Repeatable.
        #[arg(long = "slot", required = true)]
        slots: Vec<String>,
    },
}

/// `jig-nameserver keys ...`: works on the key file only. The keyfile and
/// `[v0_0_2.keys]` come from the same config `serve` reads (`--config` or
/// `JIG_NS_CONFIG`). With `--keyfile` and no config named at all, as on an
/// offline ceremony machine, it runs without one: only the environment
/// (`JIG_KEY_UNLOCK`, `JIG_KEY_PASSPHRASE`) opens the key. A config that is
/// named is always loaded, and an error in it is an error here.
fn run_keys(keys: KeysCommand, config: Option<&std::path::Path>) -> Result<String, String> {
    use jig_client::server_key::KeysAction;
    let keyfile = match &keys {
        KeysCommand::Seal { keyfile, .. }
        | KeysCommand::AddSlot { keyfile, .. }
        | KeysCommand::Show { keyfile }
        | KeysCommand::Verify { keyfile, .. }
        | KeysCommand::Generate { keyfile, .. } => keyfile.clone(),
    };
    let named = config.is_some() || std::env::var_os("JIG_NS_CONFIG").is_some();
    let config = if keyfile.is_some() && !named {
        NameServerConfig::default()
    } else {
        NameServerConfig::load(config).map_err(|e| e.to_string())?
    };
    let keyfile = keyfile.unwrap_or_else(|| {
        std::path::PathBuf::from(
            shellexpand::tilde(&jig_nameserver::server::resolve_v0_0_2_keyfile(&config))
                .into_owned(),
        )
    });
    let action = match keys {
        KeysCommand::Seal { slots, .. } => KeysAction::Seal { keyfile, slots },
        KeysCommand::AddSlot { slot, .. } => KeysAction::AddSlot { keyfile, slot },
        KeysCommand::Show { .. } => KeysAction::Show { keyfile },
        KeysCommand::Verify { slot, .. } => KeysAction::Verify { keyfile, slot },
        KeysCommand::Generate { slots, .. } => KeysAction::Generate { keyfile, slots },
    };
    jig_client::server_key::run(
        action,
        &jig_nameserver::v0_0_2::key_options(&config.v0_0_2.keys),
    )
    .map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Before any logging is set up, so stdout carries the DID and nothing else.
    if let Some(Command::Keygen { out, slots }) = &cli.command {
        match jig_nameserver::v0_0_2::keygen(out, slots) {
            Ok(did) => {
                println!("{did}");
                if slots.len() == 1 {
                    // stderr: stdout carries the DID and nothing else.
                    eprintln!(
                        "warning: the key has one slot; add a second (`jig-nameserver keys \
                         add-slot`) before relying on it, or losing that secret loses the key"
                    );
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(1);
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match cli.command {
        // If no command specified, run the server
        None => serve(cli.config.as_deref(), None, None).await,

        Some(Command::Serve { bind, port }) => serve(cli.config.as_deref(), bind, port).await,

        Some(Command::Keygen { .. }) => unreachable!("handled before logging starts"),

        Some(Command::Keys { keys }) => match run_keys(keys, cli.config.as_deref()) {
            Ok(out) => println!("{out}"),
            Err(msg) => {
                eprintln!("error: {msg}");
                std::process::exit(1);
            }
        },
    }

    Ok(())
}

/// Start the HTTP server, or exit(1) with an operator-legible reason.
///
/// Startup failures (an invalid config, a port already in use, an unreadable
/// DB) used to surface as a panic — which reaches stderr through the
/// default panic hook only, so a systemd unit capturing stdout logged nothing
/// but an exit code. Log through BOTH `tracing` and stderr, then exit non-zero.
async fn serve(config: Option<&std::path::Path>, bind: Option<String>, port: Option<u16>) {
    if let Err(e) = run_http_server(config, bind, port).await {
        tracing::error!("jig-nameserver failed to start: {e}");
        eprintln!("error: jig-nameserver failed to start: {e}");
        std::process::exit(1);
    }
}
