//! Jig Nameserver binary

use clap::{Parser, Subcommand};
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
        /// Where to write the key (created 0600)
        #[arg(long)]
        out: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Before any logging is set up, so stdout carries the DID and nothing else.
    if let Some(Command::Keygen { out }) = &cli.command {
        match jig_nameserver::v0_0_2::keygen(out) {
            Ok(did) => {
                println!("{did}");
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
