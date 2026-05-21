//! Jig CLI - block-first command line interface

mod cmd;
mod commands;
mod config;
mod http_client;
mod receipt;

#[cfg(feature = "local-runtime")]
mod runtime;

use anyhow::Result;
use clap::{Parser, Subcommand};
use http_client::JigHttpClient;
use std::path::PathBuf;
use std::{io, io::IsTerminal};

#[derive(Parser, Debug)]
#[command(name = "jig", about = "Command-line client for Jig blocks")]
struct Cli {
    /// Optional path to configuration file
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override server base URL (e.g. http://127.0.0.1:7117)
    #[arg(long)]
    server: Option<String>,

    /// Override DID for the author
    #[arg(long)]
    did: Option<String>,

    /// Override display name
    #[arg(long)]
    display_name: Option<String>,

    /// Override default channel
    #[arg(long)]
    channel: Option<String>,

    /// Output JSON when listing blocks
    #[arg(long)]
    json: bool,

    /// Suppress console output (useful for piping)
    #[arg(long)]
    quiet: bool,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Message provided without a subcommand (implicit send)
    message: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a fresh keypair and write `~/.jig/cli.toml`. Optionally
    /// request an alias attestation from a nameserver.
    Init {
        /// Optional nickname; defaults to whoami::username()
        #[arg()]
        nickname: Option<String>,

        /// Overwrite existing cli.toml if present
        #[arg(long)]
        force: bool,

        /// Request an alias from a nameserver after generating keys
        #[arg(long)]
        request_alias: Option<String>,

        /// Nameserver URL (required with --request-alias)
        #[arg(long)]
        nameserver: Option<String>,
    },

    /// Send a text message block
    Send {
        #[arg()]
        message: Vec<String>,
        #[arg(long)]
        channel: Option<String>,
    },

    /// List recent blocks
    Read {
        #[arg(long)]
        channel: Option<String>,
        #[arg(long, default_value = "50")]
        limit: usize,
    },

    /// Follow new blocks in real time
    Tail {
        #[arg(long)]
        channel: Option<String>,
    },

    /// Interactive ratatui TUI: scrolling history + input box. The
    /// "demo command" — `install.sh` invokes this at the end of
    /// first-run setup. Enter sends, Ctrl+Q or Esc quits.
    Chat {
        /// Channel slug to join (e.g. `#hello`).
        #[arg()]
        channel: String,
    },

    /// View and inspect block receipts
    Receipt {
        #[command(subcommand)]
        action: ReceiptAction,
    },

    /// Manage identity keys (renew / rotate alias attestations).
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },

    /// Configure the server this client talks to (`set`) or query its
    /// `/.well-known/jig` advertised capabilities (`info`).
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },

    /// Create, join, or list channels on the configured server. Uses the
    /// `/_admin_v0_0_2/*` admin endpoints in v0.0.2 (server must have
    /// `[debug] admin_endpoints = true`); the list endpoint is public.
    Channel {
        #[command(subcommand)]
        action: ChannelAction,
    },

    /// Execute WASM blocks locally
    #[cfg(feature = "local-runtime")]
    Block {
        #[command(subcommand)]
        action: BlockAction,
    },
}

#[derive(Subcommand, Debug)]
enum ChannelAction {
    /// Create a new channel. Builds a signed channel-create block and
    /// POSTs it to `/_admin_v0_0_2/channels` on the configured server.
    Create {
        /// Channel slug (e.g. `#hello`).
        #[arg()]
        slug: String,

        /// Channel visibility — `open` (anyone can read; default) or
        /// `restricted` (membership-gated reads).
        #[arg(long, default_value = "open")]
        visibility: String,
    },

    /// Join an existing channel by adding the caller's DID as a member.
    /// Builds a signed member-add block and POSTs it to
    /// `/_admin_v0_0_2/channels/<slug>/members`.
    Join {
        /// Channel slug to join (e.g. `#hello`).
        #[arg()]
        slug: String,
    },

    /// List all channels known to the configured server.
    /// GETs `/api/v1/channels` and renders an aligned table.
    List,
}

#[derive(Subcommand, Debug)]
enum ServerAction {
    /// Persist a new server base URL to `~/.jig/cli.toml`. Accepts
    /// `http://`, `https://`, `ws://`, or `wss://`. v0.0.2 stores
    /// whatever the operator supplies (validated for basic URL shape).
    Set {
        /// e.g. `http://127.0.0.1:7117` or `wss://deji.jig.onl`.
        #[arg()]
        url: String,
    },

    /// Fetch `/.well-known/jig` from the configured server (or
    /// `--url <override>`) and pretty-print the response.
    Info {
        /// Query a different server without modifying `cli.toml`. Useful
        /// for diagnostics ("does that peer think it's federated with me?").
        #[arg(long)]
        url: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
#[cfg(feature = "local-runtime")]
enum BlockAction {
    /// Initialize a new block project from a template
    Init {
        /// Name of the block project
        name: String,

        /// Template to use (rust-wasi, tinygo-wasi, text-only)
        #[arg(long, short = 't', default_value = "rust-wasi")]
        template: String,

        /// Output directory (default: current directory)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Run a WASM block locally and generate a receipt
    Run {
        /// Path to WASM file
        wasm: String,

        /// Deterministic seed for RNG (for reproducible execution)
        #[arg(long)]
        seed: Option<u64>,

        /// Maximum fuel budget
        #[arg(long)]
        fuel: Option<u64>,

        /// Maximum memory in MB
        #[arg(long)]
        memory: Option<u32>,

        /// Execution timeout in milliseconds
        #[arg(long)]
        timeout: Option<u64>,

        /// Enable capability (can be specified multiple times)
        #[arg(long = "cap")]
        capabilities: Vec<String>,

        /// Write receipt JSON to file
        #[arg(long)]
        receipt: Option<String>,

        /// Output as JSON instead of pretty format
        #[arg(long)]
        json: bool,

        /// Enable pricing in receipt
        #[arg(long)]
        pricing: bool,
    },

    /// Lint and validate a block manifest and WASM module
    Lint {
        /// Path to block directory or manifest file
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Sign a block with your DID key
    Sign {
        /// Path to block directory or manifest file
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Path to private key file
        #[arg(long)]
        key: Option<PathBuf>,
    },

    /// Verify a block's signature
    Verify {
        /// Path to block directory or manifest file
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Inspect block capabilities
    Capabilities {
        /// Path to block directory or manifest file
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum KeysAction {
    /// Renew the validity window of an existing alias attestation
    /// (same DID, extended TTL).
    Renew {
        /// Fully-qualified alias to renew, e.g. `dj@dj.jig`.
        #[arg()]
        alias: String,

        /// Nameserver base URL (e.g. http://127.0.0.1:7118).
        #[arg(long)]
        nameserver: String,
    },

    /// Mint a fresh keypair and rotate the alias binding from the
    /// current DID to the new one. The old keyfile is preserved as
    /// `<old_did>.key.rotated` for offline recovery.
    Rotate {
        /// Fully-qualified alias whose DID binding is being rotated.
        #[arg()]
        alias: String,

        /// Nameserver base URL.
        #[arg(long)]
        nameserver: String,
    },
}

#[derive(Subcommand, Debug)]
enum ReceiptAction {
    /// View a receipt from a file or server
    View {
        /// Load receipt from file path
        #[arg(long)]
        file: Option<String>,

        /// Fetch receipt by block ID from server
        #[arg(long)]
        block: Option<String>,
    },

    /// Compare two receipts (for parity testing)
    Compare {
        /// First receipt (file path or block ID with --block)
        first: String,

        /// Second receipt (file path or block ID with --block)
        second: String,

        /// Treat arguments as block IDs instead of file paths
        #[arg(long)]
        block: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle init early — it doesn't need the loaded config / HTTP client.
    if let Some(Commands::Init {
        nickname,
        force,
        request_alias,
        nameserver,
    }) = cli.command
    {
        cmd::init::run(cmd::init::InitArgs {
            nickname,
            force,
            request_alias,
            nameserver,
        })
        .await?;
        return Ok(());
    }

    // Handle keys subcommands early — they own their own config load
    // and don't touch the messaging HTTP client.
    if let Some(Commands::Keys { action }) = cli.command {
        match action {
            KeysAction::Renew { alias, nameserver } => {
                cmd::keys::renew(cmd::keys::KeysRenewArgs { alias, nameserver }).await?;
            }
            KeysAction::Rotate { alias, nameserver } => {
                cmd::keys::rotate(cmd::keys::KeysRotateArgs { alias, nameserver }).await?;
            }
        }
        return Ok(());
    }

    // Handle server subcommands early — `set` mutates ~/.jig/cli.toml
    // and `info` issues a one-shot HTTP GET; neither needs the messaging
    // pipeline wired up.
    if let Some(Commands::Server { action }) = cli.command {
        match action {
            ServerAction::Set { url } => {
                cmd::server::set(&url)?;
            }
            ServerAction::Info { url } => {
                cmd::server::info(url.as_deref()).await?;
            }
        }
        return Ok(());
    }

    // Handle channel subcommands early — they don't touch the legacy
    // messaging HTTP client; they go straight to `/_admin_v0_0_2/*` or
    // `/api/v1/channels` via reqwest.
    if let Some(Commands::Channel { action }) = cli.command {
        match action {
            ChannelAction::Create { slug, visibility } => {
                cmd::channel::create(slug, visibility).await?;
            }
            ChannelAction::Join { slug } => {
                cmd::channel::join(slug).await?;
            }
            ChannelAction::List => {
                cmd::channel::list().await?;
            }
        }
        return Ok(());
    }

    let mut config = config::load_config(cli.config.as_deref())?;
    if let Some(server) = cli.server {
        config.server.base_url = server;
    }
    if let Some(did) = cli.did {
        config.user.did = did;
    }
    if let Some(name) = cli.display_name {
        config.user.display_name = name;
    }
    if let Some(ch) = cli.channel.clone() {
        config.user.default_channel = ch;
    }

    let client = JigHttpClient::new(&config.server.base_url)?;
    let default_channel = config.user.default_channel.clone();

    let stdin_pipe = !io::stdin().is_terminal();
    let direct_message = cli.message;

    match cli.command {
        Some(Commands::Send { message, channel }) => {
            // F5: route through jig-client WSS submit. The CLI surface
            // preserves the `<message...>` positional vec so `jig send "hello
            // world"` and `jig send hello world` both work, and the
            // `--channel` flag still falls back to `[user] default_channel`
            // from cli.toml.
            let msg = if message.is_empty() {
                direct_message.join(" ")
            } else {
                message.join(" ")
            };
            let body = msg.trim().to_string();
            if body.is_empty() {
                return Ok(());
            }
            let channel = channel.unwrap_or(default_channel.clone());
            cmd::send::run(channel, body).await?;
        }
        Some(Commands::Read { channel, limit }) => {
            let channel = channel.unwrap_or(default_channel.clone());
            commands::read_messages(&client, &channel, limit, cli.json).await?;
        }
        Some(Commands::Tail { channel }) => {
            // F5: route through jig-client WSS subscribe. v0.0.1's HTTP-
            // polling tail (`commands::tail_messages`) is removed; this is
            // an intentional regression — v0.0.2 only ships the WSS path.
            let channel = channel.unwrap_or(default_channel.clone());
            cmd::tail::run(channel).await?;
        }
        Some(Commands::Chat { channel }) => {
            // F6: ratatui TUI combining `tail` (live history) with an
            // input box. The end-of-install demo command.
            cmd::chat::run(cmd::chat::ChatArgs { channel }).await?;
        }
        Some(Commands::Receipt { action }) => match action {
            ReceiptAction::View { file, block } => {
                use cmd::receipt::{ReceiptSource, view_receipt};

                let source = if let Some(file_path) = file {
                    ReceiptSource::File(file_path.clone())
                } else if let Some(block_id) = block {
                    let cid: cid::Cid = block_id.parse()?;
                    ReceiptSource::BlockId(cid)
                } else {
                    anyhow::bail!("Must specify either --file or --block");
                };

                view_receipt(Some(&client), source, cli.json).await?;
            }
            ReceiptAction::Compare {
                first,
                second,
                block,
            } => {
                use cmd::receipt::{ReceiptSource, compare_receipts};

                let source_a = if block {
                    let cid: cid::Cid = first.parse()?;
                    ReceiptSource::BlockId(cid)
                } else {
                    ReceiptSource::File(first.clone())
                };

                let source_b = if block {
                    let cid: cid::Cid = second.parse()?;
                    ReceiptSource::BlockId(cid)
                } else {
                    ReceiptSource::File(second.clone())
                };

                compare_receipts(Some(&client), source_a, source_b).await?;
            }
        },
        #[cfg(feature = "local-runtime")]
        Some(Commands::Block { action }) => match action {
            BlockAction::Init {
                name,
                template,
                output,
            } => {
                use cmd::block_init::{Template, init_block};

                let template_enum = Template::from_name(&template).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unknown template '{}'. Available: rust-wasi, tinygo-wasi, text-only",
                        template
                    )
                })?;

                init_block(&name, template_enum, output.as_deref(), &config.user.did)?;
            }
            BlockAction::Run {
                wasm,
                seed,
                fuel,
                memory,
                timeout,
                capabilities,
                receipt,
                json,
                pricing,
            } => {
                use cmd::block_run::run_block;
                run_block(
                    &wasm,
                    seed,
                    fuel,
                    memory,
                    timeout,
                    capabilities,
                    receipt.as_deref(),
                    json || cli.json,
                    pricing,
                )?;
            }
            BlockAction::Lint { path } => {
                eprintln!("error: 'jig block lint' is not yet implemented in v0.0.1");
                eprintln!("  (waiting for jig-core Wasm validation API)");
                eprintln!("  block: {}", path.display());
                std::process::exit(1);
            }
            BlockAction::Sign { path, key } => {
                eprintln!("error: 'jig block sign' is not yet implemented in v0.0.1");
                eprintln!("  (waiting for jig-core Ed25519 signing API)");
                eprintln!("  block: {}", path.display());
                if let Some(key_path) = key {
                    eprintln!("  key: {}", key_path.display());
                }
                std::process::exit(1);
            }
            BlockAction::Verify { path } => {
                eprintln!("error: 'jig block verify' is not yet implemented in v0.0.1");
                eprintln!("  (waiting for jig-core Ed25519 verification API)");
                eprintln!("  block: {}", path.display());
                std::process::exit(1);
            }
            BlockAction::Capabilities { path } => {
                eprintln!("error: 'jig block capabilities' is not yet implemented in v0.0.1");
                eprintln!("  (waiting for jig-core capability DSL)");
                eprintln!("  block: {}", path.display());
                std::process::exit(1);
            }
        },
        Some(Commands::Init { .. }) => unreachable!("init handled earlier"),
        Some(Commands::Keys { .. }) => unreachable!("keys handled earlier"),
        Some(Commands::Server { .. }) => unreachable!("server handled earlier"),
        Some(Commands::Channel { .. }) => unreachable!("channel handled earlier"),
        None => {
            if !direct_message.is_empty() {
                let msg = direct_message.join(" ");
                let cid =
                    commands::send_text(&client, &config, &default_channel, msg.trim()).await?;
                if !cli.quiet {
                    println!("Block published: {}", cid);
                }
            } else if stdin_pipe {
                commands::pipe_mode(&client, &config, &default_channel).await?;
            } else {
                commands::interactive_mode(&client, &config, &default_channel).await?;
            }
        }
    }

    Ok(())
}
