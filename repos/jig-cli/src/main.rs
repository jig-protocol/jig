//! Jig CLI - block-first command line interface

mod channel_arg;
mod cmd;
mod config;
mod receipt;

#[cfg(feature = "local-runtime")]
mod runtime;

use anyhow::Result;
use channel_arg::ChannelArg;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::{io, io::IsTerminal};

#[derive(Parser, Debug)]
#[command(name = "jig", version, about = "Command-line client for Jig blocks")]
struct Cli {
    /// Config file to use instead of ~/.jig/cli.toml (must exist)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override server base URL (e.g. https://127.0.0.1:7117)
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
        /// Flag-only, unlike the other channel-scoped commands: the
        /// positional slot here is the message body, so a positional channel
        /// would be ambiguous. See `channel_arg::ChannelArg`.
        #[arg(long)]
        channel: Option<String>,
    },

    /// Direct-message someone: a locked, end-to-end encrypted channel with
    /// the two of you in it, created on first use. With a message, sends it
    /// and exits; without, opens the chat.
    Dm {
        /// A did:jig, a name from `[contacts]` in cli.toml, or an
        /// `alias@suffix`, verified and pinned on first use.
        #[arg()]
        who: String,
        #[arg()]
        message: Vec<String>,
    },

    /// Print a channel's recent messages and exit (decrypting an encrypted
    /// channel you belong to).
    Read {
        #[command(flatten)]
        channel: ChannelArg,
        #[arg(long, default_value = "50")]
        limit: usize,
    },

    /// Follow new blocks in real time
    Tail {
        #[command(flatten)]
        channel: ChannelArg,
    },

    /// Interactive ratatui TUI: scrolling history + input box. The
    /// "demo command" — `install.sh` invokes this at the end of
    /// first-run setup. Enter sends, Ctrl+Q or Esc quits.
    Chat {
        #[command(flatten)]
        channel: ChannelArg,
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

    /// What this device pinned and trusts: verify and pin a name
    /// (`verify-name`), or move its pin after its holder confirms a new DID
    /// (`accept-name`).
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },

    /// Create, join, delete, or list channels on the configured server via
    /// `/api/v1/channels*`.
    Channel {
        #[command(subcommand)]
        action: ChannelAction,
    },

    /// Query a nameserver: resolve an alias to a DID, or list the aliases
    /// it knows about.
    Ns {
        #[command(subcommand)]
        action: NsAction,
    },

    /// Write, build, check and run blocks
    Block {
        #[command(subcommand)]
        action: BlockAction,
    },
}

#[derive(Subcommand, Debug)]
enum ChannelAction {
    /// Create a new channel. Builds a signed channel-create block and
    /// POSTs it to `/api/v1/channels` on the configured server.
    Create {
        /// Channel slug (e.g. `#hello`).
        #[arg()]
        slug: String,

        /// Channel visibility — `open` (anyone can read; default) or
        /// `restricted` (members only, and always end-to-end encrypted).
        #[arg(long, default_value = "open")]
        visibility: String,

        /// Succeed (exit 0) if the channel already exists instead of failing.
        #[arg(long)]
        exist_ok: bool,

        /// End-to-end encrypt the channel with MLS: the server stores and
        /// relays ciphertext it cannot read. Fixed at creation. Restricted
        /// channels are always encrypted, so this only changes open ones.
        #[arg(long)]
        encrypted: bool,
    },

    /// Add someone to a channel you own. On an encrypted channel this also
    /// adds them to its MLS group.
    Add {
        #[arg()]
        slug: String,
        /// A did:jig, a name from `[contacts]`, or a verified `alias@suffix`.
        #[arg()]
        who: String,
    },

    /// Remove someone from a channel you own. On an encrypted channel they
    /// can read nothing sent after this.
    #[command(alias = "remove")]
    Kick {
        #[arg()]
        slug: String,
        /// A did:jig, a name from `[contacts]`, or a verified `alias@suffix`.
        #[arg()]
        who: String,
    },

    /// Leave a channel. The owner cannot leave; it deletes the channel instead.
    Leave {
        #[arg()]
        slug: String,
    },

    /// Open a restricted channel (or DM) you own to anyone: `restricted` →
    /// `open`. An encrypted channel stays encrypted.
    Promote {
        #[arg()]
        slug: String,
    },

    /// List a channel's members.
    Members {
        #[arg()]
        slug: String,
    },

    /// Join an existing channel by adding the caller's DID as a member.
    /// Builds a signed member-add block and POSTs it to
    /// `/api/v1/channels/<slug>/members`.
    ///
    /// Only `open` channels can be joined this way. A `restricted` channel is
    /// invite-only: its owner adds members, and a self-join is refused.
    Join {
        /// Channel slug to join (e.g. `#hello`).
        #[arg()]
        slug: String,
    },

    /// Delete (archive) a channel you own. Builds a signed channel-archive
    /// block and POSTs it to `/api/v1/channels/<slug>/archive`.
    ///
    /// Soft delete: the server stops listing the channel but keeps its
    /// history, and only the channel's owner DID may do it.
    #[command(alias = "archive")]
    Delete {
        /// Channel slug to delete (e.g. `#hello`).
        #[arg()]
        slug: String,

        /// Skip the interactive confirmation. Required when stdin is not a
        /// terminal, since there is nobody to prompt.
        #[arg(long)]
        yes: bool,
    },

    /// List the channels on the configured server that you may read: every
    /// `open` channel, plus the `restricted` ones you own or belong to.
    /// GETs `/api/v1/channels` and renders an aligned table.
    List,
}

#[derive(Subcommand, Debug)]
enum NsAction {
    /// Resolve a name (e.g. `dj@jig`) to the DID its suffix's authority attests.
    Resolve {
        /// Name to look up, as `alias@suffix`. Only an attestation from the
        /// suffix's delegated authority is printed.
        #[arg()]
        alias: String,

        /// Ask this nameserver instead of the ones the suffix's
        /// `[naming.delegations]` entry lists. The authorities stay the same.
        #[arg(long)]
        nameserver: Option<String>,
    },

    /// List every alias the nameserver currently attests. Debug-gated
    /// server-side behind `[debug] list_handles`.
    List {
        /// Nameserver base URL. Defaults to `[server] nameserver_url`
        /// in cli.toml.
        #[arg(long)]
        nameserver: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum TrustAction {
    /// Resolve `name` (alias@suffix), verify it, and pin it on first sight; a
    /// name that now resolves to another DID than the pinned one is refused.
    VerifyName {
        name: String,
        /// Nameserver to ask (with `--authority`); otherwise the suffix's
        /// `[naming.delegations]` entry, or DNS discovery.
        #[arg(long)]
        nameserver: Vec<String>,
        /// DID whose attestations count for the suffix.
        #[arg(long)]
        authority: Vec<String>,
    },
    /// Move the pin for `name` (alias@suffix) to the DID it resolves to now.
    /// Only after its holder confirms that DID out of band: `--did` must name
    /// exactly what the nameserver attests, or nothing changes.
    AcceptName {
        name: String,
        /// The DID the holder confirmed.
        #[arg(long)]
        did: String,
        /// Nameserver to ask (with `--authority`); otherwise the suffix's
        /// `[naming.delegations]` entry, or DNS discovery.
        #[arg(long)]
        nameserver: Vec<String>,
        /// DID whose attestations count for the suffix.
        #[arg(long)]
        authority: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ServerAction {
    /// Persist a new server base URL to `~/.jig/cli.toml`. Accepts
    /// `http://`, `https://`, `ws://`, or `wss://`. v0.0.2 stores
    /// whatever the operator supplies (validated for basic URL shape).
    Set {
        /// e.g. `https://127.0.0.1:7117` or `wss://deji.jig.onl`.
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

    /// Drop what this device pinned for the configured server (or
    /// `--url <server>`): the DID that signs its welcome, the suites it
    /// advertised, and the channels seen there. Do this only when you know
    /// why the server changed; the next contact pins it afresh.
    Forget {
        #[arg(long)]
        url: Option<String>,
    },
}

// Parsed once per process; boxing `Run`'s fields would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum BlockAction {
    /// Create a block project from a template
    New {
        /// The block's name: lowercase letters, digits and `-`
        name: String,

        /// The template to start from
        #[arg(long, value_enum, default_value = "renderer")]
        template: cmd::block_new::Template,

        /// Write the project here instead of ./<name>
        #[arg(long)]
        dir: Option<std::path::PathBuf>,
    },

    /// Build the block project in the current directory into a component, then lint it
    Build {
        /// The project directory
        #[arg(default_value = ".")]
        path: std::path::PathBuf,
    },

    /// Check a component against the determinism profile jig-det-1
    Lint {
        /// A block project directory (lints its built component), or a .wasm file
        #[arg(default_value = ".")]
        path: std::path::PathBuf,

        /// The memory limit in 64 KiB pages, when linting a .wasm file directly
        #[arg(long, default_value_t = cmd::block_project::DEFAULT_MEMORY_PAGES)]
        max_memory_pages: u32,
    },

    /// Run a block once, locally. A component (a block project, or a .wasm component) runs
    /// through the same component path as the server and client; a core module runs on the
    /// legacy ABI and gets a v0.2 receipt.
    #[cfg(feature = "local-runtime")]
    Run {
        /// A block project directory, or a .wasm file
        #[arg(default_value = ".")]
        wasm: String,

        /// Component input: the message text
        #[arg(long, conflicts_with = "input_file")]
        input: Option<String>,

        /// Component input: read the message body from this file
        #[arg(long)]
        input_file: Option<std::path::PathBuf>,

        /// Component input: the body's media type
        #[arg(long, default_value = "text/plain")]
        media_type: String,

        /// Component input: the sender's DID
        #[arg(long)]
        sender: Option<String>,

        /// Component input: the channel CID
        #[arg(long)]
        channel: Option<String>,

        /// Component input: the ingest sequence number
        #[arg(long)]
        seq: Option<u64>,

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

    /// Run a block project's vectors (tests/vectors/*.toml) and compare their outcomes
    #[cfg(feature = "local-runtime")]
    Test {
        /// The project directory
        #[arg(default_value = ".")]
        path: std::path::PathBuf,

        /// Record the outcome of every vector that has none, or whose outcome changed
        #[arg(long)]
        bless: bool,

        /// Maximum fuel per run
        #[arg(long)]
        fuel: Option<u64>,

        /// Wall-clock limit per run, in milliseconds
        #[arg(long)]
        timeout: Option<u64>,
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

        /// Nameserver base URL (e.g. http://127.0.0.1:7070).
        #[arg(long)]
        nameserver: String,
    },

    /// Mint a fresh keypair and rotate the alias binding from the
    /// current DID to the new one. The old keyfile is preserved, still
    /// sealed, as `<old_did>.jigkey.rotated` for offline recovery.
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
    /// View a receipt from a file
    View {
        /// Path to the receipt JSON
        #[arg(long)]
        file: String,
    },

    /// Compare two receipt files (for parity testing)
    Compare {
        /// First receipt file
        first: String,

        /// Second receipt file
        second: String,
    },
}

/// `jig block new`, `build` and `lint`, or `None` for the block actions that need a config.
// `global_json` is read only by `run`, which needs the `local-runtime` feature.
#[cfg_attr(not(feature = "local-runtime"), allow(unused_variables))]
fn run_local_block_action(action: &BlockAction, global_json: bool) -> Option<Result<()>> {
    Some(match action {
        BlockAction::New {
            name,
            template,
            dir,
        } => std::env::current_dir()
            .map_err(anyhow::Error::from)
            .and_then(|cwd| cmd::block_new::new_block(name, *template, &cwd, dir.as_deref()))
            .map(|root| print!("{}", cmd::block_new::next_steps(&root))),
        BlockAction::Build { path } => cmd::block_build::build(path).and_then(|built| {
            println!("built {}", built.component.display());
            println!("component {}", built.component_hash);
            print!("{}", built.lint.render());
            if built.lint.passes() {
                Ok(())
            } else {
                Err(anyhow::anyhow!("the component does not pass jig-det-1"))
            }
        }),
        BlockAction::Lint {
            path,
            max_memory_pages,
        } => cmd::block_lint::lint_path(path, *max_memory_pages).and_then(|l| {
            print!("{}", l.render());
            if l.passes() {
                Ok(())
            } else {
                Err(anyhow::anyhow!("the component does not pass jig-det-1"))
            }
        }),
        #[cfg(feature = "local-runtime")]
        BlockAction::Run {
            wasm,
            input,
            input_file,
            media_type,
            sender,
            channel,
            seq,
            fuel,
            timeout,
            json,
            ..
        } => {
            let target = match cmd::block_exec::load_target(std::path::Path::new(wasm)) {
                Ok(t) => t,
                Err(e) => return Some(Err(e)),
            };
            // A core module takes the legacy path, after the config is loaded.
            if !cmd::block_exec::is_component(&target.bytes) {
                return None;
            }
            cmd::block_run::run_component(
                &target,
                cmd::block_run::ComponentRunArgs {
                    input: input.as_deref(),
                    input_file: input_file.as_deref(),
                    media_type,
                    sender: sender.as_deref(),
                    channel: channel.as_deref(),
                    seq: *seq,
                    fuel: *fuel,
                    timeout_ms: *timeout,
                    json: *json || global_json,
                },
            )
        }
        #[cfg(feature = "local-runtime")]
        BlockAction::Test {
            path,
            bless,
            fuel,
            timeout,
        } => cmd::block_run::run_vectors(path, *bless, *fuel, *timeout),
    })
}

/// Exit status when no key slot can seal a new identity key: no OS keychain,
/// no terminal, and no `JIG_KEY_PASSPHRASE` or `JIG_KEY_UNLOCK`. `install.sh`
/// matches it, not the message, to fall back to plaintext keys. 78 is
/// `EX_CONFIG` in sysexits.h.
const EXIT_NO_KEY_SLOT: u8 = 78;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // The same report `fn main() -> anyhow::Result<()>` prints.
            eprintln!("Error: {e:?}");
            let no_slot = e.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<jig_client::IdentityError>(),
                    Some(jig_client::IdentityError::NoWayToSeal { .. })
                )
            });
            if no_slot {
                std::process::ExitCode::from(EXIT_NO_KEY_SLOT)
            } else {
                std::process::ExitCode::FAILURE
            }
        }
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Writing, building and linting a block touch only local files: they need no config,
    // identity or server, so they run before any of those is loaded.
    if let Some(Commands::Block { action }) = &cli.command
        && let Some(result) = run_local_block_action(action, cli.json)
    {
        return result;
    }

    // Lift the global flags out of `cli` FIRST. Everything below reads
    // config through the resolved context, so `--server` / `--config` /
    // `--did` apply uniformly. They used to be applied only after the
    // Init/Keys/Server/Channel blocks had already dispatched and
    // returned, which meant those four commands silently ignored them.
    let overrides = cmd::common::GlobalOverrides {
        config: cli.config,
        server: cli.server,
        did: cli.did,
        display_name: cli.display_name,
        channel: cli.channel,
    };

    // `init` is resolved from the raw overrides rather than a loaded
    // context: it CREATES the config file, so demanding one exist first
    // would be circular.
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
            config_path: overrides.config.clone(),
            server_url: overrides.server.clone(),
        })
        .await?;
        return Ok(());
    }

    let ctx = cmd::common::CliContext::resolve(&overrides)?;

    // Handle keys subcommands early — they don't touch the messaging
    // HTTP client.
    if let Some(Commands::Keys { action }) = cli.command {
        match action {
            KeysAction::Renew { alias, nameserver } => {
                cmd::keys::renew(&ctx, cmd::keys::KeysRenewArgs { alias, nameserver }).await?;
            }
            KeysAction::Rotate { alias, nameserver } => {
                cmd::keys::rotate(&ctx, cmd::keys::KeysRotateArgs { alias, nameserver }).await?;
            }
        }
        return Ok(());
    }

    // Handle server subcommands early — `set` mutates the config file
    // and `info` issues a one-shot HTTP GET; neither needs the messaging
    // pipeline wired up.
    if let Some(Commands::Server { action }) = cli.command {
        match action {
            ServerAction::Set { url } => {
                cmd::server::set(&ctx, &url)?;
                let ctx = cmd::common::CliContext::resolve(&overrides)?;
                // A server that asks new identities for proof of work gets it
                // now, while the user expects `set` to talk to it, rather
                // than in the middle of their first message.
                if let Err(e) = cmd::admission::ensure(&ctx).await {
                    eprintln!("warning: {e:#}");
                }
                // Publish MLS key packages to the new server so others can
                // add this identity to encrypted channels and DMs straight
                // away. Best effort: the server may be down, or predate v0.2.
                if let Ok(secure) = cmd::secure::Secure::open(&ctx)
                    && secure.ensure_key_packages().await.is_ok()
                {
                    println!(
                        "published MLS key packages (others can now add you to encrypted channels)"
                    );
                }
            }
            ServerAction::Info { url } => {
                cmd::server::info(&ctx, url.as_deref()).await?;
            }
            ServerAction::Forget { url } => {
                cmd::server::forget(&ctx, url.as_deref())?;
            }
        }
        return Ok(());
    }

    if let Some(Commands::Trust { action }) = cli.command {
        match action {
            TrustAction::VerifyName {
                name,
                nameserver,
                authority,
            } => {
                let delegations =
                    cmd::trust::delegations_for(ctx.effective(), &name, nameserver, authority)?;
                use jig_client::naming::Verified;
                match cmd::trust::verify_name(&name, &delegations).await? {
                    Verified::New(b) => println!(
                        "{name} → {} (attested by {}); pinned on first contact.",
                        b.did(),
                        b.attestation.ns_did
                    ),
                    Verified::Pinned(b) | Verified::Rotated { binding: b, .. } => println!(
                        "{name} → {} (attested by {}); matches this device's pin.",
                        b.did(),
                        b.attestation.ns_did
                    ),
                }
            }
            TrustAction::AcceptName {
                name,
                did,
                nameserver,
                authority,
            } => {
                let delegations =
                    cmd::trust::delegations_for(ctx.effective(), &name, nameserver, authority)?;
                match cmd::trust::accept_name(&name, &did, &delegations).await? {
                    Some(old) => println!("{name} is now pinned to {did} (was {old})."),
                    None => println!("{name} is now pinned to {did}."),
                }
            }
        }
        return Ok(());
    }

    // Handle nameserver lookups early — read-only HTTP GETs against a
    // nameserver, nothing to do with the messaging pipeline.
    if let Some(Commands::Ns { action }) = cli.command {
        match action {
            NsAction::Resolve { alias, nameserver } => {
                cmd::ns::resolve(&ctx, alias, nameserver).await?;
            }
            NsAction::List { nameserver } => {
                cmd::ns::list(&ctx, nameserver).await?;
            }
        }
        return Ok(());
    }

    // Handle channel subcommands early — they don't touch the legacy
    // messaging HTTP client; they go straight to `/api/v1/channels*` via reqwest.
    if let Some(Commands::Channel { action }) = cli.command {
        cmd::admission::ensure(&ctx).await?;
        match action {
            ChannelAction::Create {
                slug,
                visibility,
                exist_ok,
                encrypted,
            } => {
                cmd::channel::create(&ctx, slug, visibility, exist_ok, encrypted).await?;
            }
            ChannelAction::Add { slug, who } => cmd::channel::add(&ctx, slug, who).await?,
            ChannelAction::Kick { slug, who } => cmd::channel::kick(&ctx, slug, who).await?,
            ChannelAction::Leave { slug } => cmd::channel::leave(&ctx, slug).await?,
            ChannelAction::Promote { slug } => cmd::channel::promote(&ctx, slug).await?,
            ChannelAction::Members { slug } => cmd::channel::members(&ctx, slug).await?,
            ChannelAction::Join { slug } => {
                cmd::channel::join(&ctx, slug).await?;
            }
            ChannelAction::Delete { slug, yes } => {
                cmd::channel::delete(&ctx, slug, yes).await?;
            }
            ChannelAction::List => {
                cmd::channel::list(&ctx).await?;
            }
        }
        return Ok(());
    }

    let config = ctx.effective().clone();
    // Fail every command below on a malformed server URL up front, as the
    // legacy HTTP client's constructor used to.
    reqwest::Url::parse(&config.server.base_url)
        .map_err(|e| anyhow::anyhow!("invalid base url: {e}"))?;
    let default_channel = config.user.default_channel.clone();

    let stdin_pipe = !io::stdin().is_terminal();
    let direct_message = cli.message;

    // Every command below but the local ones talks to the server.
    let local = matches!(
        &cli.command,
        Some(Commands::Receipt { .. } | Commands::Block { .. })
    );
    if !local {
        cmd::admission::ensure(&ctx).await?;
    }

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
            cmd::send::run(&ctx, channel, body).await?;
        }
        Some(Commands::Dm { who, message }) => {
            cmd::dm::run(&ctx, who, message.join(" ")).await?;
        }
        Some(Commands::Read { channel, limit }) => {
            // The signed history endpoint. The v0.0.1 `GET /blocks` this used
            // to call is gated off on every default server, so `jig read`
            // 404'd out of the box.
            let channel = channel.resolve(&default_channel);
            cmd::tail::read(&ctx, channel, limit, cli.json).await?;
        }
        Some(Commands::Tail { channel }) => {
            // F5: route through jig-client WSS subscribe. v0.0.1's HTTP-
            // polling tail (`commands::tail_messages`) is removed; this is
            // an intentional regression — v0.0.2 only ships the WSS path.
            let channel = channel.resolve(&default_channel);
            cmd::tail::run(&ctx, channel).await?;
        }
        Some(Commands::Chat { channel }) => {
            // F6: ratatui TUI combining `tail` (live history) with an
            // input box. The end-of-install demo command.
            let channel = channel.resolve(&default_channel);
            cmd::chat::run(&ctx, cmd::chat::ChatArgs { channel }).await?;
        }
        Some(Commands::Receipt { action }) => match action {
            ReceiptAction::View { file } => cmd::receipt::view_receipt(&file, cli.json)?,
            ReceiptAction::Compare { first, second } => {
                cmd::receipt::compare_receipts(&first, &second)?
            }
        },
        Some(Commands::Block { action }) => match action {
            BlockAction::New { .. } | BlockAction::Build { .. } | BlockAction::Lint { .. } => {
                unreachable!("handled before the config is loaded")
            }
            #[cfg(feature = "local-runtime")]
            BlockAction::Test { .. } => unreachable!("handled before the config is loaded"),
            #[cfg(feature = "local-runtime")]
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
                input,
                input_file,
                sender,
                channel,
                seq,
                ..
            } => {
                use cmd::block_run::{RunBlockArgs, run_block};
                if input.is_some()
                    || input_file.is_some()
                    || sender.is_some()
                    || channel.is_some()
                    || seq.is_some()
                {
                    anyhow::bail!(
                        "{wasm} is a core module; --input, --input-file, --sender, --channel and \
                         --seq apply only to components (`jig block build` makes one)"
                    );
                }
                run_block(RunBlockArgs {
                    wasm_path: &wasm,
                    seed,
                    fuel,
                    memory_mb: memory,
                    timeout_ms: timeout,
                    capabilities,
                    receipt_out: receipt.as_deref(),
                    json_output: json || cli.json,
                    enable_pricing: pricing,
                })?;
            }
        },
        Some(Commands::Init { .. }) => unreachable!("init handled earlier"),
        Some(Commands::Keys { .. }) => unreachable!("keys handled earlier"),
        Some(Commands::Server { .. }) => unreachable!("server handled earlier"),
        Some(Commands::Trust { .. }) => unreachable!("trust handled earlier"),
        Some(Commands::Channel { .. }) => unreachable!("channel handled earlier"),
        Some(Commands::Ns { .. }) => unreachable!("ns handled earlier"),
        // No subcommand. These used to post through the v0.0.1 `POST /blocks`
        // route, which every default server has gated off, so all three
        // failed out of the box; they now take the same path as `jig send`
        // and `jig chat`.
        None => {
            if !direct_message.is_empty() {
                let msg = direct_message.join(" ");
                cmd::send::run(&ctx, default_channel, msg.trim().to_string()).await?;
            } else if stdin_pipe {
                use std::io::BufRead as _;
                for line in io::stdin().lock().lines() {
                    let line = line?;
                    if !line.trim().is_empty() {
                        cmd::send::run(&ctx, default_channel.clone(), line).await?;
                    }
                }
            } else {
                cmd::chat::run(
                    &ctx,
                    cmd::chat::ChatArgs {
                        channel: default_channel,
                    },
                )
                .await?;
            }
        }
    }

    Ok(())
}
