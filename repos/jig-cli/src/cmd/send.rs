//! `jig send <channel> <body>` — Phase F5 of v0.0.2 hello-world.
//!
//! Connects to the configured server via WSS (using `jig_client::Client`),
//! builds a signed `text-render` block, submits it, and prints the CID on
//! success. One-shot — no interactive loop, no persistent connection.
//!
//! The v0.0.1 path (`commands::send_text` → HTTP POST `/api/v1/blocks`) is
//! preserved for `pipe_mode`, `interactive_mode`, and the no-subcommand
//! fallback in `main.rs`; only the `jig send` subcommand routes here. Phase H
//! end-to-end tests exercise the live WSS path; this module's unit tests
//! cover the wiring shape (block construction + identity loading).

use anyhow::{Context, Result};
use jig_client::{Client, blocks::build_text_render};
use jig_core::HlcTimestamp;

use crate::cmd::common::CliContext;

/// Apply `jig send <channel> <body>`.
///
/// Behaviour:
///   1. Load the identity named by the resolved context (`--did` override
///      or `[user] did`) from `~/.jig/keys/<did>.key`.
///   2. Take the resolved server base URL (`--server` override or
///      `[server] base_url`).
///   3. Open a WSS connection (or transpose `http(s)://` → `ws(s)://` —
///      `Client::connect` handles that itself).
///   4. Build + submit a signed `text-render` block.
///   5. Print the assigned block CID. Exit.
pub async fn run(ctx: &CliContext, channel: String, body: String) -> Result<()> {
    let id = ctx.identity()?;
    let server_url = ctx.server_url()?;

    let client = Client::connect(&server_url, id)
        .await
        .with_context(|| format!("connecting to {server_url}"))?;

    // Each invocation is its own short-lived process — no persistent HLC
    // clock to carry between sends. Server re-bases against its own HLC on
    // ingest (`HlcClock::update_on_receive`), so client wall time is fine.
    //
    // We re-load the identity to derive a DID for the HLC stamp; the
    // Client owns the original Identity at this point. This is cheap —
    // identity load is a 32-byte file read + ed25519 pubkey derivation.
    let id_for_hlc = ctx.identity()?;
    let hlc = HlcTimestamp::now_wall(id_for_hlc.did().clone());
    let block = build_text_render(&id_for_hlc, &channel, &body, hlc);

    let cid = client
        .submit(block)
        .await
        .with_context(|| format!("submitting block to {server_url}"))?;
    println!("{cid}");
    Ok(())
}
