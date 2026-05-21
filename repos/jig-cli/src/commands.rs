//! Command implementations for the block-based CLI.
//!
//! Note: the `jig init` command moved to `cmd::init` for Phase F1 of the
//! v0.0.2 hello-world plan (keypair generation + optional alias
//! registration). The legacy `init_config` placeholder that used to live
//! here has been removed.

use crate::config::Config;
use crate::http_client::{BlockDetail, BlockSummary, JigHttpClient};
use anyhow::Result;
use chrono::{DateTime, Utc};
use cid::Cid;
use serde_json::Value;
use std::io::{self, BufRead, Write};
use std::time::Duration;

pub async fn send_text(
    client: &JigHttpClient,
    config: &Config,
    channel: &str,
    text: &str,
) -> Result<Cid> {
    let cid = client.ingest_text(&config.user.did, channel, text).await?;
    Ok(cid)
}

pub async fn read_messages(
    client: &JigHttpClient,
    channel: &str,
    limit: usize,
    json_output: bool,
) -> Result<()> {
    let summaries = client.list_blocks(limit).await?;
    let mut filtered = summaries
        .into_iter()
        .filter(|summary| manifest_matches_channel(&summary.manifest, channel))
        .collect::<Vec<_>>();
    filtered.sort_by_key(|b| b.created_at());

    if json_output {
        println!("{}", serde_json::to_string_pretty(&filtered)?);
        return Ok(());
    }

    for block in filtered {
        print_summary(&block);
    }
    Ok(())
}

pub async fn tail_messages(client: &JigHttpClient, channel: &str) -> Result<()> {
    println!("Following {}... (Ctrl+C to exit)", channel);
    let mut last_seen: Option<DateTime<Utc>> = None;
    loop {
        let summaries = client.list_blocks(200).await?;
        let mut filtered = summaries
            .into_iter()
            .filter(|summary| manifest_matches_channel(&summary.manifest, channel))
            .collect::<Vec<_>>();
        filtered.sort_by_key(|b| b.created_at());

        for block in filtered {
            let block_ts = block.created_at();
            let should_print = match (block_ts, last_seen) {
                (Some(ts), Some(last)) => ts > last,
                (Some(_), None) => true,
                (None, _) => true,
            };
            if should_print {
                print_summary(&block);
                if let Some(ts) = block_ts {
                    last_seen = Some(ts);
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(750)).await;
    }
}

pub async fn interactive_mode(
    client: &JigHttpClient,
    config: &Config,
    channel: &str,
) -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        print!("> ");
        stdout.flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line == "/quit" || line == "/exit" {
            break;
        }

        let cid = send_text(client, config, channel, line).await?;
        println!("Block published: {}", cid);
    }

    Ok(())
}

pub async fn pipe_mode(client: &JigHttpClient, config: &Config, channel: &str) -> Result<()> {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        send_text(client, config, channel, &line).await?;
    }
    Ok(())
}

fn manifest_matches_channel(manifest: &Value, channel: &str) -> bool {
    manifest
        .get("metadata")
        .and_then(|meta| meta.get("channel"))
        .and_then(Value::as_str)
        .map(|c| c == channel)
        .unwrap_or(false)
}

fn manifest_text(manifest: &Value) -> Option<&str> {
    manifest
        .get("metadata")
        .and_then(|meta| meta.get("content"))
        .and_then(Value::as_str)
}

fn print_summary(summary: &BlockSummary) {
    let created = summary
        .created_at()
        .unwrap_or_else(|| DateTime::<Utc>::from(std::time::SystemTime::now()));
    let ts = created.format("%H:%M:%S");
    let manifest = &summary.manifest;
    let display_name = manifest
        .get("authors")
        .and_then(|arr| arr.as_array())
        .and_then(|arr| arr.first())
        .and_then(|author| author.get("did"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let content = manifest_text(manifest).unwrap_or("[non-text block]");
    println!("[{}] <{}> {}", ts, display_name, content);
}

#[allow(dead_code)]
pub async fn fetch_block(client: &JigHttpClient, cid: &Cid) -> Result<BlockDetail> {
    client.get_block(cid).await
}
