//! A burst of text-render posts against a running jig-server, to see how
//! often a render misses the server's deadline under load, and what the
//! `retry_after_ms` a missed deadline returns (#382) does to the retries.
//!
//! cargo run --release -p integration-tests --example render_flood -- \
//!     URL WRITERS POSTS_EACH MODE [OUT.tsv]
//!
//! MODE is `once` (a missed deadline is a failure), `fixed` (wait exactly
//! `retry_after_ms`, then resend, up to 5 times) or `jitter` (wait a uniform
//! 0.5x..1.5x of it). Every writer is its own DID and starts at the same
//! instant. Each attempt is a line in OUT.tsv: writer, post, attempt,
//! start_ms (from the burst), latency_ms, status, code.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jig_client::Identity;
use jig_client::blocks::{BuiltBlock, build_text_render, build_with_metadata};
use jig_core::{BlockKind, HlcTimestamp};
use serde_json::{Value, json};

const MAX_ATTEMPTS: u32 = 6;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Once,
    Fixed,
    Jitter,
}

struct Attempt {
    writer: usize,
    post: usize,
    attempt: u32,
    start_ms: u128,
    latency_ms: u128,
    status: u16,
    code: String,
}

fn identity() -> Identity {
    Identity::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&rand::random()))
}

fn body(block: &BuiltBlock) -> Value {
    json!({
        "bundle_b64": STANDARD.encode(block.canonical_bytes()),
        "sig_b64": STANDARD.encode(&block.sender_sig),
    })
}

async fn post(http: &reqwest::Client, url: &str, block: &BuiltBlock) -> (u16, Value) {
    match http
        .post(url)
        .header("jig-capabilities", "tiers")
        .json(&body(block))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let value = resp.json::<Value>().await.unwrap_or(Value::Null);
            (status, value)
        }
        Err(e) => (0, json!({"code": format!("transport: {e}")})),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(
        args.len() >= 5,
        "usage: URL WRITERS POSTS_EACH MODE [OUT.tsv]"
    );
    let base = args[1].trim_end_matches('/').to_string();
    let writers: usize = args[2].parse()?;
    let posts_each: usize = args[3].parse()?;
    let mode = match args[4].as_str() {
        "once" => Mode::Once,
        "fixed" => Mode::Fixed,
        "jitter" => Mode::Jitter,
        other => anyhow::bail!("MODE is once, fixed or jitter, not {other}"),
    };
    let out = args.get(5).cloned();

    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(writers)
        .build()?;
    let info: Value = http
        .get(format!("{base}/.well-known/jig"))
        .send()
        .await?
        .json()
        .await?;
    let server_did = info["server_did"].as_str().unwrap_or_default().to_string();

    // One public channel for the whole burst.
    let owner = identity();
    let slug = format!("#flood-{:08x}", rand::random::<u32>());
    let create = build_with_metadata(
        &owner,
        BlockKind::ChannelCreate,
        HlcTimestamp::now_wall(owner.did().clone()),
        json!({"slug": slug, "tier": "public", "sequencer": server_did}),
    );
    let (status, value) = post(&http, &format!("{base}/api/v1/channels"), &create).await;
    anyhow::ensure!(status < 300, "channel create: {status} {value}");

    let url = format!("{base}/api/v1/blocks");
    let start = Arc::new(tokio::sync::Barrier::new(writers));
    let t0 = Arc::new(std::sync::OnceLock::<Instant>::new());
    let mut tasks = Vec::new();
    for w in 0..writers {
        let (http, url, slug, start, t0) = (
            http.clone(),
            url.clone(),
            slug.clone(),
            start.clone(),
            t0.clone(),
        );
        tasks.push(tokio::spawn(async move {
            let me = identity();
            let blocks: Vec<BuiltBlock> = (0..posts_each)
                .map(|p| {
                    build_text_render(
                        &me,
                        &slug,
                        &format!("flood w{w} p{p}"),
                        HlcTimestamp::now_wall(me.did().clone()),
                    )
                })
                .collect();
            start.wait().await;
            let t0 = *t0.get_or_init(Instant::now);
            let mut log = Vec::new();
            for (p, block) in blocks.iter().enumerate() {
                for attempt in 1..=MAX_ATTEMPTS {
                    let sent = Instant::now();
                    let (status, value) = post(&http, &url, block).await;
                    let code = value["code"].as_str().unwrap_or("").to_string();
                    log.push(Attempt {
                        writer: w,
                        post: p,
                        attempt,
                        start_ms: sent.duration_since(t0).as_millis(),
                        latency_ms: sent.elapsed().as_millis(),
                        status,
                        code: code.clone(),
                    });
                    let retry_after = value["retry_after_ms"].as_u64();
                    let missed = status == 503 && code == "RENDER_FAILED";
                    if !missed || mode == Mode::Once || attempt == MAX_ATTEMPTS {
                        break;
                    }
                    let wait = retry_after.unwrap_or(1_000) as f64;
                    let wait = match mode {
                        Mode::Jitter => wait * (0.5 + rand::random::<f64>()),
                        _ => wait,
                    };
                    tokio::time::sleep(Duration::from_millis(wait as u64)).await;
                }
            }
            log
        }));
    }
    let mut all = Vec::new();
    for t in tasks {
        all.extend(t.await?);
    }

    if let Some(out) = out {
        let mut text = String::from("writer\tpost\tattempt\tstart_ms\tlatency_ms\tstatus\tcode\n");
        for a in &all {
            text.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                a.writer, a.post, a.attempt, a.start_ms, a.latency_ms, a.status, a.code
            ));
        }
        std::fs::write(out, text)?;
    }
    let missed = |a: &Attempt| a.status == 503 && a.code == "RENDER_FAILED";
    let posts = writers * posts_each;
    let first_missed = all.iter().filter(|a| a.attempt == 1 && missed(a)).count();
    let landed = all.iter().filter(|a| a.status < 300).count();
    let other = all.iter().filter(|a| a.status >= 300 && !missed(a)).count();
    println!(
        "posts {posts}  first-try missed deadline {first_missed} ({:.1} %)  attempts {}  landed {landed} ({:.1} %)  other errors {other}",
        100.0 * first_missed as f64 / posts as f64,
        all.len(),
        100.0 * landed as f64 / posts as f64,
    );
    Ok(())
}
