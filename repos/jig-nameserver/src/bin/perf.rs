use clap::Parser;
use hdrhistogram::Histogram;
use jig_nameserver::storage::NamesStorage;
use jig_nameserver::{NameServerConfig, server::app_router, storage::MemoryStorage};
use pprof::ProfilerGuardBuilder;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "jig-nameserver perf driver")]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:7070")]
    url: String,

    #[arg(long, value_parser=["challenge","resolve"], default_value = "challenge")]
    endpoint: String,

    #[arg(long, default_value_t = 1000)]
    requests: usize,

    #[arg(long, default_value_t = 50)]
    concurrency: usize,

    #[arg(long)]
    subject: Option<String>,

    #[arg(long)]
    scope: Option<String>,

    /// If set, runs an in-process server on a random port and targets it
    #[arg(long)]
    self_host: bool,

    /// Enable CPU profiling (pprof) and write flamegraph
    #[arg(long)]
    profile: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();

    let mut handle: Option<JoinHandle<()>> = None;
    let target_url = if args.self_host {
        let (url, h) = start_inproc_server().await?;
        handle = Some(h);
        url
    } else {
        args.url.clone()
    };

    let client = reqwest::Client::new();
    let start = Instant::now();
    let guard = if args.profile {
        ProfilerGuardBuilder::default().frequency(1000).build().ok()
    } else {
        None
    };
    let hist = Arc::new(tokio::sync::Mutex::new(Histogram::<u64>::new(3)?));
    let success = Arc::new(AtomicUsize::new(0));
    let fail = Arc::new(AtomicUsize::new(0));

    let mut tasks = Vec::new();
    let per_worker = args.requests.div_ceil(args.concurrency);
    for _ in 0..args.concurrency {
        let client = client.clone();
        let endpoint = args.endpoint.clone();
        let url = target_url.clone();
        let subject = args
            .subject
            .clone()
            .unwrap_or_else(|| "alice@example.com".into());
        let scope = args.scope.clone().unwrap_or_else(|| "room1".into());
        let hist = hist.clone();
        let success = success.clone();
        let fail = fail.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..per_worker {
                let body = match endpoint.as_str() {
                    "challenge" => {
                        if subject.is_empty() {
                            serde_json::json!({"action":"alias","scope": scope})
                        } else {
                            serde_json::json!({"action":"claim","subject": subject})
                        }
                    }
                    "resolve" => {
                        // Use query param instead of body
                        serde_json::json!({})
                    }
                    _ => serde_json::json!({}),
                };
                let t0 = Instant::now();
                let res = match endpoint.as_str() {
                    "challenge" => {
                        client
                            .post(format!("{url}/v1/challenge"))
                            .json(&body)
                            .send()
                            .await
                    }
                    "resolve" => {
                        client
                            .get(format!("{url}/v1/resolve?name={subject}"))
                            .send()
                            .await
                    }
                    _ => unreachable!(),
                };
                let elapsed = t0.elapsed();
                let mut h = hist.lock().await;
                let _ = h.record(elapsed.as_micros() as u64);
                drop(h);
                match res {
                    Ok(resp) if resp.status().is_success() => {
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    let total = start.elapsed();
    let h = hist.lock().await;
    let p50 = h.value_at_quantile(0.50) as f64 / 1000.0;
    let p95 = h.value_at_quantile(0.95) as f64 / 1000.0;
    let mean = h.mean() / 1000.0;
    let succ = success.load(std::sync::atomic::Ordering::Relaxed);
    let failed = fail.load(std::sync::atomic::Ordering::Relaxed);
    let rps = (succ + failed) as f64 / total.as_secs_f64();
    println!(
        "Endpoint: {}\nRequests: {}\nConcurrency: {}\nSuccess: {} Failed: {}\nTotal: {:.3}s RPS: {:.1}\nLatency ms: p50={:.2} p95={:.2} mean={:.2}",
        args.endpoint,
        args.requests,
        args.concurrency,
        succ,
        failed,
        total.as_secs_f64(),
        rps,
        p50,
        p95,
        mean
    );

    // Write results JSON
    let out_dir = std::path::Path::new("repos/jig-nameserver/perf/results");
    let _ = std::fs::create_dir_all(out_dir);
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let fname = format!("{}/{}.json", out_dir.display(), ts);
    let out = serde_json::json!({
        "endpoint": args.endpoint,
        "url": target_url,
        "requests": args.requests,
        "concurrency": args.concurrency,
        "success": succ,
        "failed": failed,
        "total_secs": total.as_secs_f64(),
        "rps": rps,
        "latency_ms": {"p50": p50, "p95": p95, "mean": mean},
    });
    std::fs::write(&fname, serde_json::to_vec_pretty(&out)?)?;

    // Write flamegraph if profiler enabled
    if let Some(g) = guard
        && let Ok(report) = g.report().build()
    {
        let fg = format!("{}/flamegraph-{}.svg", out_dir.display(), ts);
        if let Ok(mut file) = std::fs::File::create(&fg) {
            let _ = report.flamegraph(&mut file);
        }
    }

    if let Some(h) = handle {
        h.abort();
    }
    Ok(())
}

async fn start_inproc_server() -> anyhow::Result<(String, JoinHandle<()>)> {
    let mut cfg = NameServerConfig::default();
    cfg.rate_limits.per_key_per_min = u32::MAX / 2;
    cfg.rate_limits.per_ip_per_min = u32::MAX / 2;
    let storage: Arc<dyn NamesStorage> = Arc::new(MemoryStorage::default());
    let app = app_router(jig_nameserver::server::AppState {
        cfg: cfg.clone(),
        storage,
        ns_id: "perf".into(),
        ns_pubkey_hex: String::new(),
        federation: None,
        federation_coordinator: None,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let url = format!("http://{}:{}", addr.ip(), addr.port());
    let make = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, make).await;
    });
    // Small delay to ensure server is ready
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok((url, h))
}
