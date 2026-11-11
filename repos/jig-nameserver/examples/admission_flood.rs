//! Bot-flood admission benchmark: what an honest `jig ns register` meets
//! when agents outnumber humans on one suffix.
//!
//! It drives the nameserver's own [`Market`] (pool, queue, controller) in
//! tokio's paused clock, so six simulated hours take seconds and a seed gives
//! the same numbers on any machine. Nothing else is simulated in the server:
//! the effort asked is `Market::register_effort`, the admission is
//! `Market::admit`, with the bid the client proved.
//!
//! What is modelled, not run:
//! - **Work.** A solve at effort `E` takes `Exp(E)` digests (the geometric
//!   lottery of `jig_core::pow::meets`), at a rate in digests per second.
//!   The honest rate is this machine's `jig_client::pow::measure_rate`
//!   unless `--rate` gives one; agents solve `--agent-speedup` times faster.
//! - **The honest client** is `jig-cli`'s `with_pow`: bid what is asked; a
//!   solve that would pass the challenge's life less `SEND_MARGIN` is
//!   abandoned and retried once on a fresh challenge; a `REGISTRATION_BUSY`
//!   with `Retry-After` up to 60 s is waited out and retried once at
//!   `max(asked, 2 × last bid)`, capped at what this machine solves in
//!   `JIG_POW_MAX_SOLVE_SECS` (60 s) and in the challenge's life. A second
//!   refusal ends the attempt, as it does for a user.
//! - **Agents** come in two kinds. `client` agents run the honest client's
//!   code at their own rate: pure volume. `outbid` agents bid `4 ×` what is
//!   asked, which beats an honest retry's `2 ×`, resend the same proof after
//!   each busy refusal while the challenge lives (a busy refusal leaves it
//!   usable), and keep going on fresh challenges for up to an hour.
//! - Every identity is a fresh DID with an 8-letter alias from its own
//!   address, so no short-name multiplier and no penalty applies; per-IP
//!   rate limits are assumed evaded (a botnet, or one address: one address's
//!   30 registrations a minute already exceed the pool's 60 an hour).
//! - Network time and server CPU are taken as zero.
//!
//! Run: `cargo run --release -p jig-nameserver --example admission_flood --
//! [--rate DIGESTS_PER_SEC] [--seed N] [--hours H] [--honest-per-hour N]
//! [--ratios 0,1,10,100,1000] [--agent-speedup M] [--csv FILE]`

use std::sync::{Arc, Mutex};
use std::time::Duration;

use jig_config::v0_0_2_server::{PoolPolicy, PowPolicy};
use jig_nameserver::v0_0_2_pow_policy::Market;
use tokio::time::Instant;

/// The challenge's life (`DEFAULT_CHALLENGE_TTL` in jig-nameserver).
const CHALLENGE_TTL: f64 = 60.0;
/// What a client keeps in hand to send its proof (`jig_client::pow::SEND_MARGIN`).
const SEND_MARGIN: f64 = 5.0;
/// `jig_client::pow::DEFAULT_MAX_SOLVE_SECS`.
const MAX_SOLVE_SECS: f64 = 60.0;
/// `jig-cli`'s `MAX_BUSY_WAIT_SECS`.
const MAX_BUSY_WAIT_SECS: u64 = 60;
/// `jig_core::pow::MAX_EFFORT`: no proof is worth more.
const MAX_EFFORT: u64 = 1 << 28;
/// How much an `outbid` agent bids over the asked effort.
const OUTBID: u64 = 4;
/// How far the clock moves at a time.
const STEP: Duration = Duration::from_millis(1);
/// How long an `outbid` identity keeps trying.
const OUTBID_PATIENCE: f64 = 3600.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Agents {
    /// The honest client's own logic, at the agents' rate.
    Client,
    /// Bid over the asked effort and keep trying.
    Outbid,
}

impl Agents {
    fn name(self) -> &'static str {
        match self {
            Agents::Client => "client",
            Agents::Outbid => "outbid",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pool {
    Recommended,
    Off,
}

impl Pool {
    fn name(self) -> &'static str {
        match self {
            Pool::Recommended => "recommended",
            Pool::Off => "off",
        }
    }
}

#[derive(Clone)]
struct Args {
    rate: Option<f64>,
    seed: u64,
    hours: f64,
    honest_per_hour: f64,
    ratios: Vec<f64>,
    agent_speedup: f64,
    csv: Option<String>,
}

fn parse_args() -> Args {
    let mut a = Args {
        rate: None,
        seed: 1,
        hours: 6.0,
        honest_per_hour: 10.0,
        ratios: vec![0.0, 1.0, 10.0, 100.0, 1000.0],
        agent_speedup: 10.0,
        csv: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--rate" => a.rate = Some(value().parse().expect("--rate: digests per second")),
            "--seed" => a.seed = value().parse().expect("--seed: an integer"),
            "--hours" => a.hours = value().parse().expect("--hours: a number"),
            "--honest-per-hour" => {
                a.honest_per_hour = value().parse().expect("--honest-per-hour: a number")
            }
            "--ratios" => {
                a.ratios = value()
                    .split(',')
                    .map(|r| r.parse().expect("--ratios: numbers, comma-separated"))
                    .collect()
            }
            "--agent-speedup" => {
                a.agent_speedup = value().parse().expect("--agent-speedup: a number")
            }
            "--csv" => a.csv = Some(value()),
            other => panic!("unknown flag {other}"),
        }
    }
    a
}

/// SplitMix64: small, seedable, and the same on every platform and `rand`
/// version, so a seed names one run.
#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64, stream: u64) -> Self {
        let mut r = Rng(seed ^ stream.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        r.next();
        r
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in (0, 1].
    fn unit(&mut self) -> f64 {
        ((self.next() >> 11) as f64 + 1.0) / (1u64 << 53) as f64
    }

    /// Exponential with mean `mean`.
    fn exp(&mut self, mean: f64) -> f64 {
        -self.unit().ln() * mean
    }
}

/// How one identity's attempt ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    Admitted,
    /// Refused busy twice, or a wait longer than the client takes.
    Busy,
    /// The challenge expired under the work twice, or the work would not fit.
    Expired,
}

#[derive(Default)]
struct Tally {
    started: u64,
    admitted: u64,
    busy: u64,
    expired: u64,
    /// Seconds from start to admission, admitted identities only.
    latencies: Vec<f64>,
    /// Digests spent, admitted or not.
    digests: f64,
}

impl Tally {
    fn record(&mut self, end: End, latency: f64, digests: f64) {
        self.digests += digests;
        match end {
            End::Admitted => {
                self.admitted += 1;
                self.latencies.push(latency);
            }
            End::Busy => self.busy += 1,
            End::Expired => self.expired += 1,
        }
    }

    fn percentile(&mut self, p: f64) -> Option<f64> {
        if self.latencies.is_empty() {
            return None;
        }
        self.latencies.sort_by(f64::total_cmp);
        let i = ((self.latencies.len() as f64 - 1.0) * p).round() as usize;
        Some(self.latencies[i])
    }
}

/// Solve at `bid` with `left` seconds before the work must be sent: the
/// digests spent, and whether a proof came out in time.
fn solve(rng: &mut Rng, bid: u64, rate: f64, left: f64) -> (f64, bool) {
    let digests = rng.exp(bid as f64);
    let secs = digests / rate;
    if secs <= left {
        (digests, true)
    } else {
        (left * rate, false)
    }
}

/// `jig-cli`'s `with_pow` for one registration. Sleeps for the work and the
/// waits in paused time; returns how it ended and the digests spent.
async fn honest(
    market: &Market,
    alias: &str,
    did: &str,
    ip: &str,
    rate: f64,
    rng: &mut Rng,
) -> (End, f64) {
    let cap = (rate * MAX_SOLVE_SECS).clamp(1.0, MAX_EFFORT as f64) as u64;
    let mut digests = 0.0;
    let mut bid = 0u64;
    let mut expired = false;
    for attempt in 0..2 {
        let asked = market.register_effort(alias, did, ip);
        let left = CHALLENGE_TTL - SEND_MARGIN;
        // `Cap::within`: no more than fits before the challenge expires.
        let cap = cap.min((rate * left) as u64);
        if asked > cap {
            return (End::Expired, digests);
        }
        bid = if attempt == 0 || expired {
            asked
        } else {
            asked.max(bid.saturating_mul(2)).min(cap)
        };
        let (spent, solved) = solve(rng, bid, rate, left);
        digests += spent;
        tokio::time::sleep(Duration::from_secs_f64(spent / rate)).await;
        if !solved {
            if attempt == 0 {
                expired = true;
                continue;
            }
            return (End::Expired, digests);
        }
        match market.admit(bid).await {
            Ok(()) => return (End::Admitted, digests),
            Err(busy) => {
                if attempt > 0 || busy.retry_after > MAX_BUSY_WAIT_SECS {
                    return (End::Busy, digests);
                }
                tokio::time::sleep(Duration::from_secs(busy.retry_after)).await;
                expired = false;
            }
        }
    }
    unreachable!("the second attempt always returns")
}

/// An agent that bids over the asking price and keeps trying.
async fn outbid(
    market: &Market,
    alias: &str,
    did: &str,
    ip: &str,
    rate: f64,
    rng: &mut Rng,
) -> (End, f64) {
    let start = Instant::now();
    let mut digests = 0.0;
    let mut last = End::Busy;
    while start.elapsed().as_secs_f64() < OUTBID_PATIENCE {
        let asked = market.register_effort(alias, did, ip);
        let issued = Instant::now();
        let bid = asked.saturating_mul(OUTBID).min(MAX_EFFORT);
        let left = CHALLENGE_TTL - SEND_MARGIN;
        let (spent, solved) = solve(rng, bid, rate, left);
        digests += spent;
        tokio::time::sleep(Duration::from_secs_f64(spent / rate)).await;
        if !solved {
            last = End::Expired;
            continue;
        }
        // The same proof, resent while its challenge lives.
        loop {
            match market.admit(bid).await {
                Ok(()) => return (End::Admitted, digests),
                Err(busy) => {
                    last = End::Busy;
                    let resend_at = issued.elapsed().as_secs_f64() + busy.retry_after as f64;
                    if resend_at > CHALLENGE_TTL - SEND_MARGIN {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(busy.retry_after)).await;
                }
            }
        }
    }
    (last, digests)
}

struct Scenario {
    pool: Pool,
    agents: Agents,
    ratio: f64,
}

struct Outcome {
    honest: Tally,
    agents: Tally,
    /// The suggested effort sampled each controller window.
    suggested: Vec<u64>,
    admitted_per_hour: f64,
    /// Seconds from the start until the last identity finished.
    elapsed_s: f64,
}

/// Poisson arrivals at `per_hour` over `hours`, in seconds from the start.
fn arrivals(rng: &mut Rng, per_hour: f64, hours: f64) -> Vec<f64> {
    let mut out = Vec::new();
    if per_hour <= 0.0 {
        return out;
    }
    let mut t = 0.0;
    loop {
        t += rng.exp(3600.0 / per_hour);
        if t >= hours * 3600.0 {
            return out;
        }
        out.push(t);
    }
}

async fn run(args: &Args, rate: f64, sc: &Scenario) -> Outcome {
    let pool = match sc.pool {
        Pool::Recommended => PoolPolicy::recommended(),
        Pool::Off => PoolPolicy {
            enabled: false,
            ..PoolPolicy::recommended()
        },
    };
    let window = pool.controller_window_secs;
    let market = Arc::new(Market::new(PowPolicy::recommended(), pool));
    let honest_tally = Arc::new(Mutex::new(Tally::default()));
    let agent_tally = Arc::new(Mutex::new(Tally::default()));
    let start = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();

    let mut spawn = |at: f64, n: u64, agent: bool| {
        let market = market.clone();
        let tally = if agent {
            agent_tally.clone()
        } else {
            honest_tally.clone()
        };
        let kind = sc.agents;
        let seed = args.seed;
        let rate = if agent {
            rate * args.agent_speedup
        } else {
            rate
        };
        tasks.spawn(async move {
            tokio::time::sleep_until(start + Duration::from_secs_f64(at)).await;
            let mut rng = Rng::new(seed, (n << 1) | u64::from(agent));
            let who = if agent { 'a' } else { 'h' };
            let alias = format!("{who}{n:07}");
            let did = format!("did:jig:z{who}{n}");
            let ip = format!("{who}{n}");
            tally.lock().unwrap().started += 1;
            let began = Instant::now();
            let (end, digests) = if agent && kind == Agents::Outbid {
                outbid(&market, &alias, &did, &ip, rate, &mut rng).await
            } else {
                honest(&market, &alias, &did, &ip, rate, &mut rng).await
            };
            tally
                .lock()
                .unwrap()
                .record(end, began.elapsed().as_secs_f64(), digests);
        });
    };

    let mut rng = Rng::new(args.seed, u64::MAX);
    for (n, at) in arrivals(&mut rng, args.honest_per_hour, args.hours)
        .into_iter()
        .enumerate()
    {
        spawn(at, n as u64, false);
    }
    let mut rng = Rng::new(args.seed, u64::MAX - 1);
    for (n, at) in arrivals(&mut rng, args.honest_per_hour * sc.ratio, args.hours)
        .into_iter()
        .enumerate()
    {
        spawn(at, n as u64, true);
    }

    // The clock moves in steps of STEP, not by tokio's auto-advance: a
    // waiter in `Market::admit` that finds the pool a float's breadth short
    // of a token sleeps for 0 ns, which never lets a paused runtime go idle,
    // so auto-advance would never move the clock again.
    let clock = tokio::spawn(async {
        loop {
            tokio::time::advance(STEP).await;
        }
    });
    // The controller's suggested effort, once a window, until every
    // identity has finished.
    let suggested = Arc::new(Mutex::new(Vec::new()));
    let sampler = {
        let (market, suggested) = (market.clone(), suggested.clone());
        tokio::spawn(async move {
            loop {
                suggested
                    .lock()
                    .unwrap()
                    .push(market.stats().suggested_effort);
                tokio::time::sleep(Duration::from_secs(window)).await;
            }
        })
    };
    while tasks.join_next().await.is_some() {}
    let elapsed_h = start.elapsed().as_secs_f64() / 3600.0;
    sampler.abort();
    clock.abort();
    let take = |t: Arc<Mutex<Tally>>| {
        Arc::try_unwrap(t)
            .ok()
            .expect("tasks done")
            .into_inner()
            .unwrap()
    };
    let (honest, agents) = (take(honest_tally), take(agent_tally));
    let suggested = suggested.lock().unwrap().clone();
    Outcome {
        // Over the whole run, the last identities' tail included.
        admitted_per_hour: (honest.admitted + agents.admitted) as f64 / elapsed_h,
        elapsed_s: elapsed_h * 3600.0,
        honest,
        agents,
        suggested,
    }
}

fn pct(n: u64, of: u64) -> String {
    if of == 0 {
        "–".into()
    } else {
        format!("{:.1}%", 100.0 * n as f64 / of as f64)
    }
}

fn secs(s: Option<f64>) -> String {
    s.map_or("–".into(), |s| format!("{s:.0}"))
}

fn log2(e: u64) -> String {
    format!("2^{:.1}", (e.max(1) as f64).log2())
}

fn main() {
    let args = parse_args();
    let rate = args.rate.unwrap_or_else(jig_client::pow::measure_rate);
    let pow = PowPolicy::recommended();
    let pool = PoolPolicy::recommended();
    println!(
        "# Admission flood: {} h per run, seed {}",
        args.hours, args.seed
    );
    println!();
    println!(
        "- Honest rate {rate:.0} digests/s ({}); agents {}× that.",
        if args.rate.is_some() {
            "given"
        } else {
            "measured on this machine"
        },
        args.agent_speedup
    );
    println!(
        "- Honest arrivals {}/h; agents at ratio × that. Effort {}..{}; pool {}/h, burst {}, \
         queue {} for {} s, window {} s.",
        args.honest_per_hour,
        log2(pow.min_effort),
        log2(pow.max_effort),
        pool.strangers_per_hour,
        pool.burst,
        pool.queue_len,
        pool.queue_wait_secs,
        pool.controller_window_secs
    );
    println!(
        "- Work is in digests; seconds are at the honest rate. Agent fleet: the agents' work \
         over the run, in machines at the honest rate running without pause."
    );
    println!("- Latencies are of admitted honest users only, from arrival to admission.");
    println!();
    println!(
        "| pool | agents | agents:human | honest admitted | busy | expired | p50 s | p95 s | \
         honest s/admit | agents admitted | agent s/identity | agent fleet | asked (max) | \
         admitted/h |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|");

    let mut grid = Vec::new();
    for &ratio in &args.ratios {
        grid.push(Scenario {
            pool: Pool::Recommended,
            agents: Agents::Client,
            ratio,
        });
    }
    for &ratio in args.ratios.iter().filter(|&&r| r > 0.0) {
        grid.push(Scenario {
            pool: Pool::Recommended,
            agents: Agents::Outbid,
            ratio,
        });
    }
    for &ratio in &args.ratios {
        grid.push(Scenario {
            pool: Pool::Off,
            agents: Agents::Client,
            ratio,
        });
    }

    let mut csv = String::from(
        "pool,agents,ratio,honest_started,honest_admitted,honest_busy,honest_expired,\
         honest_p50_s,honest_p95_s,honest_digests,agents_started,agents_admitted,\
         agent_digests,max_suggested_effort,admitted_per_hour,elapsed_s\n",
    );
    for sc in &grid {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .expect("a runtime");
        let mut out = rt.block_on(run(&args, rate, sc));
        let h = &mut out.honest;
        let (p50, p95) = (h.percentile(0.5), h.percentile(0.95));
        let max_asked = out
            .suggested
            .iter()
            .copied()
            .max()
            .unwrap_or(pow.min_effort);
        let per = |digests: f64, n: u64| {
            if n == 0 {
                "–".to_string()
            } else {
                format!("{:.1}", digests / n as f64 / rate)
            }
        };
        let a = &out.agents;
        println!(
            "| {} | {} | {}:1 | {} of {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {:.1} |",
            sc.pool.name(),
            sc.agents.name(),
            sc.ratio,
            pct(h.admitted, h.started),
            h.started,
            pct(h.busy, h.started),
            pct(h.expired, h.started),
            secs(p50),
            secs(p95),
            per(h.digests, h.admitted),
            if a.started == 0 {
                "–".to_string()
            } else {
                format!("{} of {}", a.admitted, a.started)
            },
            per(a.digests, a.admitted),
            if a.started == 0 {
                "–".to_string()
            } else {
                format!("{:.2}", a.digests / out.elapsed_s / rate)
            },
            log2(max_asked),
            out.admitted_per_hour,
        );
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{:.0},{},{},{:.0},{},{:.2},{:.0}\n",
            sc.pool.name(),
            sc.agents.name(),
            sc.ratio,
            h.started,
            h.admitted,
            h.busy,
            h.expired,
            p50.map_or(String::new(), |s| format!("{s:.1}")),
            p95.map_or(String::new(), |s| format!("{s:.1}")),
            h.digests,
            a.started,
            a.admitted,
            a.digests,
            max_asked,
            out.admitted_per_hour,
            out.elapsed_s,
        ));
    }
    if let Some(path) = &args.csv {
        std::fs::write(path, csv).expect("write the CSV");
    }
}
