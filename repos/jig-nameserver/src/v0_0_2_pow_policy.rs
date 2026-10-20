//! What a registration costs on one suffix, and how many are admitted
//! (JEP-0008 rules 17, 18, 21–24, 26–27; R1 task 3).
//!
//! - **Effort.** `E = clamp(max(min_effort, suggested) × m_length × m_penalty,
//!   min_effort, max_effort)`. `suggested` is the controller's; `m_length` is
//!   `short_name_factor ^ (short_name_len − len)`; `m_penalty` is `2^points`
//!   for the (alias, DID) pair and the client's IP. `m_standing` is 1 until
//!   JEP-0009 standing exists. An allowlisted registration pays `min_effort`.
//! - **The pool.** A token bucket of `strangers_per_hour` with `burst`. A
//!   stranger registration whose work and signature verified takes a token;
//!   with none, it waits in a queue of `queue_len`, served highest effort
//!   first and in arrival order between equals, for at most
//!   `queue_wait_secs`. A full queue takes a newcomer only if it bids more
//!   than the queue's lowest, which is then refused.
//! - **The controller** (`doubling`) doubles the suggested effort after a
//!   window in which the queue was full, and halves it after a window in
//!   which nothing queued, never below `min_effort` nor above `max_effort`.
//! - **Penalties** last `penalty_decay_secs`; a repeat offence before one
//!   lapses adds a point and doubles its life (rule 27).
//!
//! Everything is in memory and per process, like the rate limits.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use jig_config::v0_0_2_server::{PoolPolicy, PowPolicy};
use tokio::sync::Notify;
use tokio::time::Instant;

/// The most penalty points that count: effort is clamped at `max_effort`
/// long before this.
const MAX_POINTS: u32 = 32;

/// Why a registration was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Busy {
    /// Seconds until the pool's next token.
    pub retry_after: u64,
}

/// Counts for the runbook and the opening checklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MarketStats {
    pub admitted: u64,
    pub refused: u64,
    pub suggested_effort: u64,
    pub queued: usize,
    pub tokens: u32,
}

/// One suffix's pool, controller and penalties.
#[derive(Debug)]
pub struct Market {
    pow: PowPolicy,
    pool: PoolPolicy,
    state: Mutex<State>,
    changed: Notify,
}

#[derive(Debug)]
struct State {
    tokens: f64,
    refilled: Instant,
    queue: Vec<Waiter>,
    next_id: u64,
    suggested: u64,
    window_start: Instant,
    /// The queue was full at some point this window.
    full_seen: bool,
    /// Something queued this window.
    queued_seen: bool,
    penalties: HashMap<String, Penalty>,
    stats: MarketStats,
}

#[derive(Debug, Clone, Copy)]
struct Waiter {
    id: u64,
    effort: u64,
}

#[derive(Debug, Clone, Copy)]
struct Penalty {
    points: u32,
    life: Duration,
    expires: Instant,
}

impl Market {
    pub fn new(pow: PowPolicy, pool: PoolPolicy) -> Self {
        let now = Instant::now();
        Self {
            state: Mutex::new(State {
                tokens: f64::from(pool.burst),
                refilled: now,
                queue: Vec::new(),
                next_id: 0,
                suggested: pow.min_effort,
                window_start: now,
                full_seen: false,
                queued_seen: false,
                penalties: HashMap::new(),
                stats: MarketStats::default(),
            }),
            pow,
            pool,
            changed: Notify::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The effort an ordinary registration of the lowercased local part
    /// `alias` by `did` from `ip` is asked for now.
    pub fn register_effort(&self, alias: &str, did: &str, ip: &str) -> u64 {
        let p = &self.pow;
        if p.min_effort == 0 {
            return 0;
        }
        let now = Instant::now();
        let mut st = self.lock();
        self.roll(&mut st, now);
        let points = (points(&mut st, &pair_key(alias, did), now)
            + points(&mut st, &ip_key(ip), now))
        .min(MAX_POINTS);
        let base = st.suggested.max(p.min_effort);
        let short_by = p.short_name_len.saturating_sub(alias.chars().count());
        let m_length = p
            .short_name_factor
            .checked_pow(u32::try_from(short_by).unwrap_or(u32::MAX))
            .unwrap_or(u64::MAX);
        base.saturating_mul(m_length)
            .saturating_mul(1u64 << points)
            .clamp(p.min_effort, p.max_effort)
    }

    /// Charge `ip` for work that did not verify. Only the IP: the work is
    /// checked before any signature, so the DID it names is not proven, and
    /// charging it would let anyone raise another DID's price.
    pub fn penalize_ip(&self, ip: &str) {
        self.penalize(ip_key(ip));
    }

    /// Charge `did` for an attempt on `alias` that it signed for and that
    /// failed: the name is another DID's. Others asking for `alias` pay
    /// nothing more.
    pub fn penalize_pair(&self, alias: &str, did: &str) {
        self.penalize(pair_key(alias, did));
    }

    fn penalize(&self, key: String) {
        let now = Instant::now();
        let base = Duration::from_secs(self.pow.penalty_decay_secs);
        let mut st = self.lock();
        let next = match st.penalties.get(&key) {
            Some(p) if p.expires > now => Penalty {
                points: (p.points + 1).min(MAX_POINTS),
                life: p.life.saturating_mul(2),
                expires: now + p.life.saturating_mul(2),
            },
            _ => Penalty {
                points: 1,
                life: base,
                expires: now + base,
            },
        };
        st.penalties.insert(key, next);
    }

    /// Admit a stranger registration that bid `effort`: take a token, or wait
    /// in the queue for one. A pool that is off admits at once.
    pub async fn admit(&self, effort: u64) -> Result<(), Busy> {
        if !self.pool.enabled {
            return Ok(());
        }
        let wait = Duration::from_secs(self.pool.queue_wait_secs);
        let deadline = Instant::now() + wait;
        let id = {
            let now = Instant::now();
            let mut st = self.lock();
            self.roll(&mut st, now);
            self.refill(&mut st, now);
            if st.queue.is_empty() && st.tokens >= 1.0 {
                st.tokens -= 1.0;
                st.stats.admitted += 1;
                return Ok(());
            }
            st.queued_seen = true;
            if st.queue.len() >= self.pool.queue_len {
                st.full_seen = true;
                // The lowest bid, the latest arrival among equals.
                let lowest = st
                    .queue
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, w)| (w.effort, std::cmp::Reverse(w.id)))
                    .map(|(i, w)| (i, w.effort));
                match lowest {
                    Some((i, low)) if effort > low => {
                        st.queue.remove(i);
                        self.changed.notify_waiters();
                    }
                    _ => {
                        st.stats.refused += 1;
                        return Err(self.busy(&st, now));
                    }
                }
            }
            let id = st.next_id;
            st.next_id += 1;
            st.queue.push(Waiter { id, effort });
            id
        };
        loop {
            let notified = self.changed.notified();
            let wake_at = {
                let now = Instant::now();
                let mut st = self.lock();
                self.refill(&mut st, now);
                let Some(pos) = st.queue.iter().position(|w| w.id == id) else {
                    // Bumped by a higher bid.
                    st.stats.refused += 1;
                    return Err(self.busy(&st, now));
                };
                let head = st
                    .queue
                    .iter()
                    .max_by_key(|w| (w.effort, std::cmp::Reverse(w.id)))
                    .map(|w| w.id);
                if head == Some(id) && st.tokens >= 1.0 {
                    st.tokens -= 1.0;
                    st.queue.remove(pos);
                    st.stats.admitted += 1;
                    self.changed.notify_waiters();
                    return Ok(());
                }
                if now >= deadline {
                    st.queue.remove(pos);
                    st.stats.refused += 1;
                    self.changed.notify_waiters();
                    return Err(self.busy(&st, now));
                }
                deadline.min(now + self.until_token(&st))
            };
            tokio::select! {
                _ = tokio::time::sleep_until(wake_at) => {}
                _ = notified => {}
            }
        }
    }

    pub fn stats(&self) -> MarketStats {
        let now = Instant::now();
        let mut st = self.lock();
        self.roll(&mut st, now);
        self.refill(&mut st, now);
        let mut s = st.stats;
        s.suggested_effort = st.suggested;
        s.queued = st.queue.len();
        s.tokens = st.tokens as u32;
        s
    }

    fn busy(&self, st: &State, _now: Instant) -> Busy {
        Busy {
            retry_after: self.until_token(st).as_secs().max(1),
        }
    }

    fn rate_per_sec(&self) -> f64 {
        f64::from(self.pool.strangers_per_hour) / 3600.0
    }

    fn until_token(&self, st: &State) -> Duration {
        let rate = self.rate_per_sec();
        if rate <= 0.0 {
            return Duration::from_secs(self.pool.queue_wait_secs.max(1));
        }
        let missing = (1.0 - st.tokens).max(0.0);
        Duration::from_secs_f64(missing / rate)
    }

    fn refill(&self, st: &mut State, now: Instant) {
        let elapsed = now.saturating_duration_since(st.refilled).as_secs_f64();
        st.tokens = (st.tokens + elapsed * self.rate_per_sec()).min(f64::from(self.pool.burst));
        st.refilled = now;
    }

    /// Close every controller window that has ended (rule 17).
    fn roll(&self, st: &mut State, now: Instant) {
        let window = Duration::from_secs(self.pool.controller_window_secs.max(1));
        while now.saturating_duration_since(st.window_start) >= window {
            let floor = self.pow.min_effort;
            if st.full_seen {
                st.suggested = st
                    .suggested
                    .max(floor)
                    .saturating_mul(2)
                    .min(self.pow.max_effort);
            } else if !st.queued_seen {
                st.suggested = (st.suggested / 2).max(floor);
            }
            // Only the first window that ended saw this traffic.
            st.full_seen = false;
            st.queued_seen = !st.queue.is_empty();
            st.window_start += window;
        }
    }
}

fn pair_key(alias: &str, did: &str) -> String {
    format!("pair:{alias}|{did}")
}

fn ip_key(ip: &str) -> String {
    format!("ip:{ip}")
}

/// Live points under `key`, dropping a lapsed penalty.
fn points(st: &mut State, key: &str, now: Instant) -> u32 {
    match st.penalties.get(key) {
        Some(p) if p.expires > now => p.points,
        Some(_) => {
            st.penalties.remove(key);
            0
        }
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pow() -> PowPolicy {
        PowPolicy {
            min_effort: 16,
            max_effort: 1 << 16,
            ..PowPolicy::recommended()
        }
    }

    fn pool(per_hour: u32, burst: u32) -> PoolPolicy {
        PoolPolicy {
            strangers_per_hour: per_hour,
            burst,
            queue_len: 2,
            queue_wait_secs: 10,
            ..PoolPolicy::recommended()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_third_stranger_in_the_hour_is_busy() {
        let m = Market::new(pow(), pool(2, 2));
        assert_eq!(m.admit(16).await, Ok(()));
        assert_eq!(m.admit(16).await, Ok(()));
        let busy = m.admit(16).await.unwrap_err();
        assert!(busy.retry_after > 0);
        assert_eq!(m.stats().refused, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_queue_serves_the_higher_bid_first() {
        let m = std::sync::Arc::new(Market::new(pow(), pool(3600, 1)));
        assert_eq!(m.admit(16).await, Ok(())); // the burst token
        let low = tokio::spawn({
            let m = m.clone();
            async move { m.admit(16).await.map(|()| Instant::now()) }
        });
        tokio::task::yield_now().await;
        let high = tokio::spawn({
            let m = m.clone();
            async move { m.admit(64).await.map(|()| Instant::now()) }
        });
        let (low, high) = (low.await.unwrap().unwrap(), high.await.unwrap().unwrap());
        assert!(
            high < low,
            "the higher bid, though later, got the first token"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_queue_refuses_a_lower_bid_and_bumps_for_a_higher_one() {
        let m = std::sync::Arc::new(Market::new(pow(), pool(1, 0)));
        let waiting: Vec<_> = [32, 32]
            .into_iter()
            .map(|e| {
                let m = m.clone();
                tokio::spawn(async move { m.admit(e).await })
            })
            .collect();
        tokio::task::yield_now().await;
        assert_eq!(m.stats().queued, 2);
        assert!(m.admit(16).await.is_err(), "lower than the queue's lowest");
        let bumper = tokio::spawn({
            let m = m.clone();
            async move { m.admit(64).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(m.stats().queued, 2, "the newcomer took a place");
        // Nobody gets a token in 10 s at one an hour: all time out.
        for w in waiting {
            assert!(w.await.unwrap().is_err());
        }
        assert!(bumper.await.unwrap().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn short_names_pay_more_even_when_the_controller_is_idle() {
        let m = Market::new(pow(), pool(60, 10));
        let five = m.register_effort("alice", "did:a", "1.2.3.4");
        let three = m.register_effort("abc", "did:a", "1.2.3.4");
        assert_eq!(five, 16);
        assert_eq!(three, 16 * 16);
    }

    #[tokio::test(start_paused = true)]
    async fn effort_stops_at_max_effort() {
        let m = Market::new(pow(), pool(60, 10));
        for _ in 0..20 {
            m.penalize_pair("a", "did:a");
        }
        assert_eq!(m.register_effort("a", "did:a", "1.2.3.4"), 1 << 16);
    }

    #[tokio::test(start_paused = true)]
    async fn penalties_land_on_the_pair_or_the_ip_and_nobody_else() {
        let m = Market::new(pow(), pool(60, 10));
        m.penalize_pair("alice", "did:mallory");
        assert_eq!(m.register_effort("alice", "did:mallory", "1.1.1.1"), 32);
        assert_eq!(
            m.register_effort("alice", "did:bob", "1.1.1.1"),
            16,
            "no griefing"
        );
        m.penalize_ip("2.2.2.2");
        assert_eq!(m.register_effort("alice", "did:bob", "2.2.2.2"), 32);
        assert_eq!(m.register_effort("alice", "did:bob", "1.1.1.1"), 16);
    }

    #[tokio::test(start_paused = true)]
    async fn a_repeat_offence_adds_a_point_and_doubles_the_life() {
        let m = Market::new(pow(), pool(60, 10));
        m.penalize_ip("1.1.1.1");
        tokio::time::advance(Duration::from_secs(300)).await;
        m.penalize_ip("1.1.1.1");
        assert_eq!(m.register_effort("alice", "did:a", "1.1.1.1"), 64);
        // 600 s base, doubled to 1200 s from the second offence.
        tokio::time::advance(Duration::from_secs(1100)).await;
        assert_eq!(m.register_effort("alice", "did:a", "1.1.1.1"), 64);
        tokio::time::advance(Duration::from_secs(200)).await;
        assert_eq!(m.register_effort("alice", "did:a", "1.1.1.1"), 16, "lapsed");
    }

    #[tokio::test(start_paused = true)]
    async fn the_suggested_effort_doubles_when_full_and_halves_when_quiet() {
        let m = std::sync::Arc::new(Market::new(pow(), pool(1, 0)));
        let held: Vec<_> = (0..2)
            .map(|_| {
                let m = m.clone();
                tokio::spawn(async move { m.admit(16).await })
            })
            .collect();
        tokio::task::yield_now().await;
        let _ = m.admit(16).await; // refused: the queue is full
        for h in held {
            let _ = h.await;
        }
        tokio::time::advance(Duration::from_secs(300)).await;
        assert_eq!(m.stats().suggested_effort, 32, "doubled");
        assert_eq!(m.register_effort("alice", "did:a", "1.1.1.1"), 32);
        tokio::time::advance(Duration::from_secs(300)).await;
        assert_eq!(m.stats().suggested_effort, 16, "halved");
        tokio::time::advance(Duration::from_secs(300)).await;
        assert_eq!(m.stats().suggested_effort, 16, "never below min_effort");
    }

    #[tokio::test(start_paused = true)]
    async fn a_pool_that_is_off_admits_everyone() {
        let m = Market::new(pow(), PoolPolicy::default());
        for _ in 0..100 {
            assert_eq!(m.admit(1).await, Ok(()));
        }
    }
}
