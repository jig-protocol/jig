//! Token buckets, one per key: a verified DID, or a remote address.
//!
//! A bucket holds up to `burst` tokens and refills at `per_second`; each
//! request takes one. Memory is bounded by `max_tracked` keys. When the table
//! is full, buckets that have refilled to `burst` (their key has been idle long
//! enough that forgetting it changes nothing) are dropped to make room. If
//! none has, a new key is refused: resetting a busy key's bucket would hand
//! whoever is flooding the table a fresh burst.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiter {
    burst: f64,
    per_second: f64,
    max_tracked: usize,
    buckets: Mutex<HashMap<String, Bucket>>,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn refilled(self, now: Instant, burst: f64, per_second: f64) -> Self {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        Self {
            tokens: (self.tokens + elapsed * per_second).min(burst),
            at: now,
        }
    }
}

impl RateLimiter {
    /// `None` when `per_second` is 0: that limit is off.
    pub fn new(burst: u32, per_second: u32, max_tracked: usize) -> Option<Self> {
        (per_second > 0).then(|| Self {
            burst: f64::from(burst.max(1)),
            per_second: f64::from(per_second),
            max_tracked: max_tracked.max(1),
            buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Take one token for `key` at `now`. False when its bucket is empty, or
    /// when `key` is new and the table is full of keys that are not idle.
    pub fn try_take(&self, key: &str, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().expect("rate limiter lock poisoned");
        let (burst, per_second) = (self.burst, self.per_second);
        if !buckets.contains_key(key) && buckets.len() >= self.max_tracked {
            buckets.retain(|_, b| b.refilled(now, burst, per_second).tokens < burst);
            if buckets.len() >= self.max_tracked {
                return false;
            }
        }
        let bucket = buckets
            .get(key)
            .map(|b| b.refilled(now, burst, per_second))
            .unwrap_or(Bucket {
                tokens: burst,
                at: now,
            });
        let (tokens, allowed) = if bucket.tokens >= 1.0 {
            (bucket.tokens - 1.0, true)
        } else {
            (bucket.tokens, false)
        };
        buckets.insert(key.to_string(), Bucket { tokens, at: now });
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_burst_then_the_refill_rate() {
        let limiter = RateLimiter::new(3, 2, 10).unwrap();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(limiter.try_take("a", t0));
        }
        assert!(!limiter.try_take("a", t0), "the burst is spent");
        assert!(limiter.try_take("b", t0), "another key has its own bucket");
        assert!(
            limiter.try_take("a", t0 + Duration::from_millis(500)),
            "half a second at 2/s refills one"
        );
        assert!(!limiter.try_take("a", t0 + Duration::from_millis(500)));
    }

    #[test]
    fn a_full_table_forgets_idle_keys_but_never_resets_a_busy_one() {
        let limiter = RateLimiter::new(2, 1, 2).unwrap();
        let t0 = Instant::now();
        assert!(limiter.try_take("busy", t0));
        assert!(limiter.try_take("busy", t0));
        assert!(limiter.try_take("other", t0));
        // Both tracked keys are short of a full bucket: a newcomer is refused
        // rather than either being forgotten.
        assert!(!limiter.try_take("new", t0));
        assert!(!limiter.try_take("busy", t0), "busy kept its empty bucket");
        // Once both have idled back to full, they can be forgotten.
        let later = t0 + Duration::from_secs(5);
        assert!(limiter.try_take("new", later));
    }

    #[test]
    fn a_rate_of_zero_is_no_limit() {
        assert!(RateLimiter::new(10, 0, 10).is_none());
    }
}
