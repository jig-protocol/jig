//! Capacity pools: members, invited and strangers (JEP-0008 rules 21–23).
//!
//! The server's accepted local writes per second are split three ways. Each
//! pool is a token bucket holding its share of the burst and refilling at its
//! share of the rate. A write takes a token from its own pool first. When that
//! pool is empty it may borrow from another pool that is **idle**: one that
//! has had no demand of its own for [`IDLE_AFTER`], and then only what that
//! pool holds above half its burst.
//!
//! - Capacity is returned under demand: the first request from the owner
//!   pool, admitted or not, ends its idleness, and lending stops at once.
//! - Members never wait on the others: while members are writing, nobody
//!   borrows from them, and what they lent while idle never takes their
//!   bucket below half.
//! - A server with no members at all (no records, nobody aged in) lends the
//!   whole member share to strangers, so the pools cost it nothing.
//!
//! No clock is read here: every call takes `now`, so tests run on injected
//! time.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use jig_config::v0_0_2_server::PoolsSection;

/// How long a pool must go without demand of its own before it lends.
pub const IDLE_AFTER: Duration = Duration::from_secs(1);

/// Which pool a subject's requests are served from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pool {
    Member,
    Invited,
    Stranger,
}

impl Pool {
    fn index(self) -> usize {
        match self {
            Pool::Member => 0,
            Pool::Invited => 1,
            Pool::Stranger => 2,
        }
    }

    /// The pools this one may borrow from, cheapest to lend first.
    fn lenders(self) -> &'static [Pool] {
        match self {
            Pool::Member => &[Pool::Stranger, Pool::Invited],
            Pool::Invited => &[Pool::Stranger, Pool::Member],
            Pool::Stranger => &[Pool::Invited, Pool::Member],
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    burst: f64,
    per_second: f64,
    at: Instant,
    /// The last request from this bucket's own pool.
    demand: Option<Instant>,
}

impl Bucket {
    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.per_second).min(self.burst);
        self.at = now.max(self.at);
    }

    /// Whether it may lend one token at `now`: idle, and above half after.
    fn lends(&self, now: Instant) -> bool {
        let idle = self
            .demand
            .is_none_or(|at| now.saturating_duration_since(at) >= IDLE_AFTER);
        idle && self.tokens - 1.0 >= self.burst / 2.0
    }
}

/// The write capacity, split into the three pools.
pub struct WritePools {
    buckets: Mutex<[Bucket; 3]>,
}

impl WritePools {
    /// `None` when `writes_per_second` is 0: the pools are off. Fails on
    /// shares that leave members nothing, and on a nonzero share whose burst
    /// is under one write.
    pub fn new(section: &PoolsSection, now: Instant) -> anyhow::Result<Option<Self>> {
        let (stranger, invited) = (section.stranger_share_pct, section.invited_share_pct);
        if u16::from(stranger) + u16::from(invited) >= 100 {
            anyhow::bail!(
                "[auth.pools] stranger_share_pct + invited_share_pct must be below 100, \
                 so members keep a share; got {stranger} + {invited}"
            );
        }
        if section.writes_per_second == 0 {
            return Ok(None);
        }
        let rate = f64::from(section.writes_per_second);
        let burst = f64::from(section.writes_burst.max(section.writes_per_second));
        let bucket = |pct: f64| Bucket {
            tokens: burst * pct / 100.0,
            burst: burst * pct / 100.0,
            per_second: rate * pct / 100.0,
            at: now,
            demand: None,
        };
        let member = 100.0 - f64::from(stranger) - f64::from(invited);
        // A share whose burst is under one token could never serve a write
        // from its own bucket.
        for (name, pct) in [
            ("member", member),
            ("invited", f64::from(invited)),
            ("stranger", f64::from(stranger)),
        ] {
            if pct > 0.0 && burst * pct / 100.0 < 1.0 {
                anyhow::bail!(
                    "[auth.pools] the {name} share of writes_burst {burst} is under one write; \
                     raise writes_burst or set that share to 0"
                );
            }
        }
        Ok(Some(Self {
            buckets: Mutex::new([
                bucket(member),
                bucket(f64::from(invited)),
                bucket(f64::from(stranger)),
            ]),
        }))
    }

    /// One token's refill in `pool`'s own bucket. `None` when its share is
    /// 0: it never refills, and writes from it only borrow.
    pub fn refill_interval(&self, pool: Pool) -> Option<Duration> {
        let buckets = self.buckets.lock().expect("write pools lock poisoned");
        let rate = buckets[pool.index()].per_second;
        (rate > 0.0).then(|| Duration::from_secs_f64(1.0 / rate))
    }

    /// Take one write's worth for `pool` at `now`: from its own bucket, or
    /// else from an idle pool. False when neither has it.
    pub fn try_take(&self, pool: Pool, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().expect("write pools lock poisoned");
        for bucket in buckets.iter_mut() {
            bucket.refill(now);
        }
        let own = &mut buckets[pool.index()];
        own.demand = Some(now.max(own.demand.unwrap_or(now)));
        if own.tokens >= 1.0 {
            own.tokens -= 1.0;
            return true;
        }
        for lender in pool.lenders() {
            let lender = &mut buckets[lender.index()];
            if lender.lends(now) {
                lender.tokens -= 1.0;
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 100 writes a second, burst 100: members 70, invited 10, strangers 20.
    fn pools(now: Instant) -> WritePools {
        WritePools::new(
            &PoolsSection {
                writes_per_second: 100,
                writes_burst: 100,
                ..PoolsSection::default()
            },
            now,
        )
        .unwrap()
        .unwrap()
    }

    fn take_all(pools: &WritePools, pool: Pool, now: Instant) -> usize {
        (0..10_000)
            .take_while(|_| pools.try_take(pool, now))
            .count()
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// A refused writer is told its own pool's refill: members' 70 a second,
    /// strangers' 20. A share of 0 never refills, and gives no time.
    #[test]
    fn the_retry_wait_is_the_writers_pools_refill() {
        let now = Instant::now();
        let pools = pools(now);
        assert_eq!(
            pools.refill_interval(Pool::Member),
            Some(Duration::from_secs_f64(1.0 / 70.0))
        );
        assert_eq!(pools.refill_interval(Pool::Stranger), Some(ms(50)));
        let no_invited = WritePools::new(
            &PoolsSection {
                writes_per_second: 100,
                writes_burst: 100,
                invited_share_pct: 0,
                ..PoolsSection::default()
            },
            now,
        )
        .unwrap()
        .unwrap();
        assert_eq!(no_invited.refill_interval(Pool::Invited), None);
    }

    /// The plan's flood test, on injected time: while members are writing, a
    /// thousand fresh DIDs, each a stranger, get the stranger share and what
    /// idle invited lends, never members' capacity; and members keep writing
    /// at their full rate through the flood.
    #[test]
    fn a_stranger_flood_leaves_members_their_share() {
        let t0 = Instant::now();
        let pools = pools(t0);
        assert!(pools.try_take(Pool::Member, t0), "members are active");
        let flood = |at| {
            (0..1_000)
                .filter(|_| pools.try_take(Pool::Stranger, at))
                .count()
        };
        assert_eq!(flood(t0), 20 + 5, "their 20, and invited's 5 above half");
        assert_eq!(
            take_all(&pools, Pool::Member, t0),
            69,
            "the rest of members' burst"
        );
        // Every half second for ten seconds: the flood goes first, then
        // members. (Half seconds keep the refill arithmetic exact.)
        let mut members = 0;
        for tick in 1..=20 {
            let at = t0 + ms(500 * tick);
            flood(at);
            members += take_all(&pools, Pool::Member, at);
        }
        assert_eq!(members, 700, "members' 70/s, all ten seconds of it");
    }

    /// A server whose members are quiet lends their capacity above half to
    /// strangers; the first member write stops the lending.
    #[test]
    fn idle_capacity_is_lent_and_returned_under_demand() {
        let t0 = Instant::now();
        let pools = pools(t0);
        // Nobody else has asked for anything: strangers get their 20, then
        // invited's 5 and members' 35 above half.
        assert_eq!(take_all(&pools, Pool::Stranger, t0), 20 + 5 + 35);
        // Members still have the half that was never lent, at once.
        assert_eq!(take_all(&pools, Pool::Member, t0), 35);
        // Members just asked: for the next second they lend nothing, though
        // their bucket refills above half.
        let t1 = t0 + ms(900);
        assert_eq!(
            take_all(&pools, Pool::Stranger, t1),
            18 + 5,
            "own 18, invited's 5"
        );
        // A second after members last asked, they are idle and lend again.
        let t2 = t0 + ms(2_000);
        assert_eq!(
            take_all(&pools, Pool::Stranger, t2),
            20 + 5 + 35,
            "own burst of 20 again"
        );
    }

    /// The guarantee rule 23 states: a member arriving while strangers hold
    /// borrowed capacity is served at once from the reserved half of its
    /// burst, and lending stops with that first request.
    #[test]
    fn a_member_arriving_mid_borrow_is_served_from_the_reserve_at_once() {
        let t0 = Instant::now();
        let pools = pools(t0);
        // Strangers flood a quiet server and borrow members' capacity down
        // to the reserve: 35 of members' 70.
        assert_eq!(take_all(&pools, Pool::Stranger, t0), 20 + 5 + 35);
        // A member burst arriving now: all 35 of the reserve, with no wait.
        let t1 = t0 + ms(1);
        for i in 0..35 {
            assert!(pools.try_take(Pool::Member, t1), "member write {i} waited");
        }
        // Lending stopped at the first member request: strangers, still
        // flooding, get only their own refill, none of members'.
        let t2 = t1 + ms(500);
        assert_eq!(
            take_all(&pools, Pool::Stranger, t2),
            10 + 5,
            "own 10, invited's 5"
        );
        assert_eq!(
            take_all(&pools, Pool::Member, t2),
            35,
            "members' own half-second refill"
        );
    }

    /// With no members and no invited at all, strangers get the whole
    /// capacity above the idle pools' reserves, so the pools cost a server
    /// without records nothing at a sustained rate.
    #[test]
    fn a_server_with_no_members_lends_their_share_to_strangers() {
        let t0 = Instant::now();
        let pools = pools(t0);
        let mut strangers = take_all(&pools, Pool::Stranger, t0);
        for tick in 1..=20 {
            strangers += take_all(&pools, Pool::Stranger, t0 + ms(500 * tick));
        }
        // 60 at once, then the full 100/s for ten seconds.
        assert_eq!(strangers, 60 + 1_000);
    }

    #[test]
    fn a_rate_of_zero_turns_the_pools_off() {
        let section = PoolsSection {
            writes_per_second: 0,
            ..PoolsSection::default()
        };
        assert!(WritePools::new(&section, Instant::now()).unwrap().is_none());
    }

    #[test]
    fn shares_that_leave_members_nothing_are_refused() {
        for (s, i) in [(90, 10), (100, 0), (60, 50), (255, 255)] {
            let section = PoolsSection {
                stranger_share_pct: s,
                invited_share_pct: i,
                ..PoolsSection::default()
            };
            let err = match WritePools::new(&section, Instant::now()) {
                Ok(_) => panic!("{s} + {i} must be refused"),
                Err(e) => e,
            };
            assert!(err.to_string().contains("stranger_share_pct"), "{err}");
        }
    }

    #[test]
    fn a_share_whose_burst_is_under_one_write_is_refused() {
        let section = PoolsSection {
            writes_per_second: 1,
            writes_burst: 1,
            ..PoolsSection::default()
        };
        let err = match WritePools::new(&section, Instant::now()) {
            Ok(_) => panic!("a burst of 0.2 strangers must be refused"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("writes_burst"), "{err}");
        // Enough burst for every share: 5 × 20 % is one stranger write.
        let section = PoolsSection {
            writes_per_second: 1,
            writes_burst: 10,
            ..section
        };
        assert!(WritePools::new(&section, Instant::now()).unwrap().is_some());
    }

    /// A stranger share of 0: strangers write only what idle pools lend.
    #[test]
    fn a_zero_stranger_share_lends_only_idle_capacity() {
        let t0 = Instant::now();
        let pools = WritePools::new(
            &PoolsSection {
                writes_per_second: 100,
                writes_burst: 100,
                stranger_share_pct: 0,
                ..PoolsSection::default()
            },
            t0,
        )
        .unwrap()
        .unwrap();
        assert!(pools.try_take(Pool::Member, t0));
        assert!(pools.try_take(Pool::Invited, t0));
        assert!(!pools.try_take(Pool::Stranger, t0), "both others are busy");
    }
}
