//! Capacity pools: members, invited and strangers (JEP-0008 rules 21–23).
//!
//! The server's accepted local writes per second are split three ways, and
//! the member share is split again: aged-proof members (JEP-0009 rule 49)
//! draw only from its `aged_share_pct`, and established members from all of
//! it. Each part is a token bucket holding its share of the burst and refilling at its
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
//! - Aged-proof members are bounded by capacity, not by count: a farm of
//!   proofs that ages in together shares the aged part, and cannot crowd out
//!   established members (rule 23).
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
    /// An established member: today, a DID in the operator's records.
    Member,
    /// A member by aged admission proof (JEP-0009 rule 49): the member pool,
    /// but only its `aged_share_pct`.
    AgedMember,
    Invited,
    Stranger,
}

/// Bucket indices. The member pool is two buckets: the part only
/// established members draw from, and the aged part both draw from.
const ESTABLISHED: usize = 0;
const AGED: usize = 1;
const INVITED: usize = 2;
const STRANGER: usize = 3;

impl Pool {
    /// The buckets this pool draws on as its own, in order: no idleness
    /// needed, and its requests are demand on each. Established members own
    /// the whole member pool.
    fn owned(self) -> &'static [usize] {
        match self {
            Pool::Member => &[ESTABLISHED, AGED],
            Pool::AgedMember => &[AGED],
            Pool::Invited => &[INVITED],
            Pool::Stranger => &[STRANGER],
        }
    }

    /// The buckets this pool may borrow from while they are idle, cheapest
    /// to lend first.
    fn lenders(self) -> &'static [usize] {
        match self {
            Pool::Member => &[STRANGER, INVITED],
            Pool::AgedMember => &[STRANGER, INVITED, ESTABLISHED],
            Pool::Invited => &[STRANGER, AGED, ESTABLISHED],
            Pool::Stranger => &[INVITED, AGED, ESTABLISHED],
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

/// The write capacity, split into the three pools, the member pool in two.
pub struct WritePools {
    buckets: Mutex<[Bucket; 4]>,
    warnings: Vec<String>,
}

impl WritePools {
    /// `None` when `writes_per_second` is 0: the pools are off. Fails on
    /// shares that leave members nothing, an aged share above 100, and a
    /// nonzero member, invited or stranger share whose burst is under one
    /// write. An aged part under one write is raised to one, with a warning.
    pub fn new(section: &PoolsSection, now: Instant) -> anyhow::Result<Option<Self>> {
        let (stranger, invited) = (section.stranger_share_pct, section.invited_share_pct);
        if u16::from(stranger) + u16::from(invited) >= 100 {
            anyhow::bail!(
                "[auth.pools] stranger_share_pct + invited_share_pct must be below 100, \
                 so members keep a share; got {stranger} + {invited}"
            );
        }
        let aged_pct = section.aged_share_pct;
        if aged_pct > 100 {
            anyhow::bail!(
                "[auth.pools] aged_share_pct is a percent of the member pool, at most 100; \
                 got {aged_pct}"
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
        // from its own bucket. These shares were checked before the member
        // split, so a config that booted before still boots.
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
        // The member pool's split. Established members own both parts, so
        // their part may hold under one write. The aged part may not, and
        // refusing to boot over it would turn an upgrade into an outage: it
        // is raised to one write, taken from the established part, and the
        // operator is told.
        let member_burst = burst * member / 100.0;
        let mut aged_burst = member_burst * f64::from(aged_pct) / 100.0;
        let mut warnings = Vec::new();
        if aged_pct > 0 && aged_burst < 1.0 {
            warnings.push(format!(
                "[auth.pools] aged_share_pct {aged_pct} of the member share of writes_burst \
                 {burst} is under one write; members by aged proof get one write of burst \
                 instead. Raise writes_burst, or set aged_share_pct to 0 or 100"
            ));
            aged_burst = 1.0;
        }
        let aged_rate = rate * member / 100.0 * f64::from(aged_pct) / 100.0;
        let part = |burst: f64, per_second: f64| Bucket {
            tokens: burst,
            burst,
            per_second,
            at: now,
            demand: None,
        };
        Ok(Some(Self {
            buckets: Mutex::new([
                part(member_burst - aged_burst, rate * member / 100.0 - aged_rate),
                part(aged_burst, aged_rate),
                bucket(f64::from(invited)),
                bucket(f64::from(stranger)),
            ]),
            warnings,
        }))
    }

    /// What boot should log as a warning: a setting the pools adjusted
    /// rather than refused.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// One token's refill in the buckets `pool` owns. `None` when its share
    /// is 0: it never refills, and writes from it only borrow.
    pub fn refill_interval(&self, pool: Pool) -> Option<Duration> {
        let buckets = self.buckets.lock().expect("write pools lock poisoned");
        let rate: f64 = pool.owned().iter().map(|&i| buckets[i].per_second).sum();
        (rate > 0.0).then(|| Duration::from_secs_f64(1.0 / rate))
    }

    /// Take one write's worth for `pool` at `now`: from a bucket it owns, or
    /// else from an idle one. False when none has it.
    pub fn try_take(&self, pool: Pool, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().expect("write pools lock poisoned");
        for bucket in buckets.iter_mut() {
            bucket.refill(now);
        }
        // Demand on every bucket the pool owns: while established members
        // write, the aged part does not lend to strangers either.
        for &i in pool.owned() {
            let own = &mut buckets[i];
            own.demand = Some(now.max(own.demand.unwrap_or(now)));
        }
        // The buckets a pool owns count together: splitting the member pool
        // must not strand a write's worth in fractions on either side.
        let owned: f64 = pool.owned().iter().map(|&i| buckets[i].tokens).sum();
        if owned >= 1.0 {
            let mut due = 1.0;
            for &i in pool.owned() {
                let take = buckets[i].tokens.min(due);
                buckets[i].tokens -= take;
                due -= take;
            }
            return true;
        }
        for &i in pool.lenders() {
            if buckets[i].lends(now) {
                buckets[i].tokens -= 1.0;
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
    /// The aged part of the members' 70 is 14 (20 %), so every bucket holds
    /// whole writes.
    fn pools(now: Instant) -> WritePools {
        WritePools::new(
            &PoolsSection {
                writes_per_second: 100,
                writes_burst: 100,
                aged_share_pct: 20,
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
        // Enough burst for every share: 10 × 10 % is one invited write.
        let section = PoolsSection {
            writes_per_second: 1,
            writes_burst: 10,
            ..section
        };
        assert!(WritePools::new(&section, Instant::now()).unwrap().is_some());
    }

    /// 100 writes a second, burst 100, aged share 20 %: established members
    /// 56, aged members 14, invited 10, strangers 20.
    fn aged_pools(aged_share_pct: u8, now: Instant) -> WritePools {
        WritePools::new(
            &PoolsSection {
                writes_per_second: 100,
                writes_burst: 100,
                aged_share_pct,
                ..PoolsSection::default()
            },
            now,
        )
        .unwrap()
        .unwrap()
    }

    /// Rule 23's bound on aged-proof members: while everyone is writing, a
    /// farm of aged proofs gets the aged part of the member pool and no
    /// more, and established members keep the rest.
    #[test]
    fn aged_members_draw_only_their_share_while_members_write() {
        let t0 = Instant::now();
        let pools = aged_pools(20, t0);
        let busy = |at| {
            assert!(pools.try_take(Pool::Invited, at));
            assert!(pools.try_take(Pool::Stranger, at));
        };
        busy(t0);
        assert!(pools.try_take(Pool::Member, t0), "members are active");
        let mut aged = take_all(&pools, Pool::AgedMember, t0);
        let mut members = 1 + take_all(&pools, Pool::Member, t0);
        assert_eq!((aged, members), (14, 56), "each its own burst");
        for tick in 1..=20 {
            let at = t0 + ms(500 * tick);
            busy(at);
            aged += take_all(&pools, Pool::AgedMember, at);
            members += take_all(&pools, Pool::Member, at);
        }
        assert_eq!(aged, 14 + 140, "aged members' 14/s, all ten seconds");
        assert_eq!(members, 56 + 560, "established members' 56/s");
    }

    /// Established members draw from the whole member pool, aged part
    /// included; an aged member arriving then waits like any other pool.
    #[test]
    fn established_members_draw_from_the_whole_member_pool() {
        let t0 = Instant::now();
        let pools = aged_pools(20, t0);
        assert!(pools.try_take(Pool::Invited, t0));
        assert!(pools.try_take(Pool::Stranger, t0));
        assert_eq!(take_all(&pools, Pool::Member, t0), 70);
        assert!(
            !pools.try_take(Pool::AgedMember, t0),
            "nothing idle to borrow"
        );
        assert_eq!(pools.refill_interval(Pool::Member), Some(ms(1_000) / 70));
        assert_eq!(
            pools.refill_interval(Pool::AgedMember),
            Some(ms(1_000) / 14)
        );
    }

    /// While established members are quiet, aged members borrow their idle
    /// capacity above half, as any pool may; the members' first write stops
    /// it.
    #[test]
    fn aged_members_borrow_idle_established_capacity() {
        let t0 = Instant::now();
        let pools = aged_pools(20, t0);
        assert!(pools.try_take(Pool::Invited, t0));
        assert!(pools.try_take(Pool::Stranger, t0));
        assert_eq!(take_all(&pools, Pool::AgedMember, t0), 14 + 28);
        let t1 = t0 + ms(1_000);
        assert!(pools.try_take(Pool::Invited, t1));
        assert!(pools.try_take(Pool::Stranger, t1));
        assert!(pools.try_take(Pool::Member, t1), "the reserve is there");
        // A second's refill: aged 14 of its own, established now busy.
        assert_eq!(take_all(&pools, Pool::AgedMember, t1), 14);
    }

    /// An aged share of 100 is the split turned off: aged-proof members draw
    /// from the whole member pool, as before the split.
    #[test]
    fn an_aged_share_of_100_gives_aged_members_the_whole_member_pool() {
        let t0 = Instant::now();
        let pools = aged_pools(100, t0);
        assert!(pools.try_take(Pool::Invited, t0));
        assert!(pools.try_take(Pool::Stranger, t0));
        assert!(pools.try_take(Pool::Member, t0));
        assert_eq!(take_all(&pools, Pool::AgedMember, t0), 69);
        assert_eq!(pools.refill_interval(Pool::Member), Some(ms(1_000) / 70));
    }

    /// A burst small enough for every pool before the split leaves the aged
    /// part under one write. The config booted before the split, so it still
    /// boots: the aged part gets one write of burst, taken from established
    /// members, and boot is told to warn.
    #[test]
    fn a_tiny_aged_part_boots_with_one_write_and_a_warning() {
        let t0 = Instant::now();
        let section = PoolsSection {
            writes_per_second: 3,
            writes_burst: 3,
            stranger_share_pct: 0,
            invited_share_pct: 0,
            ..PoolsSection::default()
        };
        let pools = WritePools::new(&section, t0).unwrap().unwrap();
        let [warning] = pools.warnings() else {
            panic!("one warning, got {:?}", pools.warnings())
        };
        assert!(warning.contains("aged_share_pct 25"), "{warning}");
        assert!(
            warning.contains("set aged_share_pct to 0 or 100"),
            "{warning}"
        );
        // While members write, the aged part holds one write, and the member
        // pool still holds three in all.
        assert!(pools.try_take(Pool::Member, t0), "members are active");
        assert!(pools.try_take(Pool::AgedMember, t0));
        assert!(!pools.try_take(Pool::AgedMember, t0), "only one");
        assert_eq!(take_all(&pools, Pool::Member, t0), 1);
        // Shares that need no adjusting give no warning.
        for aged_share_pct in [0, 100] {
            let section = PoolsSection {
                aged_share_pct,
                ..section.clone()
            };
            let pools = WritePools::new(&section, t0).unwrap().unwrap();
            assert!(pools.warnings().is_empty(), "{aged_share_pct}");
        }
        let pools = WritePools::new(&PoolsSection::default(), t0)
            .unwrap()
            .unwrap();
        assert!(pools.warnings().is_empty());
    }

    #[test]
    fn an_aged_share_above_100_is_refused() {
        let section = PoolsSection {
            aged_share_pct: 101,
            ..PoolsSection::default()
        };
        let err = match WritePools::new(&section, Instant::now()) {
            Ok(_) => panic!("101 % of the member pool must be refused"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("aged_share_pct"), "{err}");
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
