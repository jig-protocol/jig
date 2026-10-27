//! The admission effort controller (JEP-0008 rules 17–19).
//!
//! Under `unknown_dids = "proof-of-work"`, the effort asked of a DID this
//! server has not admitted follows load:
//!
//! - **Input:** the distinct unknown, unproven DIDs that reached gate 2 in a
//!   window (`controller_window_secs`). They are the strangers queueing for
//!   admission. Relayed and bridged authors are not counted (rule 30).
//! - **Raise:** after a window with more than `controller_target` of them,
//!   the suggested effort doubles, starting from `controller_start_effort`,
//!   up to `max_effort`. It never rises while arrivals are at or below the
//!   target (rule 17).
//! - **Lower:** after a window with at most half the target, it halves, and
//!   below `controller_start_effort` it drops to zero (rule 17's decay).
//! - **Floor:** the effort asked is `max(min_effort, suggested)`, clamped to
//!   `max_effort`. With `min_effort = 0` an idle server asks no work at all.
//!
//! A proof is checked against the lowest nonzero effort this server asked
//! within the last [`ADMIT_OFFER_SECS`], so a client is never refused for a
//! rise that came while it solved an offer that had not expired.
//!
//! No clock is read here: every call takes `now`.

use std::collections::{HashSet, VecDeque};
use std::num::NonZeroU64;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long an offer stays good: the welcome's `expires_at` (JEP-0008 rule
/// 15).
pub const ADMIT_OFFER_SECS: u64 = crate::v0_0_2_ws::ADMIT_OFFER_SECS.unsigned_abs();

/// After this many empty windows the suggested effort is zero whatever it
/// was: halving from `2^28` reaches zero well within it.
const MAX_WINDOWS_ROLLED: u32 = 64;

/// The fewest leading zero bits whose expected work is at least `effort`.
pub fn bits_at_least(effort: std::num::NonZeroU64) -> u8 {
    let bits = u64::BITS - (effort.get() - 1).leading_zeros();
    u8::try_from(bits)
        .unwrap_or(u8::MAX)
        .clamp(1, jig_core::admission_pow::MAX_BITS)
}

/// The controller's configuration, validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffortConfig {
    /// The floor (rule 19); `0` asks no work while idle.
    pub min_effort: u64,
    pub max_effort: u64,
    /// The first step above zero when load arrives.
    pub start_effort: u64,
    pub window: Duration,
    /// Distinct new strangers per window above which effort rises.
    pub target: usize,
}

pub struct EffortController {
    cfg: EffortConfig,
    inner: Mutex<Inner>,
}

struct Inner {
    window_start: Instant,
    /// Distinct strangers seen this window, capped: past the target the
    /// count no longer changes the decision.
    seen: HashSet<String>,
    suggested: u64,
    /// Efforts that stopped being asked, and when; for the offer window.
    retired: VecDeque<(Instant, u64)>,
}

impl EffortController {
    pub fn new(cfg: EffortConfig, now: Instant) -> Self {
        Self {
            cfg,
            inner: Mutex::new(Inner {
                window_start: now,
                seen: HashSet::new(),
                suggested: 0,
                retired: VecDeque::new(),
            }),
        }
    }

    /// The effort asked of a new DID at `now`; `0` asks none.
    pub fn effort(&self, now: Instant) -> u64 {
        let mut inner = self.lock();
        self.roll(&mut inner, now);
        self.effective(inner.suggested)
    }

    /// Count `did`, an unknown DID without a proof, as one stranger arriving
    /// at `now`.
    pub fn observe_stranger(&self, did: &str, now: Instant) {
        let mut inner = self.lock();
        self.roll(&mut inner, now);
        if inner.seen.len() <= self.cfg.target {
            inner.seen.insert(did.to_string());
        }
    }

    /// The least effort a proof posted at `now` must carry: the lowest
    /// nonzero effort asked within the last [`ADMIT_OFFER_SECS`], or `None`
    /// when no work has been asked in that time.
    pub fn accepted_floor(&self, now: Instant) -> Option<NonZeroU64> {
        let mut inner = self.lock();
        self.roll(&mut inner, now);
        let ttl = Duration::from_secs(ADMIT_OFFER_SECS);
        while inner
            .retired
            .front()
            .is_some_and(|(ended, _)| now.saturating_duration_since(*ended) > ttl)
        {
            inner.retired.pop_front();
        }
        let current = self.effective(inner.suggested);
        std::iter::once(current)
            .chain(inner.retired.iter().map(|(_, effort)| *effort))
            .filter(|effort| *effort > 0)
            .min()
            .and_then(NonZeroU64::new)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("admission effort lock poisoned")
    }

    fn effective(&self, suggested: u64) -> u64 {
        let asked = self.cfg.min_effort.max(suggested);
        if asked == 0 {
            0
        } else {
            asked.min(self.cfg.max_effort)
        }
    }

    /// Close every window that ended by `now`.
    fn roll(&self, inner: &mut Inner, now: Instant) {
        let mut rolled = 0;
        while now.saturating_duration_since(inner.window_start) >= self.cfg.window {
            let before = self.effective(inner.suggested);
            if rolled >= MAX_WINDOWS_ROLLED {
                // Idle for a long time: every further window would halve.
                inner.suggested = 0;
                inner.window_start = now;
            } else {
                inner.suggested = self.next(inner.suggested, inner.seen.len());
                inner.window_start += self.cfg.window;
            }
            inner.seen.clear();
            let after = self.effective(inner.suggested);
            if after != before && before > 0 {
                inner.retired.push_back((inner.window_start, before));
            }
            rolled += 1;
        }
    }

    fn next(&self, suggested: u64, arrivals: usize) -> u64 {
        let cfg = &self.cfg;
        if arrivals > cfg.target {
            suggested
                .saturating_mul(2)
                .max(cfg.start_effort)
                .min(cfg.max_effort)
        } else if arrivals <= cfg.target / 2 {
            let half = suggested / 2;
            if half < cfg.start_effort { 0 } else { half }
        } else {
            suggested
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: u64 = 1 << 16;
    const MAX: u64 = 1 << 20;

    fn controller(min_effort: u64, now: Instant) -> EffortController {
        EffortController::new(
            EffortConfig {
                min_effort,
                max_effort: MAX,
                start_effort: START,
                window: Duration::from_secs(60),
                target: 10,
            },
            now,
        )
    }

    fn window(n: u32) -> Duration {
        Duration::from_secs(60 * u64::from(n))
    }

    fn flood(c: &EffortController, strangers: usize, at: Instant) {
        for i in 0..strangers {
            c.observe_stranger(&format!("did:jig:z{i}"), at);
        }
    }

    /// Idle, with no floor: admission asks nothing.
    #[test]
    fn an_idle_server_without_a_floor_asks_no_work() {
        let t0 = Instant::now();
        let c = controller(0, t0);
        assert_eq!(c.effort(t0), 0);
        assert_eq!(c.effort(t0 + window(10)), 0);
        assert_eq!(c.accepted_floor(t0 + window(10)), None);
    }

    /// A flood above the target raises effort window by window up to the
    /// cap; the same DID many times counts once.
    #[test]
    fn a_flood_raises_effort_to_the_cap() {
        let t0 = Instant::now();
        let c = controller(0, t0);
        for _ in 0..100 {
            c.observe_stranger("did:jig:zSame", t0);
        }
        assert_eq!(c.effort(t0 + window(1)), 0, "one DID is not a flood");
        let mut asked = Vec::new();
        for n in 1..=6 {
            flood(&c, 50, t0 + window(n));
            asked.push(c.effort(t0 + window(n + 1)));
        }
        assert_eq!(asked, [START, 2 * START, 4 * START, 8 * START, MAX, MAX]);
    }

    /// At or below the target effort never rises (rule 17); at most half
    /// it decays, to zero below the start.
    #[test]
    fn effort_holds_at_target_and_decays_when_quiet() {
        let t0 = Instant::now();
        let c = controller(0, t0);
        flood(&c, 11, t0);
        flood(&c, 11, t0 + window(1));
        assert_eq!(c.effort(t0 + window(2)), 2 * START);
        flood(&c, 10, t0 + window(2));
        assert_eq!(c.effort(t0 + window(3)), 2 * START, "at target: held");
        flood(&c, 5, t0 + window(3));
        assert_eq!(c.effort(t0 + window(4)), START, "half the target: halved");
        assert_eq!(c.effort(t0 + window(5)), 0, "below the start: none");
    }

    /// The floor holds whatever the controller says, and the cap holds over
    /// the floor's multiples.
    #[test]
    fn the_floor_is_the_least_asked() {
        let t0 = Instant::now();
        let c = controller(1 << 18, t0);
        assert_eq!(c.effort(t0), 1 << 18);
        flood(&c, 50, t0);
        assert_eq!(
            c.effort(t0 + window(1)),
            1 << 18,
            "suggested 2^16 is under the floor"
        );
        assert_eq!(
            c.effort(t0 + window(100)),
            1 << 18,
            "and it decays back to it"
        );
    }

    /// A rise mid-solve does not refuse a proof made for an offer that has
    /// not expired; once it has, the new effort is the floor.
    #[test]
    fn a_proof_for_an_unexpired_offer_is_accepted_after_a_rise() {
        let t0 = Instant::now();
        let c = controller(0, t0);
        flood(&c, 50, t0);
        let t1 = t0 + window(1);
        assert_eq!(c.accepted_floor(t1), NonZeroU64::new(START));
        flood(&c, 50, t1);
        let t2 = t0 + window(2);
        assert_eq!(c.effort(t2), 2 * START);
        assert_eq!(
            c.accepted_floor(t2),
            NonZeroU64::new(START),
            "the old offer holds"
        );
        // Two quiet windows later effort is back to zero, but the last
        // offers made (2S, then S) have not expired: S still admits.
        let later = t2 + Duration::from_secs(ADMIT_OFFER_SECS + 1);
        assert_eq!(c.effort(later), 0);
        assert_eq!(c.accepted_floor(later), NonZeroU64::new(START));
    }

    /// Once a flood has passed and its offers expired, no proof is needed and
    /// none is recorded.
    #[test]
    fn after_the_flood_and_its_offers_no_work_is_asked() {
        let t0 = Instant::now();
        let c = controller(0, t0);
        flood(&c, 50, t0);
        assert_eq!(c.effort(t0 + window(1)), START);
        let quiet = t0 + window(2);
        assert_eq!(c.effort(quiet), 0);
        assert_eq!(
            c.accepted_floor(quiet),
            NonZeroU64::new(START),
            "the last offer has not expired"
        );
        let later = quiet + Duration::from_secs(ADMIT_OFFER_SECS + 1);
        assert_eq!(c.accepted_floor(later), None);
    }

    /// A server idle for days rolls its windows in bounded time.
    #[test]
    fn a_long_idle_rolls_in_bounded_time() {
        let t0 = Instant::now();
        let c = controller(0, t0);
        flood(&c, 50, t0);
        assert_eq!(c.effort(t0 + Duration::from_secs(30 * 24 * 3600)), 0);
    }
}
