//! Replay defence for tier-0 requests.
//!
//! A valid signature proves who sent a request, not that they meant to send it
//! *now*. Two defences combine:
//!
//! 1. An **acceptance window** on the request's timestamp, so a captured request
//!    stops being usable once it ages out.
//! 2. A **record of nonces** seen inside that window, so a request cannot be
//!    used twice while it is still fresh.
//!
//! # Never evict a live nonce
//!
//! Memory must be bounded, but **not** by evicting entries that are still
//! inside the window. Evicting one turns a replay into a cache miss, and a miss
//! is an accept: the signature still verifies and the timestamp still passes. An
//! attacker forces that by flooding unique nonces until the victim's entry is
//! pushed out, then replaying the captured request.
//!
//! So expired entries are reclaimed freely, and when everything retained is
//! still live the guard refuses new requests instead. That trades a denial of
//! service for a replay — the right direction, since a refused request is
//! recoverable by retrying and an accepted replay is not.
//!
//! Size `capacity` above the expected `rate × window` product so refusal is a
//! safety net rather than routine. At 10,000 msg/s with a ±30s window that is
//! on the order of 300,000 nonces if every request is tier 0. Capability-
//! authenticated (tier-1) requests need no nonce at all, which is an
//! independent reason busy servers will want trusted connections.

use std::collections::{HashSet, VecDeque};

/// Why a request was refused by the replay guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRejection {
    /// This nonce was already seen inside the acceptance window.
    AlreadySeen,
    /// The request's timestamp is outside the acceptance window, in either
    /// direction.
    OutsideWindow,
    /// The guard is full of entries that are all still inside the window, so
    /// accepting this request would mean forgetting one that can still be
    /// replayed. Refusing is the safe direction; see the module docs.
    CapacityExhausted,
}

/// Bounded record of recently-seen request nonces.
///
/// Not internally synchronised: hold it behind the server's existing state lock
/// rather than adding a second locking discipline.
pub struct ReplayGuard {
    window_ms: u64,
    capacity: usize,
    seen: HashSet<String>,
    /// Arrival order plus each entry's request timestamp, so expiry can be
    /// evaluated without a second index.
    order: VecDeque<(String, u64)>,
}

impl ReplayGuard {
    /// `window_ms` is the half-width of the acceptance window: a request is
    /// accepted if its timestamp is within `window_ms` of now, in either
    /// direction. `capacity` is the hard cap on retained nonces.
    pub fn new(window_ms: u64, capacity: usize) -> Self {
        Self {
            window_ms,
            capacity,
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Number of nonces currently retained.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True when no nonces are retained.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Check a request's freshness and uniqueness, recording it if it passes.
    ///
    /// `now_ms` is supplied by the caller rather than read from the clock here,
    /// so this type stays a pure function of its inputs and is testable without
    /// sleeping.
    pub fn check_and_record(
        &mut self,
        nonce: &str,
        request_ms: u64,
        now_ms: u64,
    ) -> Result<(), ReplayRejection> {
        let skew = request_ms.abs_diff(now_ms);
        if skew > self.window_ms {
            return Err(ReplayRejection::OutsideWindow);
        }

        if self.seen.contains(nonce) {
            return Err(ReplayRejection::AlreadySeen);
        }

        // Reclaim only entries that have aged out of the window. Those are free
        // to forget: the OutsideWindow check above refuses them regardless, so
        // they can no longer be replayed.
        self.drop_expired(now_ms);

        // Everything still retained is inside the window and therefore still
        // replayable. Refuse rather than forget one — forgetting turns a replay
        // into a cache miss, and a miss is an ACCEPT.
        if self.seen.len() >= self.capacity {
            return Err(ReplayRejection::CapacityExhausted);
        }

        self.seen.insert(nonce.to_string());
        self.order.push_back((nonce.to_string(), request_ms));
        Ok(())
    }

    /// Forget entries whose timestamps have left the acceptance window.
    ///
    /// `order` is append-only in arrival order, which is not perfectly sorted by
    /// `request_ms` under clock skew — but skew is bounded by the window, so
    /// stopping at the first live entry can retain a few expired ones. That is
    /// harmless: retaining too long is the safe direction, and the capacity cap
    /// still bounds memory.
    fn drop_expired(&mut self, now_ms: u64) {
        while let Some((nonce, stamped)) = self.order.front() {
            if stamped.abs_diff(now_ms) > self.window_ms {
                let nonce = nonce.clone();
                self.order.pop_front();
                self.seen.remove(&nonce);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_nonce_is_accepted_once() {
        let mut guard = ReplayGuard::new(1000, 100);
        assert!(guard.check_and_record("nonce-a", 5_000, 5_000).is_ok());
    }

    #[test]
    fn the_same_nonce_twice_is_a_replay() {
        let mut guard = ReplayGuard::new(1000, 100);
        guard.check_and_record("nonce-a", 5_000, 5_000).unwrap();
        assert_eq!(
            guard.check_and_record("nonce-a", 5_000, 5_000),
            Err(ReplayRejection::AlreadySeen)
        );
    }

    /// A timestamp far in the past is stale. Without this, a captured request
    /// could be replayed forever once its nonce fell out of the structure.
    #[test]
    fn a_timestamp_before_the_window_is_stale() {
        let mut guard = ReplayGuard::new(1000, 100);
        assert_eq!(
            guard.check_and_record("nonce-a", 1_000, 5_000),
            Err(ReplayRejection::OutsideWindow)
        );
    }

    /// A timestamp in the future is equally refused. Allowing it would let a
    /// caller mint requests valid long after capture; the window is symmetric
    /// so that clock skew is tolerated in both directions and no further.
    #[test]
    fn a_timestamp_after_the_window_is_stale() {
        let mut guard = ReplayGuard::new(1000, 100);
        assert_eq!(
            guard.check_and_record("nonce-a", 9_000, 5_000),
            Err(ReplayRejection::OutsideWindow)
        );
    }

    #[test]
    fn a_timestamp_at_the_window_edge_is_accepted() {
        let mut guard = ReplayGuard::new(1000, 100);
        assert!(guard.check_and_record("edge-early", 4_000, 5_000).is_ok());
        assert!(guard.check_and_record("edge-late", 6_000, 5_000).is_ok());
    }

    /// Memory is capped by capacity, not by traffic. This is the property that
    /// keeps a flood from exhausting a $5 VPS.
    #[test]
    fn memory_is_bounded_by_capacity_under_flood() {
        let capacity = 50;
        let mut guard = ReplayGuard::new(1000, capacity);
        for i in 0..10_000 {
            let _ = guard.check_and_record(&format!("nonce-{i}"), 5_000, 5_000);
        }
        assert!(
            guard.len() <= capacity,
            "guard grew to {} entries against a capacity of {capacity}",
            guard.len()
        );
    }

    /// THE test this whole design turns on: a full guard must refuse new
    /// requests, never forget an unexpired nonce to make room.
    ///
    /// Forgetting one turns a replay into a cache miss, and a miss is an
    /// ACCEPT — the signature still verifies and the timestamp is still in
    /// window. An attacker floods unique nonces to force exactly that.
    #[test]
    fn a_full_guard_refuses_rather_than_forgetting_a_live_nonce() {
        let mut guard = ReplayGuard::new(10_000, 2);
        guard.check_and_record("victim", 5_000, 5_000).unwrap();
        guard.check_and_record("filler", 5_000, 5_000).unwrap();

        // Guard is full and both entries are still inside the window.
        assert_eq!(
            guard.check_and_record("attacker", 5_000, 5_000),
            Err(ReplayRejection::CapacityExhausted),
            "a full guard must refuse the new request, not evict to make room"
        );

        // And the victim's nonce must still be remembered, so replaying it fails.
        assert_eq!(
            guard.check_and_record("victim", 5_000, 5_000),
            Err(ReplayRejection::AlreadySeen),
            "the flood must not have opened a replay window on the victim"
        );
    }

    /// Entries that have aged out of the window ARE reclaimable — the timestamp
    /// check refuses those requests regardless, so forgetting them is free.
    /// Without this, a guard would wedge permanently after its first busy
    /// second.
    #[test]
    fn expired_entries_are_reclaimed_to_make_room() {
        let window = 1_000;
        let mut guard = ReplayGuard::new(window, 2);
        guard.check_and_record("old-a", 5_000, 5_000).unwrap();
        guard.check_and_record("old-b", 5_000, 5_000).unwrap();

        // Advance well past the window: both entries are now unreplayable.
        let later = 5_000 + window * 5;
        assert!(
            guard.check_and_record("fresh", later, later).is_ok(),
            "expired entries must be reclaimed rather than wedging the guard"
        );
    }
}
