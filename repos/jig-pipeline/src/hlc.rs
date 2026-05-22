//! HLC clock for jig-pipeline.
//!
//! Holds a single server's running HLC state. Built on top of
//! [`jig_core::HlcTimestamp`] (the pure value type). One [`HlcClock`] per
//! server process; share via `Arc` across the ingest pipeline.

use jig_core::{Did, HlcTimestamp};
use std::sync::Mutex;

pub use jig_core::HlcTimestamp as Timestamp;

/// Process-wide HLC state for one server.
pub struct HlcClock {
    state: Mutex<HlcTimestamp>,
}

impl HlcClock {
    /// New clock at wall=0, logical=0 with the given server DID.
    pub fn new(server_did: Did) -> Self {
        Self {
            state: Mutex::new(HlcTimestamp {
                wall_ms: 0,
                logical: 0,
                server_did,
            }),
        }
    }

    /// Advance the wall component without producing a timestamp.
    /// Use when the server's wall clock has moved forward but no event needs an HLC yet.
    pub fn observe_at_wall_ms(&self, wall_now_ms: u64) {
        let mut state = self.state.lock().expect("HlcClock mutex poisoned");
        if wall_now_ms > state.wall_ms {
            state.wall_ms = wall_now_ms;
            state.logical = 0;
        }
    }

    /// Produce a new HLC timestamp for an outgoing local event.
    ///
    /// If `wall_now_ms` is strictly ahead of current state, the wall component
    /// advances and the logical counter resets to 0. Otherwise the logical
    /// counter increments (using saturating arithmetic per Task A1's design).
    pub fn tick(&self, wall_now_ms: u64) -> HlcTimestamp {
        let mut state = self.state.lock().expect("HlcClock mutex poisoned");
        if wall_now_ms > state.wall_ms {
            state.wall_ms = wall_now_ms;
            state.logical = 0;
        } else {
            state.logical = state.logical.saturating_add(1);
        }
        state.clone()
    }

    /// Merge an incoming HLC timestamp with local state. Returns the new local HLC.
    ///
    /// Implements `local = HlcTimestamp::max(local, received, wall_now_ms)` —
    /// the standard HLC update rule. After this call, `current()` returns the
    /// same value that's returned here.
    pub fn update_on_receive(&self, received: HlcTimestamp, wall_now_ms: u64) -> HlcTimestamp {
        let mut state = self.state.lock().expect("HlcClock mutex poisoned");
        let new = HlcTimestamp::max(state.clone(), received, wall_now_ms);
        *state = new.clone();
        new
    }

    /// Read the current clock state without mutating.
    pub fn current(&self) -> HlcTimestamp {
        self.state.lock().expect("HlcClock mutex poisoned").clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::Did;

    fn test_did(s: &str) -> Did {
        Did::from_str_unchecked(s)
    }

    #[test]
    fn tick_increments_logical_when_wall_unchanged() {
        let clock = HlcClock::new(test_did("a"));
        clock.observe_at_wall_ms(1000);
        let t1 = clock.tick(1000);
        let t2 = clock.tick(1000);
        assert_eq!(t1.wall_ms, t2.wall_ms);
        assert!(t2.logical > t1.logical);
    }

    #[test]
    fn tick_advances_wall_and_resets_logical_when_wall_jumps_forward() {
        let clock = HlcClock::new(test_did("a"));
        clock.observe_at_wall_ms(1000);
        let _ = clock.tick(1000);
        let _ = clock.tick(1000);
        // wall jumps forward
        let t = clock.tick(2000);
        assert_eq!(t.wall_ms, 2000);
        assert_eq!(t.logical, 0);
    }

    #[test]
    fn update_on_receive_advances_to_max_of_local_received_wall_now() {
        let clock = HlcClock::new(test_did("server-a"));
        clock.observe_at_wall_ms(1000);

        let recv = HlcTimestamp {
            wall_ms: 2000,
            logical: 5,
            server_did: test_did("server-b"),
        };
        let new_local = clock.update_on_receive(recv, 1500);

        assert_eq!(new_local.wall_ms, 2000);
        assert_eq!(new_local.logical, 6);
        assert_eq!(clock.current(), new_local);
    }

    #[test]
    fn update_on_receive_preserves_local_server_did() {
        // The result of update_on_receive must keep the LOCAL server DID,
        // not the remote's — per Task A1 + jig-core::HlcTimestamp::max semantics.
        let local_did = test_did("local");
        let clock = HlcClock::new(local_did.clone());
        clock.observe_at_wall_ms(1000);

        let recv = HlcTimestamp {
            wall_ms: 2000,
            logical: 0,
            server_did: test_did("remote"),
        };
        let new_local = clock.update_on_receive(recv, 0);
        assert_eq!(new_local.server_did, local_did);
    }

    #[test]
    fn observe_at_wall_ms_only_advances_wall_does_not_emit_timestamp() {
        let clock = HlcClock::new(test_did("a"));
        clock.observe_at_wall_ms(1000);
        clock.observe_at_wall_ms(500); // earlier than current; should not move backward
        let cur = clock.current();
        assert_eq!(cur.wall_ms, 1000);
        assert_eq!(cur.logical, 0);
    }

    #[test]
    fn current_returns_same_state_as_last_tick() {
        let clock = HlcClock::new(test_did("a"));
        let t = clock.tick(1000);
        assert_eq!(clock.current(), t);
    }

    #[test]
    fn logical_counter_uses_saturating_add_under_adversarial_input() {
        let clock = HlcClock::new(test_did("a"));
        // Manually set the state to u32::MAX logical to simulate the adversarial
        // edge case (a federated peer that sent logical = u32::MAX).
        {
            let mut state = clock.state.lock().unwrap();
            state.wall_ms = 1000;
            state.logical = u32::MAX;
        }
        // tick at the same wall — would overflow without saturating_add
        let t = clock.tick(1000);
        // saturated, not wrapped
        assert_eq!(t.logical, u32::MAX);
        assert_eq!(t.wall_ms, 1000);
    }
}
