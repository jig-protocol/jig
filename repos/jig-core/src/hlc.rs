//! Hybrid Logical Clock (HLC) timestamp for causal ordering across federated servers.
//!
//! HLC combines wall-clock time with a logical counter so that causally-related events always
//! compare correctly even when system clocks have small skew.  The sort key is
//! `(wall_ms, logical, server_did)`, which gives a total, causal-respecting order.
//!
//! Update rule on receive:
//! ```text
//! local_clock = HLC::max(local.tick(), received.tick(), HLC::now_wall())
//! ```

use crate::Did;
use serde::{Deserialize, Serialize};

/// A Hybrid Logical Clock timestamp.
///
/// Carries the originating server DID so that ties can be broken deterministically
/// across federation peers even when wall time and logical counters match.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct HlcTimestamp {
    /// Wall-clock time in milliseconds since the Unix epoch.
    pub wall_ms: u64,
    /// Logical counter incremented when wall time has not advanced.
    pub logical: u32,
    /// DID of the server that generated this timestamp.
    pub server_did: Did,
}

impl HlcTimestamp {
    /// Create a new timestamp anchored to the current wall clock.
    ///
    /// # Panics
    ///
    /// Panics if the system clock is set before the Unix epoch — that is a
    /// hardware/admin misconfiguration, not a recoverable condition, and emitting
    /// bogus HLC values would corrupt protocol state.  Operators must ensure NTP /
    /// a sane clock source before running jig-server.
    pub fn now_wall(server_did: Did) -> Self {
        let wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before epoch")
            .as_millis() as u64;
        Self {
            wall_ms,
            logical: 0,
            server_did,
        }
    }

    /// Advance the clock by one logical tick (wall time unchanged).
    pub fn tick(&self) -> Self {
        Self {
            wall_ms: self.wall_ms,
            logical: self.logical.saturating_add(1),
            server_did: self.server_did.clone(),
        }
    }

    /// Merge a local clock and a received clock, producing the next local clock state.
    ///
    /// `wall_now_ms` is the current wall-clock reading at the moment of the merge.
    /// The result's `wall_ms` is the maximum of all three wall-clock inputs; the
    /// `logical` counter captures how many events occurred at that wall time.
    pub fn max(local: Self, received: Self, wall_now_ms: u64) -> Self {
        let max_wall = local.wall_ms.max(received.wall_ms).max(wall_now_ms);
        let logical = if max_wall == local.wall_ms && max_wall == received.wall_ms {
            // Both clocks are at the same max wall time — keep the higher logical + 1.
            local.logical.max(received.logical).saturating_add(1)
        } else if max_wall == local.wall_ms {
            local.logical.saturating_add(1)
        } else if max_wall == received.wall_ms {
            received.logical.saturating_add(1)
        } else {
            // wall_now_ms is strictly ahead of both; reset logical counter.
            0
        };
        Self {
            wall_ms: max_wall,
            logical,
            server_did: local.server_did,
        }
    }
}

impl PartialOrd for HlcTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HlcTimestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Total order: wall time first, then logical counter, then server DID for tie-breaking.
        (self.wall_ms, self.logical, &self.server_did).cmp(&(
            other.wall_ms,
            other.logical,
            &other.server_did,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper — construct a test DID by deriving 32 bytes from the label via blake3.
    fn server_did(s: &str) -> crate::Did {
        crate::Did::from_test_string(s)
    }

    #[test]
    fn hlc_now_uses_wall_clock_ms() {
        let now = HlcTimestamp::now_wall(server_did("a"));
        let ms_since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(now.wall_ms.abs_diff(ms_since_epoch) < 1000);
        assert_eq!(now.logical, 0);
    }

    #[test]
    fn hlc_tick_increments_logical_when_wall_unchanged() {
        let a = HlcTimestamp {
            wall_ms: 1000,
            logical: 0,
            server_did: server_did("a"),
        };
        let b = a.tick();
        assert_eq!(b.wall_ms, 1000);
        assert_eq!(b.logical, 1);
    }

    #[test]
    fn hlc_max_advances_wall_when_received_is_ahead() {
        let local = HlcTimestamp {
            wall_ms: 1000,
            logical: 5,
            server_did: server_did("a"),
        };
        let recv = HlcTimestamp {
            wall_ms: 2000,
            logical: 0,
            server_did: server_did("b"),
        };
        let merged = HlcTimestamp::max(local, recv, /* wall_now = */ 1500);
        assert_eq!(merged.wall_ms, 2000);
        assert_eq!(merged.logical, 1); // recv.logical + 1
    }

    #[test]
    fn hlc_ordering_is_total_and_causal() {
        let earlier = HlcTimestamp {
            wall_ms: 1000,
            logical: 0,
            server_did: server_did("a"),
        };
        let later_logical = earlier.tick();
        let later_wall = HlcTimestamp {
            wall_ms: 2000,
            logical: 0,
            server_did: server_did("a"),
        };
        assert!(earlier < later_logical);
        assert!(later_logical < later_wall);
    }
}
