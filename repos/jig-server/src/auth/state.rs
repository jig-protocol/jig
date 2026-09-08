//! Per-server authentication state, shared across every request.
//!
//! # Why this is `Arc`-wrapped in `AppState`
//!
//! `AppState` derives `Clone` and is cloned per request handler. The replay
//! guard must be **one** structure shared by every clone: it defends by
//! remembering nonces, and a guard that each clone owned privately would
//! remember nothing another clone had seen. A replayed request would land on a
//! clone with an empty set and be accepted.
//!
//! So `AppState` holds `Arc<AuthState>`, not `AuthState`. If a future change
//! makes this fail to compile, the fix is more `Arc`, **never** making
//! `ReplayGuard` cloneable — that would compile fine and silently disable
//! replay defence.

use std::sync::Mutex;

use jig_config::v0_0_2_server::AuthSection;

use crate::auth::{DisclosurePolicy, ReplayGuard};

/// Authentication state owned by the server and shared by all requests.
pub struct AuthState {
    /// Replay defence for tier-0 requests.
    ///
    /// `Mutex` rather than `RwLock`: every check mutates by recording the
    /// nonce, so a read lock would never be taken and would only add a second
    /// locking discipline to reason about.
    pub replay_guard: Mutex<ReplayGuard>,
    /// How much of a refusal's truth this server discloses to the caller.
    pub disclosure: DisclosurePolicy,
}

impl AuthState {
    /// Build from the operator's `[auth]` section.
    pub fn from_config(auth: &AuthSection) -> Self {
        Self {
            replay_guard: Mutex::new(ReplayGuard::new(
                auth.replay_window_ms,
                auth.replay_capacity,
            )),
            disclosure: DisclosurePolicy::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard must be sized from config, not from a hardcoded default —
    /// otherwise the `[auth]` knobs are decorative.
    #[test]
    fn the_guard_is_sized_from_config() {
        let section = AuthSection {
            require_authenticated_reads: true,
            replay_window_ms: 1_234,
            replay_capacity: 7,
        };
        let state = AuthState::from_config(&section);
        let mut guard = state.replay_guard.lock().unwrap();

        // Capacity 7: the eighth distinct nonce in-window must be refused.
        for i in 0..7 {
            guard
                .check_and_record(&format!("n{i}"), 5_000, 5_000)
                .expect("within capacity");
        }
        assert!(
            guard.check_and_record("n7", 5_000, 5_000).is_err(),
            "capacity from config must actually bound the guard"
        );

        // Window 1234ms: a request 2s old must be outside it.
        assert!(
            guard.check_and_record("late", 5_000, 7_000).is_err(),
            "window from config must actually bound freshness"
        );
    }

    /// Truthful disclosure is the default; a server that conceals should do so
    /// because an operator asked it to.
    #[test]
    fn disclosure_defaults_to_truthful() {
        let state = AuthState::from_config(&AuthSection::default());
        assert_eq!(state.disclosure, DisclosurePolicy::Truthful);
    }
}
