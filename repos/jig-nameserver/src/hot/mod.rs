//! Hot state backend abstraction for ephemeral data
//!
//! This module provides composable backends for hot/ephemeral state:
//! - Rate limiting
//! - PoW challenge caching
//! - Federation identity caching
//! - Penalty tracking
//! - Session state
//!
//! Backend implementations:
//! - Tier 1 (Potato): In-memory HashMap (no persistence)
//! - Tier 2 (Prosumer): Redis, Valkey, DragonflyDB (in-memory + optional persistence)
//! - Tier 3 (Hyperscale): ScyllaDB (distributed persistent cache with TTL)

pub mod backend;
pub mod backends;

// Re-export key types
pub use backend::{HotBackend, HotBackendCapabilities};
pub use backends::create_hot_backend;

use serde::{Deserialize, Serialize};

/// Hot state entry with TTL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotEntry<T> {
    pub value: T,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl<T> HotEntry<T> {
    pub fn new(value: T, ttl_secs: Option<u64>) -> Self {
        let expires_at =
            ttl_secs.map(|secs| chrono::Utc::now() + chrono::Duration::seconds(secs as i64));
        Self { value, expires_at }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            chrono::Utc::now() > expires
        } else {
            false
        }
    }
}

/// Rate limit state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub count: u32,
    pub window_start: i64, // Unix timestamp
}

/// Penalty state with decay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyState {
    pub points: u32,
    pub last_updated: i64, // Unix timestamp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hot_entry_expiry() {
        let entry = HotEntry::new("test", Some(1));
        assert!(!entry.is_expired());

        let expired = HotEntry {
            value: "test",
            expires_at: Some(chrono::Utc::now() - chrono::Duration::seconds(1)),
        };
        assert!(expired.is_expired());
    }
}
