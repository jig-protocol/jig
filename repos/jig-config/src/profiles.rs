//! Profile-based configuration system for tiered deployments.
//!
//! Profiles provide opinionated defaults for different deployment scenarios:
//! - **Potato**: Single-node, <100 users, SQLite, zero setup (default)
//! - **Standard**: 1K-10K users, PostgreSQL + optional Redis
//! - **Hyperscale**: 100K+ users, multi-tier storage (CockroachDB + ScyllaDB + ClickHouse + S3)
//! - **Custom**: User-defined configuration with no defaults
//!
//! ## Design Philosophy
//!
//! 1. **Dead-simple defaults**: Users only specify overrides; system merges with profile defaults
//! 2. **Potato-friendly**: Default profile is Potato (curl-to-hello-world in 60s)
//! 3. **Simple inheritance**: Standard/Hyperscale overlay Potato base
//! 4. **No deep hierarchy**: Keep to 3 built-in profiles; custom profiles via overrides

use serde::{Deserialize, Serialize};
use std::fmt;

/// Deployment profile determining default settings.
///
/// Profiles cascade from Potato (most constrained) to Hyperscale (most capable).
/// Custom profiles provide a blank slate with no defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Profile {
    /// Single-node deployment optimized for <60 second first message.
    ///
    /// **Defaults:**
    /// - Storage: SQLite only (truth layer)
    /// - Runtime: fuel_max = 1M, memory_max = 32MB, timeout = 250ms
    /// - Analytics: DuckDB (local file)
    /// - Features: Core + IRC only
    /// - Network: 127.0.0.1 (localhost)
    #[default]
    Potato,

    /// Mid-scale deployment for 1K-10K users.
    ///
    /// **Defaults (extends Potato):**
    /// - Storage: PostgreSQL (truth) + optional Redis (speed)
    /// - Runtime: fuel_max = 5M, memory_max = 64MB, timeout = 500ms
    /// - Analytics: Parquet files (local)
    /// - Features: Core + IRC + WebSocket
    /// - Network: 0.0.0.0 (public)
    Standard,

    /// Large-scale deployment for 100K+ users or federated hubs.
    ///
    /// **Defaults (extends Standard):**
    /// - Storage: CockroachDB (truth), ScyllaDB (speed), ClickHouse (intel), S3 (archive)
    /// - Runtime: fuel_max = 50M, memory_max = 256MB, timeout = 2000ms
    /// - Analytics: ClickHouse (federated)
    /// - Features: All enabled
    /// - Network: 0.0.0.0 with TLS
    Hyperscale,

    /// Custom configuration with no defaults applied.
    ///
    /// Users must explicitly configure all settings.
    /// Use this when the built-in profiles don't match your deployment.
    Custom,
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Profile::Potato => write!(f, "potato"),
            Profile::Standard => write!(f, "standard"),
            Profile::Hyperscale => write!(f, "hyperscale"),
            Profile::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for Profile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "potato" => Ok(Profile::Potato),
            "standard" => Ok(Profile::Standard),
            "hyperscale" => Ok(Profile::Hyperscale),
            "custom" => Ok(Profile::Custom),
            _ => Err(format!("unknown profile: {s}")),
        }
    }
}

impl Profile {
    /// Check if this is the default profile.
    pub fn is_default(&self) -> bool {
        matches!(self, Profile::Potato)
    }

    /// Get the base profile this extends (inheritance chain).
    ///
    /// - Standard extends Potato
    /// - Hyperscale extends Standard (which extends Potato)
    /// - Potato and Custom have no base
    pub fn base_profile(&self) -> Option<Profile> {
        match self {
            Profile::Potato => None,
            Profile::Standard => Some(Profile::Potato),
            Profile::Hyperscale => Some(Profile::Standard),
            Profile::Custom => None,
        }
    }

    /// Check if auto-start services is enabled for this profile.
    ///
    /// Potato and Standard profiles auto-start for quick setup.
    /// Hyperscale requires explicit service management.
    pub fn auto_start(&self) -> bool {
        matches!(self, Profile::Potato | Profile::Standard)
    }

    /// Get recommended concurrency limits for this profile.
    pub fn max_concurrent_blocks(&self) -> usize {
        match self {
            Profile::Potato => 10,
            Profile::Standard => 100,
            Profile::Hyperscale => 10_000,
            Profile::Custom => 50, // conservative default
        }
    }

    /// Get storage cache size in MB for this profile.
    pub fn storage_cache_mb(&self) -> usize {
        match self {
            Profile::Potato => 100,
            Profile::Standard => 512,
            Profile::Hyperscale => 1024,
            Profile::Custom => 100,
        }
    }

    /// Get maximum storage connections for this profile.
    pub fn storage_max_connections(&self) -> usize {
        match self {
            Profile::Potato => 10,
            Profile::Standard => 50,
            Profile::Hyperscale => 100,
            Profile::Custom => 10,
        }
    }

    /// Get ScyllaDB replication factor for this profile.
    pub fn scylla_replication_factor(&self) -> u32 {
        match self {
            Profile::Potato => 1,
            Profile::Standard => 2,
            Profile::Hyperscale => 3,
            Profile::Custom => 1,
        }
    }

    /// Get analytics batch size for this profile.
    pub fn analytics_batch_size(&self) -> usize {
        match self {
            Profile::Potato => 1_000,
            Profile::Standard => 5_000,
            Profile::Hyperscale => 10_000,
            Profile::Custom => 1_000,
        }
    }
}

/// Profile override mechanism for deep merging configurations.
///
/// Overrides are applied on top of profile defaults using precedence:
/// ENV var > CLI flag > file `profile.override` section > profile defaults
///
/// ## Example
///
/// ```toml
/// [meta]
/// profile = "potato"
///
/// [[profile.override]]
/// name = "standard"
/// [profile.override.storage]
/// backend = "postgres"
/// connection_string = "postgres://localhost/jig"
/// ```
///
/// This applies Standard's storage config over Potato defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileOverride {
    /// Name of the profile to apply overrides from.
    pub name: Profile,

    /// Specific overrides (populated by downstream config sections).
    ///
    /// Structure mirrors the main config but all fields are `Option<T>`.
    /// Non-None values override the corresponding profile default.
    ///
    /// TODO: This will be expanded with actual override fields as we
    /// implement storage, runtime, pricing, etc. in subsequent phases.
    #[serde(flatten)]
    pub overrides: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_profile_is_potato() {
        assert_eq!(Profile::default(), Profile::Potato);
        assert!(Profile::Potato.is_default());
        assert!(!Profile::Standard.is_default());
    }

    #[test]
    fn test_profile_display() {
        assert_eq!(Profile::Potato.to_string(), "potato");
        assert_eq!(Profile::Standard.to_string(), "standard");
        assert_eq!(Profile::Hyperscale.to_string(), "hyperscale");
        assert_eq!(Profile::Custom.to_string(), "custom");
    }

    #[test]
    fn test_profile_from_str() {
        assert_eq!("potato".parse::<Profile>().unwrap(), Profile::Potato);
        assert_eq!("STANDARD".parse::<Profile>().unwrap(), Profile::Standard);
        assert_eq!(
            "HyperScale".parse::<Profile>().unwrap(),
            Profile::Hyperscale
        );
        assert!("invalid".parse::<Profile>().is_err());
    }

    #[test]
    fn test_profile_inheritance() {
        assert_eq!(Profile::Potato.base_profile(), None);
        assert_eq!(Profile::Standard.base_profile(), Some(Profile::Potato));
        assert_eq!(Profile::Hyperscale.base_profile(), Some(Profile::Standard));
        assert_eq!(Profile::Custom.base_profile(), None);
    }

    #[test]
    fn test_auto_start() {
        assert!(Profile::Potato.auto_start());
        assert!(Profile::Standard.auto_start());
        assert!(!Profile::Hyperscale.auto_start());
        assert!(!Profile::Custom.auto_start());
    }

    #[test]
    fn test_concurrency_limits() {
        assert_eq!(Profile::Potato.max_concurrent_blocks(), 10);
        assert_eq!(Profile::Standard.max_concurrent_blocks(), 100);
        assert_eq!(Profile::Hyperscale.max_concurrent_blocks(), 10_000);
        assert_eq!(Profile::Custom.max_concurrent_blocks(), 50);
    }

    #[test]
    fn test_serde_roundtrip() {
        let profile = Profile::Standard;
        let json = serde_json::to_string(&profile).unwrap();
        assert_eq!(json, "\"standard\"");
        let deserialized: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, profile);
    }
}
