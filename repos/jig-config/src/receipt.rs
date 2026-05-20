//! Receipt configuration for execution attestation and outcome-based pricing.
//!
//! Aligns with jig-core BlockReceipt v0.2 schema, providing policy controls for:
//! - Receipt validation requirements
//! - Canonicalization and hash algorithms
//! - Outcome affordances and reason codes
//! - Retention and storage policies

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::profiles::Profile;

/// Receipt configuration policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptConfig {
    /// Require v0.2 fields (counters, timings, limits, outcome) in all receipts
    #[serde(default = "default_true")]
    pub require_v2_fields: bool,

    /// Require renders_match field to be set
    #[serde(default = "default_false")]
    pub require_renders_match: bool,

    /// Require fuel_by_capability breakdown in counters
    #[serde(default = "default_true")]
    pub require_fuel_breakdown: bool,

    /// Canonicalization rules
    #[serde(default)]
    pub canonicalization: CanonicalizationRules,

    /// Outcome configuration
    #[serde(default)]
    pub outcome: OutcomeConfig,

    /// Retention and storage policies
    #[serde(default)]
    pub retention: RetentionConfig,
}

/// Canonicalization rules for deterministic receipt serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalizationRules {
    /// Hash algorithm for block IDs (default: "blake3-256")
    #[serde(default = "default_block_id_hash")]
    pub block_id_algorithm: String,

    /// Hash algorithm for render hashes (default: "sha256")
    #[serde(default = "default_render_hash")]
    pub render_hash_algorithm: String,

    /// Enforce strict field ordering in JSON (always true for receipts)
    #[serde(default = "default_true")]
    pub strict_field_order: bool,

    /// Compact JSON (no whitespace) for canonical bytes
    #[serde(default = "default_true")]
    pub compact_json: bool,
}

/// Outcome configuration for execution results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeConfig {
    /// Default affordances granted on successful execution
    #[serde(default)]
    pub default_affordances: Vec<String>,

    /// Reason code templates for common failure modes
    #[serde(default)]
    pub reason_codes: HashMap<String, ReasonCodeTemplate>,

    /// Require outcome field in all receipts
    #[serde(default = "default_true")]
    pub require_outcome: bool,
}

/// Template for standardized reason codes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReasonCodeTemplate {
    /// Machine-readable reason code (e.g., "FUEL_EXHAUSTED")
    pub code: String,

    /// Human-readable description template
    pub description: String,

    /// Outcome status this applies to (ok, soft_fail, hard_fail)
    pub status: OutcomeStatus,

    /// Whether this reason code allows retry
    #[serde(default = "default_false")]
    pub retryable: bool,
}

/// Outcome status enum (mirrors jig-core OutcomeStatus).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    /// Execution completed successfully
    Ok,

    /// Soft failure (partial success, may retry)
    SoftFail,

    /// Hard failure (permanent error, do not retry)
    HardFail,
}

impl Default for OutcomeStatus {
    fn default() -> Self {
        Self::Ok
    }
}

/// Retention and storage policies for receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Store receipts to persistent storage
    #[serde(default = "default_true")]
    pub persist: bool,

    /// Retention period in days (0 = infinite)
    #[serde(default)]
    pub retention_days: u32,

    /// Archive receipts to cold storage after N days
    #[serde(default)]
    pub archive_after_days: Option<u32>,

    /// Compress receipts before storage
    #[serde(default = "default_true")]
    pub compress: bool,

    /// Storage tier to use (defaults to intelligence layer)
    #[serde(default = "default_storage_tier")]
    pub storage_tier: String,
}

impl Default for ReceiptConfig {
    fn default() -> Self {
        Self {
            require_v2_fields: true,
            require_renders_match: false,
            require_fuel_breakdown: true,
            canonicalization: CanonicalizationRules::default(),
            outcome: OutcomeConfig::default(),
            retention: RetentionConfig::default(),
        }
    }
}

impl Default for CanonicalizationRules {
    fn default() -> Self {
        Self {
            block_id_algorithm: default_block_id_hash(),
            render_hash_algorithm: default_render_hash(),
            strict_field_order: true,
            compact_json: true,
        }
    }
}

impl Default for OutcomeConfig {
    fn default() -> Self {
        Self {
            default_affordances: vec![],
            reason_codes: default_reason_codes(),
            require_outcome: true,
        }
    }
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            persist: true,
            retention_days: 0, // infinite by default
            archive_after_days: None,
            compress: true,
            storage_tier: default_storage_tier(),
        }
    }
}

impl ReceiptConfig {
    /// Create default receipt config for a given profile.
    pub fn default_for_profile(profile: Profile) -> Self {
        let mut config = Self::default();

        match profile {
            Profile::Potato => {
                // Relaxed requirements for potato
                config.require_renders_match = false;
                config.retention.retention_days = 30; // 30 days
                config.retention.archive_after_days = None;
            }
            Profile::Standard => {
                // Standard requirements
                config.require_renders_match = false;
                config.retention.retention_days = 90; // 90 days
                config.retention.archive_after_days = Some(30);
            }
            Profile::Hyperscale => {
                // Strict requirements for hyperscale
                config.require_renders_match = true;
                config.require_v2_fields = true;
                config.retention.retention_days = 365; // 1 year
                config.retention.archive_after_days = Some(90);
            }
            Profile::Custom => {
                // Conservative defaults
                config.require_renders_match = true;
                config.retention.retention_days = 90;
            }
        }

        config
    }

    /// Validate receipt configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Validate hash algorithms are non-empty
        if self.canonicalization.block_id_algorithm.is_empty() {
            return Err("block_id_algorithm cannot be empty".to_string());
        }
        if self.canonicalization.render_hash_algorithm.is_empty() {
            return Err("render_hash_algorithm cannot be empty".to_string());
        }

        // Validate retention policies
        if let Some(archive_days) = self.retention.archive_after_days
            && self.retention.retention_days > 0
            && archive_days > self.retention.retention_days
        {
            return Err(format!(
                "archive_after_days ({}) cannot exceed retention_days ({})",
                archive_days, self.retention.retention_days
            ));
        }

        Ok(())
    }
}

impl CanonicalizationRules {
    /// Check if using default hash algorithms.
    pub fn is_default(&self) -> bool {
        self.block_id_algorithm == default_block_id_hash()
            && self.render_hash_algorithm == default_render_hash()
    }
}

impl OutcomeConfig {
    /// Get reason code template by code string.
    pub fn get_reason_code(&self, code: &str) -> Option<&ReasonCodeTemplate> {
        self.reason_codes.get(code)
    }

    /// Add or update a reason code template.
    pub fn set_reason_code(&mut self, code: String, template: ReasonCodeTemplate) {
        self.reason_codes.insert(code, template);
    }
}

// Default value functions for serde
fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_block_id_hash() -> String {
    "blake3-256".to_string()
}

fn default_render_hash() -> String {
    "sha256".to_string()
}

fn default_storage_tier() -> String {
    "intelligence".to_string()
}

/// Default reason codes for common failure modes.
fn default_reason_codes() -> HashMap<String, ReasonCodeTemplate> {
    let mut codes = HashMap::new();

    codes.insert(
        "NET_TIMEOUT".to_string(),
        ReasonCodeTemplate {
            code: "NET_TIMEOUT".to_string(),
            description: "Network request exceeded timeout".to_string(),
            status: OutcomeStatus::SoftFail,
            retryable: true,
        },
    );

    codes.insert(
        "UPSTREAM_5XX".to_string(),
        ReasonCodeTemplate {
            code: "UPSTREAM_5XX".to_string(),
            description: "Upstream service returned 5xx response".to_string(),
            status: OutcomeStatus::SoftFail,
            retryable: true,
        },
    );

    codes.insert(
        "CAPABILITY_DENIED".to_string(),
        ReasonCodeTemplate {
            code: "CAPABILITY_DENIED".to_string(),
            description: "Block requested unauthorized capability".to_string(),
            status: OutcomeStatus::HardFail,
            retryable: false,
        },
    );

    codes.insert(
        "MANIFEST_INVALID".to_string(),
        ReasonCodeTemplate {
            code: "MANIFEST_INVALID".to_string(),
            description: "Block manifest failed validation".to_string(),
            status: OutcomeStatus::HardFail,
            retryable: false,
        },
    );

    codes.insert(
        "NONDETERMINISM_DETECTED".to_string(),
        ReasonCodeTemplate {
            code: "NONDETERMINISM_DETECTED".to_string(),
            description: "Non-deterministic behaviour detected during execution".to_string(),
            status: OutcomeStatus::HardFail,
            retryable: false,
        },
    );

    codes.insert(
        "RENDER_MISMATCH".to_string(),
        ReasonCodeTemplate {
            code: "RENDER_MISMATCH".to_string(),
            description: "Render output did not match expected hash".to_string(),
            status: OutcomeStatus::SoftFail,
            retryable: true,
        },
    );

    codes.insert(
        "RUNTIME_TIMEOUT".to_string(),
        ReasonCodeTemplate {
            code: "RUNTIME_TIMEOUT".to_string(),
            description: "Execution exceeded runtime timeout".to_string(),
            status: OutcomeStatus::HardFail,
            retryable: false,
        },
    );

    codes.insert(
        "RUNTIME_TRAP".to_string(),
        ReasonCodeTemplate {
            code: "RUNTIME_TRAP".to_string(),
            description: "Wasm trap occurred during execution".to_string(),
            status: OutcomeStatus::HardFail,
            retryable: false,
        },
    );

    codes.insert(
        "FUEL_EXHAUSTED".to_string(),
        ReasonCodeTemplate {
            code: "FUEL_EXHAUSTED".to_string(),
            description: "Block execution exceeded fuel limit".to_string(),
            status: OutcomeStatus::HardFail,
            retryable: false,
        },
    );

    codes.insert(
        "MEMORY_LIMIT_EXCEEDED".to_string(),
        ReasonCodeTemplate {
            code: "MEMORY_LIMIT_EXCEEDED".to_string(),
            description: "Block execution exceeded memory limit".to_string(),
            status: OutcomeStatus::HardFail,
            retryable: false,
        },
    );

    codes.insert(
        "TABLE_LIMIT_EXCEEDED".to_string(),
        ReasonCodeTemplate {
            code: "TABLE_LIMIT_EXCEEDED".to_string(),
            description: "Block execution exceeded table limit".to_string(),
            status: OutcomeStatus::HardFail,
            retryable: false,
        },
    );

    codes.insert(
        "HOST_PANIC".to_string(),
        ReasonCodeTemplate {
            code: "HOST_PANIC".to_string(),
            description: "Host capability panicked during execution".to_string(),
            status: OutcomeStatus::HardFail,
            retryable: false,
        },
    );

    codes.insert(
        "UNKNOWN".to_string(),
        ReasonCodeTemplate {
            code: "UNKNOWN".to_string(),
            description: "Unknown execution failure".to_string(),
            status: OutcomeStatus::HardFail,
            retryable: false,
        },
    );

    codes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_config_defaults() {
        let config = ReceiptConfig::default();
        assert!(config.require_v2_fields);
        assert!(!config.require_renders_match);
        assert!(config.require_fuel_breakdown);
        assert!(config.canonicalization.strict_field_order);
        assert!(config.outcome.require_outcome);
        assert!(config.retention.persist);
    }

    #[test]
    fn test_profile_specific_receipt_config() {
        let potato = ReceiptConfig::default_for_profile(Profile::Potato);
        assert_eq!(potato.retention.retention_days, 30);
        assert!(!potato.require_renders_match);

        let standard = ReceiptConfig::default_for_profile(Profile::Standard);
        assert_eq!(standard.retention.retention_days, 90);
        assert_eq!(standard.retention.archive_after_days, Some(30));

        let hyperscale = ReceiptConfig::default_for_profile(Profile::Hyperscale);
        assert_eq!(hyperscale.retention.retention_days, 365);
        assert!(hyperscale.require_renders_match);
    }

    #[test]
    fn test_canonicalization_defaults() {
        let rules = CanonicalizationRules::default();
        assert_eq!(rules.block_id_algorithm, "blake3-256");
        assert_eq!(rules.render_hash_algorithm, "sha256");
        assert!(rules.is_default());
        assert!(rules.compact_json);
    }

    #[test]
    fn test_validation_catches_empty_algorithms() {
        let mut config = ReceiptConfig::default();
        config.canonicalization.block_id_algorithm = String::new();
        assert!(config.validate().is_err());

        let mut config = ReceiptConfig::default();
        config.canonicalization.render_hash_algorithm = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_catches_archive_exceeds_retention() {
        let mut config = ReceiptConfig::default();
        config.retention.retention_days = 30;
        config.retention.archive_after_days = Some(60);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_default_reason_codes_exist() {
        let config = OutcomeConfig::default();
        assert!(config.get_reason_code("FUEL_EXHAUSTED").is_some());
        assert!(config.get_reason_code("NET_TIMEOUT").is_some());
        assert!(config.get_reason_code("UPSTREAM_5XX").is_some());
        assert!(config.get_reason_code("MEMORY_LIMIT_EXCEEDED").is_some());
        assert!(config.get_reason_code("CAPABILITY_DENIED").is_some());
        assert!(config.get_reason_code("MANIFEST_INVALID").is_some());
        assert!(config.get_reason_code("NONDETERMINISM_DETECTED").is_some());
        assert!(config.get_reason_code("RENDER_MISMATCH").is_some());
        assert!(config.get_reason_code("RUNTIME_TIMEOUT").is_some());
        assert!(config.get_reason_code("UNKNOWN").is_some());
    }

    #[test]
    fn test_reason_code_properties() {
        let config = OutcomeConfig::default();

        let fuel_exhausted = config.get_reason_code("FUEL_EXHAUSTED").unwrap();
        assert_eq!(fuel_exhausted.status, OutcomeStatus::HardFail);
        assert!(!fuel_exhausted.retryable);

        let net_timeout = config.get_reason_code("NET_TIMEOUT").unwrap();
        assert_eq!(net_timeout.status, OutcomeStatus::SoftFail);
        assert!(net_timeout.retryable);

        let render_mismatch = config.get_reason_code("RENDER_MISMATCH").unwrap();
        assert_eq!(render_mismatch.status, OutcomeStatus::SoftFail);
        assert!(render_mismatch.retryable);
    }

    #[test]
    fn test_outcome_status_serialization() {
        let ok = OutcomeStatus::Ok;
        let json = serde_json::to_string(&ok).unwrap();
        assert_eq!(json, r#""ok""#);

        let soft_fail = OutcomeStatus::SoftFail;
        let json = serde_json::to_string(&soft_fail).unwrap();
        assert_eq!(json, r#""soft_fail""#);

        let hard_fail = OutcomeStatus::HardFail;
        let json = serde_json::to_string(&hard_fail).unwrap();
        assert_eq!(json, r#""hard_fail""#);
    }

    #[test]
    fn test_outcome_config_add_reason_code() {
        let mut config = OutcomeConfig::default();
        config.set_reason_code(
            "CUSTOM_ERROR".to_string(),
            ReasonCodeTemplate {
                code: "CUSTOM_ERROR".to_string(),
                description: "Custom error condition".to_string(),
                status: OutcomeStatus::SoftFail,
                retryable: true,
            },
        );

        assert!(config.get_reason_code("CUSTOM_ERROR").is_some());
    }

    #[test]
    fn test_retention_config_defaults() {
        let retention = RetentionConfig::default();
        assert!(retention.persist);
        assert_eq!(retention.retention_days, 0); // infinite
        assert!(retention.archive_after_days.is_none());
        assert!(retention.compress);
        assert_eq!(retention.storage_tier, "intelligence");
    }

    #[test]
    fn test_serde_roundtrip() {
        let config = ReceiptConfig::default_for_profile(Profile::Hyperscale);
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ReceiptConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.require_v2_fields, parsed.require_v2_fields);
        assert_eq!(config.require_renders_match, parsed.require_renders_match);
        assert_eq!(
            config.retention.retention_days,
            parsed.retention.retention_days
        );
    }
}
