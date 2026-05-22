//! Integration tests for receipt configuration.

use jig_config::profiles::Profile;
use jig_config::receipt::{
    CanonicalizationRules, OutcomeConfig, OutcomeStatus, ReasonCodeTemplate, ReceiptConfig,
    RetentionConfig,
};

#[test]
fn test_receipt_config_potato_defaults() {
    let config = ReceiptConfig::default_for_profile(Profile::Potato);

    // Potato has relaxed requirements
    assert!(config.require_v2_fields);
    assert!(!config.require_renders_match);
    assert_eq!(config.retention.retention_days, 30);
    assert!(config.retention.archive_after_days.is_none());
}

#[test]
fn test_receipt_config_standard_defaults() {
    let config = ReceiptConfig::default_for_profile(Profile::Standard);

    // Standard has moderate requirements
    assert!(config.require_v2_fields);
    assert!(!config.require_renders_match);
    assert_eq!(config.retention.retention_days, 90);
    assert_eq!(config.retention.archive_after_days, Some(30));
}

#[test]
fn test_receipt_config_hyperscale_defaults() {
    let config = ReceiptConfig::default_for_profile(Profile::Hyperscale);

    // Hyperscale has strict requirements
    assert!(config.require_v2_fields);
    assert!(config.require_renders_match);
    assert_eq!(config.retention.retention_days, 365);
    assert_eq!(config.retention.archive_after_days, Some(90));
}

#[test]
fn test_toml_deserialization_basic() {
    let toml = r#"
        require_v2_fields = true
        require_renders_match = false
        require_fuel_breakdown = true

        [canonicalization]
        block_id_algorithm = "blake3-256"
        render_hash_algorithm = "sha256"
        strict_field_order = true
        compact_json = true

        [outcome]
        require_outcome = true

        [retention]
        persist = true
        retention_days = 90
        compress = true
        storage_tier = "intelligence"
    "#;

    let config: ReceiptConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert!(config.require_v2_fields);
    assert!(!config.require_renders_match);
    assert_eq!(config.canonicalization.block_id_algorithm, "blake3-256");
    assert_eq!(config.retention.retention_days, 90);
}

#[test]
fn test_toml_deserialization_outcome_config() {
    let toml = r#"
        [outcome]
        require_outcome = true
        default_affordances = ["read", "write"]

        [retention]
        persist = true
        retention_days = 90
    "#;

    let config: ReceiptConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert!(config.outcome.require_outcome);
    assert_eq!(config.outcome.default_affordances.len(), 2);
    assert_eq!(config.retention.retention_days, 90);

    // Note: reason_codes HashMap doesn't have a clean TOML representation
    // In practice, reason codes are configured via code or programmatic API
}

#[test]
fn test_validation_requires_non_empty_algorithms() {
    let mut config = ReceiptConfig::default();
    config.canonicalization.block_id_algorithm = String::new();

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("block_id_algorithm")
    );
}

#[test]
fn test_validation_archive_within_retention() {
    let mut config = ReceiptConfig::default();
    config.retention.retention_days = 30;
    config.retention.archive_after_days = Some(60);

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("archive_after_days")
    );
}

#[test]
fn test_validation_archive_equal_to_retention_is_ok() {
    let mut config = ReceiptConfig::default();
    config.retention.retention_days = 90;
    config.retention.archive_after_days = Some(90);

    assert!(config.validate().is_ok());
}

#[test]
fn test_validation_infinite_retention_allows_any_archive() {
    let mut config = ReceiptConfig::default();
    config.retention.retention_days = 0; // infinite
    config.retention.archive_after_days = Some(365);

    // Should be OK - infinite retention allows any archive period
    assert!(config.validate().is_ok());
}

#[test]
fn test_canonicalization_is_default() {
    let rules = CanonicalizationRules::default();
    assert!(rules.is_default());

    let mut custom_rules = CanonicalizationRules::default();
    custom_rules.block_id_algorithm = "sha256".to_string();
    assert!(!custom_rules.is_default());
}

#[test]
fn test_outcome_config_reason_code_lookup() {
    let config = OutcomeConfig::default();

    let fuel_exhausted = config.get_reason_code("FUEL_EXHAUSTED");
    assert!(fuel_exhausted.is_some());
    assert_eq!(fuel_exhausted.unwrap().status, OutcomeStatus::HardFail);
    assert!(!fuel_exhausted.unwrap().retryable);

    let net_timeout = config.get_reason_code("NET_TIMEOUT");
    assert!(net_timeout.is_some());
    assert_eq!(net_timeout.unwrap().status, OutcomeStatus::SoftFail);
    assert!(net_timeout.unwrap().retryable);
}

#[test]
fn test_outcome_config_custom_reason_code() {
    let mut config = OutcomeConfig::default();

    config.set_reason_code(
        "RATE_LIMITED".to_string(),
        ReasonCodeTemplate {
            code: "RATE_LIMITED".to_string(),
            description: "Request rate limit exceeded".to_string(),
            status: OutcomeStatus::SoftFail,
            retryable: true,
        },
    );

    let rate_limited = config.get_reason_code("RATE_LIMITED");
    assert!(rate_limited.is_some());
    assert_eq!(rate_limited.unwrap().code, "RATE_LIMITED");
}

#[test]
fn test_retention_config_profile_scaling() {
    let potato = ReceiptConfig::default_for_profile(Profile::Potato);
    let standard = ReceiptConfig::default_for_profile(Profile::Standard);
    let hyperscale = ReceiptConfig::default_for_profile(Profile::Hyperscale);

    // Retention scales with profile
    assert_eq!(potato.retention.retention_days, 30);
    assert_eq!(standard.retention.retention_days, 90);
    assert_eq!(hyperscale.retention.retention_days, 365);

    // Archive threshold scales too
    assert!(potato.retention.archive_after_days.is_none());
    assert_eq!(standard.retention.archive_after_days, Some(30));
    assert_eq!(hyperscale.retention.archive_after_days, Some(90));
}

#[test]
fn test_toml_serialization_roundtrip() {
    let config = ReceiptConfig::default_for_profile(Profile::Standard);

    // Serialize to TOML
    let toml_str = toml::to_string(&config).expect("failed to serialize");

    // Deserialize back
    let parsed: ReceiptConfig = toml::from_str(&toml_str).expect("failed to deserialize");

    // Should match original
    assert_eq!(config.require_v2_fields, parsed.require_v2_fields);
    assert_eq!(config.require_renders_match, parsed.require_renders_match);
    assert_eq!(
        config.canonicalization.block_id_algorithm,
        parsed.canonicalization.block_id_algorithm
    );
    assert_eq!(
        config.retention.retention_days,
        parsed.retention.retention_days
    );
}

#[test]
fn test_outcome_status_ordering() {
    // Verify enum values serialize correctly
    assert_eq!(
        serde_json::to_string(&OutcomeStatus::Ok).unwrap(),
        r#""ok""#
    );
    assert_eq!(
        serde_json::to_string(&OutcomeStatus::SoftFail).unwrap(),
        r#""soft_fail""#
    );
    assert_eq!(
        serde_json::to_string(&OutcomeStatus::HardFail).unwrap(),
        r#""hard_fail""#
    );
}

#[test]
fn test_default_reason_codes_coverage() {
    let config = OutcomeConfig::default();

    // Verify all expected reason codes exist
    let expected_codes = vec![
        "FUEL_EXHAUSTED",
        "RUNTIME_TIMEOUT",
        "MEMORY_LIMIT_EXCEEDED",
        "CAPABILITY_DENIED",
        "MANIFEST_INVALID",
        "NONDETERMINISM_DETECTED",
        "RENDER_MISMATCH",
        "NET_TIMEOUT",
        "UPSTREAM_5XX",
        "RUNTIME_TRAP",
        "TABLE_LIMIT_EXCEEDED",
        "HOST_PANIC",
        "UNKNOWN",
    ];

    for code in expected_codes {
        assert!(
            config.get_reason_code(code).is_some(),
            "Missing reason code: {code}"
        );
    }
}

#[test]
fn test_reason_code_retryable_vs_permanent() {
    let config = OutcomeConfig::default();

    // Permanent failures (not retryable)
    assert!(!config.get_reason_code("FUEL_EXHAUSTED").unwrap().retryable);
    assert!(
        !config
            .get_reason_code("MEMORY_LIMIT_EXCEEDED")
            .unwrap()
            .retryable
    );
    assert!(
        !config
            .get_reason_code("CAPABILITY_DENIED")
            .unwrap()
            .retryable
    );
    assert!(
        !config
            .get_reason_code("MANIFEST_INVALID")
            .unwrap()
            .retryable
    );
    assert!(
        !config
            .get_reason_code("NONDETERMINISM_DETECTED")
            .unwrap()
            .retryable
    );
    assert!(!config.get_reason_code("RUNTIME_TIMEOUT").unwrap().retryable);
    assert!(!config.get_reason_code("RUNTIME_TRAP").unwrap().retryable);
    assert!(
        !config
            .get_reason_code("TABLE_LIMIT_EXCEEDED")
            .unwrap()
            .retryable
    );
    assert!(!config.get_reason_code("HOST_PANIC").unwrap().retryable);
    assert!(!config.get_reason_code("UNKNOWN").unwrap().retryable);

    // Transient failures (retryable)
    assert!(config.get_reason_code("NET_TIMEOUT").unwrap().retryable);
    assert!(config.get_reason_code("UPSTREAM_5XX").unwrap().retryable);
    assert!(config.get_reason_code("RENDER_MISMATCH").unwrap().retryable);
}

#[test]
fn test_retention_config_compression_flag() {
    let mut config = RetentionConfig::default();
    assert!(config.compress);

    config.compress = false;
    assert!(!config.compress);
}

#[test]
fn test_retention_config_storage_tier_default() {
    let config = RetentionConfig::default();
    assert_eq!(config.storage_tier, "intelligence");
}
