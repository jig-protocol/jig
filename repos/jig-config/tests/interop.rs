//! Integration tests for bridge and interoperability configuration.

use jig_config::interop::{
    BridgeConfig, ExportConfig, ExportFormat, ExportFormatConfig, IngestConfig,
    MultiFormatExportConfig, RenderMode, SanitizationMode, TransformConfig, TransformType,
    ValidationMode,
};
use jig_config::profiles::Profile;

#[test]
fn test_potato_profile_bridges_disabled() {
    let config = BridgeConfig::default_for_profile(Profile::Potato);

    // Potato disables bridges by default (resource-constrained)
    assert!(!config.enabled);
    assert_eq!(config.ingest.max_content_size_mb, 5);
    assert_eq!(config.ingest.schema_validation, ValidationMode::Strict);
    assert_eq!(
        config.ingest.sanitization_mode,
        SanitizationMode::Aggressive
    );
    assert_eq!(config.block.fuel_budget_default, 50_000);
    assert_eq!(config.block.fuel_budget_max, 500_000);
    assert_eq!(config.limits.rate_limit_per_user, 10);
    assert_eq!(config.limits.rate_limit_global, 100);

    // Should validate
    assert!(config.validate().is_ok());
}

#[test]
fn test_standard_profile_bridges_enabled() {
    let config = BridgeConfig::default_for_profile(Profile::Standard);

    // Standard enables bridges with moderate settings
    assert!(config.enabled);
    assert_eq!(config.ingest.max_content_size_mb, 10);
    assert_eq!(config.ingest.sanitization_mode, SanitizationMode::Moderate);
    assert_eq!(config.block.fuel_budget_default, 100_000);
    assert_eq!(config.limits.rate_limit_per_user, 100);
    assert_eq!(config.limits.rate_limit_global, 10_000);

    // Should validate
    assert!(config.validate().is_ok());
}

#[test]
fn test_hyperscale_profile_high_limits() {
    let config = BridgeConfig::default_for_profile(Profile::Hyperscale);

    // Hyperscale has high limits and lenient validation
    assert!(config.enabled);
    assert_eq!(config.ingest.max_content_size_mb, 50);
    assert_eq!(config.ingest.schema_validation, ValidationMode::Lenient);
    assert_eq!(config.block.fuel_budget_default, 500_000);
    assert_eq!(config.block.fuel_budget_max, 5_000_000);
    assert_eq!(config.limits.rate_limit_per_user, 1000);
    assert_eq!(config.limits.rate_limit_global, 100_000);
    assert_eq!(config.limits.min_reputation_tier, "low_sec");
    assert!(config.limits.require_verified_for_outbound);
    assert_eq!(config.monitoring.analytics_backend, "clickhouse");

    // Should validate
    assert!(config.validate().is_ok());
}

#[test]
fn test_custom_profile_defaults() {
    let config = BridgeConfig::default_for_profile(Profile::Custom);

    // Custom profile uses base defaults
    assert!(!config.enabled);
    assert_eq!(config.block.fuel_budget_default, 100_000);

    // Should validate
    assert!(config.validate().is_ok());
}

#[test]
fn test_export_format_canonical_only_jcs() {
    assert!(ExportFormat::Jcs.is_canonical());
    assert!(!ExportFormat::Yaml.is_canonical());
    assert!(!ExportFormat::Json.is_canonical());
    assert!(!ExportFormat::ActivityPub.is_canonical());
    assert!(!ExportFormat::AtProto.is_canonical());
    assert!(!ExportFormat::Text.is_canonical());
    assert!(!ExportFormat::Html.is_canonical());
    assert!(!ExportFormat::Markdown.is_canonical());
}

#[test]
fn test_export_format_mime_types() {
    assert_eq!(ExportFormat::Yaml.mime_type(), "application/yaml");
    assert_eq!(ExportFormat::Json.mime_type(), "application/json");
    assert_eq!(ExportFormat::Jcs.mime_type(), "application/json");
    assert_eq!(
        ExportFormat::ActivityPub.mime_type(),
        "application/activity+json"
    );
    assert_eq!(ExportFormat::AtProto.mime_type(), "application/json");
    assert_eq!(ExportFormat::Text.mime_type(), "text/plain");
    assert_eq!(ExportFormat::Html.mime_type(), "text/html");
    assert_eq!(ExportFormat::Markdown.mime_type(), "text/markdown");
}

#[test]
fn test_validation_rejects_zero_content_size() {
    let mut config = BridgeConfig::default();
    config.ingest.max_content_size_mb = 0;

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("max_content_size_mb")
    );
}

#[test]
fn test_validation_rejects_fuel_budget_exceeds_max() {
    let mut config = BridgeConfig::default();
    config.block.fuel_budget_default = 2_000_000;
    config.block.fuel_budget_max = 1_000_000;

    assert!(config.validate().is_err());
    assert!(config.validate().unwrap_err().contains("fuel_budget"));
}

#[test]
fn test_validation_rejects_transform_fuel_exceeds_max() {
    let mut config = BridgeConfig::default();
    config.ingest.transform_pipeline.push(TransformConfig {
        transform_type: TransformType::TextToStructured,
        fuel_budget: 2_000_000,
        fuel_max: 1_000_000,
        ..Default::default()
    });

    assert!(config.validate().is_err());
    assert!(config.validate().unwrap_err().contains("fuel"));
}

#[test]
fn test_validation_rejects_zero_rate_limit_per_user() {
    let mut config = BridgeConfig::default();
    config.limits.rate_limit_per_user = 0;

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("rate_limit_per_user")
    );
}

#[test]
fn test_validation_rejects_zero_rate_limit_global() {
    let mut config = BridgeConfig::default();
    config.limits.rate_limit_global = 0;

    assert!(config.validate().is_err());
    assert!(config.validate().unwrap_err().contains("rate_limit_global"));
}

#[test]
fn test_validation_rejects_invalid_reputation_tier() {
    let mut config = BridgeConfig::default();
    config.limits.min_reputation_tier = "invalid_tier".to_string();

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("Invalid reputation tier")
    );
}

#[test]
fn test_validation_accepts_valid_reputation_tiers() {
    let valid_tiers = ["null_sec", "low_sec", "high_sec", "verified"];

    for tier in &valid_tiers {
        let mut config = BridgeConfig::default();
        config.limits.min_reputation_tier = tier.to_string();
        assert!(config.validate().is_ok(), "Tier {tier} should be valid");
    }
}

#[test]
fn test_total_fuel_budget_calculation() {
    let mut config = BridgeConfig::default();
    config.block.fuel_budget_default = 100_000;

    // Add ingest transform
    config.ingest.transform_pipeline.push(TransformConfig {
        transform_type: TransformType::AudioToText,
        fuel_budget: 50_000,
        fuel_max: 500_000,
        ..Default::default()
    });

    // Add export transform
    config.export.transform_pipeline.push(TransformConfig {
        transform_type: TransformType::TextToAudio,
        fuel_budget: 30_000,
        fuel_max: 300_000,
        ..Default::default()
    });

    assert_eq!(config.total_fuel_budget(), 180_000);
}

#[test]
fn test_transform_pipeline_with_multiple_transforms() {
    let mut config = BridgeConfig::default();

    // Add multiple ingest transforms (pipeline)
    config.ingest.transform_pipeline.push(TransformConfig {
        transform_type: TransformType::AudioToText,
        fuel_budget: 200_000,
        fuel_max: 2_000_000,
        required_capabilities: vec!["audio.decode".to_string()],
        ..Default::default()
    });

    config.ingest.transform_pipeline.push(TransformConfig {
        transform_type: TransformType::TextToStructured,
        fuel_budget: 100_000,
        fuel_max: 1_000_000,
        required_capabilities: vec!["nlp.parse".to_string()],
        ..Default::default()
    });

    assert_eq!(config.ingest.transform_pipeline.len(), 2);

    let total_ingest_fuel: u64 = config
        .ingest
        .transform_pipeline
        .iter()
        .map(|t| t.fuel_budget)
        .sum();

    assert_eq!(total_ingest_fuel, 300_000);
    assert!(config.validate().is_ok());
}

#[test]
fn test_capability_mapping() {
    let mut config = BridgeConfig::default();

    // Map external actions to Jig capabilities
    config.block.capability_mapping.insert(
        "send_email".to_string(),
        vec!["net.smtp".to_string(), "net.dns".to_string()],
    );

    config.block.capability_mapping.insert(
        "upload_file".to_string(),
        vec!["storage.write".to_string(), "net.http".to_string()],
    );

    assert_eq!(config.block.capability_mapping.len(), 2);
    assert_eq!(
        config.block.capability_mapping.get("send_email").unwrap(),
        &vec!["net.smtp".to_string(), "net.dns".to_string()]
    );
}

#[test]
fn test_toml_deserialization_basic() {
    let toml = r#"
        enabled = true
        bridge_version = "1.0"

        [ingest]
        schema_validation = "strict"
        max_content_size_mb = 25
        sanitization_mode = "aggressive"
        mark_legacy_source = true
        allowed_mime_types = ["text/plain", "text/html"]

        [block]
        fuel_budget_default = 500_000
        fuel_budget_max = 5_000_000

        [export]
        render_mode = "full"
        include_provenance = true
        include_receipt = false
        privacy_mode = "anonymized"

        [limits]
        rate_limit_per_user = 100
        rate_limit_global = 10_000
        min_reputation_tier = "low_sec"
        require_verified_for_outbound = true

        [monitoring]
        log_all_ingress = true
        log_all_egress = true
        track_fuel_usage = true
        alert_on_anomalies = true
        analytics_backend = "clickhouse"
    "#;

    let config: BridgeConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert!(config.enabled);
    assert_eq!(config.bridge_version, "1.0");
    assert_eq!(config.ingest.max_content_size_mb, 25);
    assert_eq!(config.ingest.schema_validation, ValidationMode::Strict);
    assert_eq!(
        config.ingest.sanitization_mode,
        SanitizationMode::Aggressive
    );
    assert_eq!(config.block.fuel_budget_default, 500_000);
    assert_eq!(config.export.render_mode, RenderMode::Full);
    assert_eq!(config.limits.rate_limit_per_user, 100);
    assert_eq!(config.monitoring.analytics_backend, "clickhouse");

    // Should validate
    assert!(config.validate().is_ok());
}

#[test]
fn test_toml_deserialization_with_transforms() {
    let toml = r#"
        enabled = true
        bridge_version = "1.0"

        [ingest]
        schema_validation = "lenient"
        max_content_size_mb = 10
        sanitization_mode = "moderate"
        mark_legacy_source = true

        [[ingest.transform_pipeline]]
        transform_type = "audio_to_text"
        fuel_budget = 200_000
        fuel_max = 2_000_000
        required_capabilities = ["audio.decode"]
        validate_determinism = true
        preserve_provenance = true

        [block]
        fuel_budget_default = 100_000
        fuel_budget_max = 1_000_000

        [export]
        render_mode = "summary"
        include_provenance = true

        [[export.transform_pipeline]]
        transform_type = "text_to_audio"
        fuel_budget = 150_000
        fuel_max = 1_500_000
        required_capabilities = ["audio.encode"]
        validate_determinism = true
        preserve_provenance = true

        [limits]
        rate_limit_per_user = 50
        rate_limit_global = 5_000
        min_reputation_tier = "null_sec"
        require_verified_for_outbound = false
    "#;

    let config: BridgeConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.ingest.transform_pipeline.len(), 1);
    assert_eq!(config.export.transform_pipeline.len(), 1);

    let ingest_transform = &config.ingest.transform_pipeline[0];
    assert_eq!(ingest_transform.fuel_budget, 200_000);
    assert_eq!(ingest_transform.fuel_max, 2_000_000);
    assert_eq!(ingest_transform.required_capabilities.len(), 1);

    let export_transform = &config.export.transform_pipeline[0];
    assert_eq!(export_transform.fuel_budget, 150_000);

    // Should validate
    assert!(config.validate().is_ok());
}

#[test]
fn test_toml_serialization_roundtrip() {
    let config = BridgeConfig::default_for_profile(Profile::Hyperscale);

    // Serialize to TOML
    let toml_str = toml::to_string(&config).expect("failed to serialize");

    // Deserialize back
    let parsed: BridgeConfig = toml::from_str(&toml_str).expect("failed to deserialize");

    // Should match original
    assert_eq!(config.enabled, parsed.enabled);
    assert_eq!(config.bridge_version, parsed.bridge_version);
    assert_eq!(
        config.ingest.max_content_size_mb,
        parsed.ingest.max_content_size_mb
    );
    assert_eq!(
        config.block.fuel_budget_default,
        parsed.block.fuel_budget_default
    );
    assert_eq!(
        config.limits.rate_limit_per_user,
        parsed.limits.rate_limit_per_user
    );
}

#[test]
fn test_multi_format_export_defaults() {
    let config = MultiFormatExportConfig::default();

    // YAML enabled but not canonical
    assert!(config.yaml.enabled);
    assert!(!config.yaml.canonical_format);

    // JSON enabled but not canonical
    assert!(config.json.enabled);
    assert!(!config.json.canonical_format);

    // JCS enabled and IS canonical
    assert!(config.jcs.enabled);
    assert!(config.jcs.canonical_format);

    // ActivityPub disabled by default
    assert!(!config.activitypub.enabled);

    // ATProto disabled by default
    assert!(!config.atproto.enabled);
}

#[test]
fn test_export_format_config_provenance() {
    let mut config = ExportFormatConfig::default();
    assert!(config.include_provenance);

    config.include_provenance = false;
    assert!(!config.include_provenance);
}

#[test]
fn test_validation_mode_enum_values() {
    let strict = ValidationMode::Strict;
    let lenient = ValidationMode::Lenient;
    let disabled = ValidationMode::Disabled;

    assert_eq!(strict, ValidationMode::Strict);
    assert_ne!(strict, lenient);
    assert_ne!(lenient, disabled);
}

#[test]
fn test_sanitization_mode_enum_values() {
    let aggressive = SanitizationMode::Aggressive;
    let moderate = SanitizationMode::Moderate;
    let minimal = SanitizationMode::Minimal;
    let disabled = SanitizationMode::Disabled;

    assert_eq!(aggressive, SanitizationMode::Aggressive);
    assert_ne!(aggressive, moderate);
    assert_ne!(moderate, minimal);
    assert_ne!(minimal, disabled);
}

#[test]
fn test_render_mode_enum_values() {
    let full = RenderMode::Full;
    let summary = RenderMode::Summary;
    let minimal = RenderMode::Minimal;

    assert_eq!(full, RenderMode::Full);
    assert_ne!(full, summary);
    assert_ne!(summary, minimal);
}

#[test]
fn test_transform_type_custom() {
    let custom1 = TransformType::Custom("my_custom_transform".to_string());
    let custom2 = TransformType::Custom("my_custom_transform".to_string());
    let custom3 = TransformType::Custom("different_transform".to_string());

    assert_eq!(custom1, custom2);
    assert_ne!(custom1, custom3);
}

#[test]
fn test_ingest_config_defaults() {
    let config = IngestConfig::default();

    assert_eq!(config.schema_validation, ValidationMode::Strict);
    assert_eq!(config.max_content_size_mb, 10);
    assert_eq!(config.sanitization_mode, SanitizationMode::Aggressive);
    assert!(config.mark_legacy_source);
    assert!(config.transform_pipeline.is_empty());
}

#[test]
fn test_export_config_defaults() {
    let config = ExportConfig::default();

    assert_eq!(config.render_mode, RenderMode::Full);
    assert!(config.include_provenance);
    assert!(!config.include_receipt);
    assert_eq!(config.privacy_mode, "anonymized");
    assert!(config.transform_pipeline.is_empty());
}

#[test]
fn test_zero_ambient_authority() {
    let config = BridgeConfig::default();

    // Bridges should have zero ambient authority by default
    assert!(config.block.default_capabilities.is_empty());
    assert!(config.block.capability_mapping.is_empty());
}

#[test]
fn test_profile_scaling_fuel_budgets() {
    let potato = BridgeConfig::default_for_profile(Profile::Potato);
    let standard = BridgeConfig::default_for_profile(Profile::Standard);
    let hyperscale = BridgeConfig::default_for_profile(Profile::Hyperscale);

    // Fuel budgets scale with profile
    assert_eq!(potato.block.fuel_budget_default, 50_000);
    assert_eq!(standard.block.fuel_budget_default, 100_000);
    assert_eq!(hyperscale.block.fuel_budget_default, 500_000);

    // Max fuel also scales
    assert_eq!(potato.block.fuel_budget_max, 500_000);
    assert_eq!(standard.block.fuel_budget_max, 1_000_000);
    assert_eq!(hyperscale.block.fuel_budget_max, 5_000_000);
}

#[test]
fn test_profile_scaling_rate_limits() {
    let potato = BridgeConfig::default_for_profile(Profile::Potato);
    let standard = BridgeConfig::default_for_profile(Profile::Standard);
    let hyperscale = BridgeConfig::default_for_profile(Profile::Hyperscale);

    // Rate limits scale with profile
    assert_eq!(potato.limits.rate_limit_per_user, 10);
    assert_eq!(standard.limits.rate_limit_per_user, 100);
    assert_eq!(hyperscale.limits.rate_limit_per_user, 1000);

    // Global limits also scale
    assert_eq!(potato.limits.rate_limit_global, 100);
    assert_eq!(standard.limits.rate_limit_global, 10_000);
    assert_eq!(hyperscale.limits.rate_limit_global, 100_000);
}
