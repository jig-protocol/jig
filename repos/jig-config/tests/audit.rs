//! Integration tests for audit and compliance configuration.

use jig_config::audit::{
    AuditConfig, AuditEventCategory, AuditRetention, AuditSeverity, ComplianceStandard,
};
use jig_config::profiles::Profile;

#[test]
fn test_potato_profile_minimal_audit() {
    let config = AuditConfig::default_for_profile(Profile::Potato);

    // Potato has minimal audit requirements
    assert_eq!(config.compliance_standard, ComplianceStandard::None);
    assert_eq!(config.enabled_categories.len(), 2);
    assert!(config.is_category_enabled(AuditEventCategory::Security));
    assert!(config.is_category_enabled(AuditEventCategory::Execution));
    assert_eq!(config.min_severity, AuditSeverity::Warn);
    assert!(!config.log_payloads);
    assert!(!config.anonymize_pii);
    assert!(!config.sign_audit_logs);
    assert!(!config.tamper_evident);

    // Minimal retention
    assert_eq!(config.retention.retention_days, 7);
    assert!(config.retention.archive_after_days.is_none());
    assert!(!config.retention.stream_to_siem);

    // Should validate
    assert!(config.validate().is_ok());
}

#[test]
fn test_standard_profile_soc2_compliance() {
    let config = AuditConfig::default_for_profile(Profile::Standard);

    // Standard has SOC2 compliance
    assert_eq!(config.compliance_standard, ComplianceStandard::Soc2);
    assert_eq!(config.enabled_categories.len(), 4);
    assert!(config.is_category_enabled(AuditEventCategory::Security));
    assert!(config.is_category_enabled(AuditEventCategory::Access));
    assert!(config.is_category_enabled(AuditEventCategory::Execution));
    assert!(config.is_category_enabled(AuditEventCategory::Billing));
    assert_eq!(config.min_severity, AuditSeverity::Info);
    assert!(config.anonymize_pii);
    assert!(config.sign_audit_logs);
    assert!(config.tamper_evident);

    // SOC2 retention requirements
    assert_eq!(config.retention.retention_days, 365);
    assert_eq!(config.retention.archive_after_days, Some(90));

    // Should validate
    assert!(config.validate().is_ok());
}

#[test]
fn test_hyperscale_profile_enterprise_compliance() {
    let config = AuditConfig::default_for_profile(Profile::Hyperscale);

    // Hyperscale has Enterprise compliance (all standards)
    assert_eq!(config.compliance_standard, ComplianceStandard::Enterprise);
    assert_eq!(config.enabled_categories.len(), 7);
    assert!(config.log_payloads);
    assert!(config.anonymize_pii);
    assert!(config.include_stack_traces);
    assert!(config.sign_audit_logs);
    assert!(config.tamper_evident);

    // Enterprise retention (7 years)
    assert_eq!(config.retention.retention_days, 2555);
    assert_eq!(config.retention.archive_after_days, Some(365));
    assert!(config.retention.stream_to_siem);
    assert!(config.retention.siem_endpoint.is_some());

    // Should validate
    assert!(config.validate().is_ok());
}

#[test]
fn test_custom_profile_no_defaults() {
    let config = AuditConfig::default_for_profile(Profile::Custom);

    assert_eq!(config.compliance_standard, ComplianceStandard::None);
    assert_eq!(config.enabled_categories.len(), 0);
    assert!(!config.log_payloads);
    assert!(!config.anonymize_pii);
    assert!(!config.sign_audit_logs);
    assert!(!config.tamper_evident);

    // Custom profile should validate (no compliance requirements)
    assert!(config.validate().is_ok());
}

#[test]
fn test_compliance_standard_retention_requirements() {
    assert_eq!(ComplianceStandard::None.min_retention_days(), 7);
    assert_eq!(ComplianceStandard::Soc2.min_retention_days(), 365);
    assert_eq!(ComplianceStandard::Hipaa.min_retention_days(), 2555);
    assert_eq!(ComplianceStandard::Gdpr.min_retention_days(), 730);
    assert_eq!(ComplianceStandard::Enterprise.min_retention_days(), 2555);
}

#[test]
fn test_compliance_standard_pii_requirements() {
    assert!(!ComplianceStandard::None.requires_pii_anonymization());
    assert!(!ComplianceStandard::Soc2.requires_pii_anonymization());
    assert!(ComplianceStandard::Hipaa.requires_pii_anonymization());
    assert!(ComplianceStandard::Gdpr.requires_pii_anonymization());
    assert!(ComplianceStandard::Enterprise.requires_pii_anonymization());
}

#[test]
fn test_validation_rejects_insufficient_retention() {
    let mut config = AuditConfig::default_for_profile(Profile::Potato);
    config.compliance_standard = ComplianceStandard::Soc2;
    config.retention.retention_days = 30; // Too short for SOC2 (365 required)

    // Need to add required categories for SOC2
    config.enabled_categories.insert(AuditEventCategory::Access);
    config
        .enabled_categories
        .insert(AuditEventCategory::Execution);

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("less than minimum required")
    );
}

#[test]
fn test_validation_rejects_archive_exceeds_retention() {
    let mut config = AuditConfig::default_for_profile(Profile::Standard);
    config.compliance_standard = ComplianceStandard::None; // No retention minimum
    config.retention.retention_days = 90;
    config.retention.archive_after_days = Some(180); // Archive > retention

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("exceeds retention period")
    );
}

#[test]
fn test_validation_allows_infinite_retention() {
    let mut config = AuditConfig::default_for_profile(Profile::Hyperscale);
    config.retention.retention_days = 0; // Infinite
    config.retention.archive_after_days = Some(365);

    // Infinite retention should allow any archive period
    assert!(config.validate().is_ok());
}

#[test]
fn test_validation_enforces_pii_anonymization_for_gdpr() {
    let mut config = AuditConfig::default_for_profile(Profile::Standard);
    config.compliance_standard = ComplianceStandard::Gdpr;
    config.anonymize_pii = false;
    config.retention.retention_days = 730; // Meet GDPR retention
    config
        .enabled_categories
        .insert(AuditEventCategory::Storage); // GDPR requires Storage

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("requires PII anonymization")
    );
}

#[test]
fn test_validation_enforces_pii_anonymization_for_hipaa() {
    let mut config = AuditConfig::default_for_profile(Profile::Standard);
    config.compliance_standard = ComplianceStandard::Hipaa;
    config.anonymize_pii = false;
    config.retention.retention_days = 2555; // Meet HIPAA retention
    config
        .enabled_categories
        .insert(AuditEventCategory::Storage); // HIPAA requires Storage

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("requires PII anonymization")
    );
}

#[test]
fn test_validation_enforces_siem_endpoint() {
    let mut config = AuditConfig::default_for_profile(Profile::Potato);
    config.retention.stream_to_siem = true;
    config.retention.siem_endpoint = None;

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("no endpoint configured")
    );
}

#[test]
fn test_validation_accepts_siem_with_endpoint() {
    let mut config = AuditConfig::default_for_profile(Profile::Potato);
    config.retention.stream_to_siem = true;
    config.retention.siem_endpoint = Some("https://siem.example.com/ingest".to_string());

    assert!(config.validate().is_ok());
}

#[test]
fn test_validation_enforces_soc2_categories() {
    let mut config = AuditConfig::default_for_profile(Profile::Potato);
    config.compliance_standard = ComplianceStandard::Soc2;
    config.retention.retention_days = 365; // Meet SOC2 retention
    config.enabled_categories.clear(); // Remove all categories

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("requires audit categories")
    );
}

#[test]
fn test_validation_enforces_hipaa_categories() {
    let mut config = AuditConfig::default_for_profile(Profile::Potato);
    config.compliance_standard = ComplianceStandard::Hipaa;
    config.retention.retention_days = 2555; // Meet HIPAA retention
    config.anonymize_pii = true;
    config.enabled_categories.clear();
    config
        .enabled_categories
        .insert(AuditEventCategory::Security);
    // Missing Access and Storage

    assert!(config.validate().is_err());
    assert!(
        config
            .validate()
            .unwrap_err()
            .contains("requires audit categories")
    );
}

#[test]
fn test_validation_enforces_enterprise_categories() {
    let mut config = AuditConfig::default_for_profile(Profile::Potato);
    config.compliance_standard = ComplianceStandard::Enterprise;
    config.retention.retention_days = 2555;
    config.anonymize_pii = true;
    config.enabled_categories.clear();
    config
        .enabled_categories
        .insert(AuditEventCategory::Security);
    config.enabled_categories.insert(AuditEventCategory::Access);
    // Missing Execution, Storage, Billing

    assert!(config.validate().is_err());
}

#[test]
fn test_severity_filtering() {
    let config = AuditConfig {
        min_severity: AuditSeverity::Error,
        ..Default::default()
    };

    assert!(!config.should_log_severity(AuditSeverity::Info));
    assert!(!config.should_log_severity(AuditSeverity::Warn));
    assert!(config.should_log_severity(AuditSeverity::Error));
    assert!(config.should_log_severity(AuditSeverity::Critical));
}

#[test]
fn test_category_filtering() {
    let mut config = AuditConfig::default_for_profile(Profile::Potato);
    config.enabled_categories.clear();
    config
        .enabled_categories
        .insert(AuditEventCategory::Security);
    config
        .enabled_categories
        .insert(AuditEventCategory::Billing);

    assert!(config.is_category_enabled(AuditEventCategory::Security));
    assert!(config.is_category_enabled(AuditEventCategory::Billing));
    assert!(!config.is_category_enabled(AuditEventCategory::Access));
    assert!(!config.is_category_enabled(AuditEventCategory::Execution));
}

#[test]
fn test_toml_deserialization_potato() {
    let toml = r#"
        compliance_standard = "none"
        enabled_categories = ["security", "execution"]
        min_severity = "warn"
        log_payloads = false
        anonymize_pii = false
        include_stack_traces = false
        sign_audit_logs = false
        tamper_evident = false

        [retention]
        enabled = true
        retention_days = 7
        compress = true
        storage_tier = "truth"
        stream_to_siem = false
    "#;

    let config: AuditConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.compliance_standard, ComplianceStandard::None);
    assert_eq!(config.enabled_categories.len(), 2);
    assert_eq!(config.min_severity, AuditSeverity::Warn);
    assert_eq!(config.retention.retention_days, 7);
}

#[test]
fn test_toml_deserialization_hyperscale() {
    let toml = r#"
        compliance_standard = "enterprise"
        enabled_categories = ["security", "access", "execution", "storage", "billing", "config", "system"]
        min_severity = "info"
        log_payloads = true
        anonymize_pii = true
        include_stack_traces = true
        sign_audit_logs = true
        tamper_evident = true

        [retention]
        enabled = true
        retention_days = 2555
        archive_after_days = 365
        compress = true
        storage_tier = "truth"
        stream_to_siem = true
        siem_endpoint = "https://siem.example.com/ingest"
    "#;

    let config: AuditConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.compliance_standard, ComplianceStandard::Enterprise);
    assert_eq!(config.enabled_categories.len(), 7);
    assert_eq!(config.min_severity, AuditSeverity::Info);
    assert!(config.log_payloads);
    assert!(config.anonymize_pii);
    assert!(config.sign_audit_logs);
    assert!(config.tamper_evident);
    assert_eq!(config.retention.retention_days, 2555);
    assert!(config.retention.stream_to_siem);
    assert!(config.retention.siem_endpoint.is_some());

    // Should validate
    assert!(config.validate().is_ok());
}

#[test]
fn test_toml_serialization_roundtrip() {
    let config = AuditConfig::default_for_profile(Profile::Hyperscale);

    // Serialize to TOML
    let toml_str = toml::to_string(&config).expect("failed to serialize");

    // Deserialize back
    let parsed: AuditConfig = toml::from_str(&toml_str).expect("failed to deserialize");

    // Should match original
    assert_eq!(config.compliance_standard, parsed.compliance_standard);
    assert_eq!(config.enabled_categories, parsed.enabled_categories);
    assert_eq!(config.min_severity, parsed.min_severity);
    assert_eq!(config.log_payloads, parsed.log_payloads);
    assert_eq!(config.anonymize_pii, parsed.anonymize_pii);
    assert_eq!(
        config.retention.retention_days,
        parsed.retention.retention_days
    );
}

#[test]
fn test_compliance_standard_serialization() {
    assert_eq!(
        serde_json::to_string(&ComplianceStandard::None).unwrap(),
        r#""none""#
    );
    assert_eq!(
        serde_json::to_string(&ComplianceStandard::Soc2).unwrap(),
        r#""soc2""#
    );
    assert_eq!(
        serde_json::to_string(&ComplianceStandard::Hipaa).unwrap(),
        r#""hipaa""#
    );
    assert_eq!(
        serde_json::to_string(&ComplianceStandard::Gdpr).unwrap(),
        r#""gdpr""#
    );
    assert_eq!(
        serde_json::to_string(&ComplianceStandard::Enterprise).unwrap(),
        r#""enterprise""#
    );
}

#[test]
fn test_severity_serialization() {
    assert_eq!(
        serde_json::to_string(&AuditSeverity::Info).unwrap(),
        r#""info""#
    );
    assert_eq!(
        serde_json::to_string(&AuditSeverity::Warn).unwrap(),
        r#""warn""#
    );
    assert_eq!(
        serde_json::to_string(&AuditSeverity::Error).unwrap(),
        r#""error""#
    );
    assert_eq!(
        serde_json::to_string(&AuditSeverity::Critical).unwrap(),
        r#""critical""#
    );
}

#[test]
fn test_category_serialization() {
    assert_eq!(
        serde_json::to_string(&AuditEventCategory::Security).unwrap(),
        r#""security""#
    );
    assert_eq!(
        serde_json::to_string(&AuditEventCategory::Access).unwrap(),
        r#""access""#
    );
    assert_eq!(
        serde_json::to_string(&AuditEventCategory::Execution).unwrap(),
        r#""execution""#
    );
    assert_eq!(
        serde_json::to_string(&AuditEventCategory::Storage).unwrap(),
        r#""storage""#
    );
    assert_eq!(
        serde_json::to_string(&AuditEventCategory::Billing).unwrap(),
        r#""billing""#
    );
    assert_eq!(
        serde_json::to_string(&AuditEventCategory::Config).unwrap(),
        r#""config""#
    );
    assert_eq!(
        serde_json::to_string(&AuditEventCategory::System).unwrap(),
        r#""system""#
    );
}

#[test]
fn test_retention_config_defaults() {
    let retention = AuditRetention::default();

    assert!(retention.enabled);
    assert_eq!(retention.retention_days, 90);
    assert_eq!(retention.archive_after_days, Some(30));
    assert!(retention.compress);
    assert_eq!(retention.storage_tier, "truth");
    assert!(!retention.stream_to_siem);
    assert!(retention.siem_endpoint.is_none());
}
