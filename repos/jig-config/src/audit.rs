//! Audit and compliance logging configuration.
//!
//! Configures audit event tracking, compliance standards (SOC2, HIPAA, GDPR),
//! and retention policies for different deployment profiles.

use crate::profiles::Profile;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Compliance standard to enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStandard {
    /// No compliance requirements
    None,
    /// SOC2 Type II compliance
    Soc2,
    /// HIPAA compliance for healthcare data
    Hipaa,
    /// GDPR compliance for EU data
    Gdpr,
    /// Enterprise compliance (all standards)
    Enterprise,
}

impl ComplianceStandard {
    /// Returns the minimum audit retention period in days for this standard.
    pub fn min_retention_days(&self) -> u32 {
        match self {
            ComplianceStandard::None => 7,
            ComplianceStandard::Soc2 => 365,
            ComplianceStandard::Hipaa => 2555, // 7 years
            ComplianceStandard::Gdpr => 730,   // 2 years
            ComplianceStandard::Enterprise => 2555,
        }
    }

    /// Returns whether PII anonymization is required.
    pub fn requires_pii_anonymization(&self) -> bool {
        matches!(
            self,
            ComplianceStandard::Gdpr | ComplianceStandard::Hipaa | ComplianceStandard::Enterprise
        )
    }
}

/// Category of audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventCategory {
    /// Authentication and authorization events
    Security,
    /// User access and permission changes
    Access,
    /// Block execution events
    Execution,
    /// Storage operations
    Storage,
    /// Billing and pricing events
    Billing,
    /// Configuration changes
    Config,
    /// System health and performance
    System,
}

/// Severity level for audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    /// Informational events
    Info,
    /// Warning events
    Warn,
    /// Error events
    Error,
    /// Critical security events
    Critical,
}

/// Audit event retention configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRetention {
    /// Enable audit logging
    pub enabled: bool,

    /// Retention period in days (0 = infinite)
    pub retention_days: u32,

    /// Archive to cold storage after N days
    pub archive_after_days: Option<u32>,

    /// Compress audit logs
    pub compress: bool,

    /// Storage tier for audit logs
    pub storage_tier: String,

    /// Enable real-time streaming to external SIEM
    pub stream_to_siem: bool,

    /// SIEM endpoint (if streaming enabled)
    pub siem_endpoint: Option<String>,
}

impl Default for AuditRetention {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 90,
            archive_after_days: Some(30),
            compress: true,
            storage_tier: "truth".to_string(),
            stream_to_siem: false,
            siem_endpoint: None,
        }
    }
}

/// Main audit configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Compliance standard to enforce
    pub compliance_standard: ComplianceStandard,

    /// Event categories to audit
    pub enabled_categories: HashSet<AuditEventCategory>,

    /// Minimum severity to log
    pub min_severity: AuditSeverity,

    /// Include full request/response payloads
    pub log_payloads: bool,

    /// Anonymize PII in audit logs
    pub anonymize_pii: bool,

    /// Include stack traces in error events
    pub include_stack_traces: bool,

    /// Audit retention configuration
    pub retention: AuditRetention,

    /// Require cryptographic signing of audit logs
    pub sign_audit_logs: bool,

    /// Enable tamper-evident audit log chaining
    pub tamper_evident: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::default())
    }
}

impl AuditConfig {
    /// Creates default audit configuration for a profile.
    pub fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                compliance_standard: ComplianceStandard::None,
                enabled_categories: [AuditEventCategory::Security, AuditEventCategory::Execution]
                    .into_iter()
                    .collect(),
                min_severity: AuditSeverity::Warn,
                log_payloads: false,
                anonymize_pii: false,
                include_stack_traces: false,
                retention: AuditRetention {
                    enabled: true,
                    retention_days: 7,
                    archive_after_days: None,
                    compress: true,
                    storage_tier: "truth".to_string(),
                    stream_to_siem: false,
                    siem_endpoint: None,
                },
                sign_audit_logs: false,
                tamper_evident: false,
            },

            Profile::Standard => Self {
                compliance_standard: ComplianceStandard::Soc2,
                enabled_categories: [
                    AuditEventCategory::Security,
                    AuditEventCategory::Access,
                    AuditEventCategory::Execution,
                    AuditEventCategory::Billing,
                ]
                .into_iter()
                .collect(),
                min_severity: AuditSeverity::Info,
                log_payloads: false,
                anonymize_pii: true,
                include_stack_traces: true,
                retention: AuditRetention {
                    enabled: true,
                    retention_days: 365,
                    archive_after_days: Some(90),
                    compress: true,
                    storage_tier: "truth".to_string(),
                    stream_to_siem: false,
                    siem_endpoint: None,
                },
                sign_audit_logs: true,
                tamper_evident: true,
            },

            Profile::Hyperscale => Self {
                compliance_standard: ComplianceStandard::Enterprise,
                enabled_categories: [
                    AuditEventCategory::Security,
                    AuditEventCategory::Access,
                    AuditEventCategory::Execution,
                    AuditEventCategory::Storage,
                    AuditEventCategory::Billing,
                    AuditEventCategory::Config,
                    AuditEventCategory::System,
                ]
                .into_iter()
                .collect(),
                min_severity: AuditSeverity::Info,
                log_payloads: true,
                anonymize_pii: true,
                include_stack_traces: true,
                retention: AuditRetention {
                    enabled: true,
                    retention_days: 2555, // 7 years
                    archive_after_days: Some(365),
                    compress: true,
                    storage_tier: "truth".to_string(),
                    stream_to_siem: true,
                    siem_endpoint: Some("https://siem.example.com/ingest".to_string()),
                },
                sign_audit_logs: true,
                tamper_evident: true,
            },

            Profile::Custom => Self {
                compliance_standard: ComplianceStandard::None,
                enabled_categories: HashSet::new(),
                min_severity: AuditSeverity::Info,
                log_payloads: false,
                anonymize_pii: false,
                include_stack_traces: false,
                retention: AuditRetention::default(),
                sign_audit_logs: false,
                tamper_evident: false,
            },
        }
    }

    /// Validates the audit configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Check retention meets compliance minimum
        let min_retention = self.compliance_standard.min_retention_days();
        if self.retention.enabled
            && self.retention.retention_days > 0
            && self.retention.retention_days < min_retention
        {
            return Err(format!(
                "Retention period ({} days) is less than minimum required for {:?} compliance ({} days)",
                self.retention.retention_days, self.compliance_standard, min_retention
            ));
        }

        // Check archive period is within retention
        if let Some(archive_days) = self.retention.archive_after_days
            && self.retention.retention_days > 0
            && archive_days > self.retention.retention_days
        {
            return Err(format!(
                "Archive period ({} days) exceeds retention period ({} days)",
                archive_days, self.retention.retention_days
            ));
        }

        // Check PII anonymization for GDPR/HIPAA
        if self.compliance_standard.requires_pii_anonymization() && !self.anonymize_pii {
            return Err(format!(
                "{:?} compliance requires PII anonymization",
                self.compliance_standard
            ));
        }

        // Check SIEM endpoint if streaming enabled
        if self.retention.stream_to_siem && self.retention.siem_endpoint.is_none() {
            return Err("SIEM streaming enabled but no endpoint configured".to_string());
        }

        // Check required categories for compliance
        let required_categories = self.required_categories_for_compliance();
        let missing: Vec<_> = required_categories
            .difference(&self.enabled_categories)
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "{:?} compliance requires audit categories: {:?}",
                self.compliance_standard, missing
            ));
        }

        Ok(())
    }

    /// Returns required audit categories for the current compliance standard.
    fn required_categories_for_compliance(&self) -> HashSet<AuditEventCategory> {
        match self.compliance_standard {
            ComplianceStandard::None => HashSet::new(),
            ComplianceStandard::Soc2 => [
                AuditEventCategory::Security,
                AuditEventCategory::Access,
                AuditEventCategory::Execution,
            ]
            .into_iter()
            .collect(),
            ComplianceStandard::Hipaa => [
                AuditEventCategory::Security,
                AuditEventCategory::Access,
                AuditEventCategory::Storage,
            ]
            .into_iter()
            .collect(),
            ComplianceStandard::Gdpr => [
                AuditEventCategory::Security,
                AuditEventCategory::Access,
                AuditEventCategory::Storage,
            ]
            .into_iter()
            .collect(),
            ComplianceStandard::Enterprise => [
                AuditEventCategory::Security,
                AuditEventCategory::Access,
                AuditEventCategory::Execution,
                AuditEventCategory::Storage,
                AuditEventCategory::Billing,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Checks if a specific event category is enabled.
    pub fn is_category_enabled(&self, category: AuditEventCategory) -> bool {
        self.enabled_categories.contains(&category)
    }

    /// Checks if an event with given severity should be logged.
    pub fn should_log_severity(&self, severity: AuditSeverity) -> bool {
        severity >= self.min_severity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_standard_retention_minimums() {
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
    fn test_audit_config_potato_defaults() {
        let config = AuditConfig::default_for_profile(Profile::Potato);

        assert_eq!(config.compliance_standard, ComplianceStandard::None);
        assert_eq!(config.enabled_categories.len(), 2);
        assert!(config.is_category_enabled(AuditEventCategory::Security));
        assert!(config.is_category_enabled(AuditEventCategory::Execution));
        assert_eq!(config.min_severity, AuditSeverity::Warn);
        assert!(!config.log_payloads);
        assert!(!config.anonymize_pii);
        assert_eq!(config.retention.retention_days, 7);
        assert!(!config.sign_audit_logs);
        assert!(!config.tamper_evident);
    }

    #[test]
    fn test_audit_config_standard_defaults() {
        let config = AuditConfig::default_for_profile(Profile::Standard);

        assert_eq!(config.compliance_standard, ComplianceStandard::Soc2);
        assert_eq!(config.enabled_categories.len(), 4);
        assert_eq!(config.min_severity, AuditSeverity::Info);
        assert!(config.anonymize_pii);
        assert_eq!(config.retention.retention_days, 365);
        assert!(config.sign_audit_logs);
        assert!(config.tamper_evident);
    }

    #[test]
    fn test_audit_config_hyperscale_defaults() {
        let config = AuditConfig::default_for_profile(Profile::Hyperscale);

        assert_eq!(config.compliance_standard, ComplianceStandard::Enterprise);
        assert_eq!(config.enabled_categories.len(), 7);
        assert!(config.log_payloads);
        assert!(config.anonymize_pii);
        assert_eq!(config.retention.retention_days, 2555);
        assert!(config.retention.stream_to_siem);
        assert!(config.retention.siem_endpoint.is_some());
        assert!(config.sign_audit_logs);
        assert!(config.tamper_evident);
    }

    #[test]
    fn test_validation_enforces_compliance_retention() {
        let mut config = AuditConfig::default_for_profile(Profile::Standard);
        config.compliance_standard = ComplianceStandard::Soc2;
        config.retention.retention_days = 30; // Too short for SOC2

        assert!(config.validate().is_err());
        assert!(
            config
                .validate()
                .unwrap_err()
                .contains("less than minimum required")
        );
    }

    #[test]
    fn test_validation_enforces_pii_anonymization() {
        let mut config = AuditConfig::default_for_profile(Profile::Standard);
        config.compliance_standard = ComplianceStandard::Gdpr;
        config.anonymize_pii = false;
        config.retention.retention_days = 730; // Meet GDPR retention minimum
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
    fn test_validation_enforces_required_categories() {
        let mut config = AuditConfig::default_for_profile(Profile::Standard);
        config.compliance_standard = ComplianceStandard::Soc2;
        config.enabled_categories.clear();

        assert!(config.validate().is_err());
        assert!(
            config
                .validate()
                .unwrap_err()
                .contains("requires audit categories")
        );
    }

    #[test]
    fn test_validation_checks_siem_endpoint() {
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
    fn test_severity_ordering() {
        assert!(AuditSeverity::Critical > AuditSeverity::Error);
        assert!(AuditSeverity::Error > AuditSeverity::Warn);
        assert!(AuditSeverity::Warn > AuditSeverity::Info);
    }

    #[test]
    fn test_should_log_severity() {
        let config = AuditConfig {
            min_severity: AuditSeverity::Warn,
            ..Default::default()
        };

        assert!(!config.should_log_severity(AuditSeverity::Info));
        assert!(config.should_log_severity(AuditSeverity::Warn));
        assert!(config.should_log_severity(AuditSeverity::Error));
        assert!(config.should_log_severity(AuditSeverity::Critical));
    }

    #[test]
    fn test_is_category_enabled() {
        let config = AuditConfig::default_for_profile(Profile::Standard);

        assert!(config.is_category_enabled(AuditEventCategory::Security));
        assert!(config.is_category_enabled(AuditEventCategory::Access));
        assert!(!config.is_category_enabled(AuditEventCategory::System));
    }

    #[test]
    fn test_serde_roundtrip() {
        let config = AuditConfig::default_for_profile(Profile::Hyperscale);
        let toml_str = toml::to_string(&config).expect("failed to serialize");
        let parsed: AuditConfig = toml::from_str(&toml_str).expect("failed to deserialize");

        assert_eq!(config.compliance_standard, parsed.compliance_standard);
        assert_eq!(config.enabled_categories, parsed.enabled_categories);
        assert_eq!(config.min_severity, parsed.min_severity);
    }
}
