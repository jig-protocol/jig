//! Cross-Config Validation
//!
//! This module provides comprehensive validation across all configuration sections,
//! checking for required fields, range limits, and cross-section dependencies.
//!
//! ## Usage
//!
//! ```no_run
//! use jig_config::validation::ConfigValidator;
//!
//! let validator = ConfigValidator::new();
//! match validator.validate_all() {
//!     Ok(()) => println!("Configuration is valid"),
//!     Err(errors) => {
//!         for error in errors {
//!             eprintln!("Validation error: {}", error);
//!         }
//!     }
//! }
//! ```

use std::collections::HashSet;

/// Validation error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Section where the error occurred
    pub section: String,
    /// Field that caused the error
    pub field: Option<String>,
    /// Error message
    pub message: String,
    /// Error severity
    pub severity: Severity,
}

/// Error severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Warning - config will work but may not be optimal
    Warning,
    /// Error - config is invalid and must be fixed
    Error,
    /// Critical - config could cause data loss or security issues
    Critical,
}

impl ValidationError {
    /// Create a new error
    pub fn error(
        section: impl Into<String>,
        field: Option<impl Into<String>>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            section: section.into(),
            field: field.map(|f| f.into()),
            message: message.into(),
            severity: Severity::Error,
        }
    }

    /// Create a new warning
    pub fn warning(
        section: impl Into<String>,
        field: Option<impl Into<String>>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            section: section.into(),
            field: field.map(|f| f.into()),
            message: message.into(),
            severity: Severity::Warning,
        }
    }

    /// Create a new critical error
    pub fn critical(
        section: impl Into<String>,
        field: Option<impl Into<String>>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            section: section.into(),
            field: field.map(|f| f.into()),
            message: message.into(),
            severity: Severity::Critical,
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let severity = match self.severity {
            Severity::Warning => "WARNING",
            Severity::Error => "ERROR",
            Severity::Critical => "CRITICAL",
        };

        if let Some(field) = &self.field {
            write!(
                f,
                "[{}] {}.{}: {}",
                severity, self.section, field, self.message
            )
        } else {
            write!(f, "[{}] {}: {}", severity, self.section, self.message)
        }
    }
}

/// Configuration validator
pub struct ConfigValidator {
    errors: Vec<ValidationError>,
}

impl ConfigValidator {
    /// Create a new validator
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    /// Add an error
    fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    /// Check if there are any errors
    pub fn has_errors(&self) -> bool {
        self.errors.iter().any(|e| e.severity >= Severity::Error)
    }

    /// Check if there are any warnings
    pub fn has_warnings(&self) -> bool {
        self.errors.iter().any(|e| e.severity == Severity::Warning)
    }

    /// Get all errors
    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }

    /// Get errors of a specific severity or higher
    pub fn errors_at_least(&self, severity: Severity) -> Vec<&ValidationError> {
        self.errors
            .iter()
            .filter(|e| e.severity >= severity)
            .collect()
    }

    /// Return result with errors if any
    pub fn result(self) -> Result<(), Vec<ValidationError>> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }

    // ========================================================================
    // Runtime Validation
    // ========================================================================

    /// Validate runtime constraints are sensible
    pub fn validate_runtime_constraints(
        &mut self,
        fuel_max: u64,
        memory_max_mb: u32,
        timeout_ms: u64,
    ) {
        // Fuel limits
        if fuel_max == 0 {
            self.add_error(ValidationError::error(
                "runtime.constraints",
                Some("fuel_max"),
                "fuel_max must be greater than 0",
            ));
        }

        if fuel_max > 1_000_000_000 {
            self.add_error(ValidationError::warning(
                "runtime.constraints",
                Some("fuel_max"),
                format!("fuel_max ({fuel_max}) is very high, may cause performance issues"),
            ));
        }

        // Memory limits
        if memory_max_mb == 0 {
            self.add_error(ValidationError::error(
                "runtime.constraints",
                Some("memory_max_mb"),
                "memory_max_mb must be greater than 0",
            ));
        }

        if memory_max_mb > 4096 {
            self.add_error(ValidationError::warning(
                "runtime.constraints",
                Some("memory_max_mb"),
                format!(
                    "memory_max_mb ({memory_max_mb}) is very high, consider chunking large data"
                ),
            ));
        }

        // Timeout limits
        if timeout_ms == 0 {
            self.add_error(ValidationError::error(
                "runtime.constraints",
                Some("execution_timeout_ms"),
                "execution_timeout_ms must be greater than 0",
            ));
        }

        if timeout_ms < 50 {
            self.add_error(ValidationError::warning(
                "runtime.constraints",
                Some("execution_timeout_ms"),
                format!("execution_timeout_ms ({timeout_ms}) is very low, may cause timeouts"),
            ));
        }

        if timeout_ms > 60_000 {
            self.add_error(ValidationError::warning(
                "runtime.constraints",
                Some("execution_timeout_ms"),
                format!("execution_timeout_ms ({timeout_ms}) is very high (>1 minute)"),
            ));
        }
    }

    // ========================================================================
    // Storage Validation
    // ========================================================================

    /// Validate storage configuration
    pub fn validate_storage(
        &mut self,
        backend: &str,
        path: Option<&str>,
        connection_string: Option<&str>,
    ) {
        match backend {
            "sqlite" => {
                if path.is_none() {
                    self.add_error(ValidationError::error(
                        "storage",
                        Some("path"),
                        "SQLite backend requires 'path' field",
                    ));
                }
            }
            "postgres" | "cockroachdb" => {
                if connection_string.is_none() {
                    self.add_error(ValidationError::error(
                        "storage",
                        Some("connection_string"),
                        format!("{backend} backend requires 'connection_string' field"),
                    ));
                }
            }
            "scylladb" => {
                // ScyllaDB validated elsewhere (contact_points)
            }
            "s3" => {
                // S3 validated elsewhere (bucket, region)
            }
            _ => {
                self.add_error(ValidationError::error(
                    "storage",
                    Some("backend"),
                    format!("Unknown storage backend: {backend}"),
                ));
            }
        }
    }

    // ========================================================================
    // Analytics Validation
    // ========================================================================

    /// Validate analytics configuration
    pub fn validate_analytics(&mut self, backend: &str, retention_days: u32, sample_rate: f64) {
        // Backend validation
        match backend {
            "duckdb" | "parquet" | "clickhouse" | "disabled" => {}
            _ => {
                self.add_error(ValidationError::error(
                    "analytics",
                    Some("backend"),
                    format!("Unknown analytics backend: {backend}"),
                ));
            }
        }

        // Retention validation
        if retention_days == 0 {
            self.add_error(ValidationError::warning(
                "analytics",
                Some("retention_days"),
                "retention_days is 0, analytics will be deleted immediately",
            ));
        }

        if retention_days > 3650 {
            self.add_error(ValidationError::warning(
                "analytics",
                Some("retention_days"),
                format!("retention_days ({retention_days}) is very high (>10 years)"),
            ));
        }

        // Sample rate validation
        if !(0.0..=1.0).contains(&sample_rate) {
            self.add_error(ValidationError::error(
                "analytics",
                Some("sample_rate"),
                format!("sample_rate ({sample_rate}) must be between 0.0 and 1.0"),
            ));
        }
    }

    /// Validate telemetry configuration
    pub fn validate_telemetry(&mut self, trace_sampling: f64, log_level: &str) {
        // Trace sampling validation
        if !(0.0..=1.0).contains(&trace_sampling) {
            self.add_error(ValidationError::error(
                "telemetry",
                Some("trace_sampling"),
                format!("trace_sampling ({trace_sampling}) must be between 0.0 and 1.0"),
            ));
        }

        // Log level validation
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&log_level) {
            self.add_error(ValidationError::error(
                "telemetry",
                Some("log_level"),
                format!(
                    "log_level '{}' must be one of: {}",
                    log_level,
                    valid_levels.join(", ")
                ),
            ));
        }
    }

    // ========================================================================
    // Cross-Config Validation
    // ========================================================================

    /// Validate federation requires encryption
    pub fn validate_federation_requires_encryption(
        &mut self,
        federation_enabled: bool,
        encryption_enabled: bool,
    ) {
        if federation_enabled && !encryption_enabled {
            self.add_error(ValidationError::critical(
                "federation",
                None::<String>,
                "Federation requires encryption to be enabled (security requirement)",
            ));
        }
    }

    /// Validate bridges require appropriate storage
    pub fn validate_bridges_storage(&mut self, enabled_bridges: &[String], storage_backend: &str) {
        let high_throughput_bridges: HashSet<&str> = ["websocket", "federation", "activitypub"]
            .iter()
            .copied()
            .collect();

        let has_high_throughput = enabled_bridges
            .iter()
            .any(|b| high_throughput_bridges.contains(b.as_str()));

        if has_high_throughput && storage_backend == "sqlite" {
            self.add_error(ValidationError::warning(
                "bridges",
                None::<String>,
                format!(
                    "High-throughput bridges ({:?}) with SQLite may cause performance issues",
                    enabled_bridges
                        .iter()
                        .filter(|b| high_throughput_bridges.contains(b.as_str()))
                        .collect::<Vec<_>>()
                ),
            ));
        }
    }

    /// Validate hyperscale profile has appropriate backends
    pub fn validate_hyperscale_requirements(
        &mut self,
        profile: &str,
        analytics_backend: &str,
        storage_backend: &str,
    ) {
        if profile == "hyperscale" {
            if analytics_backend != "clickhouse" {
                self.add_error(ValidationError::warning(
                    "analytics",
                    Some("backend"),
                    format!(
                        "Hyperscale profile typically uses ClickHouse, but {analytics_backend} is configured"
                    ),
                ));
            }

            if storage_backend == "sqlite" {
                self.add_error(ValidationError::warning(
                    "storage",
                    Some("backend"),
                    "Hyperscale profile typically uses distributed storage (CockroachDB/ScyllaDB), but SQLite is configured",
                ));
            }
        }
    }

    /// Validate useful work requires nameserver
    pub fn validate_useful_work_requires_nameserver(
        &mut self,
        useful_work_enabled: bool,
        nameserver_url: Option<&str>,
    ) {
        if useful_work_enabled && nameserver_url.is_none() {
            self.add_error(ValidationError::error(
                "pricing",
                None::<String>,
                "Useful work discounts require a nameserver URL to be configured",
            ));
        }
    }

    /// Validate audit compliance requirements
    pub fn validate_audit_compliance(
        &mut self,
        compliance_standard: Option<&str>,
        retention_days: u32,
        anonymize_pii: bool,
    ) {
        if let Some(standard) = compliance_standard {
            match standard {
                "hipaa" => {
                    if retention_days < 2555 {
                        self.add_error(ValidationError::error(
                            "audit",
                            Some("retention_days"),
                            "HIPAA requires audit logs to be retained for at least 7 years (2555 days)",
                        ));
                    }
                    if !anonymize_pii {
                        self.add_error(ValidationError::critical(
                            "audit",
                            Some("anonymize_pii"),
                            "HIPAA requires PII to be anonymized in audit logs",
                        ));
                    }
                }
                "gdpr" => {
                    if !anonymize_pii {
                        self.add_error(ValidationError::warning(
                            "audit",
                            Some("anonymize_pii"),
                            "GDPR strongly recommends PII anonymization in audit logs",
                        ));
                    }
                }
                "soc2" => {
                    if retention_days < 365 {
                        self.add_error(ValidationError::error(
                            "audit",
                            Some("retention_days"),
                            "SOC 2 requires audit logs to be retained for at least 1 year (365 days)",
                        ));
                    }
                }
                _ => {}
            }
        }
    }
}

impl Default for ConfigValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_validation_zero_fuel() {
        let mut validator = ConfigValidator::new();
        validator.validate_runtime_constraints(0, 32, 250);
        assert!(validator.has_errors());
        assert!(
            validator
                .errors()
                .iter()
                .any(|e| e.field == Some("fuel_max".to_string()))
        );
    }

    #[test]
    fn test_runtime_validation_high_fuel_warning() {
        let mut validator = ConfigValidator::new();
        validator.validate_runtime_constraints(2_000_000_000, 32, 250);
        assert!(!validator.has_errors());
        assert!(validator.has_warnings());
    }

    #[test]
    fn test_storage_validation_sqlite_requires_path() {
        let mut validator = ConfigValidator::new();
        validator.validate_storage("sqlite", None, None);
        assert!(validator.has_errors());
    }

    #[test]
    fn test_storage_validation_postgres_requires_connection_string() {
        let mut validator = ConfigValidator::new();
        validator.validate_storage("postgres", None, None);
        assert!(validator.has_errors());
    }

    #[test]
    fn test_analytics_validation_sample_rate_bounds() {
        let mut validator = ConfigValidator::new();
        validator.validate_analytics("duckdb", 90, 1.5);
        assert!(validator.has_errors());
        assert!(
            validator
                .errors()
                .iter()
                .any(|e| e.field == Some("sample_rate".to_string()))
        );
    }

    #[test]
    fn test_telemetry_validation_invalid_log_level() {
        let mut validator = ConfigValidator::new();
        validator.validate_telemetry(0.1, "invalid");
        assert!(validator.has_errors());
    }

    #[test]
    fn test_federation_requires_encryption() {
        let mut validator = ConfigValidator::new();
        validator.validate_federation_requires_encryption(true, false);
        assert!(validator.has_errors());
        assert!(
            validator
                .errors()
                .iter()
                .any(|e| e.severity == Severity::Critical)
        );
    }

    #[test]
    fn test_bridges_storage_warning() {
        let mut validator = ConfigValidator::new();
        validator.validate_bridges_storage(&["websocket".to_string()], "sqlite");
        assert!(!validator.has_errors());
        assert!(validator.has_warnings());
    }

    #[test]
    fn test_hyperscale_requirements_warning() {
        let mut validator = ConfigValidator::new();
        validator.validate_hyperscale_requirements("hyperscale", "duckdb", "sqlite");
        assert!(!validator.has_errors());
        assert!(validator.has_warnings());
    }

    #[test]
    fn test_audit_compliance_hipaa() {
        let mut validator = ConfigValidator::new();
        validator.validate_audit_compliance(Some("hipaa"), 365, false);
        assert!(validator.has_errors());
        // Should have both retention and PII errors
        assert!(validator.errors().len() >= 2);
    }

    #[test]
    fn test_validation_error_display() {
        let error = ValidationError::error("test", Some("field"), "message");
        let display = format!("{}", error);
        assert!(display.contains("ERROR"));
        assert!(display.contains("test.field"));
        assert!(display.contains("message"));
    }

    #[test]
    fn test_errors_at_least_severity() {
        let mut validator = ConfigValidator::new();
        validator.add_error(ValidationError::warning("test", None::<String>, "warning"));
        validator.add_error(ValidationError::error("test", None::<String>, "error"));
        validator.add_error(ValidationError::critical(
            "test",
            None::<String>,
            "critical",
        ));

        let errors = validator.errors_at_least(Severity::Error);
        assert_eq!(errors.len(), 2); // error + critical
    }
}
