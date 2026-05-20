//! Bridge and interoperability configuration.
//!
//! Configures bidirectional bridges between Jig's deterministic Wasm block execution
//! and third-party systems (email, IRC, Slack, ActivityPub, etc.) while maintaining
//! security, fuel accounting, provenance, and determinism.

use crate::profiles::Profile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default privacy mode for exports.
fn default_privacy_mode() -> String {
    "anonymized".to_string()
}

/// Schema validation mode for ingesting external content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMode {
    /// Reject any content that doesn't match expected schema
    Strict,
    /// Accept content with extra fields, warn on missing fields
    Lenient,
    /// Accept any content (dangerous, use with caution)
    Disabled,
}

/// Content sanitization level for external inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SanitizationMode {
    /// Strip all potentially dangerous content (scripts, iframes, forms)
    Aggressive,
    /// Allow safe HTML subset, sanitize attributes
    Moderate,
    /// Only remove obviously malicious content
    Minimal,
    /// No sanitization (dangerous, external content is trusted)
    Disabled,
}

/// Render mode for exporting blocks to external systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderMode {
    /// Full content with all metadata
    Full,
    /// Summary/preview only
    Summary,
    /// Minimal output (link to block only)
    Minimal,
}

/// Export format for interoperability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// YAML (interop only, not canonical)
    Yaml,
    /// JSON (interop only, not canonical)
    Json,
    /// JCS (JSON Canonicalization Scheme - canonical format)
    Jcs,
    /// ActivityPub object
    ActivityPub,
    /// AT Protocol record
    AtProto,
    /// Plain text
    Text,
    /// HTML
    Html,
    /// Markdown
    Markdown,
}

impl ExportFormat {
    /// Returns whether this format is canonical (deterministic).
    pub fn is_canonical(&self) -> bool {
        matches!(self, ExportFormat::Jcs)
    }

    /// Returns the MIME type for this format.
    pub fn mime_type(&self) -> &'static str {
        match self {
            ExportFormat::Yaml => "application/yaml",
            ExportFormat::Json => "application/json",
            ExportFormat::Jcs => "application/json",
            ExportFormat::ActivityPub => "application/activity+json",
            ExportFormat::AtProto => "application/json",
            ExportFormat::Text => "text/plain",
            ExportFormat::Html => "text/html",
            ExportFormat::Markdown => "text/markdown",
        }
    }
}

/// Transform type for block content transformations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformType {
    /// Text to structured data (tasks, events, etc.)
    TextToStructured,
    /// Structured data to text
    StructuredToText,
    /// Text to audio (TTS)
    TextToAudio,
    /// Audio to text (STT)
    AudioToText,
    /// Text to video (with visuals)
    TextToVideo,
    /// Video to text (transcription + description)
    VideoToText,
    /// Image to text (OCR + description)
    ImageToText,
    /// Text to image (generation)
    TextToImage,
    /// Format conversion (e.g., Markdown → HTML)
    FormatConversion,
    /// Custom transform (Wasm block-defined)
    Custom(String),
}

/// Configuration for a single transform in the pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransformConfig {
    /// Transform type
    pub transform_type: TransformType,

    /// Fuel budget for this transform
    pub fuel_budget: u64,

    /// Maximum fuel allowed for this transform
    pub fuel_max: u64,

    /// Required capabilities for this transform
    pub required_capabilities: Vec<String>,

    /// Validate output determinism
    pub validate_determinism: bool,

    /// Preserve provenance metadata
    pub preserve_provenance: bool,
}

impl Default for TransformConfig {
    fn default() -> Self {
        Self {
            transform_type: TransformType::TextToStructured,
            fuel_budget: 100_000,
            fuel_max: 1_000_000,
            required_capabilities: Vec::new(),
            validate_determinism: true,
            preserve_provenance: true,
        }
    }
}

/// Ingest layer configuration for importing external content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngestConfig {
    /// Schema validation mode
    pub schema_validation: ValidationMode,

    /// Maximum content size in MB
    pub max_content_size_mb: u32,

    /// Allowed MIME types (empty = allow all)
    #[serde(default)]
    pub allowed_mime_types: Vec<String>,

    /// Content sanitization mode
    pub sanitization_mode: SanitizationMode,

    /// Mark external content as legacy source
    pub mark_legacy_source: bool,

    /// Transform pipeline for ingested content
    #[serde(default)]
    pub transform_pipeline: Vec<TransformConfig>,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            schema_validation: ValidationMode::Strict,
            max_content_size_mb: 10,
            allowed_mime_types: Vec::new(),
            sanitization_mode: SanitizationMode::Aggressive,
            mark_legacy_source: true,
            transform_pipeline: Vec::new(),
        }
    }
}

/// Block layer configuration for wrapping external content as blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockConfig {
    /// Default fuel budget for block wrapping
    pub fuel_budget_default: u64,

    /// Maximum fuel allowed for block wrapping
    pub fuel_budget_max: u64,

    /// Default capabilities (should be empty - zero ambient authority)
    #[serde(default)]
    pub default_capabilities: Vec<String>,

    /// Capability mapping: external action → required Jig capabilities
    #[serde(default)]
    pub capability_mapping: HashMap<String, Vec<String>>,
}

impl Default for BlockConfig {
    fn default() -> Self {
        Self {
            fuel_budget_default: 100_000,
            fuel_budget_max: 1_000_000,
            default_capabilities: Vec::new(),
            capability_mapping: HashMap::new(),
        }
    }
}

/// Export layer configuration for rendering blocks to external systems.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportConfig {
    /// Render mode
    pub render_mode: RenderMode,

    /// Include provenance metadata (block ID, signature)
    pub include_provenance: bool,

    /// Include receipt in export
    #[serde(default)]
    pub include_receipt: bool,

    /// Privacy mode for exported content
    #[serde(default = "default_privacy_mode")]
    pub privacy_mode: String,

    /// Transform pipeline for exported content
    #[serde(default)]
    pub transform_pipeline: Vec<TransformConfig>,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            render_mode: RenderMode::Full,
            include_provenance: true,
            include_receipt: false,
            privacy_mode: "anonymized".to_string(),
            transform_pipeline: Vec::new(),
        }
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Operations per hour per user
    pub rate_limit_per_user: u32,

    /// Global operations per hour
    pub rate_limit_global: u32,

    /// Minimum reputation tier required
    pub min_reputation_tier: String,

    /// Require verified identity for outbound operations
    pub require_verified_for_outbound: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_user: 100,
            rate_limit_global: 10_000,
            min_reputation_tier: "null_sec".to_string(),
            require_verified_for_outbound: false,
        }
    }
}

/// Monitoring configuration for observability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Log all incoming content
    pub log_all_ingress: bool,

    /// Log all outgoing renders
    pub log_all_egress: bool,

    /// Track fuel usage per operation
    pub track_fuel_usage: bool,

    /// Alert on anomalies
    pub alert_on_anomalies: bool,

    /// Analytics backend for metrics
    pub analytics_backend: String,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            log_all_ingress: true,
            log_all_egress: true,
            track_fuel_usage: true,
            alert_on_anomalies: true,
            analytics_backend: "duckdb".to_string(),
        }
    }
}

/// Generic bridge configuration (base for all bridge types).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Bridge enabled
    pub enabled: bool,

    /// Bridge schema version
    pub bridge_version: String,

    /// Ingest layer configuration
    #[serde(default)]
    pub ingest: IngestConfig,

    /// Block layer configuration
    #[serde(default)]
    pub block: BlockConfig,

    /// Export layer configuration
    #[serde(default)]
    pub export: ExportConfig,

    /// Rate limiting configuration
    #[serde(default)]
    pub limits: RateLimitConfig,

    /// Monitoring configuration
    #[serde(default)]
    pub monitoring: MonitoringConfig,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bridge_version: "1.0".to_string(),
            ingest: IngestConfig::default(),
            block: BlockConfig::default(),
            export: ExportConfig::default(),
            limits: RateLimitConfig::default(),
            monitoring: MonitoringConfig::default(),
        }
    }
}

impl BridgeConfig {
    /// Creates default bridge configuration for a profile.
    pub fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                enabled: false, // Bridges disabled by default in potato
                bridge_version: "1.0".to_string(),
                ingest: IngestConfig {
                    schema_validation: ValidationMode::Strict,
                    max_content_size_mb: 5,
                    sanitization_mode: SanitizationMode::Aggressive,
                    ..Default::default()
                },
                block: BlockConfig {
                    fuel_budget_default: 50_000,
                    fuel_budget_max: 500_000,
                    ..Default::default()
                },
                limits: RateLimitConfig {
                    rate_limit_per_user: 10,
                    rate_limit_global: 100,
                    ..Default::default()
                },
                monitoring: MonitoringConfig {
                    analytics_backend: "duckdb".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },

            Profile::Standard => Self {
                enabled: true,
                bridge_version: "1.0".to_string(),
                ingest: IngestConfig {
                    schema_validation: ValidationMode::Strict,
                    max_content_size_mb: 10,
                    sanitization_mode: SanitizationMode::Moderate,
                    ..Default::default()
                },
                block: BlockConfig {
                    fuel_budget_default: 100_000,
                    fuel_budget_max: 1_000_000,
                    ..Default::default()
                },
                limits: RateLimitConfig {
                    rate_limit_per_user: 100,
                    rate_limit_global: 10_000,
                    ..Default::default()
                },
                monitoring: MonitoringConfig {
                    analytics_backend: "duckdb".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },

            Profile::Hyperscale => Self {
                enabled: true,
                bridge_version: "1.0".to_string(),
                ingest: IngestConfig {
                    schema_validation: ValidationMode::Lenient,
                    max_content_size_mb: 50,
                    sanitization_mode: SanitizationMode::Moderate,
                    ..Default::default()
                },
                block: BlockConfig {
                    fuel_budget_default: 500_000,
                    fuel_budget_max: 5_000_000,
                    ..Default::default()
                },
                limits: RateLimitConfig {
                    rate_limit_per_user: 1000,
                    rate_limit_global: 100_000,
                    min_reputation_tier: "low_sec".to_string(),
                    require_verified_for_outbound: true,
                },
                monitoring: MonitoringConfig {
                    analytics_backend: "clickhouse".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },

            Profile::Custom => Self::default(),
        }
    }

    /// Validates the bridge configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Validate content size limits
        if self.ingest.max_content_size_mb == 0 {
            return Err("max_content_size_mb must be greater than 0".to_string());
        }

        // Validate fuel budgets
        if self.block.fuel_budget_default > self.block.fuel_budget_max {
            return Err(format!(
                "fuel_budget_default ({}) exceeds fuel_budget_max ({})",
                self.block.fuel_budget_default, self.block.fuel_budget_max
            ));
        }

        // Validate transform pipelines
        for transform in &self.ingest.transform_pipeline {
            if transform.fuel_budget > transform.fuel_max {
                return Err(format!(
                    "Transform fuel_budget ({}) exceeds fuel_max ({})",
                    transform.fuel_budget, transform.fuel_max
                ));
            }
        }

        for transform in &self.export.transform_pipeline {
            if transform.fuel_budget > transform.fuel_max {
                return Err(format!(
                    "Transform fuel_budget ({}) exceeds fuel_max ({})",
                    transform.fuel_budget, transform.fuel_max
                ));
            }
        }

        // Validate rate limits
        if self.limits.rate_limit_per_user == 0 {
            return Err("rate_limit_per_user must be greater than 0".to_string());
        }

        if self.limits.rate_limit_global == 0 {
            return Err("rate_limit_global must be greater than 0".to_string());
        }

        // Validate reputation tier
        let valid_tiers = ["null_sec", "low_sec", "high_sec", "verified"];
        if !valid_tiers.contains(&self.limits.min_reputation_tier.as_str()) {
            return Err(format!(
                "Invalid reputation tier: {}. Must be one of: {:?}",
                self.limits.min_reputation_tier, valid_tiers
            ));
        }

        Ok(())
    }

    /// Returns total fuel budget for a complete bridge operation (ingest + block + export).
    pub fn total_fuel_budget(&self) -> u64 {
        let ingest_fuel: u64 = self
            .ingest
            .transform_pipeline
            .iter()
            .map(|t| t.fuel_budget)
            .sum();

        let export_fuel: u64 = self
            .export
            .transform_pipeline
            .iter()
            .map(|t| t.fuel_budget)
            .sum();

        ingest_fuel + self.block.fuel_budget_default + export_fuel
    }
}

/// Export format configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportFormatConfig {
    /// Format enabled
    pub enabled: bool,

    /// Format is canonical (deterministic)
    pub canonical_format: bool,

    /// Include comments/documentation
    pub include_comments: bool,

    /// Include provenance metadata
    pub include_provenance: bool,

    /// Pretty-print output
    pub pretty_print: bool,
}

impl Default for ExportFormatConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            canonical_format: false,
            include_comments: false,
            include_provenance: true,
            pretty_print: true,
        }
    }
}

/// Multi-format export configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiFormatExportConfig {
    /// YAML export configuration
    pub yaml: ExportFormatConfig,

    /// JSON export configuration
    pub json: ExportFormatConfig,

    /// JCS (canonical JSON) export configuration
    pub jcs: ExportFormatConfig,

    /// ActivityPub export configuration
    pub activitypub: ExportFormatConfig,

    /// AT Protocol export configuration
    pub atproto: ExportFormatConfig,
}

impl Default for MultiFormatExportConfig {
    fn default() -> Self {
        Self {
            yaml: ExportFormatConfig {
                enabled: true,
                canonical_format: false,
                ..Default::default()
            },
            json: ExportFormatConfig {
                enabled: true,
                canonical_format: false,
                ..Default::default()
            },
            jcs: ExportFormatConfig {
                enabled: true,
                canonical_format: true,
                include_comments: false,
                ..Default::default()
            },
            activitypub: ExportFormatConfig {
                enabled: false,
                canonical_format: false,
                ..Default::default()
            },
            atproto: ExportFormatConfig {
                enabled: false,
                canonical_format: false,
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_format_canonical() {
        assert!(ExportFormat::Jcs.is_canonical());
        assert!(!ExportFormat::Yaml.is_canonical());
        assert!(!ExportFormat::Json.is_canonical());
        assert!(!ExportFormat::ActivityPub.is_canonical());
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
        assert_eq!(ExportFormat::Text.mime_type(), "text/plain");
        assert_eq!(ExportFormat::Html.mime_type(), "text/html");
        assert_eq!(ExportFormat::Markdown.mime_type(), "text/markdown");
    }

    #[test]
    fn test_bridge_config_potato_defaults() {
        let config = BridgeConfig::default_for_profile(Profile::Potato);

        assert!(!config.enabled); // Disabled by default
        assert_eq!(config.ingest.max_content_size_mb, 5);
        assert_eq!(config.ingest.schema_validation, ValidationMode::Strict);
        assert_eq!(
            config.ingest.sanitization_mode,
            SanitizationMode::Aggressive
        );
        assert_eq!(config.block.fuel_budget_default, 50_000);
        assert_eq!(config.limits.rate_limit_per_user, 10);
        assert_eq!(config.monitoring.analytics_backend, "duckdb");
    }

    #[test]
    fn test_bridge_config_standard_defaults() {
        let config = BridgeConfig::default_for_profile(Profile::Standard);

        assert!(config.enabled);
        assert_eq!(config.ingest.max_content_size_mb, 10);
        assert_eq!(config.ingest.sanitization_mode, SanitizationMode::Moderate);
        assert_eq!(config.block.fuel_budget_default, 100_000);
        assert_eq!(config.limits.rate_limit_per_user, 100);
    }

    #[test]
    fn test_bridge_config_hyperscale_defaults() {
        let config = BridgeConfig::default_for_profile(Profile::Hyperscale);

        assert!(config.enabled);
        assert_eq!(config.ingest.max_content_size_mb, 50);
        assert_eq!(config.ingest.schema_validation, ValidationMode::Lenient);
        assert_eq!(config.block.fuel_budget_default, 500_000);
        assert_eq!(config.limits.rate_limit_per_user, 1000);
        assert_eq!(config.limits.min_reputation_tier, "low_sec");
        assert!(config.limits.require_verified_for_outbound);
        assert_eq!(config.monitoring.analytics_backend, "clickhouse");
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
    fn test_validation_rejects_zero_rate_limits() {
        let mut config = BridgeConfig::default();
        config.limits.rate_limit_per_user = 0;

        assert!(config.validate().is_err());

        config = BridgeConfig::default();
        config.limits.rate_limit_global = 0;

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_total_fuel_budget_calculation() {
        let mut config = BridgeConfig::default();
        config.block.fuel_budget_default = 100_000;

        config.ingest.transform_pipeline.push(TransformConfig {
            fuel_budget: 50_000,
            ..Default::default()
        });

        config.export.transform_pipeline.push(TransformConfig {
            fuel_budget: 30_000,
            ..Default::default()
        });

        assert_eq!(config.total_fuel_budget(), 180_000);
    }

    #[test]
    fn test_transform_config_defaults() {
        let transform = TransformConfig::default();

        assert_eq!(transform.fuel_budget, 100_000);
        assert_eq!(transform.fuel_max, 1_000_000);
        assert!(transform.validate_determinism);
        assert!(transform.preserve_provenance);
    }

    #[test]
    fn test_validation_mode_serialization() {
        assert_eq!(
            serde_json::to_string(&ValidationMode::Strict).unwrap(),
            r#""strict""#
        );
        assert_eq!(
            serde_json::to_string(&ValidationMode::Lenient).unwrap(),
            r#""lenient""#
        );
        assert_eq!(
            serde_json::to_string(&ValidationMode::Disabled).unwrap(),
            r#""disabled""#
        );
    }

    #[test]
    fn test_sanitization_mode_serialization() {
        assert_eq!(
            serde_json::to_string(&SanitizationMode::Aggressive).unwrap(),
            r#""aggressive""#
        );
        assert_eq!(
            serde_json::to_string(&SanitizationMode::Moderate).unwrap(),
            r#""moderate""#
        );
        assert_eq!(
            serde_json::to_string(&SanitizationMode::Minimal).unwrap(),
            r#""minimal""#
        );
    }

    #[test]
    fn test_render_mode_serialization() {
        assert_eq!(
            serde_json::to_string(&RenderMode::Full).unwrap(),
            r#""full""#
        );
        assert_eq!(
            serde_json::to_string(&RenderMode::Summary).unwrap(),
            r#""summary""#
        );
        assert_eq!(
            serde_json::to_string(&RenderMode::Minimal).unwrap(),
            r#""minimal""#
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let config = BridgeConfig::default_for_profile(Profile::Hyperscale);
        let toml_str = toml::to_string(&config).expect("failed to serialize");
        let parsed: BridgeConfig = toml::from_str(&toml_str).expect("failed to deserialize");

        assert_eq!(config.enabled, parsed.enabled);
        assert_eq!(config.bridge_version, parsed.bridge_version);
        assert_eq!(
            config.ingest.schema_validation,
            parsed.ingest.schema_validation
        );
        assert_eq!(
            config.block.fuel_budget_default,
            parsed.block.fuel_budget_default
        );
    }
}
