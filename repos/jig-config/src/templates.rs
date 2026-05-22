//! Configuration Template Generation
//!
//! This module provides template generation for jig-config configurations across
//! all profiles. Templates include helpful comments explaining each section.
//!
//! ## Usage
//!
//! ```no_run
//! use jig_config::templates::TemplateGenerator;
//! use jig_config::profiles::Profile;
//!
//! // Generate a complete potato profile template
//! let template = TemplateGenerator::new()
//!     .profile(Profile::Potato)
//!     .full(true)
//!     .generate();
//!
//! println!("{}", template);
//! ```

use crate::profiles::Profile;

/// Template generation options
#[derive(Debug, Clone)]
pub struct TemplateGenerator {
    profile: Profile,
    full: bool,
    include_comments: bool,
    include_examples: bool,
}

impl TemplateGenerator {
    /// Create a new template generator with defaults
    pub fn new() -> Self {
        Self {
            profile: Profile::Potato,
            full: false,
            include_comments: true,
            include_examples: false,
        }
    }

    /// Set the profile to generate
    pub fn profile(mut self, profile: Profile) -> Self {
        self.profile = profile;
        self
    }

    /// Set whether to generate a full template with all fields
    pub fn full(mut self, full: bool) -> Self {
        self.full = full;
        self
    }

    /// Set whether to include explanatory comments
    pub fn include_comments(mut self, include: bool) -> Self {
        self.include_comments = include;
        self
    }

    /// Set whether to include example values
    pub fn include_examples(mut self, include: bool) -> Self {
        self.include_examples = include;
        self
    }

    /// Generate the TOML configuration template
    pub fn generate(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&self.generate_header());

        // Meta section
        output.push_str(&self.generate_meta());

        if self.full {
            // Full configuration with all sections
            output.push_str(&self.generate_runtime());
            output.push_str(&self.generate_storage());
            output.push_str(&self.generate_receipts());
            output.push_str(&self.generate_pricing());
            output.push_str(&self.generate_nameserver());
            output.push_str(&self.generate_analytics());
            output.push_str(&self.generate_audit());
            output.push_str(&self.generate_export());
            output.push_str(&self.generate_bridges());
        } else {
            // Minimal configuration
            output.push_str(
                "\n# For full configuration options, use: jig-config generate --profile ",
            );
            output.push_str(&format!(
                "{} --full\n",
                self.profile.to_string().to_lowercase()
            ));
        }

        output
    }

    fn generate_header(&self) -> String {
        let profile_name = match self.profile {
            Profile::Potato => "Potato Profile (Default)",
            Profile::Standard => "Standard Profile",
            Profile::Hyperscale => "Hyperscale Profile",
            Profile::Custom => "Custom Profile",
        };

        let description = match self.profile {
            Profile::Potato => {
                "Optimized for <60 second first message. SQLite only, minimal features, tight limits."
            }
            Profile::Standard => {
                "Balanced for production use. Postgres/Parquet, moderate features, standard limits."
            }
            Profile::Hyperscale => {
                "Optimized for scale. Multi-tier storage, all features, generous limits."
            }
            Profile::Custom => "Custom configuration. Define your own settings.",
        };

        format!(
            "# jig-config.toml - {}\n#\n# {}\n#\n# Generated: {}\n\n",
            profile_name,
            description,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        )
    }

    fn generate_meta(&self) -> String {
        let profile_str = self.profile.to_string().to_lowercase();

        if self.include_comments {
            if self.profile == Profile::Potato {
                "[meta]\n# Profile selection\n# profile = \"potato\"  # Default, can be omitted\n\n"
                    .to_string()
            } else {
                format!("[meta]\n# Profile selection\nprofile = \"{profile_str}\"\n\n")
            }
        } else {
            format!("[meta]\nprofile = \"{profile_str}\"\n\n")
        }
    }

    fn generate_runtime(&self) -> String {
        let (fuel, memory, timeout) = match self.profile {
            Profile::Potato => (1_000_000, 32, 250),
            Profile::Standard => (10_000_000, 64, 500),
            Profile::Hyperscale => (50_000_000, 128, 1000),
            Profile::Custom => (5_000_000, 64, 500),
        };

        let mut section = String::from(
            "# ============================================================================\n",
        );
        section.push_str("# Runtime Configuration\n");
        section.push_str(
            "# ============================================================================\n\n",
        );

        section.push_str("[runtime.constraints]\n");
        if self.include_comments {
            section.push_str(&format!("fuel_max = {fuel}  # Max fuel (instructions)\n"));
            section.push_str(&format!(
                "memory_max_mb = {memory}  # Max linear memory (MB)\n"
            ));
            section.push_str(&format!(
                "execution_timeout_ms = {timeout}  # Wall-clock timeout (ms)\n"
            ));
            section.push_str("deterministic = true  # Enforce determinism\n\n");
        } else {
            section.push_str(&format!("fuel_max = {fuel}\n"));
            section.push_str(&format!("memory_max_mb = {memory}\n"));
            section.push_str(&format!("execution_timeout_ms = {timeout}\n"));
            section.push_str("deterministic = true\n\n");
        }

        section.push_str("[runtime.determinism]\n");
        if self.include_comments {
            section.push_str("float_policy = \"deny\"  # deny | allow | deterministic\n");
            section.push_str("prng_seed_source = \"manifest\"  # manifest | host | mixed\n\n");
        } else {
            section.push_str("float_policy = \"deny\"\n");
            section.push_str("prng_seed_source = \"manifest\"\n\n");
        }

        if self.include_examples {
            section.push_str("# Forbidden imports (always denied)\n");
            section.push_str("forbidden_imports = [\n");
            section.push_str("    \"wasi_snapshot_preview1::random_get\",\n");
            section.push_str("    \"wasi_snapshot_preview1::clock_time_get\",\n");
            section.push_str("]\n\n");
        }

        section
    }

    fn generate_storage(&self) -> String {
        let mut section = String::from(
            "# ============================================================================\n",
        );
        section.push_str("# Storage Configuration\n");
        section.push_str(
            "# ============================================================================\n\n",
        );

        match self.profile {
            Profile::Potato => {
                section.push_str("[storage]\n");
                if self.include_comments {
                    section.push_str("backend = \"sqlite\"  # Single-tier storage\n");
                    section.push_str("path = \"~/.jig/jig.db\"\n");
                    section.push_str("max_connections = 10\n");
                    section.push_str("wal_mode = true  # Write-ahead logging\n\n");
                } else {
                    section.push_str("backend = \"sqlite\"\n");
                    section.push_str("path = \"~/.jig/jig.db\"\n");
                    section.push_str("max_connections = 10\n");
                    section.push_str("wal_mode = true\n\n");
                }
            }
            Profile::Standard => {
                section.push_str("[storage.truth]\n");
                if self.include_comments {
                    section.push_str("backend = \"postgres\"  # Truth layer\n");
                    section.push_str("connection_string = \"postgres://localhost/jig\"\n");
                    section.push_str("max_connections = 20\n\n");
                } else {
                    section.push_str("backend = \"postgres\"\n");
                    section.push_str("connection_string = \"postgres://localhost/jig\"\n");
                    section.push_str("max_connections = 20\n\n");
                }
            }
            Profile::Hyperscale => {
                section.push_str("[storage.truth]\n");
                section.push_str("backend = \"cockroachdb\"\n");
                section.push_str("connection_string = \"postgres://...\"\n\n");

                section.push_str("[storage.speed]\n");
                section.push_str("backend = \"scylladb\"\n");
                section.push_str("contact_points = [\"10.0.0.1:9042\"]\n\n");

                section.push_str("[storage.intelligence]\n");
                section.push_str("backend = \"clickhouse\"\n");
                section.push_str("connection_string = \"tcp://...\"\n\n");

                section.push_str("[storage.archive]\n");
                section.push_str("backend = \"s3\"\n");
                section.push_str("bucket = \"jig-blocks\"\n");
                section.push_str("region = \"us-east-1\"\n\n");
            }
            Profile::Custom => {
                section.push_str("[storage]\n");
                section.push_str("# Choose your storage backend\n");
                section.push_str("backend = \"sqlite\"  # or postgres, cockroachdb, etc.\n\n");
            }
        }

        section
    }

    fn generate_receipts(&self) -> String {
        let mut section = String::from(
            "# ============================================================================\n",
        );
        section.push_str("# Receipt Configuration\n");
        section.push_str(
            "# ============================================================================\n\n",
        );

        section.push_str("[receipts]\n");
        if self.include_comments {
            section.push_str("schema_version = \"0.2\"  # Receipt v0.2\n");
            section.push_str("canonical_format = \"jcs\"  # JSON Canonicalization Scheme\n\n");
        } else {
            section.push_str("schema_version = \"0.2\"\n");
            section.push_str("canonical_format = \"jcs\"\n\n");
        }

        section
    }

    fn generate_pricing(&self) -> String {
        let mut section = String::from(
            "# ============================================================================\n",
        );
        section.push_str("# Pricing Configuration\n");
        section.push_str(
            "# ============================================================================\n\n",
        );

        let model = match self.profile {
            Profile::Potato => "free",
            Profile::Standard => "outcome_based",
            Profile::Hyperscale => "outcome_based",
            Profile::Custom => "outcome_based",
        };

        section.push_str("[pricing]\n");
        if self.include_comments {
            section.push_str(&format!(
                "model = \"{model}\"  # free | outcome_based | fixed\n\n"
            ));
        } else {
            section.push_str(&format!("model = \"{model}\"\n\n"));
        }

        if self.profile != Profile::Potato && self.include_examples {
            section.push_str("[[pricing.fuel_bands]]\n");
            section.push_str("capability_type = \"cpu\"\n");
            section.push_str("cost_per_million = 0.001\n\n");
        }

        section
    }

    fn generate_nameserver(&self) -> String {
        if self.profile == Profile::Potato {
            return String::new(); // Nameserver typically not used in potato
        }

        let mut section = String::from(
            "# ============================================================================\n",
        );
        section.push_str("# Nameserver & Federation Configuration\n");
        section.push_str(
            "# ============================================================================\n\n",
        );

        section.push_str("[federation]\n");
        section.push_str("mode = \"isolated\"  # isolated | shared_ruleset | federated\n");
        section.push_str("enabled = false\n\n");

        section
    }

    fn generate_analytics(&self) -> String {
        let mut section = String::from(
            "# ============================================================================\n",
        );
        section.push_str("# Analytics & Telemetry Configuration\n");
        section.push_str(
            "# ============================================================================\n\n",
        );

        let (backend, retention, sample_rate) = match self.profile {
            Profile::Potato => ("duckdb", 30, 0.1),
            Profile::Standard => ("parquet", 90, 0.5),
            Profile::Hyperscale => ("clickhouse", 365, 1.0),
            Profile::Custom => ("duckdb", 90, 0.5),
        };

        section.push_str("[analytics]\n");
        if self.include_comments {
            section.push_str(&format!(
                "backend = \"{backend}\"  # duckdb | parquet | clickhouse\n"
            ));
            section.push_str(&format!(
                "retention_days = {retention}  # Data retention period\n"
            ));
            section.push_str(&format!(
                "sample_rate = {sample_rate}  # Sampling rate (0.0-1.0)\n"
            ));
            section.push_str("privacy_mode = \"anonymized\"  # anonymized | aggregated | full\n\n");
        } else {
            section.push_str(&format!("backend = \"{backend}\"\n"));
            section.push_str(&format!("retention_days = {retention}\n"));
            section.push_str(&format!("sample_rate = {sample_rate}\n"));
            section.push_str("privacy_mode = \"anonymized\"\n\n");
        }

        let trace_sampling = match self.profile {
            Profile::Potato => 0.01,
            Profile::Standard => 0.1,
            Profile::Hyperscale => 1.0,
            Profile::Custom => 0.1,
        };

        section.push_str("[telemetry]\n");
        if self.include_comments {
            section.push_str("metrics_enabled = true\n");
            section.push_str(&format!(
                "trace_sampling = {trace_sampling}  # Tracing sample rate\n"
            ));
            section.push_str("log_level = \"info\"  # trace | debug | info | warn | error\n\n");
        } else {
            section.push_str("metrics_enabled = true\n");
            section.push_str(&format!("trace_sampling = {trace_sampling}\n"));
            section.push_str("log_level = \"info\"\n\n");
        }

        section
    }

    fn generate_audit(&self) -> String {
        if self.profile == Profile::Potato {
            return String::new(); // Minimal auditing in potato
        }

        let mut section = String::from(
            "# ============================================================================\n",
        );
        section.push_str("# Audit & Compliance Configuration\n");
        section.push_str(
            "# ============================================================================\n\n",
        );

        section.push_str("[audit]\n");
        section.push_str("enabled = true\n");
        section.push_str("retention_days = 90\n");
        section.push_str("categories = [\"security\", \"access\", \"data_changes\"]\n\n");

        section
    }

    fn generate_export(&self) -> String {
        let mut section = String::from(
            "# ============================================================================\n",
        );
        section.push_str("# Export Configuration\n");
        section.push_str(
            "# ============================================================================\n\n",
        );

        section.push_str("[export.jcs]\n");
        section.push_str("enabled = true\n");
        section.push_str("canonical_format = true\n\n");

        section
    }

    fn generate_bridges(&self) -> String {
        if self.profile == Profile::Potato {
            return String::new(); // Minimal bridges in potato
        }

        let mut section = String::from(
            "# ============================================================================\n",
        );
        section.push_str("# Bridge Configuration\n");
        section.push_str(
            "# ============================================================================\n\n",
        );

        section.push_str("[bridges]\n");
        section.push_str("enabled = []  # Available: irc, websocket, email, federation\n\n");

        section
    }
}

impl Default for TemplateGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a minimal template for the specified profile
pub fn generate_minimal(profile: Profile) -> String {
    TemplateGenerator::new()
        .profile(profile)
        .full(false)
        .generate()
}

/// Generate a full template for the specified profile
pub fn generate_full(profile: Profile) -> String {
    TemplateGenerator::new()
        .profile(profile)
        .full(true)
        .include_examples(true)
        .generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_minimal_potato() {
        let template = generate_minimal(Profile::Potato);
        assert!(template.contains("[meta]"));
        assert!(template.contains("Potato Profile"));
        assert!(!template.contains("[runtime.constraints]"));
    }

    #[test]
    fn test_generate_full_potato() {
        let template = generate_full(Profile::Potato);
        assert!(template.contains("[meta]"));
        assert!(template.contains("[runtime.constraints]"));
        assert!(template.contains("[storage]"));
        assert!(template.contains("[analytics]"));
    }

    #[test]
    fn test_generate_full_standard() {
        let template = generate_full(Profile::Standard);
        assert!(template.contains("Standard Profile"));
        assert!(template.contains("[storage.truth]"));
        assert!(template.contains("postgres"));
    }

    #[test]
    fn test_generate_full_hyperscale() {
        let template = generate_full(Profile::Hyperscale);
        assert!(template.contains("Hyperscale Profile"));
        assert!(template.contains("[storage.truth]"));
        assert!(template.contains("[storage.speed]"));
        assert!(template.contains("[storage.intelligence]"));
        assert!(template.contains("[storage.archive]"));
    }

    #[test]
    fn test_template_generator_builder() {
        let template = TemplateGenerator::new()
            .profile(Profile::Standard)
            .full(true)
            .include_comments(false)
            .generate();

        assert!(template.contains("[meta]"));
        assert!(!template.contains("# Profile selection"));
    }

    #[test]
    fn test_template_includes_timestamp() {
        let template = generate_minimal(Profile::Potato);
        assert!(template.contains("Generated:"));
    }

    #[test]
    fn test_all_profiles_generate() {
        for profile in [
            Profile::Potato,
            Profile::Standard,
            Profile::Hyperscale,
            Profile::Custom,
        ] {
            let minimal = generate_minimal(profile);
            let full = generate_full(profile);

            assert!(!minimal.is_empty());
            assert!(!full.is_empty());
            assert!(full.len() > minimal.len());
        }
    }
}
