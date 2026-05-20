//! Analytics backend implementations and registry
//!
//! This module provides:
//! - Backend implementations (SQLite, DuckDB, Parquet)
//! - Backend registry for runtime selection
//! - Factory pattern for config-driven instantiation

pub mod duckdb;
pub mod parquet;
pub mod sqlite;

use crate::analytics::backend::{AnalyticsBackend, AnalyticsBackendFactory};
use crate::error::{NameServerError, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// Backend registry for runtime backend selection
pub struct BackendRegistry {
    factories: HashMap<String, Arc<dyn AnalyticsBackendFactory>>,
}

impl BackendRegistry {
    /// Create a new backend registry
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register a backend factory
    pub fn register<F: AnalyticsBackendFactory + 'static>(&mut self, factory: F) {
        let name = factory.name().to_string();
        self.factories.insert(name, Arc::new(factory));
    }

    /// Create a backend from config
    pub fn create(
        &self,
        backend_type: &str,
        config: &HashMap<String, String>,
    ) -> Result<Box<dyn AnalyticsBackend>> {
        let factory = self.factories.get(backend_type).ok_or_else(|| {
            NameServerError::Other(anyhow::anyhow!(
                "Unknown analytics backend: {}",
                backend_type
            ))
        })?;

        factory.create(config)
    }

    /// List available backend names
    pub fn list_backends(&self) -> Vec<String> {
        self.factories.keys().cloned().collect()
    }

    /// Check if a backend is registered
    pub fn has_backend(&self, backend_type: &str) -> bool {
        self.factories.contains_key(backend_type)
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Register all available backends (based on feature flags)
pub fn register_all_backends(_registry: &mut BackendRegistry) {
    // SQLite always available (Tier 1)
    // NOTE: SQLite requires storage reference, so it's created differently
    // _registry.register(sqlite::SqliteAnalyticsFactory);

    // DuckDB available with tier2-analytics feature
    #[cfg(feature = "tier2-analytics")]
    _registry.register(duckdb::DuckDBAnalyticsFactory);

    // Parquet available with tier2-analytics feature
    #[cfg(feature = "tier2-analytics")]
    _registry.register(parquet::ParquetExporterFactory);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = BackendRegistry::new();
        assert_eq!(registry.list_backends().len(), 0);
    }

    #[test]
    fn test_register_all_backends() {
        let mut registry = BackendRegistry::new();
        register_all_backends(&mut registry);

        // Tier 1 always available (but SQLite handled separately)
        // assert!(registry.has_backend("sqlite"));

        // Tier 2 only available with feature flag
        #[cfg(feature = "tier2-analytics")]
        {
            assert!(registry.has_backend("duckdb"));
            assert!(registry.has_backend("parquet"));
        }

        #[cfg(not(feature = "tier2-analytics"))]
        {
            assert!(!registry.has_backend("duckdb"));
            assert!(!registry.has_backend("parquet"));
        }
    }

    #[test]
    fn test_unknown_backend() {
        let registry = BackendRegistry::new();
        let config = HashMap::new();
        let result = registry.create("nonexistent", &config);
        assert!(result.is_err());
    }
}
