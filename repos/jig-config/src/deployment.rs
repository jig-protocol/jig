//! Deployment modes that affect default configuration

use serde::{Deserialize, Serialize};

/// Deployment mode determines default settings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    /// Optimized for <60 second first message
    /// - SQLite only
    /// - Anonymous by default
    /// - IRC enabled
    /// - Minimal features
    QuickStart,
    
    /// Development mode
    /// - All features enabled
    /// - Verbose logging
    /// - Hot reload
    Development,
    
    /// Production deployment
    /// - Security hardened
    /// - Performance optimized
    /// - Monitoring enabled
    Production,
    
    /// Custom configuration
    /// - No defaults applied
    Custom,
}

impl Default for DeploymentMode {
    fn default() -> Self {
        Self::QuickStart
    }
}

impl DeploymentMode {
    /// Get recommended features for this mode
    pub fn recommended_features(&self) -> crate::Features {
        match self {
            Self::QuickStart => crate::Features::minimal(),
            Self::Development => crate::Features::all(),
            Self::Production => crate::Features::production(),
            Self::Custom => crate::Features::none(),
        }
    }
    
    /// Get recommended network config
    pub fn recommended_network(&self) -> crate::NetworkConfig {
        match self {
            Self::QuickStart => crate::NetworkConfig {
                bind_address: "127.0.0.1".into(),
                public_address: None,
                ..Default::default()
            },
            Self::Development => crate::NetworkConfig {
                bind_address: "127.0.0.1".into(),
                public_address: None,
                ..Default::default()
            },
            Self::Production => crate::NetworkConfig {
                bind_address: "0.0.0.0".into(),
                public_address: None, // Should be set explicitly
                ..Default::default()
            },
            Self::Custom => crate::NetworkConfig::default(),
        }
    }
    
    /// Check if this mode should auto-start services
    pub fn auto_start(&self) -> bool {
        matches!(self, Self::QuickStart | Self::Development)
    }
}