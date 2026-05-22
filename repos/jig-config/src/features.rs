//! Feature flags for modular server composition

use serde::{Deserialize, Serialize};

/// Feature flags - the "lego blocks" approach
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Features {
    /// Core messaging (always on in production)
    pub core: bool,
    
    /// Federation support
    pub federation: bool,
    
    /// IRC bridge
    pub irc: bool,
    
    /// SSH transport
    pub ssh: bool,
    
    /// WebSocket API
    pub websocket: bool,
    
    /// Email bridge
    pub email: bool,
    
    /// Web UI
    pub web_ui: bool,
    
    /// Metrics/monitoring
    pub metrics: bool,
    
    /// Anonymous messaging
    pub anonymous: bool,
    
    /// End-to-end encryption
    pub encryption: bool,
}

impl Default for Features {
    fn default() -> Self {
        Self::minimal()
    }
}

impl Features {
    /// Minimal features for quickstart
    pub fn minimal() -> Self {
        Self {
            core: true,
            federation: false,
            irc: true,  // IRC for quick compatibility
            ssh: false,
            websocket: false,
            email: false,
            web_ui: false,
            metrics: false,
            anonymous: true,  // No auth required
            encryption: false,
        }
    }
    
    /// All features enabled (development)
    pub fn all() -> Self {
        Self {
            core: true,
            federation: true,
            irc: true,
            ssh: true,
            websocket: true,
            email: true,
            web_ui: true,
            metrics: true,
            anonymous: true,
            encryption: true,
        }
    }
    
    /// Production features
    pub fn production() -> Self {
        Self {
            core: true,
            federation: true,
            irc: true,
            ssh: false,  // Often not needed
            websocket: true,
            email: false,  // Optional
            web_ui: true,
            metrics: true,
            anonymous: false,  // Require auth
            encryption: true,
        }
    }
    
    /// No features (for custom builds)
    pub fn none() -> Self {
        Self {
            core: true,  // Core is always on
            federation: false,
            irc: false,
            ssh: false,
            websocket: false,
            email: false,
            web_ui: false,
            metrics: false,
            anonymous: false,
            encryption: false,
        }
    }
    
    /// Check if any transport is enabled
    pub fn has_transports(&self) -> bool {
        self.irc || self.ssh || self.websocket
    }
    
    /// Get list of enabled transports
    pub fn enabled_transports(&self) -> Vec<&'static str> {
        let mut transports = vec![];
        if self.irc { transports.push("irc"); }
        if self.ssh { transports.push("ssh"); }
        if self.websocket { transports.push("websocket"); }
        transports
    }
    
    /// Validate feature compatibility
    pub fn validate(&self) -> Result<(), String> {
        // Federation requires encryption
        if self.federation && !self.encryption {
            return Err("Federation requires encryption".into());
        }
        
        // Must have at least one transport
        if !self.has_transports() && !self.federation {
            return Err("At least one transport must be enabled".into());
        }
        
        Ok(())
    }
}