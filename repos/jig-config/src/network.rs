//! Network configuration

use serde::{Deserialize, Serialize};

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Address to bind to
    pub bind_address: String,
    
    /// Public address for federation (if different from bind)
    pub public_address: Option<String>,
    
    /// Federation/HTTP API port
    pub federation_port: u16,
    
    /// IRC port
    pub irc_port: u16,
    
    /// SSH port
    pub ssh_port: u16,
    
    /// WebSocket port
    pub websocket_port: u16,
    
    /// Email SMTP port
    pub smtp_port: u16,
    
    /// TLS configuration
    pub tls: Option<TlsConfig>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".into(),
            public_address: None,
            federation_port: 7117,
            irc_port: 6667,
            ssh_port: 2222,
            websocket_port: 8080,
            smtp_port: 2525,
            tls: None,
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: String,
    
    /// Path to key file
    pub key_path: String,
    
    /// Enable TLS for federation
    pub federation_tls: bool,
    
    /// Enable TLS for WebSocket (WSS)
    pub websocket_tls: bool,
}