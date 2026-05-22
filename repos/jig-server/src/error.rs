//! Error types for Jig server

use thiserror::Error;

/// Server error type
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Core protocol error: {0}")]
    Protocol(#[from] jig_core::JigError),

    #[error("Runtime error: {0}")]
    Runtime(String),

    #[error("Capability denied: {0}")]
    CapabilityDenied(String),

    #[error("IRC protocol error: {0}")]
    IrcProtocol(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Server error: {0}")]
    Server(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, ServerError>;
