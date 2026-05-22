//! Error types for Jig protocol

use thiserror::Error;

/// Main error type for Jig protocol
#[derive(Error, Debug)]
pub enum JigError {
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found")]
    NotFound,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, JigError>;

impl From<serde_json::Error> for JigError {
    fn from(err: serde_json::Error) -> Self {
        JigError::Serialization(err.to_string())
    }
}

impl From<std::io::Error> for JigError {
    fn from(err: std::io::Error) -> Self {
        JigError::Storage(err.to_string())
    }
}
