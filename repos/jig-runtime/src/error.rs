use jig_core::error::JigError;
use thiserror::Error;

/// Result type alias for jig-runtime operations
pub type Result<T> = std::result::Result<T, RuntimeError>;

/// Comprehensive error taxonomy for runtime operations
///
/// Each variant maps to a specific receipt outcome for deterministic error reporting.
#[derive(Error, Debug)]
pub enum RuntimeError {
    // Validation errors (before execution)
    #[error("Module validation failed: {0}")]
    ValidationError(String),

    #[error("Invalid WASM bytecode: {0}")]
    InvalidWasm(String),

    #[error("Unsupported WASM feature: {0}")]
    UnsupportedFeature(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    // Execution errors
    #[error("Execution failed: {0}")]
    ExecutionError(String),

    #[error("Trap during execution: {0}")]
    Trap(String),

    #[error("Module instantiation failed: {0}")]
    InstantiationError(String),

    // Resource limit errors
    #[error("Fuel limit exceeded: used {used}, limit {limit}")]
    FuelExhausted { used: u64, limit: u64 },

    #[error("Memory limit exceeded: peak {peak_mb}MB, limit {limit_mb}MB")]
    MemoryExhausted { peak_mb: u32, limit_mb: u32 },

    #[error("Execution timeout: {timeout_ms}ms")]
    TimeoutExceeded { timeout_ms: u64 },

    // Capability errors
    #[error("Capability denied: {capability}")]
    CapabilityDenied { capability: String },

    #[error("Capability not found: {capability}")]
    CapabilityNotFound { capability: String },

    #[error("Capability quota exceeded: {capability}")]
    CapabilityQuotaExceeded { capability: String },

    #[error("Invalid capability handle")]
    InvalidCapabilityHandle,

    // I/O and system errors
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    // Internal errors
    #[error("Internal runtime error: {0}")]
    InternalError(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

impl RuntimeError {
    /// Maps error to receipt outcome status
    pub fn outcome_status(&self) -> &'static str {
        match self {
            RuntimeError::ValidationError(_)
            | RuntimeError::InvalidWasm(_)
            | RuntimeError::UnsupportedFeature(_)
            | RuntimeError::InvalidConfig(_) => "validation_failed",

            RuntimeError::FuelExhausted { .. }
            | RuntimeError::MemoryExhausted { .. }
            | RuntimeError::TimeoutExceeded { .. } => "limits_exceeded",

            RuntimeError::CapabilityDenied { .. }
            | RuntimeError::CapabilityNotFound { .. }
            | RuntimeError::CapabilityQuotaExceeded { .. }
            | RuntimeError::InvalidCapabilityHandle => "capability_error",

            RuntimeError::ExecutionError(_)
            | RuntimeError::Trap(_)
            | RuntimeError::InstantiationError(_) => "execution_failed",

            RuntimeError::IoError(_) | RuntimeError::SerializationError(_) => "io_error",

            RuntimeError::InternalError(_) | RuntimeError::NotImplemented(_) => "internal_error",
        }
    }

    /// Returns machine-readable error code for receipts
    pub fn error_code(&self) -> &'static str {
        match self {
            RuntimeError::ValidationError(_) => "ERR_VALIDATION",
            RuntimeError::InvalidWasm(_) => "ERR_INVALID_WASM",
            RuntimeError::UnsupportedFeature(_) => "ERR_UNSUPPORTED",
            RuntimeError::InvalidConfig(_) => "ERR_CONFIG",
            RuntimeError::ExecutionError(_) => "ERR_EXECUTION",
            RuntimeError::Trap(_) => "ERR_TRAP",
            RuntimeError::InstantiationError(_) => "ERR_INSTANTIATION",
            RuntimeError::FuelExhausted { .. } => "ERR_FUEL_EXHAUSTED",
            RuntimeError::MemoryExhausted { .. } => "ERR_MEMORY_EXHAUSTED",
            RuntimeError::TimeoutExceeded { .. } => "ERR_TIMEOUT",
            RuntimeError::CapabilityDenied { .. } => "ERR_CAPABILITY_DENIED",
            RuntimeError::CapabilityNotFound { .. } => "ERR_CAPABILITY_NOT_FOUND",
            RuntimeError::CapabilityQuotaExceeded { .. } => "ERR_QUOTA_EXCEEDED",
            RuntimeError::InvalidCapabilityHandle => "ERR_INVALID_HANDLE",
            RuntimeError::IoError(_) => "ERR_IO",
            RuntimeError::SerializationError(_) => "ERR_SERIALIZATION",
            RuntimeError::InternalError(_) => "ERR_INTERNAL",
            RuntimeError::NotImplemented(_) => "ERR_NOT_IMPLEMENTED",
        }
    }
}

// Conversion helpers
impl From<serde_json::Error> for RuntimeError {
    fn from(err: serde_json::Error) -> Self {
        RuntimeError::SerializationError(err.to_string())
    }
}

impl From<toml::de::Error> for RuntimeError {
    fn from(err: toml::de::Error) -> Self {
        RuntimeError::SerializationError(err.to_string())
    }
}

impl From<JigError> for RuntimeError {
    fn from(err: JigError) -> Self {
        match err {
            // Validation errors should map to ValidationError
            JigError::Validation(_) => RuntimeError::ValidationError(err.to_string()),
            // Other JigErrors are typically serialization/parsing issues
            _ => RuntimeError::SerializationError(err.to_string()),
        }
    }
}
