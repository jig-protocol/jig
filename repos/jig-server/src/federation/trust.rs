//! Trust relationship management (placeholder)

use serde::{Deserialize, Serialize};

/// Level of trust for a known server
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustLevel {
    Verified,
    Tofu,
    Untrusted,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Verified => "verified",
            TrustLevel::Tofu => "tofu",
            TrustLevel::Untrusted => "untrusted",
        }
    }
}
