//! Federation support for Jig server

pub mod client;
pub mod discovery;
pub mod identity;
pub mod trust;

use serde::{Deserialize, Serialize};

/// Information exposed by Jig servers for federation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub version: String,
    pub server_id: String,
    pub public_key: String,
    pub endpoints: serde_json::Value,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}
