use std::path::PathBuf;

pub mod tls;

// v0.0.2 hello-world server config (jig-server boot path)
pub mod v0_0_2_server;
pub use v0_0_2_server::{
    DebugSection, FederationPeer, FederationSection, IdentityMode, IdentitySection,
    JigServerConfig, ServerSection,
};

pub fn default_config_path() -> PathBuf {
    // Reuse CLI path convention: ~/.jig/config.toml
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".jig").join("config.toml")
}
