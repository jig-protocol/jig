//! Configuration management

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub server: ServerSection,
    pub user: UserSection,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerSection {
    pub base_url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserSection {
    pub did: String,
    pub display_name: String,
    pub default_channel: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerSection {
                base_url: "http://127.0.0.1:7117".to_string(),
            },
            user: UserSection {
                did: format!("did:jig:{}", whoami::username()),
                display_name: whoami::username(),
                default_channel: "#general".to_string(),
            },
        }
    }
}

pub fn load_config(path: Option<&Path>) -> Result<Config> {
    let config_path = path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_config_path);

    if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path)?;
        Ok(toml::from_str(&contents)?)
    } else {
        Ok(Config::default())
    }
}

pub fn save_config(config: &Config, path: Option<&Path>) -> Result<()> {
    let config_path = path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_config_path);

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let contents = toml::to_string_pretty(config)?;
    std::fs::write(&config_path, contents)?;
    Ok(())
}

pub fn default_config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".jig")
        .join("config.toml")
}
