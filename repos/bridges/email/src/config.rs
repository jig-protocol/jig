//! Configuration for email bridge

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub smtp_server: SmtpServerConfig,
    pub smtp_client: SmtpClientConfig,
    pub resend_client: ResendClientConfig,
    pub outbound_transport: OutboundTransport,
    pub formatting: FormattingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SmtpServerConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub port: u16,
    pub domain: String,
    pub require_tls: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum OutboundTransport {
    #[serde(rename = "smtp")]
    Smtp,
    #[serde(rename = "resend")]
    Resend,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SmtpClientConfig {
    pub enabled: bool,
    pub relay_host: String,
    pub relay_port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from_address: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResendClientConfig {
    pub enabled: bool,
    pub from_address: String,
    #[serde(default = "default_resend_api_env")]
    pub api_key_env: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FormattingConfig {
    pub signature: String,
    pub html_template: Option<String>,
    pub wrap_at: usize,
    /// Inject viral signature into outbound emails
    #[serde(default = "default_true")]
    pub add_signature: bool,
    /// Add X-Jig-Protocol header to outbound emails
    #[serde(default = "default_true")]
    pub add_x_jig_header: bool,
    /// Add Message-Id, In-Reply-To, and References thread headers
    #[serde(default = "default_true")]
    pub add_thread_headers: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            smtp_server: SmtpServerConfig {
                enabled: true,
                listen_addr: "127.0.0.1".to_string(),
                port: 2525,
                domain: "localhost".to_string(),
                require_tls: false,
            },
            smtp_client: SmtpClientConfig {
                enabled: false,
                relay_host: "smtp.gmail.com".to_string(),
                relay_port: 587,
                username: None,
                password: None,
                from_address: "jig@example.com".to_string(),
            },
            resend_client: ResendClientConfig {
                enabled: false,
                from_address: "jig@example.com".to_string(),
                api_key_env: default_resend_api_env(),
            },
            outbound_transport: OutboundTransport::Smtp,
            formatting: FormattingConfig {
                signature: "\n\n--\nSent via Jig Protocol - https://jig.onl".to_string(),
                html_template: None,
                wrap_at: 72,
                add_signature: true,
                add_x_jig_header: true,
                add_thread_headers: true,
            },
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_resend_api_env() -> String {
    "RESEND_API_KEY".to_string()
}

pub fn load_config(path: &Path) -> Result<Config> {
    if !path.exists() {
        let config = Config::default();
        let toml = toml::to_string_pretty(&config)?;
        std::fs::write(path, toml)?;
        return Ok(config);
    }

    let contents = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}
