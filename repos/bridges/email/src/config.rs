//! Config parsed from the `[bridge.email.config]` TOML table.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct EmailBridgeConfig {
    /// Secret used to derive shadow-DID keypairs (HKDF salt/ikm). MUST be
    /// stable across restarts and kept private.
    pub bridge_secret: String,
    /// Domain the bridge sends from / receives for (e.g. "jig.onl").
    pub bridge_domain: String,
    /// Address-book cache TTL in seconds.
    #[serde(default = "default_addrbook_ttl")]
    pub addrbook_ttl_secs: i64,
    /// Strip `+tag` from local-parts when normalizing emails.
    #[serde(default)]
    pub strip_plus_tags: bool,
    /// Provider selection (only "resend" in v0.0.3).
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Resend API key (read from config; operators may use ${ENV} indirection
    /// at the deployment layer).
    pub resend_api_key: Option<String>,
    /// Resend webhook signing secret (verifies inbound POSTs).
    pub resend_webhook_secret: Option<String>,
    /// Nameserver base URL for alias resolution (address book).
    pub nameserver_url: Option<String>,
}

fn default_addrbook_ttl() -> i64 {
    3600
}
fn default_provider() -> String {
    "resend".to_string()
}

impl EmailBridgeConfig {
    pub fn from_toml(v: &toml::Value) -> anyhow::Result<Self> {
        Ok(v.clone().try_into()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let v: toml::Value = toml::toml! {
            bridge_secret = "s3cr3t"
            bridge_domain = "jig.onl"
            resend_api_key = "rk_test"
            resend_webhook_secret = "whsec_test"
            nameserver_url = "http://127.0.0.1:7200"
        }
        .into();
        let cfg = EmailBridgeConfig::from_toml(&v).unwrap();
        assert_eq!(cfg.bridge_domain, "jig.onl");
        assert_eq!(cfg.addrbook_ttl_secs, 3600); // default
        assert_eq!(cfg.provider, "resend"); // default
    }

    #[test]
    fn rejects_missing_required_fields() {
        // `bridge_secret` is required (non-Option); a config without it must
        // fail to parse rather than silently default.
        let v: toml::Value = toml::toml! {
            bridge_domain = "jig.onl"
        }
        .into();
        assert!(EmailBridgeConfig::from_toml(&v).is_err());
    }
}
