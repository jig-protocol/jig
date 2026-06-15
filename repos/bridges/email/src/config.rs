//! Config parsed from the `[bridges.per_bridge.email.config]` TOML table.

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
    /// Resend API key. Use `${VAR}` to pull from the environment at startup so
    /// the deployed config.toml carries no plaintext secrets.
    pub resend_api_key: Option<String>,
    /// Resend webhook signing secret (verifies inbound POSTs). Supports
    /// `${VAR}` env-ref syntax same as `resend_api_key`.
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
    /// Parse config from a TOML value, resolving any whole-string `${VAR}`
    /// references in secret fields from the environment. Unset env vars are a
    /// hard error so the server fails fast at startup rather than running with
    /// blank secrets.
    pub fn from_toml(v: &toml::Value) -> anyhow::Result<Self> {
        let mut cfg: Self = v.clone().try_into()?;
        cfg.bridge_secret = resolve_env_ref(&cfg.bridge_secret)?;
        if let Some(k) = cfg.resend_api_key.take() {
            cfg.resend_api_key = Some(resolve_env_ref(&k)?);
        }
        if let Some(s) = cfg.resend_webhook_secret.take() {
            cfg.resend_webhook_secret = Some(resolve_env_ref(&s)?);
        }
        Ok(cfg)
    }
}

/// Resolve a whole-string `${VAR}` reference from the environment. Any other
/// value — including one that merely contains a `$` — is returned literally, so
/// baked configs and test fixtures are untouched. A well-formed `${VAR}` whose
/// variable is unset is a hard error (fail fast at startup, never run with a
/// blank secret).
fn resolve_env_ref(value: &str) -> anyhow::Result<String> {
    if let Some(inner) = value.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        let valid_name = !inner.is_empty()
            && inner
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if valid_name {
            return std::env::var(inner).map_err(|_| {
                anyhow::anyhow!(
                    "env var {inner} referenced by [bridges.per_bridge.email.config] is not set"
                )
            });
        }
    }
    Ok(value.to_string())
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

    #[test]
    fn expands_env_ref_in_secrets() {
        // SAFETY: cargo-nextest runs each test in its own process, so setting a
        // process-global env var here can't race other tests.
        unsafe { std::env::set_var("JIG_TEST_RESEND_KEY", "rk_live_xyz") };
        let v: toml::Value = toml::toml! {
            bridge_secret = "literal-secret"
            bridge_domain = "mail.jig.onl"
            resend_api_key = "${JIG_TEST_RESEND_KEY}"
            resend_webhook_secret = "whsec_literal"
        }
        .into();
        let cfg = EmailBridgeConfig::from_toml(&v).unwrap();
        assert_eq!(cfg.resend_api_key.as_deref(), Some("rk_live_xyz"));
        assert_eq!(cfg.resend_webhook_secret.as_deref(), Some("whsec_literal"));
        assert_eq!(cfg.bridge_secret, "literal-secret");
    }

    #[test]
    fn unset_env_ref_is_an_error() {
        let v: toml::Value = toml::toml! {
            bridge_secret = "${JIG_TEST_DEFINITELY_UNSET_VAR}"
            bridge_domain = "mail.jig.onl"
        }
        .into();
        let err = EmailBridgeConfig::from_toml(&v).unwrap_err().to_string();
        assert!(err.contains("JIG_TEST_DEFINITELY_UNSET_VAR"), "got: {err}");
    }

    #[test]
    fn dollar_literal_without_braces_is_left_alone() {
        let v: toml::Value = toml::toml! {
            bridge_secret = "a$weird$literal"
            bridge_domain = "mail.jig.onl"
        }
        .into();
        let cfg = EmailBridgeConfig::from_toml(&v).unwrap();
        assert_eq!(cfg.bridge_secret, "a$weird$literal");
    }
}
