// jig-nameserver/src/discovery.rs
// License: AGPL-3.0 (core infrastructure)
// Purpose: Auto-discover Jig endpoints via DNS before falling back to email

use anyhow::Result;
use serde::{Deserialize, Serialize};
use trust_dns_resolver::Resolver;

/// DNS-based Jig endpoint discovery
/// Checks if a domain runs Jig natively before falling back to SMTP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProfile {
    pub extends: Option<String>, // Reference parent profile
    pub overrides: HashMap<String, Value>,
}
 
pub struct JigEndpoint {
    // ADD: Temporal validity (novel)
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,

    // ADD: Capability dependencies (novel)
    pub capability_chain: Vec<CapabilityRequirement>,

    // CHANGE: Use JSON-LD format instead of key=value
    pub capabilities_ld: JsonLdDocument, // Semantic descriptions

    // ADD: Load-based availability (novel)
    pub capacity_percentage: Option<u8>,
}

pub struct JigDiscovery {
    resolver: Resolver,
}

impl JigDiscovery {
    /// Check if email domain has native Jig support
    /// This is checked BEFORE attempting any SMTP operations
    pub async fn discover_endpoint(&self, email: &str) -> Result<Option<JigEndpoint>> {
        let domain = email
            .split('@')
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Invalid email"))?;

        // 1. Check TXT record for Jig capability
        if let Some(endpoint) = self.check_txt_record(domain).await? {
            return Ok(Some(endpoint));
        }

        // 2. Check SRV record for Jig service
        if let Some(endpoint) = self.check_srv_record(domain).await? {
            return Ok(Some(endpoint));
        }

        // 3. Check well-known HTTPS endpoint
        if let Some(endpoint) = self.check_wellknown(domain).await? {
            return Ok(Some(endpoint));
        }

        Ok(None)
    }

    async fn check_txt_record(&self, domain: &str) -> Result<Option<JigEndpoint>> {
        let txt_domain = format!("_jig.{}", domain);

        // Look for: "v=JIG1 endpoint=wss://jig.domain.com caps=e2e,federation"
        if let Ok(txt_records) = self.resolver.txt_lookup(&txt_domain).await {
            for record in txt_records.iter() {
                let txt = record.to_string();
                if txt.starts_with("v=JIG") {
                    return Ok(Some(self.parse_txt_record(&txt)?));
                }
            }
        }

        Ok(None)
    }

    async fn check_srv_record(&self, domain: &str) -> Result<Option<JigEndpoint>> {
        let srv_domain = format!("_jig._tcp.{}", domain);

        if let Ok(srv_records) = self.resolver.srv_lookup(&srv_domain).await {
            if let Some(srv) = srv_records.iter().next() {
                return Ok(Some(JigEndpoint {
                    protocol_version: "JIG1".to_string(),
                    endpoint: format!("wss://{}:{}", srv.target(), srv.port()),
                    capabilities: vec!["srv-discovered".to_string()],
                    public_key: None,
                }));
            }
        }

        Ok(None)
    }

    async fn check_wellknown(&self, domain: &str) -> Result<Option<JigEndpoint>> {
        // Check https://domain/.well-known/jig.json
        let url = format!("https://{}/.well-known/jig.json", domain);

        // Quick timeout to not slow down email fallback
        match tokio::time::timeout(std::time::Duration::from_secs(2), reqwest::get(&url)).await {
            Ok(Ok(response)) if response.status().is_success() => {
                let endpoint: JigEndpoint = response.json().await?;
                Ok(Some(endpoint))
            }
            _ => Ok(None),
        }
    }

    fn parse_txt_record(&self, txt: &str) -> Result<JigEndpoint> {
        let mut version = String::new();
        let mut endpoint = String::new();
        let mut capabilities = Vec::new();
        let mut public_key = None;

        for part in txt.split_whitespace() {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "v" => version = value.to_string(),
                    "endpoint" => endpoint = value.to_string(),
                    "caps" => capabilities = value.split(',').map(String::from).collect(),
                    "pubkey" => public_key = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        Ok(JigEndpoint {
            protocol_version: version,
            endpoint,
            capabilities,
            public_key,
        })
    }
}

/// Registry of known Jig-native domains (cached for performance)
/// This gets updated via federation gossip protocol
pub struct JigDomainRegistry {
    known_domains: std::sync::Arc<dashmap::DashMap<String, JigEndpoint>>,
}

impl JigDomainRegistry {
    pub fn new() -> Self {
        let registry = Self {
            known_domains: std::sync::Arc::new(dashmap::DashMap::new()),
        };

        // Pre-seed with known Jig providers
        registry.seed_known_providers();
        registry
    }

    fn seed_known_providers(&self) {
        // Partner domains that run Jig natively
        let partners = vec![
            ("jig.onl", "wss://relay.jig.onl"),
            ("jig.email", "wss://mx.jig.email"),
            // SENSITIVE: Partner deals - mark for commercial discussions
            // ("porkbun.email", "wss://jig.porkbun.com"),
        ];

        for (domain, endpoint) in partners {
            self.known_domains.insert(
                domain.to_string(),
                JigEndpoint {
                    protocol_version: "JIG1".to_string(),
                    endpoint: endpoint.to_string(),
                    capabilities: vec!["native".to_string()],
                    public_key: None,
                },
            );
        }
    }

    pub fn is_native_jig(&self, domain: &str) -> bool {
        self.known_domains.contains_key(domain)
    }

    pub fn add_discovered(&self, domain: String, endpoint: JigEndpoint) {
        self.known_domains.insert(domain, endpoint);
    }
}
