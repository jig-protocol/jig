//! DNS-based Jig protocol discovery
//!
//! Implements _jig SRV/TXT record lookup to enable native Jig routing
//! before falling back to SMTP.

use anyhow::Result;
use std::net::ToSocketAddrs;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

/// Result of Jig discovery for a domain
#[derive(Debug, Clone)]
pub struct JigEndpoint {
    /// The discovered Jig server URL
    pub url: String,
    /// Priority (lower is higher priority)
    pub priority: u16,
    /// Whether TLS is required
    pub requires_tls: bool,
}

/// DNS-based Jig protocol discovery
pub struct JigDiscovery {
    resolver: TokioAsyncResolver,
}

impl JigDiscovery {
    pub fn new() -> Result<Self> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(Self { resolver })
    }

    /// Discover Jig endpoint for an email address
    ///
    /// Checks for _jig._tcp.domain SRV records and _jig.domain TXT records
    /// Returns the endpoint if found, None if not a Jig-enabled domain
    pub async fn discover(&self, email_address: &str) -> Result<Option<JigEndpoint>> {
        // Extract domain from email address
        let domain = email_address
            .split('@')
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Invalid email address"))?;

        // Try SRV record first: _jig._tcp.domain
        if let Some(endpoint) = self.discover_srv(domain).await? {
            return Ok(Some(endpoint));
        }

        // Fall back to TXT record: _jig.domain
        if let Some(endpoint) = self.discover_txt(domain).await? {
            return Ok(Some(endpoint));
        }

        Ok(None)
    }

    async fn discover_srv(&self, domain: &str) -> Result<Option<JigEndpoint>> {
        let srv_query = format!("_jig._tcp.{}", domain);

        match self.resolver.srv_lookup(&srv_query).await {
            Ok(lookup) => {
                // Get the highest priority (lowest number) SRV record
                if let Some(srv) = lookup.iter().min_by_key(|s| s.priority()) {
                    let host = srv.target().to_utf8();
                    let port = srv.port();

                    // Construct URL - default to https if port is 443, http otherwise
                    let scheme = if port == 443 { "https" } else { "http" };
                    let url = if port == 80 || port == 443 {
                        format!("{}://{}", scheme, host)
                    } else {
                        format!("{}://{}:{}", scheme, host, port)
                    };

                    return Ok(Some(JigEndpoint {
                        url,
                        priority: srv.priority(),
                        requires_tls: port == 443,
                    }));
                }
            }
            Err(_) => {
                // No SRV record found, that's OK
            }
        }

        Ok(None)
    }

    async fn discover_txt(&self, domain: &str) -> Result<Option<JigEndpoint>> {
        let txt_query = format!("_jig.{}", domain);

        match self.resolver.txt_lookup(&txt_query).await {
            Ok(lookup) => {
                for record in lookup.iter() {
                    // TXT record format: "jig=https://jig.example.com:7117"
                    for txt in record.iter() {
                        let txt_str = String::from_utf8_lossy(txt);
                        if let Some(url) = txt_str.strip_prefix("jig=") {
                            return Ok(Some(JigEndpoint {
                                url: url.to_string(),
                                priority: 10,
                                requires_tls: url.starts_with("https://"),
                            }));
                        }
                    }
                }
            }
            Err(_) => {
                // No TXT record found
            }
        }

        Ok(None)
    }
}

impl Default for JigDiscovery {
    fn default() -> Self {
        Self::new().expect("Failed to create DNS resolver")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_discovery_extracts_domain() {
        let discovery = JigDiscovery::new().unwrap();
        // This will return None since example.com doesn't have _jig records
        let result = discovery.discover("alice@example.com").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_invalid_email() {
        let discovery = JigDiscovery::new().unwrap();
        let result = discovery.discover("not-an-email").await;
        assert!(result.is_err());
    }
}
