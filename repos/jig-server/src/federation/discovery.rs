//! DNS-based discovery of Jig servers

use crate::error::Result;
use hickory_resolver::{TokioResolver, proto::rr::RData};
use std::net::SocketAddr;

/// Discover Jig servers for a domain using SRV records with A/AAAA fallback
pub async fn discover(domain: &str) -> Result<Vec<SocketAddr>> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| crate::error::ServerError::Server(e.to_string()))?
        .build();

    let name = format!("_jig._tcp.{}", domain);
    match resolver.srv_lookup(name).await {
        Ok(lookup) => {
            let mut addrs = Vec::new();
            for record in lookup.answers() {
                let Some(srv) = (match &record.data {
                    RData::SRV(srv) => Some(srv),
                    _ => None,
                }) else {
                    continue;
                };
                let target = srv.target.to_utf8();
                let port = srv.port;
                if let Ok(ips) = resolver.lookup_ip(target).await {
                    for ip in ips.iter() {
                        addrs.push(SocketAddr::new(ip, port));
                    }
                }
            }
            Ok(addrs)
        }
        Err(_) => {
            // Fallback to A/AAAA records with default port
            let ips = resolver
                .lookup_ip(domain)
                .await
                .map_err(|e| crate::error::ServerError::Server(e.to_string()))?;
            Ok(ips.iter().map(|ip| SocketAddr::new(ip, 7117)).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_discover_localhost() {
        let addrs = discover("localhost").await.unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().any(|a| a.port() == 7117));
    }
}
