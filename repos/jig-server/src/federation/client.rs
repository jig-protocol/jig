//! Federation client for discovering and caching other servers

use super::{ServerInfo, discovery};
use crate::{error::Result, storage::SqliteBackend};
use reqwest::Client;
use std::sync::Arc;

/// Client for federation discovery
pub struct FederationClient {
    http: Client,
    storage: Arc<SqliteBackend>,
}

impl FederationClient {
    pub fn new(storage: Arc<SqliteBackend>) -> Self {
        Self {
            http: Client::new(),
            storage,
        }
    }

    /// Discover servers for a domain and cache their info
    pub async fn discover(&self, domain: &str) -> Result<Vec<ServerInfo>> {
        let addrs = discovery::discover(domain).await?;
        let mut servers = Vec::new();

        for addr in addrs {
            let url = format!("http://{}:{}/.well-known/jig", addr.ip(), addr.port());
            if let Ok(resp) = self.http.get(&url).send().await
                && resp.status().is_success()
                && let Ok(info) = resp.json::<ServerInfo>().await
            {
                let _ = self
                    .storage
                    .upsert_known_server(&info, "tofu")
                    .map_err(|e| tracing::warn!("Failed to cache server: {}", e));
                servers.push(info);
            }
        }

        Ok(servers)
    }
}
