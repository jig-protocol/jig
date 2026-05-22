//! Federation discovery and remote resolution for nameserver

use crate::error::{NameServerError, Result};
use crate::types::IdentityRecord;
use reqwest::Client;
use std::net::SocketAddr;
use trust_dns_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
};

#[async_trait::async_trait]
pub trait FederationResolver: Send + Sync + 'static {
    async fn resolve_remote(&self, handle: &str) -> Result<Option<IdentityRecord>>;
}

pub struct DefaultFederationResolver {
    http: Client,
}

impl Default for DefaultFederationResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultFederationResolver {
    pub fn new() -> Self {
        Self {
            http: Client::new(),
        }
    }
}

pub(crate) fn parse_domain_from_handle(handle: &str) -> Option<String> {
    // Heuristic: if it starts with '@' (Matrix-style), prefer ':domain'; otherwise try email-style '@domain' first.
    if handle.starts_with('@') {
        if let Some(colon) = handle.rfind(':')
            && colon < handle.len() - 1
        {
            return Some(handle[colon + 1..].to_string());
        }
        if let Some(at) = handle.rfind('@')
            && at < handle.len() - 1
        {
            return Some(handle[at + 1..].to_string());
        }
    } else {
        if let Some(at) = handle.rfind('@')
            && at < handle.len() - 1
        {
            return Some(handle[at + 1..].to_string());
        }
        if let Some(colon) = handle.rfind(':')
            && colon < handle.len() - 1
        {
            return Some(handle[colon + 1..].to_string());
        }
    }
    None
}

async fn discover_nameservers(domain: &str) -> Result<Vec<SocketAddr>> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let name = format!("_jig-ns._tcp.{domain}");
    match resolver.srv_lookup(name).await {
        Ok(lookup) => {
            let mut addrs = Vec::new();
            for srv in lookup.iter() {
                let target = srv.target().to_utf8();
                let port = srv.port();
                if let Ok(ips) = resolver.lookup_ip(target).await {
                    for ip in ips.iter() {
                        addrs.push(SocketAddr::new(ip, port));
                    }
                }
            }
            Ok(addrs)
        }
        Err(_) => {
            let ips = resolver
                .lookup_ip(domain)
                .await
                .map_err(|e| NameServerError::Other(anyhow::anyhow!(e.to_string())))?;
            Ok(ips.iter().map(|ip| SocketAddr::new(ip, 7070)).collect())
        }
    }
}

/// Public helper to discover nameservers for a domain
pub async fn discover_for_domain(domain: &str) -> Result<Vec<SocketAddr>> {
    discover_nameservers(domain).await
}

#[async_trait::async_trait]
impl FederationResolver for DefaultFederationResolver {
    async fn resolve_remote(&self, handle: &str) -> Result<Option<IdentityRecord>> {
        let Some(domain) = parse_domain_from_handle(handle) else {
            return Ok(None);
        };
        let addrs = discover_nameservers(&domain).await?;
        for addr in addrs {
            let url = format!(
                "http://{}:{}/v1/resolve?name={}",
                addr.ip(),
                addr.port(),
                urlencoding::encode(handle)
            );
            if let Ok(resp) = self.http.get(&url).send().await
                && resp.status().is_success()
                && let Ok(rec) = resp.json::<Option<IdentityRecord>>().await
                && rec.is_some()
            {
                return Ok(rec);
            }
        }
        Ok(None)
    }
}

// Federation Gossip Protocol

use crate::config::FederationConfig;
use crate::storage::NamesStorage;
use crate::types::{
    FederationHandshake, FederationPeer, FederationPeerStatus, GossipMessage, GossipMessageKind,
    PolicyHashExchange, ReputationSummaryGossip, TribunalDecisionGossip,
};
use chrono::Utc;
use std::sync::Arc;
use tokio::time::{Duration, interval};
use uuid::Uuid;

/// Federation coordinator handles peer discovery, handshakes, and gossip
pub struct FederationCoordinator {
    config: FederationConfig,
    storage: Arc<dyn NamesStorage>,
    our_domain: String,
    our_version: String,
}

impl FederationCoordinator {
    pub fn new(
        config: FederationConfig,
        storage: Arc<dyn NamesStorage>,
        our_domain: String,
        our_version: String,
    ) -> Self {
        Self {
            config,
            storage,
            our_domain,
            our_version,
        }
    }

    /// Start periodic gossip task
    pub async fn start_gossip_loop(self: Arc<Self>) {
        if !self.config.enabled {
            tracing::info!("Federation gossip disabled");
            return;
        }

        let mut ticker = interval(Duration::from_secs(self.config.gossip_interval_secs as u64));
        loop {
            ticker.tick().await;
            if let Err(e) = self.gossip_round().await {
                tracing::error!("Gossip round failed: {e}");
            }
        }
    }

    /// Perform one round of gossip with all active peers
    async fn gossip_round(&self) -> Result<()> {
        tracing::debug!("Starting gossip round");

        // Discover new peers from seeds if needed
        let peers = self
            .storage
            .list_federation_peers(self.config.max_peers)
            .await?;
        if peers.len() < self.config.max_peers && !self.config.seed_peers.is_empty() {
            for seed_url in &self.config.seed_peers {
                if let Err(e) = self.discover_peer(seed_url).await {
                    tracing::warn!("Failed to discover peer {seed_url}: {e}");
                }
            }
        }

        // Gossip with active peers
        let active_peers: Vec<_> = peers
            .into_iter()
            .filter(|p| p.status == FederationPeerStatus::Active)
            .collect();

        for peer in active_peers {
            if let Err(e) = self.gossip_with_peer(&peer).await {
                tracing::warn!("Gossip with {} failed: {e}", peer.domain);
                let _ = self
                    .storage
                    .update_peer_status(&peer.domain, FederationPeerStatus::Unreachable, Utc::now())
                    .await;
            } else {
                let _ = self
                    .storage
                    .update_peer_status(&peer.domain, FederationPeerStatus::Active, Utc::now())
                    .await;
            }
        }

        Ok(())
    }

    /// Discover and handshake with a new peer
    async fn discover_peer(&self, endpoint: &str) -> Result<()> {
        tracing::info!("Discovering peer at {endpoint}");

        let capabilities_url = format!("{endpoint}/.well-known/jig-ns/capabilities");
        let capabilities_text = match self.fetch_capabilities(&capabilities_url).await {
            Ok(text) => text,
            Err(e) => {
                tracing::warn!("Failed to fetch capabilities from {endpoint}: {e}");
                return Ok(()); // Non-fatal
            }
        };
        let capabilities_hash = blake3::hash(capabilities_text.as_bytes()).to_string();

        let peer = FederationPeer {
            id: Uuid::now_v7(),
            domain: extract_domain_from_url(endpoint),
            endpoint: endpoint.to_string(),
            public_key: None,
            status: FederationPeerStatus::Active,
            capabilities_hash: Some(capabilities_hash),
            discovered_at: Utc::now(),
            last_seen_at: Utc::now(),
            metadata: serde_json::json!({"version": self.our_version}),
        };

        self.storage.upsert_federation_peer(peer).await?;
        Ok(())
    }

    /// Fetch capabilities from peer
    async fn fetch_capabilities(&self, url: &str) -> Result<String> {
        tracing::debug!("Fetching capabilities from {url}");
        let client = Client::new();
        let resp = client
            .get(url)
            .timeout(std::time::Duration::from_secs(
                self.config.handshake_timeout_secs as u64,
            ))
            .send()
            .await
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("HTTP error: {e}")))?;

        if !resp.status().is_success() {
            return Err(NameServerError::Other(anyhow::anyhow!(
                "HTTP {}",
                resp.status()
            )));
        }

        let text = resp
            .text()
            .await
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("Read error: {e}")))?;
        Ok(text)
    }

    /// Gossip with a specific peer
    async fn gossip_with_peer(&self, peer: &FederationPeer) -> Result<()> {
        tracing::debug!("Gossiping with {}", peer.domain);

        self.exchange_policy_hash(peer).await?;
        self.exchange_reputation_summaries(peer).await?;
        self.exchange_tribunal_decisions(peer).await?;

        Ok(())
    }

    /// Exchange policy hash with peer
    async fn exchange_policy_hash(&self, _peer: &FederationPeer) -> Result<()> {
        let our_policy = PolicyHashExchange {
            domain: self.our_domain.clone(),
            policy_version: self.our_version.clone(),
            policy_hash: blake3::hash(b"placeholder-policy").to_string(),
            rulesets: vec!["high-sec".to_string()],
            capabilities_url: Some(format!(
                "https://{}/.well-known/jig-ns/capabilities",
                self.our_domain
            )),
            runtime_hash: None, // Phase C: TODO populate from actual runtime config
            affordances: Vec::new(), // Phase C: TODO populate from capabilities config
            timestamp: Utc::now(),
        };

        let message = GossipMessage {
            id: Uuid::now_v7(),
            kind: GossipMessageKind::PolicyHash,
            from_peer: self.our_domain.clone(),
            payload: serde_json::to_value(&our_policy).unwrap_or_default(),
            signature: None,
            timestamp: Utc::now(),
        };

        self.storage.store_gossip_message(message).await?;
        self.storage.store_policy_hash(our_policy).await?;

        Ok(())
    }

    /// Exchange reputation summaries with peer
    async fn exchange_reputation_summaries(&self, _peer: &FederationPeer) -> Result<()> {
        // Placeholder: aggregate recent reputation data and exchange with peer
        Ok(())
    }

    /// Exchange tribunal decisions with peer
    async fn exchange_tribunal_decisions(&self, _peer: &FederationPeer) -> Result<()> {
        // Placeholder: fetch recent tribunal decisions and propagate to peer
        Ok(())
    }

    /// Handle incoming gossip message
    pub async fn handle_gossip_message(&self, message: GossipMessage) -> Result<()> {
        tracing::debug!("Handling gossip message kind: {:?}", message.kind);

        match message.kind {
            GossipMessageKind::PolicyHash => {
                if let Ok(policy) =
                    serde_json::from_value::<PolicyHashExchange>(message.payload.clone())
                {
                    self.storage.store_policy_hash(policy).await?;
                }
            }
            GossipMessageKind::ReputationSummary => {
                if let Ok(_summary) =
                    serde_json::from_value::<ReputationSummaryGossip>(message.payload.clone())
                {
                    // Process reputation summary
                }
            }
            GossipMessageKind::TribunalDecision => {
                if let Ok(_decision) =
                    serde_json::from_value::<TribunalDecisionGossip>(message.payload.clone())
                {
                    // Process tribunal decision
                }
            }
            GossipMessageKind::Handshake => {
                if let Ok(_handshake) =
                    serde_json::from_value::<FederationHandshake>(message.payload.clone())
                {
                    // Process handshake
                }
            }
        }

        self.storage.store_gossip_message(message).await?;
        Ok(())
    }
}

/// Extract domain from URL
fn extract_domain_from_url(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_parse_variants() {
        assert_eq!(
            parse_domain_from_handle("alice@example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            parse_domain_from_handle("@alice:example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(parse_domain_from_handle("alice"), None);
    }

    #[test]
    fn extract_domain_from_url_variants() {
        assert_eq!(
            extract_domain_from_url("https://ns.example.com"),
            "ns.example.com"
        );
        assert_eq!(
            extract_domain_from_url("http://ns.example.com/path"),
            "ns.example.com"
        );
        assert_eq!(extract_domain_from_url("ns.example.com"), "ns.example.com");
    }
}
