//! Message routing for email bridge
//!
//! Implements three-pronged routing:
//! 1. Jig <> Jig: Native protocol via DNS discovery
//! 2. Jig -> Email: SMTP with viral block signature
//! 3. Email -> Jig: Convert to block and forward

use crate::discovery::{JigDiscovery, JigEndpoint};
use crate::types::EmailMessage;
use anyhow::Result;
use tracing::info;

/// Routing decision for an email message
#[derive(Debug)]
pub enum RouteDecision {
    /// Forward to Jig server as a block (native Jig routing)
    ToJigServer { server_url: String },
    /// Send via SMTP to external email address
    ToEmail,
    /// Both - send to Jig server and email (hybrid mode)
    Hybrid { server_url: String },
}

pub struct MessageRouter {
    /// Default Jig server URL (e.g., http://localhost:7117)
    default_server_url: String,
    /// DNS-based Jig discovery
    discovery: JigDiscovery,
}

impl MessageRouter {
    pub fn new(server_url: String) -> Self {
        let discovery = JigDiscovery::new().unwrap_or_else(|_| JigDiscovery::default());
        Self {
            default_server_url: server_url,
            discovery,
        }
    }

    /// Determine where to route an email message
    ///
    /// THREE-PRONGED ROUTING LOGIC:
    /// 1. Jig <> Jig: DNS discovery finds _jig records → native routing
    /// 2. Email -> Jig: No discovery → convert to block, send to default server
    /// 3. Jig -> Email: No discovery → SMTP with viral signature
    pub async fn route_message(&self, msg: &EmailMessage) -> Result<RouteDecision> {
        if msg.to.contains('@') {
            // Try DNS discovery for Jig-native routing (PRONG 1)
            match self.discovery.discover(&msg.to).await {
                Ok(Some(endpoint)) => {
                    info!(
                        "🎯 Jig<>Jig: Discovered endpoint for {}: {}",
                        msg.to, endpoint.url
                    );
                    return Ok(RouteDecision::ToJigServer {
                        server_url: endpoint.url,
                    });
                }
                Ok(None) => {
                    info!(
                        "📧 Jig->Email: No Jig endpoint for {}, routing via SMTP",
                        msg.to
                    );
                    // PRONG 3: Fall back to email with viral signature
                    return Ok(RouteDecision::ToEmail);
                }
                Err(e) => {
                    info!(
                        "⚠️  DNS discovery failed for {}: {}, falling back to SMTP",
                        msg.to, e
                    );
                    return Ok(RouteDecision::ToEmail);
                }
            }
        } else {
            // Direct Jig address (no @) - route to default server (PRONG 2)
            info!("🔷 Email->Jig: Routing {} to default Jig server", msg.to);
            Ok(RouteDecision::ToJigServer {
                server_url: self.default_server_url.clone(),
            })
        }
    }

    /// Send message to Jig server as a block
    pub async fn send_to_jig_server(
        &self,
        msg: &EmailMessage,
        server_url: &str,
        author_did: &str,
    ) -> Result<()> {
        // Convert email to BlockManifest
        let manifest = msg.to_block_manifest(author_did)?;

        // Serialize manifest
        let manifest_json = serde_json::to_vec(&manifest)?;

        // Send to server via HTTP POST
        let client = reqwest::Client::new();
        let url = format!("{}/ingest", server_url);

        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(manifest_json)
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Failed to send to Jig server: {}", response.status());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_route_email_address() {
        let router = MessageRouter::new("http://localhost:7117".to_string());
        let msg = EmailMessage::new(
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
            "Test".to_string(),
            "Body".to_string(),
        );

        let decision = router.route_message(&msg).await.unwrap();
        assert!(matches!(decision, RouteDecision::ToEmail));
    }

    #[tokio::test]
    async fn test_route_jig_address() {
        let router = MessageRouter::new("http://localhost:7117".to_string());
        let msg = EmailMessage::new(
            "alice@example.com".to_string(),
            "bob".to_string(), // No @ sign - Jig address
            "Test".to_string(),
            "Body".to_string(),
        );

        let decision = router.route_message(&msg).await.unwrap();
        assert!(matches!(decision, RouteDecision::ToJigServer { .. }));
    }
}
