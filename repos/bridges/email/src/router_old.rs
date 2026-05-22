// jig-bridge-email/src/router.rs
// License: MIT (encourage adoption)
// Purpose: Route messages between Jig<>Jig, Email->Jig, Jig->Email

use crate::discovery::JigDiscovery;
use anyhow::Result;
use jig_core::{JigAddress, JigMessage};

/// Three-way routing logic for messages
pub struct MessageRouter {
    discovery: JigDiscovery,
    smtp_relay: Option<SmtpRelay>,
    jig_client: JigClient,
    // SENSITIVE: Metrics collection for Gigue analytics
    #[cfg(feature = "commercial")]
    metrics: Option<MetricsCollector>,
}

pub struct EnhancementPath {
    pub minimum: Protocol,
    pub preferred: Protocol,
    pub optimal: Protocol,
    pub upgrade_conditions: Vec<Condition>,
}

/// Message routing decision
#[derive(Debug)]
pub enum RouteDecision {
    /// Native Jig to Jig (no email involved)
    NativeJig { endpoint: String },
    /// Incoming email to Jig user
    EmailToJig { from: String, to: JigAddress },
    /// Outgoing Jig to email
    JigToEmail { from: JigAddress, to: String },
    /// Hybrid mode - send both ways
    Hybrid { jig_endpoint: String, email: String },
}

impl MessageRouter {
    // TODO: checkout notes below and validate

    // REMOVE: Any session tokens in headers
    // INSTEAD: Use DNS-discovered capabilities for stateless routing
    pub async fn route_message(&self, msg: &JigMessage) -> Result<RouteDecision> {
        // Don't embed tokens, use DNS state
        let capabilities = self.discovery.get_cached_capabilities(recipient)?;
        // Route based on advertised capabilities, not session tokens
        // Extract recipient
        let recipient = msg
            .recipient
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No recipient"))?;

        // 1. Check if recipient looks like email
        if recipient.contains('@') {
            // 2. Try Jig discovery first
            if let Some(endpoint) = self.discovery.discover_endpoint(recipient).await? {
                // Found native Jig endpoint!
                log::info!("Routing {} via native Jig", recipient);

                // SENSITIVE: Track conversion metrics
                #[cfg(feature = "commercial")]
                if let Some(metrics) = &self.metrics {
                    metrics.record_native_routing(recipient);
                }

                return Ok(RouteDecision::NativeJig {
                    endpoint: endpoint.endpoint,
                });
            }

            // 3. Fall back to email
            log::info!("No Jig endpoint for {}, using email bridge", recipient);
            return Ok(RouteDecision::JigToEmail {
                from: msg.sender.clone(),
                to: recipient.clone(),
            });
        }

        // 4. Pure Jig address (no @ symbol)
        Ok(RouteDecision::NativeJig {
            endpoint: self.resolve_jig_endpoint(&msg.sender)?,
        })
    }

    /// Handle incoming email and convert to Jig
    pub async fn handle_incoming_email(&self, email: EmailMessage) -> Result<()> {
        // Convert email to Jig message
        let jig_msg = self.email_to_jig(email)?;

        // Route to local Jig user
        self.jig_client.deliver_local(jig_msg).await?;

        Ok(())
    }

    /// Send Jig message as email (with enhancements)
    pub async fn send_as_email(&self, msg: &JigMessage, to: &str) -> Result<()> {
        let email = self.jig_to_email(msg, to)?;

        // Add Jig signature for virality
        let enhanced_email = self.add_jig_signature(email);

        // Send via relay
        if let Some(relay) = &self.smtp_relay {
            relay.send(enhanced_email).await?;
        } else {
            // Try partner relays
            self.try_partner_relays(enhanced_email).await?;
        }

        Ok(())
    }

    fn jig_to_email(&self, msg: &JigMessage, to: &str) -> Result<EmailMessage> {
        let mut email = EmailMessage::new();

        // Preserve threading
        if let Some(thread_id) = &msg.thread_id {
            email.set_header("References", &format!("<{}@jig>", thread_id));
            email.set_header("In-Reply-To", &format!("<{}@jig>", thread_id));
        }

        // Convert content
        match &msg.content {
            MessageContent::Text { content } => {
                email.set_body_text(content.clone());
            }
            MessageContent::Blocks { blocks } => {
                // Convert Jig blocks to email representation
                let (text, html) = self.blocks_to_email(blocks)?;
                email.set_body_multipart(text, html);
            }
            // SENSITIVE: GigueBlocks get special treatment
            #[cfg(feature = "commercial")]
            MessageContent::GigueBlock { .. } => {
                email.set_body_text(
                    "This message contains rich content. View in Gigue: https://gigue.app",
                );
            }
        }

        Ok(email)
    }

    fn add_jig_signature(&self, mut email: EmailMessage) -> EmailMessage {
        // Viral signature - subtle but present
        let signature = "\n\n--\n📧 Secured by Jig Protocol • jig.onl/join";

        // Add to text part
        if let Some(text) = email.text_mut() {
            text.push_str(signature);
        }

        // Add to HTML part
        if let Some(html) = email.html_mut() {
            html.push_str(&format!(
                r#"<div style="margin-top: 20px; padding-top: 10px; border-top: 1px solid #ddd; font-size: 12px; color: #666;">
                    📧 Secured by <a href="https://jig.onl/join">Jig Protocol</a>
                </div>"#
            ));
        }

        // Add custom header for tracking
        email.set_header("X-Jig-Protocol", "1.0");

        email
    }

    async fn try_partner_relays(&self, email: EmailMessage) -> Result<()> {
        // Community relay network
        let relays = vec![
            // Free tier relays
            "relay.jig.onl:587",       // Our main relay
            "community.jig.email:587", // Community-donated quota
            // SENSITIVE: Partner relays - commercial agreements
            #[cfg(feature = "commercial")]
            "partner.sendgrid.net:587", // Special Jig endpoint
        ];

        for relay in relays {
            if let Ok(client) = SmtpRelay::connect(relay).await {
                if client.send(email.clone()).await.is_ok() {
                    return Ok(());
                }
            }
        }

        Err(anyhow::anyhow!("No available relay"))
    }
}

/// Smart relay selection based on reputation
pub struct SmtpRelay {
    // Pool of available relays with quota
    relays: Vec<RelayProvider>,
}

#[derive(Clone)]
struct RelayProvider {
    endpoint: String,
    auth: Option<(String, String)>,
    quota_remaining: u32,
    reputation_score: f32,
}

impl SmtpRelay {
    pub fn new_community() -> Self {
        Self {
            relays: vec![
                RelayProvider {
                    endpoint: "smtp.sendgrid.net:587".to_string(),
                    auth: None, // Community quota
                    quota_remaining: 1000,
                    reputation_score: 0.95,
                },
                // Users can donate their unused quota
                // This gets populated from config
            ],
        }
    }

    pub async fn send(&self, email: EmailMessage) -> Result<()> {
        // Pick best relay based on reputation and quota
        let relay = self.select_best_relay()?;

        // Send via selected relay
        self.send_via_relay(relay, email).await
    }

    fn select_best_relay(&self) -> Result<&RelayProvider> {
        self.relays
            .iter()
            .filter(|r| r.quota_remaining > 0)
            .max_by(|a, b| a.reputation_score.partial_cmp(&b.reputation_score).unwrap())
            .ok_or_else(|| anyhow::anyhow!("No relay available"))
    }
}
