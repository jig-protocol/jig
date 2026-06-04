//! Pluggable email provider seam. ResendProvider is the only impl in v0.0.3;
//! integration tests inject a MockProvider. The trait abstracts "send an
//! outbound email" and "verify + parse an inbound provider webhook" so the
//! bridge logic is provider-agnostic.

use anyhow::Result;
use async_trait::async_trait;
use axum::http::HeaderMap;

/// An outbound email the bridge asks the provider to send.
#[derive(Debug, Clone)]
pub struct OutboundEmail {
    pub to: String,
    pub from: String,
    pub subject: String,
    pub body: String,
}

/// An inbound email parsed out of a provider webhook payload.
#[derive(Debug, Clone)]
pub struct InboundEmail {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body: String,
    /// Provider's stable message id, used for inbound idempotency/dedup.
    pub provider_message_id: String,
}

/// A provider's stable identifier for a sent message.
pub type ProviderMessageId = String;

#[async_trait]
pub trait EmailProvider: Send + Sync {
    /// Send an outbound email; returns the provider's message id on success.
    async fn send(&self, msg: &OutboundEmail) -> Result<ProviderMessageId>;

    /// Parse a webhook payload into an inbound email. `Ok(None)` means the
    /// event is non-deliverable (a bounce / delivery-status notification) that
    /// should be logged but not forwarded into the protocol.
    fn parse_webhook(&self, headers: &HeaderMap, body: &[u8]) -> Result<Option<InboundEmail>>;

    /// Verify the webhook signature. `Err` => reject the request (HTTP 401).
    fn verify_webhook(&self, headers: &HeaderMap, body: &[u8]) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub;

    #[async_trait]
    impl EmailProvider for Stub {
        async fn send(&self, _: &OutboundEmail) -> Result<ProviderMessageId> {
            Ok("pmid".into())
        }
        fn parse_webhook(&self, _: &HeaderMap, _: &[u8]) -> Result<Option<InboundEmail>> {
            Ok(None)
        }
        fn verify_webhook(&self, _: &HeaderMap, _: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn stub_send_returns_id() {
        let p = Stub;
        let id = p
            .send(&OutboundEmail {
                to: "a@b".into(),
                from: "c@d".into(),
                subject: "s".into(),
                body: "b".into(),
            })
            .await
            .unwrap();
        assert_eq!(id, "pmid");
    }

    #[test]
    fn stub_parse_webhook_returns_none_for_non_deliverable() {
        let p = Stub;
        assert!(p.parse_webhook(&HeaderMap::new(), b"{}").unwrap().is_none());
    }
}
