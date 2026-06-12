//! Pluggable email provider seam. ResendProvider is the only impl in v0.0.3;
//! integration tests inject a MockProvider. The trait abstracts "send an
//! outbound email" and "verify + parse an inbound provider webhook" so the
//! bridge logic is provider-agnostic.
//!
//! Inbound is a two-step process because providers like Resend send
//! metadata-only webhooks — the body must be fetched separately:
//!   1. `parse_webhook` → `InboundNotification` (sync, no network)
//!   2. `fetch_inbound`  → `InboundEmail`        (async, HTTP fetch)

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

/// Metadata parsed synchronously from a provider webhook. The body is fetched
/// separately (async) via [`EmailProvider::fetch_inbound`], because providers
/// like Resend send metadata-only webhooks. `provider_message_id` is both the
/// fetch key and the inbound dedup key.
#[derive(Debug, Clone)]
pub struct InboundNotification {
    pub provider_message_id: String,
    pub from: String,
    pub to: String,
    pub subject: String,
}

/// A provider's stable identifier for a sent message.
pub type ProviderMessageId = String;

#[async_trait]
pub trait EmailProvider: Send + Sync {
    /// Send an outbound email; returns the provider's message id on success.
    async fn send(&self, msg: &OutboundEmail) -> Result<ProviderMessageId>;

    /// Verify the webhook signature. `Err` => reject the request (HTTP 401).
    fn verify_webhook(&self, headers: &HeaderMap, body: &[u8]) -> Result<()>;

    /// Parse a webhook into inbound *metadata* (no body). `Ok(None)` = a
    /// non-deliverable event (bounce/status) to log but not forward.
    fn parse_webhook(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Option<InboundNotification>>;

    /// Fetch the full inbound email (body) for a parsed notification.
    async fn fetch_inbound(&self, notification: &InboundNotification) -> Result<InboundEmail>;
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
        fn verify_webhook(&self, _: &HeaderMap, _: &[u8]) -> Result<()> {
            Ok(())
        }
        fn parse_webhook(&self, _: &HeaderMap, _: &[u8]) -> Result<Option<InboundNotification>> {
            Ok(None)
        }
        async fn fetch_inbound(&self, n: &InboundNotification) -> Result<InboundEmail> {
            Ok(InboundEmail {
                from: n.from.clone(),
                to: n.to.clone(),
                subject: n.subject.clone(),
                body: "stub body".into(),
                provider_message_id: n.provider_message_id.clone(),
            })
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
