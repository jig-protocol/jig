//! Inbound webhook handler: provider webhook -> verified, parsed, deduped ->
//! a text-render block authored by the sender's shadow identity, submitted to
//! ingest. Also ensures the 1:1 DM channel + memberships exist on first contact.

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use jig_bridge_core::{BridgeStorage, ManagedDidRegistrar, SubmitDenied, SubmitHandle};
use jig_client::Identity;

use crate::address_book::AddressBook;
use crate::channel::{dm_channel_slug, ensure_dm_channel, submit_built_block};
use crate::identity::shadow_signing_key;
use crate::provider::EmailProvider;
use crate::{CHANNEL_EMAIL_NS, MAX_INLINE_BYTES};

/// How long to remember a processed provider message id for dedup (1 week).
const INBOUND_SEEN_TTL_SECS: i64 = 7 * 24 * 3600;
const INBOUND_SEEN_NS: &str = "inbound-seen";

/// Everything the inbound handler needs. Built once by the bridge at `start()`.
pub struct InboundState {
    pub provider: Arc<dyn EmailProvider>,
    pub address_book: Arc<AddressBook>,
    pub submit: SubmitHandle,
    pub storage: Arc<dyn BridgeStorage>,
    pub managed_dids: ManagedDidRegistrar,
    pub bridge_secret: String,
    pub strip_plus_tags: bool,
}

/// Handle one provider webhook POST. Returns the HTTP status to reply with.
pub async fn handle_inbound(
    state: Arc<InboundState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    if state.provider.verify_webhook(&headers, &body).is_err() {
        return StatusCode::UNAUTHORIZED;
    }
    let notif = match state.provider.parse_webhook(&headers, &body) {
        Ok(Some(n)) => n,
        Ok(None) => return StatusCode::OK,
        Err(e) => {
            tracing::warn!("email bridge: inbound parse failed: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };

    // Dedup on the provider message id BEFORE the network fetch.
    match state.storage.get(INBOUND_SEEN_NS, &notif.provider_message_id).await {
        Ok(Some(_)) => return StatusCode::OK,
        Ok(None) => {}
        Err(e) => {
            tracing::error!("email bridge: inbound dedup check failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    // Fetch the body (provider webhooks are metadata-only).
    let email = match state.provider.fetch_inbound(&notif).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("email bridge: inbound body fetch failed: {e}");
            return StatusCode::BAD_GATEWAY;
        }
    };

    if email.body.trim().is_empty() {
        tracing::error!(
            "email bridge: inbound email {} has an empty body, dropping",
            email.provider_message_id
        );
        return StatusCode::OK;
    }
    if email.body.len() > MAX_INLINE_BYTES {
        tracing::warn!(
            "email bridge: inbound body {} bytes exceeds cap, rejecting",
            email.body.len()
        );
        return StatusCode::PAYLOAD_TOO_LARGE;
    }

    let sk = shadow_signing_key(&state.bridge_secret, &email.from, state.strip_plus_tags);
    let shadow = Identity::from_signing_key(sk);
    let shadow_did = shadow.did().to_string();
    state.managed_dids.register(shadow_did.clone());

    let recipient_did = match state.address_book.resolve(&email.to).await {
        Ok(r) => r.did().to_string(),
        Err(e) => {
            tracing::error!("email bridge: recipient resolve failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };
    let slug = dm_channel_slug(&shadow_did, &recipient_did);
    if let Err(e) =
        ensure_dm_channel(&state.submit, &*state.storage, &shadow, &recipient_did, &slug).await
    {
        tracing::error!("email bridge: ensure channel {slug} failed: {e}");
        return StatusCode::BAD_GATEWAY;
    }
    if let Err(e) = state
        .storage
        .put(CHANNEL_EMAIL_NS, &slug, email.from.as_bytes(), None)
        .await
    {
        tracing::warn!("email bridge: failed to record channel-email map for {slug}: {e}");
    }
    let hlc = jig_core::HlcTimestamp::now_wall(shadow.did().clone());
    let block = jig_client::blocks::build_text_render(&shadow, &slug, &email.body, hlc);
    match submit_built_block(&state.submit, block).await {
        Ok(_cid) => {
            let expires = chrono::Utc::now().timestamp() + INBOUND_SEEN_TTL_SECS;
            if let Err(e) = state
                .storage
                .put(INBOUND_SEEN_NS, &notif.provider_message_id, b"1", Some(expires))
                .await
            {
                tracing::warn!("email bridge: failed to mark inbound-seen: {e}");
            }
            StatusCode::OK
        }
        Err(SubmitDenied::RateLimited { .. }) => StatusCode::TOO_MANY_REQUESTS,
        Err(SubmitDenied::PolicyBlocked { reason }) => {
            tracing::warn!("email bridge: inbound submit policy-blocked: {reason}");
            StatusCode::BAD_GATEWAY
        }
        Err(SubmitDenied::Unavailable) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::shadow_did;
    use crate::provider::{InboundEmail, InboundNotification, OutboundEmail, ProviderMessageId};
    use anyhow::Result;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // In-memory BridgeStorage (expiry not exercised here).
    #[derive(Default)]
    struct MemStore {
        map: Mutex<HashMap<(String, String), Vec<u8>>>,
    }
    #[async_trait]
    impl BridgeStorage for MemStore {
        async fn put(&self, ns: &str, key: &str, value: &[u8], _e: Option<i64>) -> Result<()> {
            self.map
                .lock()
                .unwrap()
                .insert((ns.into(), key.into()), value.to_vec());
            Ok(())
        }
        async fn get(&self, ns: &str, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .get(&(ns.into(), key.into()))
                .cloned())
        }
        async fn delete(&self, ns: &str, key: &str) -> Result<()> {
            self.map.lock().unwrap().remove(&(ns.into(), key.into()));
            Ok(())
        }
        async fn sweep_expired(&self, _ns: &str) -> Result<u64> {
            Ok(0)
        }
    }

    // Stub provider: drives parse + fetch with configurable outcomes.
    // `fetch_body = Some(s)` → fetch returns Ok with that body.
    // `fetch_body = None`    → fetch returns Err (simulates network failure).
    struct StubProvider {
        notification: Option<InboundNotification>,
        fetch_body: Option<String>,
        verify_ok: bool,
        fetch_calls: Arc<Mutex<u32>>,
    }
    #[async_trait]
    impl EmailProvider for StubProvider {
        async fn send(&self, _: &OutboundEmail) -> Result<ProviderMessageId> {
            Ok("pmid".into())
        }
        fn verify_webhook(&self, _: &HeaderMap, _: &[u8]) -> Result<()> {
            if self.verify_ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!("bad sig"))
            }
        }
        fn parse_webhook(&self, _: &HeaderMap, _: &[u8]) -> Result<Option<InboundNotification>> {
            Ok(self.notification.clone())
        }
        async fn fetch_inbound(&self, n: &InboundNotification) -> Result<InboundEmail> {
            *self.fetch_calls.lock().unwrap() += 1;
            match &self.fetch_body {
                Some(b) => Ok(InboundEmail {
                    from: n.from.clone(),
                    to: n.to.clone(),
                    subject: n.subject.clone(),
                    body: b.clone(),
                    provider_message_id: n.provider_message_id.clone(),
                }),
                None => anyhow::bail!("stub fetch error"),
            }
        }
    }

    fn sample_notif() -> InboundNotification {
        InboundNotification {
            provider_message_id: "m1".into(),
            from: "alice@example.com".into(),
            to: "dj@jig.onl".into(),
            subject: "Hi".into(),
        }
    }

    /// Captured submit payloads, shared with the test for assertions.
    type Submitted = Arc<Mutex<Vec<Vec<u8>>>>;

    fn make_state(
        provider: Arc<dyn EmailProvider>,
    ) -> (Arc<InboundState>, Submitted) {
        let storage: Arc<dyn BridgeStorage> = Arc::new(MemStore::default());
        let submitted: Submitted = Arc::new(Mutex::new(Vec::new()));
        let s2 = submitted.clone();
        let submit = SubmitHandle::new_for_test(move |p: Vec<u8>| {
            let s = s2.clone();
            async move {
                s.lock().unwrap().push(p);
                Ok::<String, SubmitDenied>("cid".into())
            }
        });
        let state = Arc::new(build_state(provider, storage, submit));
        (state, submitted)
    }

    fn build_state(
        provider: Arc<dyn EmailProvider>,
        storage: Arc<dyn BridgeStorage>,
        submit: SubmitHandle,
    ) -> InboundState {
        let address_book = Arc::new(AddressBook::new(
            storage.clone(),
            None,
            "secret".into(),
            false,
            3600,
        ));
        InboundState {
            provider,
            address_book,
            submit,
            storage,
            managed_dids: ManagedDidRegistrar::new(|_| {}),
            bridge_secret: "secret".into(),
            strip_plus_tags: false,
        }
    }

    /// A state whose submit handle always denies. The channel-ensure marker is
    /// pre-seeded so the denial lands on the text-render submit (not channel-create).
    async fn denying_state(denial_kind: DenialKind) -> Arc<InboundState> {
        let storage: Arc<dyn BridgeStorage> = Arc::new(MemStore::default());
        let sender = shadow_did("secret", "alice@example.com", false).to_did_jig_string();
        let recipient = shadow_did("secret", "dj@jig.onl", false).to_did_jig_string();
        let slug = dm_channel_slug(&sender, &recipient);
        storage
            .put("channel-ensured", &slug, b"1", None)
            .await
            .unwrap();

        let submit = SubmitHandle::new_for_test(move |_p: Vec<u8>| async move {
            Err::<String, SubmitDenied>(match denial_kind {
                DenialKind::Rate => SubmitDenied::RateLimited {
                    retry_after_secs: 1,
                },
                DenialKind::Policy => SubmitDenied::PolicyBlocked {
                    reason: "nope".into(),
                },
                DenialKind::Unavailable => SubmitDenied::Unavailable,
            })
        });
        let provider: Arc<dyn EmailProvider> = Arc::new(StubProvider {
            notification: Some(sample_notif()),
            fetch_body: Some("hi".into()),
            verify_ok: true,
            fetch_calls: Arc::new(Mutex::new(0)),
        });
        Arc::new(build_state(provider, storage, submit))
    }

    #[derive(Clone, Copy)]
    enum DenialKind {
        Rate,
        Policy,
        Unavailable,
    }

    #[tokio::test]
    async fn inbound_submits_text_render_then_dedupes() {
        let fetch_calls = Arc::new(Mutex::new(0u32));
        let provider = Arc::new(StubProvider {
            notification: Some(sample_notif()),
            fetch_body: Some("hello from alice".into()),
            verify_ok: true,
            fetch_calls: fetch_calls.clone(),
        });
        let (state, submitted) = make_state(provider);

        let code1 =
            handle_inbound(state.clone(), HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code1, StatusCode::OK);
        let n1 = submitted.lock().unwrap().len();
        assert!(n1 >= 1, "should have submitted at least the text-render");

        // The last submitted payload is the text-render; decode + verify it.
        let last = submitted.lock().unwrap().last().unwrap().clone();
        let (manifest_bytes, _code, _sig): (Vec<u8>, Vec<u8>, Vec<u8>) =
            serde_json::from_slice(&last).unwrap();
        let manifest: jig_core::BlockManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(
            manifest.metadata.get("body").and_then(|v| v.as_str()),
            Some("hello from alice")
        );
        let expected_shadow = shadow_did("secret", "alice@example.com", false).to_did_jig_string();
        assert_eq!(
            manifest.authors.first().unwrap().did.to_string(),
            expected_shadow
        );

        // Second identical webhook (same provider_message_id) -> dedup, no new submits, no fetch.
        let code2 =
            handle_inbound(state.clone(), HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code2, StatusCode::OK);
        assert_eq!(
            submitted.lock().unwrap().len(),
            n1,
            "dedup: no second submit"
        );
        assert_eq!(
            *fetch_calls.lock().unwrap(),
            1,
            "dedup must skip the fetch on redelivery"
        );
    }

    #[tokio::test]
    async fn bad_signature_is_unauthorized() {
        let provider = Arc::new(StubProvider {
            notification: Some(sample_notif()),
            fetch_body: Some("x".into()),
            verify_ok: false,
            fetch_calls: Arc::new(Mutex::new(0)),
        });
        let (state, submitted) = make_state(provider);
        let code = handle_inbound(state, HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert_eq!(submitted.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn non_deliverable_event_is_ok_no_submit() {
        let fetch_calls = Arc::new(Mutex::new(0u32));
        let provider = Arc::new(StubProvider {
            notification: None,
            fetch_body: None,
            verify_ok: true,
            fetch_calls: fetch_calls.clone(),
        });
        let (state, submitted) = make_state(provider);
        let code = handle_inbound(state, HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(submitted.lock().unwrap().len(), 0);
        assert_eq!(*fetch_calls.lock().unwrap(), 0, "non-deliverable must not fetch");
    }

    #[tokio::test]
    async fn fetch_error_is_bad_gateway() {
        let provider = Arc::new(StubProvider {
            notification: Some(sample_notif()),
            fetch_body: None, // triggers fetch Err
            verify_ok: true,
            fetch_calls: Arc::new(Mutex::new(0)),
        });
        let (state, submitted) = make_state(provider);
        let code = handle_inbound(state, HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code, StatusCode::BAD_GATEWAY);
        assert_eq!(submitted.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn empty_body_is_dropped_not_submitted() {
        let provider = Arc::new(StubProvider {
            notification: Some(sample_notif()),
            fetch_body: Some("   ".into()),
            verify_ok: true,
            fetch_calls: Arc::new(Mutex::new(0)),
        });
        let (state, submitted) = make_state(provider);
        let code = handle_inbound(state, HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(
            submitted.lock().unwrap().len(),
            0,
            "blank-body email must not submit a block"
        );
    }

    #[tokio::test]
    async fn oversized_body_is_413() {
        let big = "x".repeat(MAX_INLINE_BYTES + 1);
        let provider = Arc::new(StubProvider {
            notification: Some(sample_notif()),
            fetch_body: Some(big),
            verify_ok: true,
            fetch_calls: Arc::new(Mutex::new(0)),
        });
        let (state, submitted) = make_state(provider);
        let code = handle_inbound(state, HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(submitted.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn rate_limited_submit_is_429() {
        let state = denying_state(DenialKind::Rate).await;
        let code = handle_inbound(state, HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn policy_blocked_submit_is_502() {
        let state = denying_state(DenialKind::Policy).await;
        let code = handle_inbound(state, HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn unavailable_submit_is_503() {
        let state = denying_state(DenialKind::Unavailable).await;
        let code = handle_inbound(state, HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    }
}
