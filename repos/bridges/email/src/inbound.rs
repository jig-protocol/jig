//! Inbound webhook handler: provider webhook -> verified, parsed, deduped ->
//! a text-render block authored by the sender's shadow identity, submitted to
//! ingest. Also ensures the 1:1 DM channel + memberships exist on first contact.

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use jig_bridge_core::{BridgeStorage, ManagedDidRegistrar, SubmitDenied, SubmitHandle};
use jig_client::Identity;

use crate::MAX_INLINE_BYTES;
use crate::address_book::AddressBook;
use crate::channel::{dm_channel_slug, ensure_dm_channel, submit_built_block};
use crate::identity::shadow_signing_key;
use crate::provider::EmailProvider;

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
pub async fn handle_inbound(state: Arc<InboundState>, headers: HeaderMap, body: Bytes) -> StatusCode {
    if state.provider.verify_webhook(&headers, &body).is_err() {
        return StatusCode::UNAUTHORIZED;
    }
    let email = match state.provider.parse_webhook(&headers, &body) {
        Ok(Some(e)) => e,
        Ok(None) => return StatusCode::OK, // bounce/status — logged upstream, no forward
        Err(e) => {
            tracing::warn!("email bridge: inbound parse failed: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };

    if email.body.len() > MAX_INLINE_BYTES {
        tracing::warn!("email bridge: inbound body {} bytes exceeds cap, rejecting", email.body.len());
        return StatusCode::PAYLOAD_TOO_LARGE;
    }

    // Dedup on the provider's stable message id (handles provider redelivery).
    match state.storage.get(INBOUND_SEEN_NS, &email.provider_message_id).await {
        Ok(Some(_)) => return StatusCode::OK,
        Ok(None) => {}
        Err(e) => {
            tracing::error!("email bridge: inbound dedup check failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    // The sender is always represented by the bridge's own shadow identity — the
    // bridge can only sign as itself, never as a real user. (Author = shadow.)
    let sk = shadow_signing_key(&state.bridge_secret, &email.from, state.strip_plus_tags);
    let shadow = Identity::from_signing_key(sk);
    let shadow_did = shadow.did().to_string();
    // Register the shadow so the server routes this channel's replies to outbound().
    // Idempotent; the registry is in-memory and rebuilt as inbound mail arrives (a
    // restart loses registrations until the next inbound per conversation).
    state.managed_dids.register(shadow_did.clone());

    // Recipient (the bridge address) -> the Jig user's DID (native if known).
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

    // Record slug -> external sender email so outbound() can find the recipient
    // when the Jig user replies (shadow DIDs are KDF-derived, not reversible).
    // Best-effort; last writer wins for a 1:1 conversation.
    if let Err(e) = state.storage.put("channel-email", &slug, email.from.as_bytes(), None).await {
        tracing::warn!("email bridge: failed to record channel-email map for {slug}: {e}");
    }

    // TODO(C9 round-trip): email.subject is currently dropped — text-render has
    // no subject metadata slot, and outbound derives a subject from the body.
    // Thread it through if/when blocks carry a subject field.
    let hlc = jig_core::HlcTimestamp::now_wall(shadow.did().clone());
    let block = jig_client::blocks::build_text_render(&shadow, &slug, &email.body, hlc);
    match submit_built_block(&state.submit, block).await {
        Ok(_cid) => {
            let expires = chrono::Utc::now().timestamp() + INBOUND_SEEN_TTL_SECS;
            if let Err(e) = state
                .storage
                .put(INBOUND_SEEN_NS, &email.provider_message_id, b"1", Some(expires))
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
    use crate::provider::{InboundEmail, OutboundEmail, ProviderMessageId};
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
            self.map.lock().unwrap().insert((ns.into(), key.into()), value.to_vec());
            Ok(())
        }
        async fn get(&self, ns: &str, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.map.lock().unwrap().get(&(ns.into(), key.into())).cloned())
        }
        async fn delete(&self, ns: &str, key: &str) -> Result<()> {
            self.map.lock().unwrap().remove(&(ns.into(), key.into()));
            Ok(())
        }
        async fn sweep_expired(&self, _ns: &str) -> Result<u64> {
            Ok(0)
        }
    }

    // Stub provider: configurable parse result + verify outcome.
    struct StubProvider {
        email: Option<InboundEmail>,
        verify_ok: bool,
    }
    #[async_trait]
    impl EmailProvider for StubProvider {
        async fn send(&self, _: &OutboundEmail) -> Result<ProviderMessageId> {
            Ok("pmid".into())
        }
        fn parse_webhook(&self, _: &HeaderMap, _: &[u8]) -> Result<Option<InboundEmail>> {
            Ok(self.email.clone())
        }
        fn verify_webhook(&self, _: &HeaderMap, _: &[u8]) -> Result<()> {
            if self.verify_ok { Ok(()) } else { Err(anyhow::anyhow!("bad sig")) }
        }
    }

    /// Captured submit payloads, shared with the test for assertions.
    type Submitted = Arc<Mutex<Vec<Vec<u8>>>>;

    fn make_state(provider: Arc<dyn EmailProvider>) -> (Arc<InboundState>, Submitted) {
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
        let address_book =
            Arc::new(AddressBook::new(storage.clone(), None, "secret".into(), false, 3600));
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

    /// A state whose submit handle always denies with `denial`, with the
    /// channel-ensure marker pre-seeded so the denial lands on the text-render
    /// submit (not the channel-create) — exercising the SubmitDenied->status map.
    async fn denying_state(denial_kind: DenialKind) -> Arc<InboundState> {
        let storage: Arc<dyn BridgeStorage> = Arc::new(MemStore::default());
        // Pre-seed the channel-ensured marker for the conversation sample_email
        // produces, so ensure_dm_channel short-circuits and the text-render submit
        // is the first (and denied) submission.
        let sender = shadow_did("secret", "alice@example.com", false).to_did_jig_string();
        let recipient = shadow_did("secret", "dj@jig.onl", false).to_did_jig_string();
        let slug = dm_channel_slug(&sender, &recipient);
        storage.put("channel-ensured", &slug, b"1", None).await.unwrap();

        let submit = SubmitHandle::new_for_test(move |_p: Vec<u8>| async move {
            Err::<String, SubmitDenied>(match denial_kind {
                DenialKind::Rate => SubmitDenied::RateLimited { retry_after_secs: 1 },
                DenialKind::Policy => SubmitDenied::PolicyBlocked { reason: "nope".into() },
                DenialKind::Unavailable => SubmitDenied::Unavailable,
            })
        });
        let provider: Arc<dyn EmailProvider> =
            Arc::new(StubProvider { email: Some(sample_email("hi")), verify_ok: true });
        Arc::new(build_state(provider, storage, submit))
    }

    #[derive(Clone, Copy)]
    enum DenialKind {
        Rate,
        Policy,
        Unavailable,
    }

    fn sample_email(body: &str) -> InboundEmail {
        InboundEmail {
            from: "alice@example.com".into(),
            to: "dj@jig.onl".into(),
            subject: "Hi".into(),
            body: body.into(),
            provider_message_id: "m1".into(),
        }
    }

    #[tokio::test]
    async fn inbound_submits_text_render_then_dedupes() {
        let provider = Arc::new(StubProvider { email: Some(sample_email("hello from alice")), verify_ok: true });
        let (state, submitted) = make_state(provider);

        let code1 = handle_inbound(state.clone(), HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code1, StatusCode::OK);
        let n1 = submitted.lock().unwrap().len();
        assert!(n1 >= 1, "should have submitted at least the text-render");

        // The last submitted payload is the text-render; decode + verify it.
        let last = submitted.lock().unwrap().last().unwrap().clone();
        let (manifest_bytes, _code, _sig): (Vec<u8>, Vec<u8>, Vec<u8>) =
            serde_json::from_slice(&last).unwrap();
        let manifest: jig_core::BlockManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(manifest.metadata.get("body").and_then(|v| v.as_str()), Some("hello from alice"));
        let expected_shadow = shadow_did("secret", "alice@example.com", false).to_did_jig_string();
        assert_eq!(manifest.authors.first().unwrap().did.to_string(), expected_shadow);

        // Second identical webhook (same provider_message_id) -> dedup, no new submits.
        let code2 = handle_inbound(state.clone(), HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code2, StatusCode::OK);
        assert_eq!(submitted.lock().unwrap().len(), n1, "dedup: no second submit");
    }

    #[tokio::test]
    async fn bad_signature_is_unauthorized() {
        let provider = Arc::new(StubProvider { email: Some(sample_email("x")), verify_ok: false });
        let (state, submitted) = make_state(provider);
        let code = handle_inbound(state, HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert_eq!(submitted.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn non_deliverable_event_is_ok_no_submit() {
        let provider = Arc::new(StubProvider { email: None, verify_ok: true });
        let (state, submitted) = make_state(provider);
        let code = handle_inbound(state, HeaderMap::new(), Bytes::from_static(b"{}")).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(submitted.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn oversized_body_is_413() {
        let big = "x".repeat(MAX_INLINE_BYTES + 1);
        let provider = Arc::new(StubProvider { email: Some(sample_email(&big)), verify_ok: true });
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
