//! End-to-end email-bridge integration tests with a MockProvider.
//!
//! These tests exercise the complete inbound/outbound path through a real
//! `AppState` + ingest pipeline + mounted webhook route without live Resend:
//!
//! * `inbound_webhook_creates_channel_and_lands_block` — one POST to
//!   `/_bridge/email/inbound` creates the shadow-DID DM channel + two members.
//! * `round_trip_reply_emails_original_sender` — after an inbound webhook, the
//!   other channel member posts a block; the dispatch task calls
//!   `outbound()` → `MockProvider::send()` → the sent email is routed back to
//!   the original external sender.
//! * `denied_bridge_route_is_not_mounted` — a policy-denied bridge mounts no
//!   route (GET `/_bridge/email/inbound` → 404).
//! * `inbound_webhook_is_idempotent_on_redelivery` — posting the same
//!   provider_message_id twice doesn't duplicate channel state.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use jig_bridge_email::{
    EmailBridge, EmailBridgeConfig, EmailProvider, InboundEmail, OutboundEmail,
    ProviderMessageId, dm_channel_slug, shadow_did, shadow_signing_key,
};
use jig_config::v0_0_2_server::JigServerConfig;
use jig_server::v0_0_2::AppState;
use jig_server::v0_0_2_ws::build_v0_0_2_router;
use tower::ServiceExt;

const SECRET: &str = "test-secret";

// ---------------------------------------------------------------------------
// MockProvider
// ---------------------------------------------------------------------------

/// Captures every `send()` call. `parse_webhook` returns the configured
/// `InboundEmail` (or `None` if unset). `verify_webhook` always succeeds.
#[derive(Default)]
struct MockProvider {
    sent: Mutex<Vec<OutboundEmail>>,
    inbound: Mutex<Option<InboundEmail>>,
}

#[async_trait]
impl EmailProvider for MockProvider {
    async fn send(&self, msg: &OutboundEmail) -> anyhow::Result<ProviderMessageId> {
        self.sent.lock().unwrap().push(msg.clone());
        Ok("mock-id".into())
    }

    fn parse_webhook(
        &self,
        _headers: &HeaderMap,
        _body: &[u8],
    ) -> anyhow::Result<Option<InboundEmail>> {
        Ok(self.inbound.lock().unwrap().clone())
    }

    fn verify_webhook(&self, _headers: &HeaderMap, _body: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn email_cfg() -> EmailBridgeConfig {
    EmailBridgeConfig {
        bridge_secret: SECRET.into(),
        bridge_domain: "jig.onl".into(),
        addrbook_ttl_secs: 3600,
        strip_plus_tags: false,
        provider: "resend".into(),
        resend_api_key: None,
        resend_webhook_secret: None,
        nameserver_url: None,
    }
}

/// Build an `AppState`, optionally register + start the email bridge, return
/// `(state, router, tempdir-guard)`.
///
/// `permit = true`  → allow_list includes "email" + enabled = true
/// `permit = false` → deny_list includes "email" (policy-denied)
///
/// The router is built AFTER bridge registration so the inbound webhook route
/// is already mounted when permit = true.
async fn setup(
    mock: Arc<MockProvider>,
    permit: bool,
) -> (Arc<AppState>, axum::Router, tempfile::TempDir) {
    let bridges_toml = if permit {
        r#"
[bridges]
allow_list = ["email"]

[bridges.per_bridge.email]
enabled = true
"#
    } else {
        r#"
[bridges]
deny_list = ["email"]

[bridges.per_bridge.email]
enabled = true
"#
    };
    setup_with_toml(mock, bridges_toml).await
}

/// Like [`setup`] but with an explicit `[bridges]` TOML, for policy variants
/// (e.g. `enabled = false`) the bool flag can't express.
async fn setup_with_toml(
    mock: Arc<MockProvider>,
    bridges_toml: &str,
) -> (Arc<AppState>, axum::Router, tempfile::TempDir) {
    let mut config: JigServerConfig = toml::from_str(bridges_toml).expect("parse bridges config");
    // Use tempdir for both the keyfile and the SQLite DB so tests are
    // hermetic and don't pollute ~/.jig.
    let tempdir = tempfile::tempdir().unwrap();
    config.server.server_did_keyfile = tempdir
        .path()
        .join("server.key")
        .to_string_lossy()
        .into_owned();
    config.server.listen = "127.0.0.1:0".into();
    // Ensure all three block kinds the email bridge submits are allowed.
    // (JigServerConfig::default() already includes them; the TOML above
    // only overrides [bridges], so ServerSection uses its Default which
    // includes text-render + channel-create + member-add.)
    // Belt-and-suspenders: set explicitly so the test is self-documenting.
    config.server.allowed_block_kinds =
        vec!["text-render".into(), "channel-create".into(), "member-add".into()];

    let db_path = tempdir.path().join("server.db");
    let state = Arc::new(AppState::new(config.clone(), db_path).expect("AppState::new"));

    let bridge = Box::new(EmailBridge::from_config_with_provider(email_cfg(), mock));
    state
        .bridges
        .register_and_start(
            bridge,
            &config,
            state.ingest_ctx.store.clone(),
            state.ingest_ctx.clone(),
            state.ingest_ctx.fanout.clone(),
            state.bridge_router_mount.clone(),
        )
        .await
        .expect("register_and_start");

    // Build the router AFTER bridge registration so `bridge_router_mount`
    // has the email sub-router to drain.
    let router = build_v0_0_2_router(state.clone());
    (state, router, tempdir)
}

fn inbound_email() -> InboundEmail {
    InboundEmail {
        from: "alice@example.com".into(),
        to: "dj@jig.onl".into(),
        subject: "Hi".into(),
        body: "hello from alice".into(),
        provider_message_id: "m1".into(),
    }
}

/// POST the inbound webhook through the router. The router is cloned so it
/// can be driven again in subsequent calls.
async fn post_inbound(router: &axum::Router) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/_bridge/email/inbound")
        .header("content-type", "application/json")
        .body(Body::from(b"{}".as_ref()))
        .unwrap();
    router
        .clone()
        .oneshot(req)
        .await
        .expect("router oneshot should not error")
        .status()
}

/// The expected DM channel slug for the alice↔dj conversation (both shadows,
/// nameserver_url=None so recipient resolves to shadow-dj).
fn convo_slug() -> String {
    let alice = shadow_did(SECRET, "alice@example.com", false).to_did_jig_string();
    let dj = shadow_did(SECRET, "dj@jig.onl", false).to_did_jig_string();
    dm_channel_slug(&alice, &dj)
}

/// Drain ready spawned tasks on the current-thread test runtime by yielding
/// repeatedly. Deterministic (no wall-clock dependence): used to let the
/// `register_bridge_did` task wire the bridge sink into the Fanout BEFORE we
/// ingest the reply block — the fanout broadcast is one-shot, so the sink must
/// be registered at broadcast time.
async fn drain_spawned_tasks() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

/// Poll `cond` every 20ms until it is true or `secs` elapse (then panic).
/// Replaces fixed sleeps so the test isn't flaky under CI load — it waits only
/// as long as needed and fails loudly with a clear message on a real hang.
async fn wait_until<F: FnMut() -> bool>(mut cond: F, secs: u64, what: &str) {
    let start = tokio::time::Instant::now();
    let deadline = std::time::Duration::from_secs(secs);
    while !cond() {
        assert!(
            start.elapsed() < deadline,
            "timed out after {secs}s waiting for: {what}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Posting one inbound webhook creates the DM channel + shadow members in the
/// server's SQLite store.
#[tokio::test]
async fn inbound_webhook_creates_channel_and_lands_block() {
    let mock = Arc::new(MockProvider::default());
    *mock.inbound.lock().unwrap() = Some(inbound_email());
    let (state, router, _tmp) = setup(mock, true).await;

    let status = post_inbound(&router).await;
    assert_eq!(status, StatusCode::OK);

    let slug = convo_slug();
    let chan = state
        .ingest_ctx
        .store
        .get_channel_by_slug(&slug)
        .unwrap()
        .expect("DM channel must be created on first inbound");

    let members = state.ingest_ctx.store.list_members(&chan.id).expect("list_members should succeed");
    let alice_did = shadow_did(SECRET, "alice@example.com", false).to_did_jig_string();
    assert!(
        members.iter().any(|m| m.member_did == alice_did),
        "shadow-alice must be a member; members = {members:?}"
    );
    assert!(
        members.len() >= 2,
        "both shadow-alice and shadow-dj must be present; members = {members:?}"
    );
}

/// After an inbound webhook (alice→dj), the other member (shadow-dj) posting a
/// block triggers the fanout sink → dispatch task → `MockProvider::send()` back
/// to `alice@example.com`.
#[tokio::test]
async fn round_trip_reply_emails_original_sender() {
    let mock = Arc::new(MockProvider::default());
    *mock.inbound.lock().unwrap() = Some(inbound_email());
    let (state, router, _tmp) = setup(mock.clone(), true).await;

    // Inbound: alice → creates dm(shadow_alice, shadow_dj), registers
    // shadow_alice as a managed DID, records slug→alice@example.com.
    assert_eq!(
        post_inbound(&router).await,
        StatusCode::OK,
        "inbound webhook must return 200"
    );

    // Let the spawned `register_bridge_did` task wire the bridge sink into the
    // Fanout map before we ingest the reply block (the broadcast is one-shot).
    drain_spawned_tasks().await;

    // The other channel member (shadow-dj) replies. `shadow_signing_key`
    // derives the same key that the inbound handler resolved for dj@jig.onl
    // (nameserver_url=None → shadow resolution). We use that key to author
    // a text-render block on the DM channel, then ingest it directly.
    let slug = convo_slug();
    let dj_sk = shadow_signing_key(SECRET, "dj@jig.onl", false);
    let dj = jig_client::Identity::from_signing_key(dj_sk);
    let hlc = jig_core::HlcTimestamp::now_wall(dj.did().clone());
    let block =
        jig_client::blocks::build_text_render(&dj, &slug, "reply from dj", hlc);
    let bundle = jig_core::BlockBundle {
        manifest_bytes: &block.manifest_bytes,
        code_bytes: &block.code_bytes,
        resources: vec![],
    };
    jig_pipeline::ingest::ingest(
        &state.ingest_ctx,
        bundle,
        block.sender_sig.clone(),
        jig_pipeline::ingest::IngestSource::LocalClient { conn_id: 99 },
    )
    .await
    .expect("ingest reply block");

    // Wait (up to 5s) for the dispatch task to call outbound() → send().
    {
        let mock = mock.clone();
        wait_until(
            move || !mock.sent.lock().unwrap().is_empty(),
            5,
            "dispatch task should call MockProvider::send",
        )
        .await;
    }

    let sent = mock.sent.lock().unwrap();
    assert_eq!(sent.len(), 1, "exactly one outbound email expected; got {sent:?}");
    assert_eq!(
        sent[0].to, "alice@example.com",
        "outbound email must be addressed to the original inbound sender"
    );
    assert!(
        sent[0].body.contains("reply from dj"),
        "outbound email body must carry the block content; body = {:?}",
        sent[0].body
    );
}

/// When the bridge is policy-denied, `register_and_start` returns `Ok(false)`
/// and the route is NOT mounted → `POST /_bridge/email/inbound` returns 404.
#[tokio::test]
async fn denied_bridge_route_is_not_mounted() {
    let mock = Arc::new(MockProvider::default());
    *mock.inbound.lock().unwrap() = Some(inbound_email());
    let (_state, router, _tmp) = setup(mock, false).await;

    let status = post_inbound(&router).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a policy-denied bridge must not mount any route"
    );
}

/// A bridge that is allow-listed but `enabled = false` is also not loaded, so
/// its route is not mounted (404). Covers the kill-switch policy branch
/// end-to-end (distinct from the deny_list branch above).
#[tokio::test]
async fn disabled_bridge_route_is_not_mounted() {
    let mock = Arc::new(MockProvider::default());
    *mock.inbound.lock().unwrap() = Some(inbound_email());
    let toml = r#"
[bridges]
allow_list = ["email"]

[bridges.per_bridge.email]
enabled = false
"#;
    let (_state, router, _tmp) = setup_with_toml(mock, toml).await;
    assert_eq!(
        post_inbound(&router).await,
        StatusCode::NOT_FOUND,
        "an allow-listed but disabled bridge must not mount any route"
    );
}

/// Delivering the same webhook twice (same provider_message_id) must be
/// idempotent: the second delivery returns 200 and does not duplicate the
/// channel or its members.
#[tokio::test]
async fn inbound_webhook_is_idempotent_on_redelivery() {
    let mock = Arc::new(MockProvider::default());
    *mock.inbound.lock().unwrap() = Some(inbound_email());
    let (state, router, _tmp) = setup(mock, true).await;

    assert_eq!(post_inbound(&router).await, StatusCode::OK);
    // Same provider_message_id again → deduped, still 200, no duplicate state.
    assert_eq!(post_inbound(&router).await, StatusCode::OK);

    let slug = convo_slug();
    let chan = state
        .ingest_ctx
        .store
        .get_channel_by_slug(&slug)
        .unwrap()
        .expect("channel must exist after first inbound");
    let members = state.ingest_ctx.store.list_members(&chan.id).expect("list_members should succeed");
    assert_eq!(
        members.len(),
        2,
        "redelivery must not duplicate membership rows; got {members:?}"
    );
}
