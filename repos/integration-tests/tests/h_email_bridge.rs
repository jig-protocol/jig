//! End-to-end email-bridge integration tests with a MockProvider.
//!
//! These tests exercise the inbound path through a real `AppState` + ingest
//! pipeline + mounted webhook route without live Resend:
//!
//! * `inbound_mail_is_refused_until_the_bridge_speaks_mls` — a mail thread is
//!   a restricted channel, restricted channels are always MLS (D25), and the
//!   bridge is not an MLS member yet: the server refuses the thread, and
//!   nothing about the mail is stored.
//! * `denied_bridge_route_is_not_mounted` — a policy-denied bridge mounts no
//!   route (GET `/_bridge/email/inbound` → 404).
//! * `disabled_bridge_route_is_not_mounted` — nor does a disabled one.
//!
//! The round trip (inbound thread, reply, outbound mail) comes back when the
//! bridge joins its threads' MLS groups; the outbound path keeps its unit
//! tests in `jig-bridge-email` meanwhile.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use jig_bridge_email::{
    EmailBridge, EmailBridgeConfig, EmailProvider, InboundEmail, InboundNotification,
    OutboundEmail, ProviderMessageId, shadow_did, thread_slug,
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
/// `InboundNotification` (or `None` if unset). `fetch_inbound` builds an
/// `InboundEmail` from the notification + the configured body.
/// `verify_webhook` always succeeds.
#[derive(Default)]
struct MockProvider {
    sent: Mutex<Vec<OutboundEmail>>,
    notification: Mutex<Option<InboundNotification>>,
    body: Mutex<String>,
}

#[async_trait]
impl EmailProvider for MockProvider {
    async fn send(&self, msg: &OutboundEmail) -> anyhow::Result<ProviderMessageId> {
        self.sent.lock().unwrap().push(msg.clone());
        Ok("mock-id".into())
    }

    fn verify_webhook(&self, _headers: &HeaderMap, _body: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }

    fn parse_webhook(
        &self,
        _headers: &HeaderMap,
        _body: &[u8],
    ) -> anyhow::Result<Option<InboundNotification>> {
        Ok(self.notification.lock().unwrap().clone())
    }

    async fn fetch_inbound(&self, n: &InboundNotification) -> anyhow::Result<InboundEmail> {
        let body = self.body.lock().unwrap().clone();
        Ok(InboundEmail {
            from: n.from.clone(),
            to: n.to.clone(),
            subject: n.subject.clone(),
            body,
            provider_message_id: n.provider_message_id.clone(),
        })
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
    config.keys.unlock = Some(jig_client::server_key::credential_for_tests(tempdir.path()));
    config.server.listen = "127.0.0.1:0".into();
    // Ensure all three block kinds the email bridge submits are allowed.
    // (JigServerConfig::default() already includes them; the TOML above
    // only overrides [bridges], so ServerSection uses its Default which
    // includes text-render + channel-create + member-add.)
    // Belt-and-suspenders: set explicitly so the test is self-documenting.
    config.server.allowed_block_kinds = vec![
        "text-render".into(),
        "channel-create".into(),
        "member-add".into(),
    ];

    let db_path = tempdir.path().join("server.db");
    let state = Arc::new(
        AppState::new(config.clone(), db_path, Default::default()).expect("AppState::new"),
    );

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

fn inbound_notification() -> InboundNotification {
    InboundNotification {
        provider_message_id: "m1".into(),
        from: "alice@example.com".into(),
        to: "dj@jig.onl".into(),
        subject: "Hi".into(),
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

/// The expected thread channel slug for the alice↔dj conversation (both shadows,
/// nameserver_url=None so recipient resolves to shadow-dj).
fn convo_slug() -> String {
    let alice = shadow_did(SECRET, "alice@example.com", false).to_did_jig_string();
    let dj = shadow_did(SECRET, "dj@jig.onl", false).to_did_jig_string();
    thread_slug(&alice, &dj)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A mail thread is a 1:1 restricted channel, and a restricted channel is
/// always MLS (D25). Until the bridge can be a member of its threads' groups,
/// the server refuses the thread: the webhook fails, and neither the channel
/// nor the mail's text is stored.
#[tokio::test]
async fn inbound_mail_is_refused_until_the_bridge_speaks_mls() {
    let mock = Arc::new(MockProvider::default());
    *mock.notification.lock().unwrap() = Some(inbound_notification());
    *mock.body.lock().unwrap() = "hello from alice".into();
    let (state, router, tmp) = setup(mock.clone(), true).await;

    assert_eq!(post_inbound(&router).await, StatusCode::BAD_GATEWAY);
    // A redelivery is refused the same way; nothing was half-made.
    assert_eq!(post_inbound(&router).await, StatusCode::BAD_GATEWAY);

    let slug = convo_slug();
    assert!(
        state
            .ingest_ctx
            .store
            .get_channel_by_slug_including_archived(&slug)
            .unwrap()
            .is_none(),
        "the server created a plaintext restricted thread"
    );
    assert!(mock.sent.lock().unwrap().is_empty());
    let mut disk = Vec::new();
    for entry in walkdir(tmp.path()) {
        disk.extend(std::fs::read(entry).unwrap_or_default());
    }
    assert!(
        !disk.windows(16).any(|w| w == b"hello from alice"),
        "the refused mail's text reached the server's disk"
    );
}

fn walkdir(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walkdir(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// When the bridge is policy-denied, `register_and_start` returns `Ok(false)`
/// and the route is NOT mounted → `POST /_bridge/email/inbound` returns 404.
#[tokio::test]
async fn denied_bridge_route_is_not_mounted() {
    let mock = Arc::new(MockProvider::default());
    *mock.notification.lock().unwrap() = Some(inbound_notification());
    *mock.body.lock().unwrap() = "hello from alice".into();
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
    *mock.notification.lock().unwrap() = Some(inbound_notification());
    *mock.body.lock().unwrap() = "hello from alice".into();
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
