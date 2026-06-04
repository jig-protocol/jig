//! `EmailBridge` — the in-process `Bridge` implementation that ties together
//! the provider, address book, inbound webhook, and server-driven outbound.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use axum::body::Bytes;
use axum::http::HeaderMap;
use base64::Engine as _;
use jig_bridge_core::{Bridge, BridgeContext, BridgeStorage, DeliveredBlock};

use crate::address_book::AddressBook;
use crate::config::EmailBridgeConfig;
use crate::inbound::{InboundState, handle_inbound};
use crate::outbound::block_to_outbound_email;
use crate::provider::EmailProvider;
use crate::resend::ResendProvider;

const OUTBOUND_SEEN_NS: &str = "outbound-seen";
const CHANNEL_EMAIL_NS: &str = "channel-email";

/// State the bridge needs to emit outbound email. Populated in `start()`.
struct OutboundCtx {
    provider: Arc<dyn EmailProvider>,
    storage: Arc<dyn BridgeStorage>,
    bridge_domain: String,
}

/// The email bridge. Construct via [`EmailBridge::from_config`] (production,
/// uses Resend) or [`EmailBridge::from_config_with_provider`] (tests, inject a
/// mock). `start()` wires everything; `outbound()` emits.
pub struct EmailBridge {
    config: EmailBridgeConfig,
    injected_provider: Option<Arc<dyn EmailProvider>>,
    outbound: Option<OutboundCtx>,
}

impl EmailBridge {
    /// Production constructor — uses a `ResendProvider` built from config.
    pub fn from_config(config: EmailBridgeConfig) -> Self {
        Self {
            config,
            injected_provider: None,
            outbound: None,
        }
    }

    /// Test/extension constructor — inject any `EmailProvider` (e.g. a mock).
    pub fn from_config_with_provider(
        config: EmailBridgeConfig,
        provider: Arc<dyn EmailProvider>,
    ) -> Self {
        Self {
            config,
            injected_provider: Some(provider),
            outbound: None,
        }
    }
}

#[async_trait]
impl Bridge for EmailBridge {
    fn name(&self) -> &'static str {
        "email"
    }

    async fn start(&mut self, ctx: BridgeContext) -> Result<()> {
        let provider: Arc<dyn EmailProvider> = match &self.injected_provider {
            Some(p) => p.clone(),
            None => {
                // Production path: require the Resend credentials up front so a
                // misconfiguration fails loudly at startup, not silently as a
                // 401 on the first send/webhook.
                let api_key = self.config.resend_api_key.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "email bridge: resend_api_key is required when provider = resend"
                    )
                })?;
                let webhook_secret =
                    self.config.resend_webhook_secret.clone().ok_or_else(|| {
                        anyhow::anyhow!(
                            "email bridge: resend_webhook_secret is required when provider = resend"
                        )
                    })?;
                Arc::new(ResendProvider::new(api_key, webhook_secret))
            }
        };

        let storage = ctx.storage.clone();
        let address_book = Arc::new(AddressBook::new(
            storage.clone(),
            self.config.nameserver_url.clone(),
            self.config.bridge_secret.clone(),
            self.config.strip_plus_tags,
            self.config.addrbook_ttl_secs,
        ));

        // The InboundState lives inside the mounted route's handler closure,
        // which the server owns after draining the mount — so it stays alive for
        // the bridge's lifetime without a separate field on `self`.
        let inbound_state = Arc::new(InboundState {
            provider: provider.clone(),
            address_book,
            submit: ctx.submit,
            storage: storage.clone(),
            managed_dids: ctx.managed_dids.clone(),
            bridge_secret: self.config.bridge_secret.clone(),
            strip_plus_tags: self.config.strip_plus_tags,
        });

        // Mount the inbound webhook route. The server merges this under
        // /_bridge/email/, so the full path is /_bridge/email/inbound.
        let router = axum::Router::new().route(
            "/inbound",
            axum::routing::post(move |headers: HeaderMap, body: Bytes| {
                let st = inbound_state.clone();
                async move { handle_inbound(st, headers, body).await }
            }),
        );
        ctx.mount_router.mount(self.name(), router);

        self.outbound = Some(OutboundCtx {
            provider,
            storage,
            bridge_domain: self.config.bridge_domain.clone(),
        });
        Ok(())
    }

    async fn outbound(&self, block: &DeliveredBlock) -> Result<()> {
        let octx = self
            .outbound
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("email bridge outbound() called before start()"))?;

        // Dedup on the delivery CID (the fanout layer may deliver more than once).
        if octx
            .storage
            .get(OUTBOUND_SEEN_NS, &block.delivery_cid)
            .await?
            .is_some()
        {
            return Ok(());
        }

        let Some((slug, author_did)) = decode_channel_and_author(&block.bundle_b64) else {
            tracing::warn!(
                "email bridge: undecodable outbound block {}",
                block.delivery_cid
            );
            return Ok(());
        };

        // Reverse-resolve the channel to the external recipient email (recorded
        // by the inbound handler). No mapping => conversation we can't route
        // outward (e.g. Jig-initiated before any inbound) — drop with a warning.
        let to = match octx.storage.get(CHANNEL_EMAIL_NS, &slug).await? {
            Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            None => {
                tracing::warn!(
                    "email bridge: no recipient email mapped for channel {slug}, dropping outbound"
                );
                return Ok(());
            }
        };

        let from = synth_from(&author_did, &octx.bridge_domain);
        let Some(email) = block_to_outbound_email(block, to, from) else {
            // no body / oversized — block_to_outbound_email already logged.
            return Ok(());
        };

        match octx.provider.send(&email).await {
            Ok(_id) => {
                let _ = octx
                    .storage
                    .put(OUTBOUND_SEEN_NS, &block.delivery_cid, b"1", None)
                    .await;
                Ok(())
            }
            Err(e) => {
                // Logged by the dispatch task; no automatic retry in restricted-mode alpha.
                Err(anyhow::anyhow!("email provider send failed: {e}"))
            }
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Decode a delivered bundle to its channel slug + author DID. `None` on any
/// decode failure (never panics on the delivered bytes).
///
/// TODO: this re-decodes the bundle that `block_to_outbound_email` also decodes
/// (via `outbound::decode_manifest`). When the outbound path is refactored,
/// decode the manifest once and thread it through to avoid the double parse.
fn decode_channel_and_author(bundle_b64: &str) -> Option<(String, String)> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(bundle_b64)
        .ok()?;
    let (manifest_bytes, _code): (Vec<u8>, Vec<u8>) = serde_json::from_slice(&raw).ok()?;
    let manifest: jig_core::BlockManifest = serde_json::from_slice(&manifest_bytes).ok()?;
    let slug = manifest
        .metadata
        .get("channel")
        .and_then(|v| v.as_str())?
        .to_string();
    let author = manifest.authors.first()?.did.to_string();
    Some((slug, author))
}

/// Synthesize the outbound `from` address from the Jig author DID and the
/// bridge domain: `<short-form-of-did>@<bridge-domain>`. A nameserver alias
/// reverse-lookup is a later refinement; the short form is a stable,
/// practically-unique local-part for restricted-mode alpha (collision
/// probability is negligible and the address is informational — NOT an identity
/// claim or a security boundary).
fn synth_from(author_did: &str, bridge_domain: &str) -> String {
    // DID bodies are already lowercase base32, so no case-folding is needed.
    let local = author_did.strip_prefix("did:jig:z").unwrap_or(author_did);
    let local: String = local.chars().take(16).collect();
    format!("{local}@{bridge_domain}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::dm_channel_slug;
    use crate::provider::{InboundEmail, OutboundEmail, ProviderMessageId};
    use async_trait::async_trait;
    use jig_bridge_core::{ManagedDidRegistrar, RouterMount, SubmitHandle, SubscribeHandle};
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemStore {
        map: Mutex<HashMap<(String, String), Vec<u8>>>,
    }
    #[async_trait]
    impl BridgeStorage for MemStore {
        async fn put(&self, ns: &str, k: &str, v: &[u8], _e: Option<i64>) -> anyhow::Result<()> {
            self.map
                .lock()
                .unwrap()
                .insert((ns.into(), k.into()), v.to_vec());
            Ok(())
        }
        async fn get(&self, ns: &str, k: &str) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .get(&(ns.into(), k.into()))
                .cloned())
        }
        async fn delete(&self, ns: &str, k: &str) -> anyhow::Result<()> {
            self.map.lock().unwrap().remove(&(ns.into(), k.into()));
            Ok(())
        }
        async fn sweep_expired(&self, _ns: &str) -> anyhow::Result<u64> {
            Ok(0)
        }
    }

    /// Captures sent emails.
    #[derive(Default)]
    struct MockProvider {
        sent: Mutex<Vec<OutboundEmail>>,
    }
    #[async_trait]
    impl EmailProvider for MockProvider {
        async fn send(&self, msg: &OutboundEmail) -> anyhow::Result<ProviderMessageId> {
            self.sent.lock().unwrap().push(msg.clone());
            Ok("mock-id".into())
        }
        fn parse_webhook(&self, _: &HeaderMap, _: &[u8]) -> anyhow::Result<Option<InboundEmail>> {
            Ok(None)
        }
        fn verify_webhook(&self, _: &HeaderMap, _: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn test_config() -> EmailBridgeConfig {
        EmailBridgeConfig {
            bridge_secret: "secret".into(),
            bridge_domain: "jig.onl".into(),
            addrbook_ttl_secs: 3600,
            strip_plus_tags: false,
            provider: "resend".into(),
            // Present so the production `from_config` path (which now requires
            // them) can build a ResendProvider in the route-mount test.
            resend_api_key: Some("rk_test".into()),
            resend_webhook_secret: Some("whsec_test".into()),
            nameserver_url: None,
        }
    }

    fn test_ctx(storage: Arc<dyn BridgeStorage>, mount: RouterMount) -> BridgeContext {
        let submit = SubmitHandle::new_for_test(|_p| async {
            Ok::<String, jig_bridge_core::SubmitDenied>("cid".into())
        });
        BridgeContext::new_with_web(
            submit,
            SubscribeHandle::new_for_test(),
            toml::Value::Table(Default::default()),
            storage,
            ManagedDidRegistrar::new(|_| {}),
            mount,
        )
    }

    #[tokio::test]
    async fn start_mounts_inbound_route() {
        let storage: Arc<dyn BridgeStorage> = Arc::new(MemStore::default());
        let mount = RouterMount::new();
        let mut bridge = EmailBridge::from_config(test_config());
        bridge
            .start(test_ctx(storage, mount.clone()))
            .await
            .unwrap();
        let drained = mount.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, "email");
    }

    #[tokio::test]
    async fn start_errors_when_resend_key_missing() {
        // Production path (no injected provider) with no resend_api_key -> fail fast.
        let mut cfg = test_config();
        cfg.resend_api_key = None;
        let storage: Arc<dyn BridgeStorage> = Arc::new(MemStore::default());
        let mut bridge = EmailBridge::from_config(cfg);
        let err = bridge
            .start(test_ctx(storage, RouterMount::new()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("resend_api_key"), "got: {err}");
    }

    #[tokio::test]
    async fn outbound_before_start_errors() {
        let bridge = EmailBridge::from_config(test_config());
        let delivered = DeliveredBlock {
            bundle_b64: "x".into(),
            receipts: vec![],
            delivery_cid: "c".into(),
        };
        assert!(bridge.outbound(&delivered).await.is_err());
    }

    #[tokio::test]
    async fn outbound_sends_to_mapped_recipient_then_dedupes() {
        use base64::Engine as _;
        let storage: Arc<dyn BridgeStorage> = Arc::new(MemStore::default());
        let mock = Arc::new(MockProvider::default());

        // Build a real text-render block on a known DM slug, authored by a Jig user.
        let dir = tempfile::tempdir().unwrap();
        let author = jig_client::Identity::generate_and_save(dir.path()).unwrap();
        let shadow = "did:jig:zShadowAlice";
        let slug = dm_channel_slug(&author.did().to_string(), shadow);
        let hlc = jig_core::HlcTimestamp::now_wall(author.did().clone());
        let blk = jig_client::blocks::build_text_render(&author, &slug, "reply body", hlc);
        let delivered = DeliveredBlock {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(blk.canonical_bytes()),
            receipts: vec![],
            delivery_cid: "deliv-1".into(),
        };

        // Pre-seed the slug -> email map (the inbound handler would have done this).
        storage
            .put("channel-email", &slug, b"alice@example.com", None)
            .await
            .unwrap();

        let mut bridge = EmailBridge::from_config_with_provider(test_config(), mock.clone());
        bridge
            .start(test_ctx(storage.clone(), RouterMount::new()))
            .await
            .unwrap();

        bridge.outbound(&delivered).await.unwrap();
        {
            let sent = mock.sent.lock().unwrap();
            assert_eq!(sent.len(), 1, "one email should have been sent");
            assert_eq!(sent[0].to, "alice@example.com");
            assert!(sent[0].body.contains("reply body"));
            assert!(sent[0].from.ends_with("@jig.onl"));
        }

        // Second delivery of the same CID -> dedup, no new send.
        bridge.outbound(&delivered).await.unwrap();
        assert_eq!(mock.sent.lock().unwrap().len(), 1, "dedup: no second send");
    }

    #[tokio::test]
    async fn outbound_without_mapping_drops_quietly() {
        use base64::Engine as _;
        let storage: Arc<dyn BridgeStorage> = Arc::new(MemStore::default());
        let mock = Arc::new(MockProvider::default());
        let dir = tempfile::tempdir().unwrap();
        let author = jig_client::Identity::generate_and_save(dir.path()).unwrap();
        let hlc = jig_core::HlcTimestamp::now_wall(author.did().clone());
        let blk = jig_client::blocks::build_text_render(&author, "#dm/unmapped", "x", hlc);
        let delivered = DeliveredBlock {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(blk.canonical_bytes()),
            receipts: vec![],
            delivery_cid: "deliv-2".into(),
        };
        let mut bridge = EmailBridge::from_config_with_provider(test_config(), mock.clone());
        bridge
            .start(test_ctx(storage, RouterMount::new()))
            .await
            .unwrap();
        bridge.outbound(&delivered).await.unwrap(); // no mapping -> Ok, no send
        assert_eq!(mock.sent.lock().unwrap().len(), 0);
    }
}
