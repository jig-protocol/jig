//! [`BridgeContext`] + the handles a bridge receives at `start()`.
//!
//! `BridgeContext` is what `Bridge::start` receives. It carries:
//! - `submit`: push translated blocks into ingest (may be denied — see [`SubmitDenied`])
//! - `subscribe`: watch channels for deliveries (unused by server-driven bridges)
//! - `config`: the bridge-specific `[bridge.<name>.config]` TOML table
//! - `storage`: the server's canonical [`crate::BridgeStorage`] backend (no bridge-owned DB)
//! - `managed_dids`: a [`ManagedDidRegistrar`] for DIDs the bridge owns, so the
//!   server routes those channels' deliveries to [`crate::Bridge::outbound`]
//! - `mount_router` (with the `web` feature): a [`crate::web::RouterMount`] for
//!   registering HTTP routes under `/_bridge/<name>/`
//!
//! [`SubmitDenied`] is the error the submit handle returns when server policy
//! rejects a submission; the bridge must translate it back to its transport.

use thiserror::Error;

/// Reasons a bridge submission may be rejected by the server. The bridge
/// is responsible for translating the denial back to its transport's
/// failure semantics (e.g., SMTP 5xx bounce, IRC error message, etc.) —
/// silently dropping is never correct.
#[derive(Debug, Error)]
pub enum SubmitDenied {
    /// Server's allow_list / deny_list / allow_channels policy blocked
    /// the submission. `reason` is a short human-readable description.
    #[error("PolicyBlocked: {reason}")]
    PolicyBlocked { reason: String },

    /// Per-bridge rate limit exceeded. `retry_after_secs` is a hint for
    /// when the bridge may retry (best-effort, server may revise).
    #[error("RateLimited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Server is shutting down or otherwise not accepting submissions.
    #[error("Unavailable: server not accepting submissions")]
    Unavailable,
}

use crate::storage::BridgeStorage;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Handle a bridge uses to submit a translated block bundle to the server's
/// ingest pipeline. Wraps `jig_pipeline::ingest::ingest` plus the per-bridge
/// policy enforcement (allow_channels, rate_limits, kill-switch).
///
/// The payload is the canonical bundle bytes (manifest + code) — same shape
/// as `jig_client::blocks::BuiltBlock::canonical_bytes`. The server applies
/// policy, then forwards to ingest.
pub struct SubmitHandle {
    inner: Arc<dyn SubmitFn>,
}

type SubmitFuture = Pin<Box<dyn Future<Output = Result<String, SubmitDenied>> + Send>>;

trait SubmitFn: Send + Sync {
    fn call(&self, payload: Vec<u8>) -> SubmitFuture;
}

impl<F, Fut> SubmitFn for F
where
    F: Fn(Vec<u8>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<String, SubmitDenied>> + Send + 'static,
{
    fn call(&self, payload: Vec<u8>) -> SubmitFuture {
        Box::pin((self)(payload))
    }
}

impl SubmitHandle {
    /// Server constructs this with a closure that performs policy
    /// enforcement + calls `jig_pipeline::ingest::ingest`.
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, SubmitDenied>> + Send + 'static,
    {
        Self { inner: Arc::new(f) }
    }

    /// Convenience for tests — constructs from a closure without explicit
    /// type bounds. Equivalent to `new` but the name flags it as test-only
    /// usage.
    #[doc(hidden)]
    pub fn new_for_test<F, Fut>(f: F) -> Self
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, SubmitDenied>> + Send + 'static,
    {
        Self::new(f)
    }

    /// Submit a translated bundle. Returns the assigned CID on success or
    /// `SubmitDenied` on policy/rate/availability failure.
    pub async fn submit(&self, payload: Vec<u8>) -> Result<String, SubmitDenied> {
        self.inner.call(payload).await
    }
}

/// Handle a bridge uses to subscribe to channel-scoped block deliveries.
/// Wraps `jig_pipeline::fanout::Fanout::subscribe_local`. Bridges typically
/// subscribe to the channels they bridge (e.g., the email bridge subscribes
/// to `#email-inbox`) so they can call `Bridge::outbound` on each delivered
/// block.
///
/// In alpha.1a this is a stub — alpha.email's in-process migration plumbs
/// real channel subscriptions through. Surfaces the type now so the trait
/// shape is stable.
pub struct SubscribeHandle {
    _private: (),
}

impl SubscribeHandle {
    /// Real constructor (used by the server). Stubbed in alpha.1a; alpha.email
    /// wires it to `jig_pipeline::fanout::Fanout`.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Test convenience constructor.
    #[doc(hidden)]
    pub fn new_for_test() -> Self {
        Self::new()
    }
}

impl Default for SubscribeHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle a bridge uses to register a DID it owns ("managed DID"). The server
/// records these so its fanout layer can call `Bridge::outbound` whenever a
/// delivered block's channel includes a managed DID (the server-driven
/// outbound model — see the email bridge design). Wraps a server-supplied
/// callback.
#[derive(Clone)]
pub struct ManagedDidRegistrar {
    inner: Arc<dyn Fn(String) + Send + Sync>,
}

impl ManagedDidRegistrar {
    pub fn new<F: Fn(String) + Send + Sync + 'static>(f: F) -> Self {
        Self { inner: Arc::new(f) }
    }
    /// Register `did` as owned by this bridge.
    ///
    /// Registration is infallible and idempotent: the server-supplied callback
    /// inserts into a managed-DID map (re-registering the same DID is a no-op).
    /// Keep it infallible — bridges call this on every shadow-DID mint, and a
    /// fallible signature would force error handling on a hot path that can't
    /// meaningfully fail.
    pub fn register(&self, did: String) {
        (self.inner)(did);
    }
}

/// What `Bridge::start` receives. Owned by the bridge for its lifetime.
pub struct BridgeContext {
    /// Push inbound-translated blocks to ingest. May be denied (see [`SubmitDenied`]).
    pub submit: SubmitHandle,
    /// Subscribe to channel-scoped block deliveries. Unused by the email
    /// bridge (server-driven outbound), retained for other bridges.
    pub subscribe: SubscribeHandle,
    /// Bridge-specific config from `[bridge.<name>.config]`.
    pub config: toml::Value,
    /// Canonical persistence handle (server's storage backend).
    pub storage: Arc<dyn BridgeStorage>,
    /// Register a DID this bridge owns, so the server routes its channels'
    /// deliveries to `Bridge::outbound`.
    pub managed_dids: ManagedDidRegistrar,
    /// HTTP route mount (only with the `web` feature).
    #[cfg(feature = "web")]
    pub mount_router: crate::web::RouterMount,
}

impl BridgeContext {
    /// Real constructor (server). The arg list is identical across feature
    /// states; with `web`, `mount_router` is initialized to a fresh collector.
    /// Prefer [`BridgeContext::new_with_web`] when the server supplies its own
    /// shared `RouterMount`.
    pub fn new(
        submit: SubmitHandle,
        subscribe: SubscribeHandle,
        config: toml::Value,
        storage: Arc<dyn BridgeStorage>,
        managed_dids: ManagedDidRegistrar,
    ) -> Self {
        Self {
            submit,
            subscribe,
            config,
            storage,
            managed_dids,
            #[cfg(feature = "web")]
            mount_router: crate::web::RouterMount::new(),
        }
    }

    /// `web` build with an explicit mount collector supplied by the server.
    #[cfg(feature = "web")]
    pub fn new_with_web(
        submit: SubmitHandle,
        subscribe: SubscribeHandle,
        config: toml::Value,
        storage: Arc<dyn BridgeStorage>,
        managed_dids: ManagedDidRegistrar,
        mount_router: crate::web::RouterMount,
    ) -> Self {
        Self {
            submit,
            subscribe,
            config,
            storage,
            managed_dids,
            mount_router,
        }
    }

    /// Convenience: register a managed DID.
    pub fn register_managed_did(&self, did: String) {
        self.managed_dids.register(did);
    }

    /// Test convenience: 3-arg shape preserved. Fills storage with a no-op
    /// stub and a no-op registrar (+ fresh RouterMount under `web`).
    #[doc(hidden)]
    pub fn new_for_test(
        submit: SubmitHandle,
        subscribe: SubscribeHandle,
        config: toml::Value,
    ) -> Self {
        struct NoopStore;
        #[async_trait::async_trait]
        impl BridgeStorage for NoopStore {
            async fn put(&self, _: &str, _: &str, _: &[u8], _: Option<i64>) -> anyhow::Result<()> {
                Ok(())
            }
            async fn get(&self, _: &str, _: &str) -> anyhow::Result<Option<Vec<u8>>> {
                Ok(None)
            }
            async fn delete(&self, _: &str, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn sweep_expired(&self, _: &str) -> anyhow::Result<u64> {
                Ok(0)
            }
        }
        Self::new(
            submit,
            subscribe,
            config,
            Arc::new(NoopStore),
            ManagedDidRegistrar::new(|_| {}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_denied_display_includes_reason() {
        let d = SubmitDenied::PolicyBlocked {
            reason: "channel #secret not in allow_channels".into(),
        };
        let s = format!("{d}");
        assert!(s.contains("PolicyBlocked"), "got: {s}");
        assert!(s.contains("channel #secret"), "got: {s}");
    }

    #[test]
    fn submit_denied_rate_limited_carries_retry_after() {
        let d = SubmitDenied::RateLimited {
            retry_after_secs: 30,
        };
        match d {
            SubmitDenied::RateLimited { retry_after_secs } => {
                assert_eq!(retry_after_secs, 30)
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn submit_denied_unavailable_no_data() {
        let d = SubmitDenied::Unavailable;
        let s = format!("{d}");
        assert!(s.contains("Unavailable"), "got: {s}");
    }

    #[tokio::test]
    async fn submit_handle_with_noop_resolver_accepts() {
        // Construct a SubmitHandle wired to a noop ingest fn that always
        // returns a CID. Verify the handle can be called and returns Ok.
        let handle =
            SubmitHandle::new_for_test(|_payload| async move { Ok("test-cid-12345".to_string()) });
        let cid = handle.submit(b"manifest|code|sig".to_vec()).await.unwrap();
        assert_eq!(cid, "test-cid-12345");
    }

    #[tokio::test]
    async fn submit_handle_propagates_denial() {
        // Wire to a noop that always denies.
        let handle = SubmitHandle::new_for_test(|_payload| async move {
            Err(SubmitDenied::PolicyBlocked {
                reason: "test denial".into(),
            })
        });
        let err = handle.submit(b"x".to_vec()).await.unwrap_err();
        match err {
            SubmitDenied::PolicyBlocked { reason } => assert_eq!(reason, "test denial"),
            other => panic!("expected PolicyBlocked, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bridge_context_carries_config_slice() {
        let cfg: toml::Value = toml::toml! {
            smtp_listen = "0.0.0.0:25"
            resend_key = "rk_test"
        }
        .into();
        let ctx = BridgeContext::new_for_test(
            SubmitHandle::new_for_test(|_| async { Ok("cid".into()) }),
            SubscribeHandle::new_for_test(),
            cfg,
        );
        assert_eq!(
            ctx.config.get("smtp_listen").and_then(|v| v.as_str()),
            Some("0.0.0.0:25")
        );
        assert_eq!(
            ctx.config.get("resend_key").and_then(|v| v.as_str()),
            Some("rk_test")
        );
    }

    #[tokio::test]
    async fn managed_did_registrar_records_dids() {
        use std::sync::{Arc, Mutex};
        let recorded = Arc::new(Mutex::new(Vec::<String>::new()));
        let rec2 = recorded.clone();
        let registrar = ManagedDidRegistrar::new(move |did: String| {
            rec2.lock().unwrap().push(did);
        });
        registrar.register("did:jig:zShadowAlice".to_string());
        registrar.register("did:jig:zShadowBob".to_string());
        assert_eq!(recorded.lock().unwrap().len(), 2);
        assert_eq!(recorded.lock().unwrap()[0], "did:jig:zShadowAlice");
    }

    #[tokio::test]
    async fn bridge_context_exposes_storage_and_registrar() {
        use std::sync::Arc;
        let storage: Arc<dyn crate::BridgeStorage> = Arc::new(NoopStorage);
        let registrar = ManagedDidRegistrar::new(|_| {});
        let ctx = BridgeContext::new(
            SubmitHandle::new_for_test(|_| async { Ok("cid".into()) }),
            SubscribeHandle::new_for_test(),
            toml::Value::Table(Default::default()),
            storage,
            registrar,
        );
        ctx.storage.put("ns", "k", b"v", None).await.unwrap();
        ctx.register_managed_did("did:jig:zX".to_string());
    }

    // Minimal storage stub for the context test.
    struct NoopStorage;
    #[async_trait::async_trait]
    impl crate::BridgeStorage for NoopStorage {
        async fn put(&self, _: &str, _: &str, _: &[u8], _: Option<i64>) -> anyhow::Result<()> {
            Ok(())
        }
        async fn get(&self, _: &str, _: &str) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn delete(&self, _: &str, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn sweep_expired(&self, _: &str) -> anyhow::Result<u64> {
            Ok(0)
        }
    }
}
