//! Bridge registry: server's load-time policy gate + lifecycle owner.
//!
//! Constructed once at AppState boot from [`JigServerConfig::bridges`].
//! For each `bridge_permitted(name)` bridge, the registry instantiates the
//! bridge (in alpha.1a, only the test fixtures; alpha.email registers the
//! real `jig-bridge-email`), calls `start()`, and tracks it for shutdown.

use anyhow::Result;
use base64::Engine as _;
use jig_bridge_core::Bridge;
use jig_config::v0_0_2_server::JigServerConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A loaded bridge, owned behind `Arc<Mutex<_>>` so both the server-driven
/// outbound dispatch task and `shutdown_all` can reach the same instance.
type LoadedBridge = Arc<Mutex<Box<dyn Bridge>>>;

pub struct BridgeRegistry {
    loaded: Mutex<HashMap<String, LoadedBridge>>,
    permitted_names: Vec<String>,
}

impl BridgeRegistry {
    /// Construct from config. Does NOT call `Bridge::start` — that happens
    /// in `register_and_start`. This separation lets tests construct a
    /// registry, register a TestBridge fixture, then call start.
    pub fn new(config: &JigServerConfig) -> Self {
        // Compute the list of permitted bridge names from the config so
        // observability surfaces (e.g., /.well-known/jig) can list them
        // even before any bridge factory has registered.
        let permitted: Vec<String> = config
            .bridges
            .per_bridge
            .keys()
            .filter(|name| config.bridge_permitted(name))
            .cloned()
            .collect();
        Self {
            loaded: Mutex::new(HashMap::new()),
            permitted_names: permitted,
        }
    }

    /// Bridge names that policy permits to load. Returned by
    /// `/.well-known/jig` so peers see what's bridged.
    pub fn permitted_names(&self) -> &[String] {
        &self.permitted_names
    }

    /// Register a bridge instance. Returns `Ok(false)` if policy denies the
    /// bridge (bridge dropped without calling start). Returns `Ok(true)` if
    /// the bridge was registered and `start()` succeeded.
    ///
    /// Builds the real [`jig_bridge_core::BridgeContext`]: the submit handle
    /// runs bridge submissions through `ingest` as [`IngestSource::Bridge`];
    /// storage is a bridge-name-scoped [`SqliteBridgeStorage`]; managed DIDs
    /// register into the fanout bridge-sink; and a spawned dispatch task turns
    /// each fanout delivery into a [`Bridge::outbound`] call.
    ///
    /// [`IngestSource::Bridge`]: jig_pipeline::ingest::IngestSource::Bridge
    /// [`SqliteBridgeStorage`]: crate::v0_0_2_bridge_storage::SqliteBridgeStorage
    pub async fn register_and_start(
        &self,
        bridge: Box<dyn Bridge>,
        config: &JigServerConfig,
        store: Arc<jig_pipeline::persist::SqliteStore>,
        ingest_ctx: Arc<jig_pipeline::ingest::IngestContext>,
        fanout: Arc<jig_pipeline::fanout::Fanout>,
        router_mount: jig_bridge_core::RouterMount,
    ) -> Result<bool> {
        let name = bridge.name().to_string();
        if !config.bridge_permitted(&name) {
            return Ok(false);
        }

        // submit handle: bridge payload (manifest, code, sig) -> ingest.
        let ingest_for_submit = ingest_ctx.clone();
        let submit = jig_bridge_core::SubmitHandle::new(move |payload: Vec<u8>| {
            let ctx = ingest_for_submit.clone();
            async move { submit_via_ingest(ctx, payload).await }
        });

        // storage: a bridge-name-scoped view over the server's SQLite store.
        let storage: Arc<dyn jig_bridge_core::BridgeStorage> = Arc::new(
            crate::v0_0_2_bridge_storage::SqliteBridgeStorage::new(store.clone(), name.clone()),
        );

        // managed-DID registrar -> fanout bridge-sink. A single mpsc carries
        // fanout deliveries for every managed DID this bridge owns; the
        // outbound task (below) turns them into Bridge::outbound calls.
        let (sink_tx, mut sink_rx) = tokio::sync::mpsc::unbounded_channel::<(
            jig_pipeline::persist::StoredBlock,
            jig_pipeline::persist::StoredReceipt,
        )>();
        let fanout_for_reg = fanout.clone();
        let sink_tx_for_reg = sink_tx.clone();
        let registrar = jig_bridge_core::ManagedDidRegistrar::new(move |did: String| {
            // register_bridge_did is synchronous, so registration completes
            // before the bridge's register() call returns — no spawn, no race.
            fanout_for_reg.register_bridge_did(did, sink_tx_for_reg.clone());
        });

        // bridge-specific config from `[bridges.per_bridge.<name>.config]`.
        let bridge_config = config
            .bridges
            .per_bridge
            .get(&name)
            .map(|b| toml::Value::Table(b.config.clone()))
            .unwrap_or_else(|| toml::Value::Table(Default::default()));

        let ctx = jig_bridge_core::BridgeContext::new_with_web(
            submit,
            jig_bridge_core::SubscribeHandle::new(),
            bridge_config,
            storage,
            registrar,
            router_mount,
        );

        let mut bridge = bridge;
        bridge.start(ctx).await?;

        // Registry owns the bridge behind Arc<Mutex> so the outbound task +
        // shutdown both reach it.
        let bridge_arc: LoadedBridge = Arc::new(Mutex::new(bridge));
        let bridge_for_outbound = bridge_arc.clone();
        tokio::spawn(async move {
            while let Some((blk, rcpt)) = sink_rx.recv().await {
                let delivered = jig_bridge_core::DeliveredBlock {
                    bundle_b64: base64::engine::general_purpose::STANDARD.encode(&blk.bundle_bytes),
                    receipts: vec![jig_bridge_core::ReceiptRef {
                        receipt_cid: rcpt.cid.clone(),
                        render_hash: rcpt.render_hash.clone(),
                        produced_at: rcpt.produced_at,
                    }],
                    delivery_cid: blk.cid.clone(),
                };
                let b = bridge_for_outbound.lock().await;
                if let Err(e) = b.outbound(&delivered).await {
                    tracing::warn!("bridge {} outbound error: {e}", b.name());
                }
            }
        });

        self.loaded.lock().await.insert(name, bridge_arc);
        Ok(true)
    }

    /// List loaded bridge names (post-start). Differs from `permitted_names`
    /// in that this reflects what actually started successfully.
    pub async fn loaded_names(&self) -> Vec<String> {
        self.loaded.lock().await.keys().cloned().collect()
    }

    /// Shut down all loaded bridges in registration order. Errors are
    /// logged via tracing but do not abort the shutdown loop.
    pub async fn shutdown_all(&self) -> Result<()> {
        let mut loaded = self.loaded.lock().await;
        for (name, bridge) in loaded.iter() {
            if let Err(e) = bridge.lock().await.shutdown().await {
                tracing::warn!("bridge {name} shutdown error: {e}");
            }
        }
        loaded.clear();
        Ok(())
    }
}

/// Construct + start every config-permitted bridge the server knows how to
/// build, mounting their routes into `state.bridge_router_mount`. Call this at
/// boot BEFORE `build_v0_0_2_router` drains the mount. A per-bridge start
/// failure is logged and skipped (the server runs without that bridge) — it
/// does not abort the whole boot.
pub async fn start_configured_bridges(state: &crate::v0_0_2::AppState) -> anyhow::Result<()> {
    if state.config.bridge_permitted("email") {
        match build_email_bridge(&state.config) {
            Ok(bridge) => {
                let started = state
                    .bridges
                    .register_and_start(
                        bridge,
                        &state.config,
                        state.ingest_ctx.store.clone(),
                        state.ingest_ctx.clone(),
                        state.ingest_ctx.fanout.clone(),
                        state.bridge_router_mount.clone(),
                    )
                    .await;
                match started {
                    Ok(true) => tracing::info!("email bridge started"),
                    Ok(false) => tracing::warn!("email bridge denied by policy after permit check"),
                    Err(e) => tracing::error!("email bridge failed to start: {e}"),
                }
            }
            Err(e) => tracing::error!("email bridge config invalid, not starting: {e}"),
        }
    }
    Ok(())
}

fn build_email_bridge(
    config: &JigServerConfig,
) -> anyhow::Result<Box<dyn jig_bridge_core::Bridge>> {
    let bcfg = config
        .bridges
        .per_bridge
        .get("email")
        .map(|b| toml::Value::Table(b.config.clone()))
        .unwrap_or_else(|| toml::Value::Table(Default::default()));
    let email_cfg = jig_bridge_email::EmailBridgeConfig::from_toml(&bcfg)?;
    Ok(Box::new(jig_bridge_email::EmailBridge::from_config(
        email_cfg,
    )))
}

/// Decode a bridge submit payload `(manifest_bytes, code_bytes, sig)` and run
/// it through the ingest pipeline as [`IngestSource::Bridge`]. Maps
/// [`IngestError`] to [`SubmitDenied`] so the bridge can translate it back to
/// its transport's failure semantics.
///
/// The payload is `serde_json::to_vec(&(manifest_bytes, code_bytes, sig))` — a
/// 3-tuple. `jig_pipeline::ingest::ingest` takes the signature separately from
/// the bundle, so the sig travels alongside the bundle bytes here (this is the
/// same canonical-bytes-plus-sig shape jig-client's `BuiltBlock` produces,
/// extended with the explicit sig field).
///
/// [`IngestSource::Bridge`]: jig_pipeline::ingest::IngestSource::Bridge
/// [`IngestError`]: jig_pipeline::ingest::IngestError
/// [`SubmitDenied`]: jig_bridge_core::SubmitDenied
async fn submit_via_ingest(
    ingest_ctx: Arc<jig_pipeline::ingest::IngestContext>,
    payload: Vec<u8>,
) -> Result<String, jig_bridge_core::SubmitDenied> {
    use jig_bridge_core::SubmitDenied;
    let (manifest_bytes, code_bytes, sig): (Vec<u8>, Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&payload).map_err(|e| SubmitDenied::PolicyBlocked {
            reason: format!("malformed bridge payload: {e}"),
        })?;
    let bundle = jig_core::BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    };
    jig_pipeline::ingest::ingest(
        &ingest_ctx,
        bundle,
        sig,
        jig_pipeline::ingest::IngestSource::Bridge,
    )
    .await
    .map_err(map_ingest_err)
}

/// Translate an ingest failure into the bridge-facing [`SubmitDenied`]. Policy
/// and validation failures map to `PolicyBlocked` (the bridge can bounce them);
/// persistence / internal failures map to `Unavailable` (transient — the bridge
/// may retry).
fn map_ingest_err(e: jig_pipeline::ingest::IngestError) -> jig_bridge_core::SubmitDenied {
    use jig_bridge_core::SubmitDenied;
    use jig_pipeline::ingest::IngestError;
    match e {
        IngestError::DisallowedBlockKind { kind } => SubmitDenied::PolicyBlocked {
            reason: format!("disallowed block kind: {kind}"),
        },
        IngestError::KindRequired => SubmitDenied::PolicyBlocked {
            reason: "block kind required".into(),
        },
        IngestError::InvalidSignature => SubmitDenied::PolicyBlocked {
            reason: "invalid signature".into(),
        },
        IngestError::BundleMalformed(m) => SubmitDenied::PolicyBlocked {
            reason: format!("bundle malformed: {m}"),
        },
        // PolicyBlocked, not Unavailable: retrying will not conjure the
        // channel. The bridge should bounce, and the operator should look at
        // why its ensure-channel step didn't run.
        ref e @ IngestError::UnknownChannel { .. } => SubmitDenied::PolicyBlocked {
            reason: e.to_string(),
        },
        IngestError::Identity(ide) => SubmitDenied::PolicyBlocked {
            reason: format!("identity: {ide}"),
        },
        // The bridge built a block without the field the kind requires — its bug,
        // and a retry sends the same thing again.
        ref e @ IngestError::MissingMetadata { .. } => SubmitDenied::PolicyBlocked {
            reason: e.to_string(),
        },
        // This server does not execute the kind at all, which is a standing
        // property of its configuration rather than a passing condition.
        ref e @ IngestError::NoExecutor { .. } => SubmitDenied::PolicyBlocked {
            reason: e.to_string(),
        },
        // The bridge's shadow identity tried to change a channel it does not
        // own. A retry sends the same signature; bounce it.
        ref e @ IngestError::NotChannelOwner { .. } => SubmitDenied::PolicyBlocked {
            reason: e.to_string(),
        },
        ref e @ IngestError::NotChannelMember { .. } => SubmitDenied::PolicyBlocked {
            reason: e.to_string(),
        },
        // Unavailable, not PolicyBlocked: the block is fine and execution failed
        // on this host, so a retry may well succeed.
        IngestError::RenderFailed { .. } => SubmitDenied::Unavailable,
        IngestError::Persist(_) | IngestError::Other(_) => SubmitDenied::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use jig_bridge_core::{BridgeContext, DeliveredBlock, RouterMount};
    use jig_pipeline::{
        executor::BlockExecutor,
        fanout::Fanout,
        hlc::HlcClock,
        identity::TofuResolver,
        ingest::{IngestContext, IngestSource, ingest},
        persist::{SqliteStore, StoredChannel, StoredMembership},
    };
    use std::sync::Arc;
    use tokio::sync::Mutex;

    struct TestBridge {
        name: &'static str,
        started: Arc<Mutex<bool>>,
    }

    impl TestBridge {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                started: Arc::new(Mutex::new(false)),
            }
        }
        fn started_flag(&self) -> Arc<Mutex<bool>> {
            self.started.clone()
        }
    }

    #[async_trait]
    impl Bridge for TestBridge {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn start(&mut self, _ctx: BridgeContext) -> Result<()> {
            *self.started.lock().await = true;
            Ok(())
        }
        async fn outbound(&self, _b: &DeliveredBlock) -> Result<()> {
            Ok(())
        }
        async fn shutdown(&mut self) -> Result<()> {
            Ok(())
        }
    }

    /// A bridge that, on `start()`, registers a managed (shadow) DID and counts
    /// every `outbound()` call. Used to prove the server-driven outbound path:
    /// ingest a block on a channel containing the shadow DID -> fanout routes
    /// it to the bridge sink -> the dispatch task calls `outbound()`.
    struct RecordingBridge {
        name: &'static str,
        shadow_did: String,
        outbound_hits: Arc<Mutex<u32>>,
    }

    #[async_trait]
    impl Bridge for RecordingBridge {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn start(&mut self, ctx: BridgeContext) -> Result<()> {
            ctx.register_managed_did(self.shadow_did.clone());
            Ok(())
        }
        async fn outbound(&self, _b: &DeliveredBlock) -> Result<()> {
            *self.outbound_hits.lock().await += 1;
            Ok(())
        }
        async fn shutdown(&mut self) -> Result<()> {
            Ok(())
        }
    }

    /// Build the dependency bundle `register_and_start` now requires. Mirrors
    /// `AppState::for_test`'s `IngestContext` build (in-memory SQLite, TOFU
    /// resolver, generated server key, text-render allowed) and shares one
    /// `Arc<Fanout>` between the ingest context and the returned fanout so a
    /// block ingested through `ingest_ctx` reaches the registered bridge sink.
    fn test_deps() -> (
        Arc<SqliteStore>,
        Arc<IngestContext>,
        Arc<Fanout>,
        RouterMount,
    ) {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let secret: [u8; 32] = rand::random();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let server_did = jig_core::Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());
        let identity = Arc::new(TofuResolver::new(store.clone()));
        let hlc_clock = Arc::new(HlcClock::new(server_did.clone()));
        let fanout = Arc::new(Fanout::new());
        let ingest_ctx = Arc::new(IngestContext {
            store: store.clone(),
            identity,
            hlc_clock,
            allowed_block_kinds: vec!["text-render".to_string()],
            server_did: server_did.clone(),
            server_key: signing_key,
            fanout: fanout.clone(),
            server_url: "ws://127.0.0.1:0".to_string(),
            naively_allow_unknown_handles_fallback: false,
            executor: Some(BlockExecutor::shared()),
        });
        (store, ingest_ctx, fanout, RouterMount::new())
    }

    #[tokio::test]
    async fn registry_default_config_denies_all() {
        let cfg = JigServerConfig::default();
        let reg = BridgeRegistry::new(&cfg);
        let bridge = TestBridge::new("email");
        let started_flag = bridge.started_flag();
        let (store, ingest_ctx, fanout, mount) = test_deps();

        let started = reg
            .register_and_start(Box::new(bridge), &cfg, store, ingest_ctx, fanout, mount)
            .await
            .unwrap();
        assert!(
            !started,
            "deny-by-default: TestBridge with no policy entry should not start"
        );
        assert!(!*started_flag.lock().await);
        assert!(reg.loaded_names().await.is_empty());
    }

    #[tokio::test]
    async fn registry_loads_allowlisted_enabled_bridge() {
        let toml = r##"
            [bridges]
            allow_list = ["email"]

            [bridges.per_bridge.email]
            enabled = true
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        let reg = BridgeRegistry::new(&cfg);
        let bridge = TestBridge::new("email");
        let started_flag = bridge.started_flag();
        let (store, ingest_ctx, fanout, mount) = test_deps();

        let started = reg
            .register_and_start(Box::new(bridge), &cfg, store, ingest_ctx, fanout, mount)
            .await
            .unwrap();
        assert!(started);
        assert!(*started_flag.lock().await);
        assert_eq!(reg.loaded_names().await, vec!["email".to_string()]);
    }

    #[tokio::test]
    async fn registry_skips_disabled_bridge() {
        let toml = r##"
            [bridges]
            allow_list = ["email"]

            [bridges.per_bridge.email]
            enabled = false
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        let reg = BridgeRegistry::new(&cfg);
        let bridge = TestBridge::new("email");
        let started_flag = bridge.started_flag();
        let (store, ingest_ctx, fanout, mount) = test_deps();

        let started = reg
            .register_and_start(Box::new(bridge), &cfg, store, ingest_ctx, fanout, mount)
            .await
            .unwrap();
        assert!(
            !started,
            "enabled=false acts as kill-switch even if allowlisted"
        );
        assert!(!*started_flag.lock().await);
    }

    #[tokio::test]
    async fn registry_deny_star_blocks_everything() {
        let toml = r##"
            [bridges]
            allow_list = ["email"]
            deny_list = ["*"]

            [bridges.per_bridge.email]
            enabled = true
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        let reg = BridgeRegistry::new(&cfg);
        let bridge = TestBridge::new("email");
        let (store, ingest_ctx, fanout, mount) = test_deps();

        let started = reg
            .register_and_start(Box::new(bridge), &cfg, store, ingest_ctx, fanout, mount)
            .await
            .unwrap();
        assert!(
            !started,
            "deny_list = [\"*\"] blocks even allowlisted+enabled bridges"
        );
    }

    #[tokio::test]
    async fn permitted_names_lists_policy_permitted_bridges() {
        let toml = r##"
            [bridges]
            allow_list = ["email", "slack"]

            [bridges.per_bridge.email]
            enabled = true

            [bridges.per_bridge.slack]
            enabled = false
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        let reg = BridgeRegistry::new(&cfg);
        // permitted_names lists what POLICY allows (= email; slack is disabled)
        // Order is by BTreeMap iteration (sorted).
        let names = reg.permitted_names();
        assert_eq!(names, &["email".to_string()]);
    }

    #[tokio::test]
    async fn registered_managed_did_receives_outbound_on_matching_block() {
        use jig_client::{Identity, blocks::build_text_render};
        use jig_core::{BlockBundle, HlcTimestamp};
        use tempfile::tempdir;

        let toml = r##"
            [bridges]
            allow_list = ["email"]

            [bridges.per_bridge.email]
            enabled = true
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        let (store, ingest_ctx, fanout, mount) = test_deps();

        // A recording bridge that registers a shadow DID in start().
        let shadow_did = "did:jig:zShadowAlice".to_string();
        let outbound_hits = Arc::new(Mutex::new(0u32));
        let bridge = RecordingBridge {
            name: "email",
            shadow_did: shadow_did.clone(),
            outbound_hits: outbound_hits.clone(),
        };

        let reg = BridgeRegistry::new(&cfg);
        let started = reg
            .register_and_start(
                Box::new(bridge),
                &cfg,
                store.clone(),
                ingest_ctx.clone(),
                fanout.clone(),
                mount,
            )
            .await
            .unwrap();
        assert!(started);

        // Channel "#dm/x" has the shadow DID as a member. Channels are keyed by
        // their channel-create CID (not the slug), and memberships reference that
        // CID — so we create the channel row with a CID-shaped id distinct from
        // the slug, and key the membership on that id. Ingest resolves the
        // block's slug -> channel CID via get_channel_by_slug before listing
        // members (see jig-pipeline ingest bridge-sink dispatch).
        store
            .upsert_channel(&StoredChannel {
                id: "bafyDmX".to_string(),
                slug: "#dm/x".to_string(),
                visibility: "restricted".to_string(),
                created_at: 0,
                owner_did: shadow_did.clone(),
            })
            .unwrap();
        store
            .upsert_membership(&StoredMembership {
                channel_id: "bafyDmX".to_string(),
                member_did: shadow_did.clone(),
                role: "member".to_string(),
                joined_at: 0,
                source_block_cid: "seed".to_string(),
            })
            .unwrap();

        // Bob (NOT the shadow DID) posts a text-render block to "#dm/x". He
        // is the DM's other member, exactly as `ensure_dm_channel` would have
        // enrolled him: the channel is restricted, and a non-member's post is
        // refused at ingest before it reaches fanout.
        let dir = tempdir().unwrap();
        let bob = Identity::generate_and_save(&dir.keep()).unwrap();
        store
            .upsert_membership(&StoredMembership {
                channel_id: "bafyDmX".to_string(),
                member_did: bob.did_string(),
                role: "member".to_string(),
                joined_at: 0,
                source_block_cid: "seed".to_string(),
            })
            .unwrap();
        let hlc = HlcTimestamp {
            wall_ms: 1_747_680_000_000,
            logical: 0,
            server_did: bob.did().clone(),
        };
        let block = build_text_render(&bob, "#dm/x", "hello shadow", hlc);
        let bundle = BlockBundle {
            manifest_bytes: &block.manifest_bytes,
            code_bytes: &block.code_bytes,
            resources: vec![],
        };
        ingest(
            &ingest_ctx,
            bundle,
            block.sender_sig.clone(),
            IngestSource::LocalClient { conn_id: 1 },
        )
        .await
        .unwrap();

        // Give the dispatch task time to deliver the fanout item to outbound().
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(
            *outbound_hits.lock().await,
            1,
            "managed DID member should trigger exactly one outbound"
        );
    }

    #[tokio::test]
    async fn submit_via_ingest_rejects_malformed_payload() {
        let (_s, ingest_ctx, _f, _m) = test_deps();
        let err = submit_via_ingest(ingest_ctx, b"not a tuple".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            jig_bridge_core::SubmitDenied::PolicyBlocked { .. }
        ));
    }

    #[tokio::test]
    async fn boot_starts_and_mounts_email_bridge_when_permitted() {
        use tower::ServiceExt;

        // Config that permits the email bridge with a minimal valid config.
        let toml = r##"
            [bridges]
            allow_list = ["email"]

            [bridges.per_bridge.email]
            enabled = true

            [bridges.per_bridge.email.config]
            bridge_secret = "s3cr3t"
            bridge_domain = "jig.onl"
            resend_api_key = "rk_test"
            resend_webhook_secret = "whsec_test"
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).expect("parse config");
        let state = std::sync::Arc::new(
            crate::v0_0_2::AppState::for_test_with_config(cfg).expect("build state"),
        );

        start_configured_bridges(&state).await.unwrap();

        // The bridge actually started.
        assert!(
            state
                .bridges
                .loaded_names()
                .await
                .contains(&"email".to_string()),
            "email bridge should be in loaded_names after boot"
        );

        // Its inbound route is mounted: build the router (drains the mount) and
        // POST to /_bridge/email/inbound — expect NOT 404 (route exists). With no
        // svix signature headers the ResendProvider verify fails -> some non-404 status.
        let router = crate::v0_0_2_ws::build_v0_0_2_router(state.clone());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/_bridge/email/inbound")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            axum::http::StatusCode::NOT_FOUND,
            "inbound route should be mounted (got {})",
            resp.status()
        );
    }
}
