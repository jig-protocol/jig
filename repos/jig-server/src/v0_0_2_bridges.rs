//! Bridge registry: server's load-time policy gate + lifecycle owner.
//!
//! Constructed once at AppState boot from [`JigServerConfig::bridges`].
//! For each `bridge_permitted(name)` bridge, the registry instantiates the
//! bridge (in alpha.1a, only the test fixtures; alpha.email registers the
//! real `jig-bridge-email`), calls `start()`, and tracks it for shutdown.

use anyhow::Result;
use jig_bridge_core::Bridge;
use jig_config::v0_0_2_server::JigServerConfig;
use std::collections::HashMap;
use tokio::sync::Mutex;

pub struct BridgeRegistry {
    loaded: Mutex<HashMap<String, Box<dyn Bridge>>>,
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
    pub async fn register_and_start(
        &self,
        bridge: Box<dyn Bridge>,
        ctx: jig_bridge_core::BridgeContext,
        config: &JigServerConfig,
    ) -> Result<bool> {
        let name = bridge.name().to_string();
        if !config.bridge_permitted(&name) {
            return Ok(false);
        }
        let mut bridge = bridge;
        bridge.start(ctx).await?;
        self.loaded.lock().await.insert(name, bridge);
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
        for (name, bridge) in loaded.iter_mut() {
            if let Err(e) = bridge.shutdown().await {
                tracing::warn!("bridge {name} shutdown error: {e}");
            }
        }
        loaded.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use jig_bridge_core::{BridgeContext, DeliveredBlock, SubmitHandle, SubscribeHandle};
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

    fn test_ctx() -> BridgeContext {
        BridgeContext::new_for_test(
            SubmitHandle::new_for_test(|_| async { Ok("cid".into()) }),
            SubscribeHandle::new_for_test(),
            toml::Value::Table(Default::default()),
        )
    }

    #[tokio::test]
    async fn registry_default_config_denies_all() {
        let cfg = JigServerConfig::default();
        let reg = BridgeRegistry::new(&cfg);
        let bridge = TestBridge::new("email");
        let started_flag = bridge.started_flag();

        let started = reg
            .register_and_start(Box::new(bridge), test_ctx(), &cfg)
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

        let started = reg
            .register_and_start(Box::new(bridge), test_ctx(), &cfg)
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

        let started = reg
            .register_and_start(Box::new(bridge), test_ctx(), &cfg)
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

        let started = reg
            .register_and_start(Box::new(bridge), test_ctx(), &cfg)
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
}
