//! Validates the `Bridge` trait shape compiles + can be implemented end-to-end
//! by a noop. Not exercising real transport — that's per-bridge crate tests.

use anyhow::Result;
use async_trait::async_trait;
use jig_bridge_core::{Bridge, BridgeContext, DeliveredBlock, SubmitHandle, SubscribeHandle};
use std::sync::Arc;
use tokio::sync::Mutex;

struct NoopBridge {
    started: Arc<Mutex<bool>>,
    outbound_count: Arc<Mutex<u32>>,
    shutdown: Arc<Mutex<bool>>,
}

impl NoopBridge {
    fn new() -> Self {
        Self {
            started: Arc::new(Mutex::new(false)),
            outbound_count: Arc::new(Mutex::new(0)),
            shutdown: Arc::new(Mutex::new(false)),
        }
    }
}

#[async_trait]
impl Bridge for NoopBridge {
    fn name(&self) -> &'static str {
        "noop"
    }

    async fn start(&mut self, _ctx: BridgeContext) -> Result<()> {
        *self.started.lock().await = true;
        Ok(())
    }

    async fn outbound(&self, _block: &DeliveredBlock) -> Result<()> {
        *self.outbound_count.lock().await += 1;
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        *self.shutdown.lock().await = true;
        Ok(())
    }
}

#[tokio::test]
async fn noop_bridge_lifecycle() {
    let mut bridge = NoopBridge::new();
    assert_eq!(bridge.name(), "noop");
    assert!(!*bridge.started.lock().await);

    let ctx = BridgeContext::new_for_test(
        SubmitHandle::new_for_test(|_| async { Ok("cid".into()) }),
        SubscribeHandle::new_for_test(),
        toml::Value::Table(Default::default()),
    );
    bridge.start(ctx).await.unwrap();
    assert!(*bridge.started.lock().await);

    let block = DeliveredBlock {
        bundle_b64: "stub".into(),
        receipts: vec![],
        delivery_cid: "stub-cid".into(),
    };
    bridge.outbound(&block).await.unwrap();
    bridge.outbound(&block).await.unwrap();
    assert_eq!(*bridge.outbound_count.lock().await, 2);

    bridge.shutdown().await.unwrap();
    assert!(*bridge.shutdown.lock().await);
}
