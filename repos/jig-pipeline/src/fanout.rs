//! Fanout primitive for local subscribers + federated peers.
//!
//! v0.0.2 minimal surface: enough for `ingest()` to compile and call.
//! Full subscription/peer-registration logic lands in Task B8.

use crate::persist::{StoredBlock, StoredReceipt};

/// Multi-subscriber delivery primitive. Internally tracks local CLI
/// subscriptions (by channel-or-federation scope) and federated peer
/// outbound streams. v0.0.2 B6 ships the type with broadcast no-op
/// methods; B8 fills in actual subscriber + peer dispatch.
#[derive(Default)]
pub struct Fanout {
    // Internal state added in B8; for now just a marker.
    _private: (),
}

impl Fanout {
    pub fn new() -> Self {
        Self::default()
    }

    /// Broadcast a block + its receipt to BOTH local subscribers AND federated peers.
    /// Called by `ingest()` for blocks from local clients or admin endpoints.
    pub async fn broadcast(
        &self,
        _block: &StoredBlock,
        _receipt: &StoredReceipt,
    ) -> anyhow::Result<()> {
        // v0.0.2 stub. B8 implements actual delivery.
        Ok(())
    }

    /// Broadcast to LOCAL subscribers only — used when the source is a
    /// federated peer (avoids relay loops).
    pub async fn broadcast_local_only(
        &self,
        _block: &StoredBlock,
        _receipt: &StoredReceipt,
    ) -> anyhow::Result<()> {
        // v0.0.2 stub. B8 implements actual delivery.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanout_new_is_constructible() {
        let _f = Fanout::new();
    }

    #[tokio::test]
    async fn broadcast_stub_returns_ok() {
        let f = Fanout::new();
        let block = StoredBlock {
            cid: "bafy_test".to_string(),
            channel_id: None,
            block_kind: "text-render".to_string(),
            sender_did: "did:jig:zS".to_string(),
            sender_sig: vec![0; 64],
            bundle_bytes: b"{}".to_vec(),
            is_synthetic: false,
            hlc_wall_ms: 0,
            hlc_logical: 0,
            hlc_origin: "did:jig:zO".to_string(),
            posted_at: 0,
            origin_server: "ws://x".to_string(),
            federated_from: None,
        };
        let receipt = StoredReceipt {
            cid: "r_test".to_string(),
            block_cid: "bafy_test".to_string(),
            server_id: "did:jig:zSrv".to_string(),
            receipt_bytes: b"{}".to_vec(),
            render_hash: None,
            produced_at: 0,
        };
        f.broadcast(&block, &receipt).await.unwrap();
        f.broadcast_local_only(&block, &receipt).await.unwrap();
    }
}
