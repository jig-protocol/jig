//! Fanout: multi-subscriber block delivery.
//!
//! Two kinds of subscribers:
//!
//! - **Local** — CLI clients on this server subscribed to a channel or
//!   to federation-level streams. Identified by a numeric `sub_id`.
//! - **Peer** — federated jig-servers (each with its own outbound stream).
//!   Identified by `peer_server_url`.
//!
//! `broadcast` delivers to BOTH; `broadcast_local_only` delivers ONLY
//! to local subs (used when the block came from a federated peer, to
//! prevent relay loops).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{RwLock, mpsc};

use crate::persist::{StoredBlock, StoredReceipt};

/// What scope a local subscriber is interested in.
#[derive(Debug, Clone)]
pub enum SubscriptionScope {
    /// A specific channel by slug (e.g. `"#hello"`).
    Channel(String),
    /// Federation-level subscription, filtered to specific block kinds.
    /// Empty `block_kinds` means "all kinds".
    Federation { block_kinds: Vec<String> },
}

type Delivery = (StoredBlock, StoredReceipt);
type DeliverySender = mpsc::UnboundedSender<Delivery>;

#[derive(Default)]
pub struct Fanout {
    next_id: AtomicU64,
    local: RwLock<HashMap<u64, (SubscriptionScope, DeliverySender)>>,
    peers: RwLock<HashMap<String, DeliverySender>>,
    bridge_dids: RwLock<HashMap<String, DeliverySender>>,
}

impl Fanout {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a local CLI subscriber. Returns a `sub_id` the caller uses
    /// to `unsubscribe_local` when the WSS connection drops.
    pub async fn subscribe_local(&self, scope: SubscriptionScope, tx: DeliverySender) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.local.write().await.insert(id, (scope, tx));
        id
    }

    pub async fn unsubscribe_local(&self, id: u64) {
        self.local.write().await.remove(&id);
    }

    /// Register an outbound federation peer. The caller is responsible for
    /// taking deliveries off `rx` and writing them onto the peer's WSS
    /// connection. Re-registering the same URL replaces the previous sender.
    pub async fn register_peer(&self, peer_server_url: String, tx: DeliverySender) {
        self.peers.write().await.insert(peer_server_url, tx);
    }

    pub async fn unregister_peer(&self, peer_server_url: &str) {
        self.peers.write().await.remove(peer_server_url);
    }

    /// Register a sink for a bridge-managed DID. When a broadcast block's
    /// channel includes this DID (and it isn't the sender), the delivery is
    /// routed here so the bridge can emit it externally. Re-registering the
    /// same DID replaces the previous sender.
    pub async fn register_bridge_did(&self, managed_did: String, tx: DeliverySender) {
        self.bridge_dids.write().await.insert(managed_did, tx);
    }

    pub async fn unregister_bridge_did(&self, managed_did: &str) {
        self.bridge_dids.write().await.remove(managed_did);
    }

    /// Like `broadcast`, but also dispatches to bridge sinks for any managed
    /// DID in `channel_member_dids` that isn't the block's sender.
    pub async fn broadcast_with_members(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
        channel_member_dids: &[String],
    ) -> anyhow::Result<()> {
        self.broadcast_to_locals(block, receipt).await;
        self.broadcast_to_peers(block, receipt).await;
        self.dispatch_to_bridges(block, receipt, channel_member_dids).await;
        Ok(())
    }

    /// Public wrapper so ingest can dispatch to bridge sinks on the
    /// federated-source path (which must skip peer re-broadcast).
    pub async fn dispatch_to_bridges_public(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
        channel_member_dids: &[String],
    ) {
        self.dispatch_to_bridges(block, receipt, channel_member_dids).await;
    }

    async fn dispatch_to_bridges(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
        channel_member_dids: &[String],
    ) {
        let sinks = self.bridge_dids.read().await;
        if sinks.is_empty() {
            return;
        }
        for did in channel_member_dids {
            if did == &block.sender_did {
                continue; // don't echo the author's own message back to them
            }
            if let Some(tx) = sinks.get(did) {
                let _ = tx.send((block.clone(), receipt.clone()));
            }
        }
    }

    /// Broadcast to BOTH local subscribers (filtered by scope match) and
    /// every registered federation peer. Called when the source is a
    /// local CLI or admin endpoint.
    pub async fn broadcast(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
    ) -> anyhow::Result<()> {
        self.broadcast_to_locals(block, receipt).await;
        self.broadcast_to_peers(block, receipt).await;
        Ok(())
    }

    /// Broadcast to LOCAL subscribers ONLY. Used when the source is a
    /// federated peer (re-broadcasting to peers would cause a relay loop).
    pub async fn broadcast_local_only(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
    ) -> anyhow::Result<()> {
        self.broadcast_to_locals(block, receipt).await;
        Ok(())
    }

    async fn broadcast_to_locals(&self, block: &StoredBlock, receipt: &StoredReceipt) {
        let subs = self.local.read().await;
        for (scope, tx) in subs.values() {
            let matches = match scope {
                SubscriptionScope::Channel(slug) => {
                    block.channel_id.as_deref() == Some(slug.as_str())
                }
                SubscriptionScope::Federation { block_kinds } => {
                    block_kinds.is_empty() || block_kinds.iter().any(|k| k == &block.block_kind)
                }
            };
            if matches {
                // Ignore send errors — receiver disconnected; cleanup happens
                // when the consumer calls unsubscribe_local.
                let _ = tx.send((block.clone(), receipt.clone()));
            }
        }
    }

    async fn broadcast_to_peers(&self, block: &StoredBlock, receipt: &StoredReceipt) {
        let peers = self.peers.read().await;
        for tx in peers.values() {
            let _ = tx.send((block.clone(), receipt.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_block(channel: Option<&str>, kind: &str) -> StoredBlock {
        StoredBlock {
            cid: "bafy_test".to_string(),
            channel_id: channel.map(String::from),
            block_kind: kind.to_string(),
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
        }
    }

    fn sample_receipt() -> StoredReceipt {
        StoredReceipt {
            cid: "r1".to_string(),
            block_cid: "bafy_test".to_string(),
            server_id: "did:jig:zSrv".to_string(),
            receipt_bytes: b"{}".to_vec(),
            render_hash: None,
            produced_at: 0,
        }
    }

    #[tokio::test]
    async fn local_subscriber_to_matching_channel_receives() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _ = f
            .subscribe_local(SubscriptionScope::Channel("#hello".to_string()), tx)
            .await;
        f.broadcast(
            &sample_block(Some("#hello"), "text-render"),
            &sample_receipt(),
        )
        .await
        .unwrap();
        let delivered = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered.0.cid, "bafy_test");
    }

    #[tokio::test]
    async fn local_subscriber_to_other_channel_does_not_receive() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _ = f
            .subscribe_local(SubscriptionScope::Channel("#other".to_string()), tx)
            .await;
        f.broadcast(
            &sample_block(Some("#hello"), "text-render"),
            &sample_receipt(),
        )
        .await
        .unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(result.is_err(), "should not have received any delivery");
    }

    #[tokio::test]
    async fn federation_subscriber_with_empty_block_kinds_gets_everything() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _ = f
            .subscribe_local(
                SubscriptionScope::Federation {
                    block_kinds: vec![],
                },
                tx,
            )
            .await;
        f.broadcast(&sample_block(None, "text-render"), &sample_receipt())
            .await
            .unwrap();
        let delivered = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered.0.block_kind, "text-render");
    }

    #[tokio::test]
    async fn federation_subscriber_filters_by_block_kinds() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _ = f
            .subscribe_local(
                SubscriptionScope::Federation {
                    block_kinds: vec!["text-render".to_string()],
                },
                tx,
            )
            .await;
        // Matching kind — delivered
        f.broadcast(&sample_block(None, "text-render"), &sample_receipt())
            .await
            .unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_ok());
        // Non-matching kind — NOT delivered
        f.broadcast(&sample_block(None, "channel-create"), &sample_receipt())
            .await
            .unwrap();
        let result2 = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn registered_peer_receives_broadcast() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        f.register_peer("wss://peer-a".to_string(), tx).await;
        f.broadcast(&sample_block(Some("#x"), "text-render"), &sample_receipt())
            .await
            .unwrap();
        let delivered = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered.0.cid, "bafy_test");
    }

    #[tokio::test]
    async fn broadcast_local_only_skips_peers() {
        let f = Fanout::new();
        let (peer_tx, mut peer_rx) = mpsc::unbounded_channel();
        let (local_tx, mut local_rx) = mpsc::unbounded_channel();
        f.register_peer("wss://peer-a".to_string(), peer_tx).await;
        let _ = f
            .subscribe_local(SubscriptionScope::Channel("#x".to_string()), local_tx)
            .await;

        f.broadcast_local_only(&sample_block(Some("#x"), "text-render"), &sample_receipt())
            .await
            .unwrap();

        // Local DID receive
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), local_rx.recv())
                .await
                .unwrap()
                .is_some()
        );
        // Peer did NOT
        let peer_result =
            tokio::time::timeout(std::time::Duration::from_millis(50), peer_rx.recv()).await;
        assert!(peer_result.is_err());
    }

    #[tokio::test]
    async fn unsubscribed_local_stops_receiving() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sub_id = f
            .subscribe_local(SubscriptionScope::Channel("#x".to_string()), tx)
            .await;
        f.unsubscribe_local(sub_id).await;
        f.broadcast(&sample_block(Some("#x"), "text-render"), &sample_receipt())
            .await
            .unwrap();
        // After unsubscribe the sender is dropped, so recv() returns None
        // immediately (channel closed) rather than timing out — both outcomes
        // confirm no delivery to the unsubscribed receiver.
        let result = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        let no_delivery = match result {
            Err(_timeout) => true, // timed out — nothing received
            Ok(None) => true,      // channel closed, no message
            Ok(Some(_)) => false,  // got a message — should not happen
        };
        assert!(
            no_delivery,
            "unsubscribed receiver should not get a delivery"
        );
    }

    #[tokio::test]
    async fn bridge_sink_receives_when_managed_did_is_member_and_not_sender() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        f.register_bridge_did("did:jig:zShadowAlice".to_string(), tx).await;

        // Block authored by bob (real), channel members = [bob, shadow-alice].
        let mut blk = sample_block(Some("#dm/x"), "text-render");
        blk.sender_did = "did:jig:zBob".to_string();
        f.broadcast_with_members(
            &blk, &sample_receipt(),
            &["did:jig:zBob".to_string(), "did:jig:zShadowAlice".to_string()],
        ).await.unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
            .await.unwrap().unwrap();
        assert_eq!(got.0.sender_did, "did:jig:zBob");
    }

    #[tokio::test]
    async fn bridge_sink_skips_when_managed_did_is_the_sender() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        f.register_bridge_did("did:jig:zShadowAlice".to_string(), tx).await;

        // Inbound: block authored BY shadow-alice. Must not echo back to her.
        let mut blk = sample_block(Some("#dm/x"), "text-render");
        blk.sender_did = "did:jig:zShadowAlice".to_string();
        f.broadcast_with_members(
            &blk, &sample_receipt(),
            &["did:jig:zBob".to_string(), "did:jig:zShadowAlice".to_string()],
        ).await.unwrap();

        let res = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(res.is_err(), "sender's own managed DID must not receive outbound");
    }

    #[tokio::test]
    async fn unregister_bridge_did_stops_delivery() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        f.register_bridge_did("did:jig:zShadowAlice".to_string(), tx).await;
        f.unregister_bridge_did("did:jig:zShadowAlice").await;
        let mut blk = sample_block(Some("#dm/x"), "text-render");
        blk.sender_did = "did:jig:zBob".to_string();
        f.broadcast_with_members(&blk, &sample_receipt(),
            &["did:jig:zBob".to_string(), "did:jig:zShadowAlice".to_string()]).await.unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        let no_delivery = res.is_err() || matches!(res, Ok(None));
        assert!(no_delivery, "unregistered bridge DID should not receive");
    }
}
