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
use std::sync::RwLock as StdRwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{RwLock, mpsc};

use crate::persist::{StoredBlock, StoredChannel, StoredReceipt};

/// What scope a local subscriber is interested in.
#[derive(Debug, Clone)]
pub enum SubscriptionScope {
    /// A specific channel by slug (e.g. `"#hello"`).
    Channel(String),
    /// Federation-level subscription, filtered to specific block kinds.
    /// Empty `block_kinds` means "all kinds".
    Federation { block_kinds: Vec<String> },
}

/// Who a local subscription belongs to, as far as delivery is concerned.
///
/// Retained per subscription so authorization is decided on **every**
/// delivery. Deciding once at subscribe time would mean a revoked member keeps
/// receiving for as long as their connection lives — precisely the person an
/// operator revoking access wants to cut off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriberIdentity {
    /// A DID this connection proved when it subscribed.
    Did(String),
    /// No identity was checked, because the server runs with reads
    /// unauthenticated (`[auth] require_authenticated_reads = false`).
    /// Deliveries are not filtered. Explicit, so that a subscription with no
    /// DID is a decision the server made, never a default it fell into.
    Unchecked,
}

/// Who may receive blocks posted to one channel, resolved once per block by
/// whoever ingested it.
///
/// Carried as plain facts rather than as a callback into the store so that the
/// delivery loop does no I/O: ingest already resolves the channel row and its
/// members for bridge dispatch, and the decision needs nothing more.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryPolicy {
    /// `true` only for `visibility = "open"`; anything else is restricted.
    pub open: bool,
    pub owner_did: String,
    pub member_dids: Vec<String>,
}

impl DeliveryPolicy {
    pub fn for_channel(channel: &StoredChannel, member_dids: Vec<String>) -> Self {
        Self {
            open: crate::visibility::is_open(&channel.visibility),
            owner_did: channel.owner_did.clone(),
            member_dids,
        }
    }

    /// The same decision as the server's read gate, over facts resolved at
    /// ingest: open channels reach anyone; restricted ones reach the owner
    /// and members. An empty `owner_did` matches nobody.
    pub fn permits(&self, who: &SubscriberIdentity) -> bool {
        match who {
            SubscriberIdentity::Unchecked => true,
            SubscriberIdentity::Did(did) => {
                self.open
                    || (!self.owner_did.is_empty() && self.owner_did == *did)
                    || self.member_dids.iter().any(|m| m == did)
            }
        }
    }
}

type Delivery = (StoredBlock, StoredReceipt);
type DeliverySender = mpsc::UnboundedSender<Delivery>;

struct LocalSubscription {
    scope: SubscriptionScope,
    who: SubscriberIdentity,
    tx: DeliverySender,
}

#[derive(Default)]
pub struct Fanout {
    next_id: AtomicU64,
    local: RwLock<HashMap<u64, LocalSubscription>>,
    peers: RwLock<HashMap<String, DeliverySender>>,
    bridge_dids: StdRwLock<HashMap<String, DeliverySender>>,
}

impl Fanout {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a local CLI subscriber. Returns a `sub_id` the caller uses
    /// to `unsubscribe_local` when the WSS connection drops.
    ///
    /// `who` is the identity the subscriber PROVED — never one it merely
    /// claimed — or [`SubscriberIdentity::Unchecked`] on a server that does
    /// not authenticate reads.
    pub async fn subscribe_local(
        &self,
        scope: SubscriptionScope,
        who: SubscriberIdentity,
        tx: DeliverySender,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.local
            .write()
            .await
            .insert(id, LocalSubscription { scope, who, tx });
        id
    }

    pub async fn unsubscribe_local(&self, id: u64) {
        self.local.write().await.remove(&id);
    }

    /// How many local subscriptions are registered. For tests and gauges; the
    /// number a leak would grow.
    pub async fn local_subscription_count(&self) -> usize {
        self.local.read().await.len()
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

    /// Register a sink for a bridge-managed DID. Synchronous: the insert
    /// completes before this returns, so a caller that registers a DID and then
    /// returns can be sure a subsequently-delivered block finds the sink (no
    /// fire-and-forget window). Re-registering the same DID replaces the sender.
    pub fn register_bridge_did(&self, managed_did: String, tx: DeliverySender) {
        self.bridge_dids
            .write()
            .expect("bridge_dids poisoned")
            .insert(managed_did, tx);
    }

    pub fn unregister_bridge_did(&self, managed_did: &str) {
        self.bridge_dids
            .write()
            .expect("bridge_dids poisoned")
            .remove(managed_did);
    }

    /// Like `broadcast`, but also dispatches to bridge sinks for any managed
    /// DID among the policy's members that isn't the block's sender.
    pub async fn broadcast_with_members(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
        policy: Option<&DeliveryPolicy>,
    ) -> anyhow::Result<()> {
        self.broadcast_to_locals(block, receipt, policy).await;
        self.broadcast_to_peers(block, receipt).await;
        self.dispatch_to_bridges(block, receipt, policy);
        Ok(())
    }

    /// Public wrapper so ingest can dispatch to bridge sinks on the
    /// federated-source path (which must skip peer re-broadcast).
    pub async fn dispatch_to_bridges_public(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
        policy: Option<&DeliveryPolicy>,
    ) {
        self.dispatch_to_bridges(block, receipt, policy);
    }

    fn dispatch_to_bridges(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
        policy: Option<&DeliveryPolicy>,
    ) {
        // No resolved channel means no members to dispatch to.
        let Some(policy) = policy else {
            return;
        };
        // Collect matching sinks under a brief read lock, then send after
        // dropping it (never hold the lock across the send loop).
        let senders: Vec<DeliverySender> = {
            let sinks = self.bridge_dids.read().expect("bridge_dids poisoned");
            policy
                .member_dids
                .iter()
                .filter(|did| *did != &block.sender_did) // don't echo to the author
                .filter_map(|did| sinks.get(did).cloned())
                .collect()
        };
        for tx in senders {
            let _ = tx.send((block.clone(), receipt.clone()));
        }
    }

    /// Broadcast to BOTH local subscribers (filtered by scope match and by
    /// `policy`) and every registered federation peer. Called when the source
    /// is a local CLI or admin endpoint.
    pub async fn broadcast(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
        policy: Option<&DeliveryPolicy>,
    ) -> anyhow::Result<()> {
        self.broadcast_to_locals(block, receipt, policy).await;
        self.broadcast_to_peers(block, receipt).await;
        Ok(())
    }

    /// Broadcast to LOCAL subscribers ONLY. Used when the source is a
    /// federated peer (re-broadcasting to peers would cause a relay loop).
    pub async fn broadcast_local_only(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
        policy: Option<&DeliveryPolicy>,
    ) -> anyhow::Result<()> {
        self.broadcast_to_locals(block, receipt, policy).await;
        Ok(())
    }

    /// Deliver to every local subscriber whose scope matches AND whom
    /// `policy` permits. Both filters apply whatever the scope: a
    /// federation-scope subscription is a kind filter, not a licence to read
    /// every channel.
    ///
    /// `None` policy means the block is not scoped to a channel this server
    /// knows (control-plane blocks, or a federated block for a channel with no
    /// local row) — there is nothing to authorize against, so scope alone
    /// decides, as before.
    async fn broadcast_to_locals(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
        policy: Option<&DeliveryPolicy>,
    ) {
        let subs = self.local.read().await;
        for sub in subs.values() {
            let matches = match &sub.scope {
                SubscriptionScope::Channel(slug) => {
                    block.channel_id.as_deref() == Some(slug.as_str())
                }
                SubscriptionScope::Federation { block_kinds } => {
                    block_kinds.is_empty() || block_kinds.iter().any(|k| k == &block.block_kind)
                }
            };
            let permitted = policy.is_none_or(|p| p.permits(&sub.who));
            if matches && permitted {
                // Ignore send errors — receiver disconnected; cleanup happens
                // when the consumer calls unsubscribe_local.
                let _ = sub.tx.send((block.clone(), receipt.clone()));
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

    /// An open channel with these members — what ingest would resolve for a
    /// public channel the bridge tests below post into.
    fn open_with_members(members: &[&str]) -> DeliveryPolicy {
        DeliveryPolicy {
            open: true,
            owner_did: "did:jig:zOwner".to_string(),
            member_dids: members.iter().map(|m| m.to_string()).collect(),
        }
    }

    fn restricted(owner: &str, members: &[&str]) -> DeliveryPolicy {
        DeliveryPolicy {
            open: false,
            owner_did: owner.to_string(),
            member_dids: members.iter().map(|m| m.to_string()).collect(),
        }
    }

    fn did(s: &str) -> SubscriberIdentity {
        SubscriberIdentity::Did(s.to_string())
    }

    async fn subscribe_channel(
        f: &Fanout,
        slug: &str,
        who: SubscriberIdentity,
    ) -> mpsc::UnboundedReceiver<Delivery> {
        let (tx, rx) = mpsc::unbounded_channel();
        f.subscribe_local(SubscriptionScope::Channel(slug.to_string()), who, tx)
            .await;
        rx
    }

    async fn received(rx: &mut mpsc::UnboundedReceiver<Delivery>) -> bool {
        tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .is_ok_and(|d| d.is_some())
    }

    // ---- delivery policy ---------------------------------------------------

    #[test]
    fn policy_is_the_read_gate_over_resolved_facts() {
        let p = restricted("did:jig:zOwner", &["did:jig:zMember"]);
        assert!(p.permits(&did("did:jig:zOwner")));
        assert!(p.permits(&did("did:jig:zMember")));
        assert!(!p.permits(&did("did:jig:zStranger")));
        assert!(open_with_members(&[]).permits(&did("did:jig:zStranger")));
    }

    /// `Unchecked` is the escape hatch: no filtering, because nobody proved
    /// anything and the server chose not to ask.
    #[test]
    fn an_unchecked_subscriber_is_never_filtered() {
        assert!(restricted("did:jig:zOwner", &[]).permits(&SubscriberIdentity::Unchecked));
    }

    /// A row with no recorded owner must not match anyone, least of all a
    /// subscriber whose DID string is also empty.
    #[test]
    fn an_empty_owner_did_permits_nobody() {
        let p = restricted("", &[]);
        assert!(!p.permits(&did("")));
        assert!(!p.permits(&did("did:jig:zAnyone")));
    }

    #[test]
    fn policy_for_channel_fails_closed_on_the_visibility_string() {
        let row = |visibility: &str| StoredChannel {
            id: "bafy".to_string(),
            slug: "#x".to_string(),
            visibility: visibility.to_string(),
            created_at: 0,
            owner_did: "did:jig:zOwner".to_string(),
        };
        assert!(DeliveryPolicy::for_channel(&row("open"), vec![]).open);
        assert!(!DeliveryPolicy::for_channel(&row("restricted"), vec![]).open);
        assert!(!DeliveryPolicy::for_channel(&row("Open"), vec![]).open);
    }

    #[tokio::test]
    async fn a_restricted_block_reaches_members_and_the_owner_but_not_strangers() {
        let f = Fanout::new();
        let mut owner_rx = subscribe_channel(&f, "#private", did("did:jig:zOwner")).await;
        let mut member_rx = subscribe_channel(&f, "#private", did("did:jig:zMember")).await;
        let mut stranger_rx = subscribe_channel(&f, "#private", did("did:jig:zStranger")).await;

        f.broadcast(
            &sample_block(Some("#private"), "text-render"),
            &sample_receipt(),
            Some(&restricted("did:jig:zOwner", &["did:jig:zMember"])),
        )
        .await
        .unwrap();

        assert!(received(&mut owner_rx).await, "the owner must receive");
        assert!(received(&mut member_rx).await, "a member must receive");
        assert!(
            !received(&mut stranger_rx).await,
            "a stranger subscribed to a restricted channel must receive nothing"
        );
    }

    /// The policy is per delivery, so what changes between two blocks is what
    /// the subscriber sees. This is the revocation property at the fanout
    /// level: the subscription is untouched, the facts changed.
    #[tokio::test]
    async fn a_member_removed_between_two_blocks_receives_only_the_first() {
        let f = Fanout::new();
        let mut rx = subscribe_channel(&f, "#private", did("did:jig:zMember")).await;
        let block = sample_block(Some("#private"), "text-render");

        f.broadcast(
            &block,
            &sample_receipt(),
            Some(&restricted("did:jig:zOwner", &["did:jig:zMember"])),
        )
        .await
        .unwrap();
        assert!(received(&mut rx).await, "precondition: a member receives");

        f.broadcast(
            &block,
            &sample_receipt(),
            Some(&restricted("did:jig:zOwner", &[])),
        )
        .await
        .unwrap();
        assert!(
            !received(&mut rx).await,
            "delivery must stop the moment the membership is gone"
        );
    }

    /// A federation-scope subscription is a kind filter, not a licence: it
    /// must not see restricted channels its DID may not read.
    #[tokio::test]
    async fn a_federation_scope_subscriber_is_still_bound_by_the_policy() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        f.subscribe_local(
            SubscriptionScope::Federation {
                block_kinds: vec![],
            },
            did("did:jig:zStranger"),
            tx,
        )
        .await;

        f.broadcast(
            &sample_block(Some("#private"), "text-render"),
            &sample_receipt(),
            Some(&restricted("did:jig:zOwner", &[])),
        )
        .await
        .unwrap();
        assert!(!received(&mut rx).await);

        f.broadcast(
            &sample_block(Some("#public"), "text-render"),
            &sample_receipt(),
            Some(&open_with_members(&[])),
        )
        .await
        .unwrap();
        assert!(received(&mut rx).await, "open channels still flow");
    }

    /// No resolved channel, nothing to authorize against: scope alone decides,
    /// exactly as before policies existed. Control-plane blocks and federated
    /// blocks for channels with no local row take this path.
    #[tokio::test]
    async fn a_block_with_no_policy_is_delivered_on_scope_alone() {
        let f = Fanout::new();
        let mut rx = subscribe_channel(&f, "#remote-only", did("did:jig:zStranger")).await;
        f.broadcast(
            &sample_block(Some("#remote-only"), "text-render"),
            &sample_receipt(),
            None,
        )
        .await
        .unwrap();
        assert!(received(&mut rx).await);
    }

    /// Peers are servers, not readers; the local policy does not apply to
    /// them. (Federation trust is its own gate, not this one.)
    #[tokio::test]
    async fn peers_are_not_filtered_by_the_local_policy() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        f.register_peer("wss://peer-a".to_string(), tx).await;
        f.broadcast(
            &sample_block(Some("#private"), "text-render"),
            &sample_receipt(),
            Some(&restricted("did:jig:zOwner", &[])),
        )
        .await
        .unwrap();
        assert!(received(&mut rx).await);
    }

    // ---- scope matching ----------------------------------------------------

    #[tokio::test]
    async fn local_subscriber_to_matching_channel_receives() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _ = f
            .subscribe_local(
                SubscriptionScope::Channel("#hello".to_string()),
                SubscriberIdentity::Unchecked,
                tx,
            )
            .await;
        f.broadcast(
            &sample_block(Some("#hello"), "text-render"),
            &sample_receipt(),
            None,
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
            .subscribe_local(
                SubscriptionScope::Channel("#other".to_string()),
                SubscriberIdentity::Unchecked,
                tx,
            )
            .await;
        f.broadcast(
            &sample_block(Some("#hello"), "text-render"),
            &sample_receipt(),
            None,
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
                SubscriberIdentity::Unchecked,
                tx,
            )
            .await;
        f.broadcast(&sample_block(None, "text-render"), &sample_receipt(), None)
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
                SubscriberIdentity::Unchecked,
                tx,
            )
            .await;
        // Matching kind — delivered
        f.broadcast(&sample_block(None, "text-render"), &sample_receipt(), None)
            .await
            .unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_ok());
        // Non-matching kind — NOT delivered
        f.broadcast(
            &sample_block(None, "channel-create"),
            &sample_receipt(),
            None,
        )
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
        f.broadcast(
            &sample_block(Some("#x"), "text-render"),
            &sample_receipt(),
            None,
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
    async fn broadcast_local_only_skips_peers() {
        let f = Fanout::new();
        let (peer_tx, mut peer_rx) = mpsc::unbounded_channel();
        let (local_tx, mut local_rx) = mpsc::unbounded_channel();
        f.register_peer("wss://peer-a".to_string(), peer_tx).await;
        let _ = f
            .subscribe_local(
                SubscriptionScope::Channel("#x".to_string()),
                SubscriberIdentity::Unchecked,
                local_tx,
            )
            .await;

        f.broadcast_local_only(
            &sample_block(Some("#x"), "text-render"),
            &sample_receipt(),
            None,
        )
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
            .subscribe_local(
                SubscriptionScope::Channel("#x".to_string()),
                SubscriberIdentity::Unchecked,
                tx,
            )
            .await;
        f.unsubscribe_local(sub_id).await;
        f.broadcast(
            &sample_block(Some("#x"), "text-render"),
            &sample_receipt(),
            None,
        )
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
        f.register_bridge_did("did:jig:zShadowAlice".to_string(), tx);

        // Block authored by bob (real), channel members = [bob, shadow-alice].
        let mut blk = sample_block(Some("#dm/x"), "text-render");
        blk.sender_did = "did:jig:zBob".to_string();
        f.broadcast_with_members(
            &blk,
            &sample_receipt(),
            Some(&open_with_members(&[
                "did:jig:zBob",
                "did:jig:zShadowAlice",
            ])),
        )
        .await
        .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.0.sender_did, "did:jig:zBob");
    }

    #[tokio::test]
    async fn bridge_sink_skips_when_managed_did_is_the_sender() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        f.register_bridge_did("did:jig:zShadowAlice".to_string(), tx);

        // Inbound: block authored BY shadow-alice. Must not echo back to her.
        let mut blk = sample_block(Some("#dm/x"), "text-render");
        blk.sender_did = "did:jig:zShadowAlice".to_string();
        f.broadcast_with_members(
            &blk,
            &sample_receipt(),
            Some(&open_with_members(&[
                "did:jig:zBob",
                "did:jig:zShadowAlice",
            ])),
        )
        .await
        .unwrap();

        let res = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(
            res.is_err(),
            "sender's own managed DID must not receive outbound"
        );
    }

    #[tokio::test]
    async fn unregister_bridge_did_stops_delivery() {
        let f = Fanout::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        f.register_bridge_did("did:jig:zShadowAlice".to_string(), tx);
        f.unregister_bridge_did("did:jig:zShadowAlice");
        let mut blk = sample_block(Some("#dm/x"), "text-render");
        blk.sender_did = "did:jig:zBob".to_string();
        f.broadcast_with_members(
            &blk,
            &sample_receipt(),
            Some(&open_with_members(&[
                "did:jig:zBob",
                "did:jig:zShadowAlice",
            ])),
        )
        .await
        .unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        let no_delivery = res.is_err() || matches!(res, Ok(None));
        assert!(no_delivery, "unregistered bridge DID should not receive");
    }
}
