//! Frames between servers that proved their DIDs to each other (JEP-0002
//! rules 4 and 5), for the federation contract (JEP-0005) to define.
//!
//! The handshake makes a server-to-server connection symmetric: whichever
//! side dialed, both may send. This module is the seam between that
//! connection and whatever speaks over it:
//!
//! - [`PeerFrames`] is told of every [`Frame::Peer`] that arrives, with the
//!   DID the handshake proved, never a claimed one. It is registered once at
//!   boot ([`crate::v0_0_2::AppState::set_peer_frames`]).
//! - [`PeerSender`] sends on one live connection, unprompted, and
//!   [`PeerRegistry::sender_for`] finds the live connection to a peer DID,
//!   whichever side dialed.
//!
//! A connection reaches neither until its peer is proven: the dialed side
//! closes (4001) on any frame before a valid `peer_proof`, and refuses a peer
//! frame on a connection that never named a peer.
//!
//! [`Frame::Peer`]: jig_pipeline::Frame::Peer

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use jig_core::did::Did;
use jig_pipeline::{Envelope, Frame};
use tokio::sync::mpsc;

/// What handles peer frames: lane F's federation contract.
pub trait PeerFrames: Send + Sync {
    /// `peer` sent a frame of `kind` with `body`. `out` sends on the same
    /// connection. An `Err` closes it with that reason.
    fn on_peer_frame(
        &self,
        peer: &Did,
        kind: &str,
        body: &[u8],
        out: &PeerSender,
    ) -> Result<(), CloseReason>;
}

/// Why a handler ends a connection: a WebSocket close code (4000–4999) and a
/// short reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseReason {
    pub code: u16,
    pub reason: String,
}

/// The connection is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the peer connection is closed")]
pub struct PeerGone;

/// Sends frames on one live connection to a proven peer.
#[derive(Debug, Clone)]
pub struct PeerSender {
    peer: Did,
    tx: mpsc::UnboundedSender<Envelope>,
}

impl PeerSender {
    /// A sender for `peer`, and the receiving end its connection loop drains.
    pub fn new(peer: Did) -> (Self, mpsc::UnboundedReceiver<Envelope>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { peer, tx }, rx)
    }

    /// The DID this connection's peer proved.
    pub fn peer(&self) -> &Did {
        &self.peer
    }

    /// Send a peer frame of `kind`.
    pub fn send(&self, kind: &str, body: Vec<u8>) -> Result<(), PeerGone> {
        self.tx
            .send(Envelope::new(Frame::Peer {
                kind: kind.to_string(),
                body,
            }))
            .map_err(|_| PeerGone)
    }

    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// The live connections to proven peers, by DID.
#[derive(Debug, Default)]
pub struct PeerRegistry {
    next: AtomicU64,
    live: Mutex<HashMap<u64, PeerSender>>,
}

/// One registration, to [`PeerRegistry::unregister`] when its connection ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration(u64);

impl PeerRegistry {
    pub fn register(&self, sender: PeerSender) -> Registration {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.lock().insert(id, sender);
        Registration(id)
    }

    pub fn unregister(&self, registration: Registration) {
        self.lock().remove(&registration.0);
    }

    /// A live connection to `peer`, the most recent if there are several
    /// (both sides dialed, or a reconnect overlapping its predecessor).
    pub fn sender_for(&self, peer: &Did) -> Option<PeerSender> {
        let key = peer.to_did_jig_string();
        self.lock()
            .iter()
            .filter(|(_, s)| s.peer.to_did_jig_string() == key && !s.is_closed())
            .max_by_key(|(id, _)| **id)
            .map(|(_, s)| s.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, PeerSender>> {
        self.live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Hand a peer frame to the registered handler. With none registered, the
/// frame is dropped: nothing on this server speaks it yet.
pub fn dispatch(
    handler: Option<&dyn PeerFrames>,
    sender: &PeerSender,
    kind: &str,
    body: &[u8],
) -> Result<(), CloseReason> {
    match handler {
        Some(handler) => handler.on_peer_frame(sender.peer(), kind, body, sender),
        None => {
            tracing::debug!(peer = %sender.peer().to_did_jig_string(), kind, "no peer-frame handler");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(n: u8) -> Did {
        Did::from_ed25519_pubkey(&[n; 32])
    }

    #[test]
    fn a_peer_is_found_on_its_newest_live_connection() {
        let registry = PeerRegistry::default();
        let (old, _old_rx) = PeerSender::new(did(1));
        let (new, mut new_rx) = PeerSender::new(did(1));
        let (other, _other_rx) = PeerSender::new(did(2));
        let first = registry.register(old);
        registry.register(new);
        registry.register(other);

        registry
            .sender_for(&did(1))
            .unwrap()
            .send("contract-offer", b"x".to_vec())
            .unwrap();
        let Frame::Peer { kind, body } = new_rx.try_recv().unwrap().frame else {
            panic!("a peer frame");
        };
        assert_eq!(
            (kind.as_str(), body.as_slice()),
            ("contract-offer", &b"x"[..])
        );

        registry.unregister(first);
        assert!(registry.sender_for(&did(3)).is_none());
        drop(new_rx);
        assert!(
            registry.sender_for(&did(1)).is_none(),
            "a connection whose loop is gone is not live"
        );
    }

    #[test]
    fn a_peer_frame_round_trips_with_a_base64_body() {
        let env = Envelope::new(Frame::Peer {
            kind: "relay-submit".into(),
            body: vec![0, 255, 7],
        });
        let text = serde_json::to_string(&env).unwrap();
        assert!(
            text.contains(r#""op":"peer""#) && text.contains("AP8H"),
            "{text}"
        );
        assert_eq!(Envelope::parse(&text).unwrap(), env);
    }
}
