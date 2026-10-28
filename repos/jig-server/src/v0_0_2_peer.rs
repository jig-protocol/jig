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
use jig_pipeline::handshake::close;
use jig_pipeline::{Envelope, Frame};
use tokio::sync::mpsc;

/// Frames a connection holds for its peer before [`PeerSender::send`] says
/// [`PeerSendError::Full`]: a peer that reads slowly holds back its sender,
/// not this server's memory.
pub const PEER_QUEUE: usize = 256;

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
/// short reason. A code outside that range is sent as
/// [`close::PROTOCOL_VIOLATION`].
///
/// For a connection that is bad, not for ending one contract: one connection
/// carries every contract between two servers. When this server dialed, it
/// redials after a delay that doubles with each such close in a row
/// ([`crate::v0_0_2_federation`]), so a peer that keeps sending the same bad
/// frame is not met with a reconnect loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseReason {
    pub code: u16,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerSendError {
    /// The connection is gone.
    #[error("the peer connection is closed")]
    Gone,
    /// [`PEER_QUEUE`] frames are waiting for the peer to read them.
    #[error("the peer is not reading: {PEER_QUEUE} frames are waiting")]
    Full,
}

/// Sends frames on one live connection to a proven peer.
#[derive(Debug, Clone)]
pub struct PeerSender {
    peer: Did,
    /// Whether the peer implements channel tiers (JEP-0014), as its handshake
    /// on this connection said.
    tiers: bool,
    tx: mpsc::Sender<Envelope>,
}

impl PeerSender {
    /// A sender for `peer`, and the receiving end its connection loop drains.
    /// The peer is not known to implement tiers.
    pub fn new(peer: Did) -> (Self, mpsc::Receiver<Envelope>) {
        Self::with_tiers(peer, false)
    }

    /// [`Self::new`], for a peer whose handshake said whether it implements
    /// tiers.
    pub fn with_tiers(peer: Did, tiers: bool) -> (Self, mpsc::Receiver<Envelope>) {
        let (tx, rx) = mpsc::channel(PEER_QUEUE);
        (Self { peer, tiers, tx }, rx)
    }

    /// The DID this connection's peer proved.
    pub fn peer(&self) -> &Did {
        &self.peer
    }

    /// Whether the peer implements channel tiers.
    pub fn tiers(&self) -> bool {
        self.tiers
    }

    /// Queue a peer frame of `kind`, without waiting.
    pub fn send(&self, kind: &str, body: Vec<u8>) -> Result<(), PeerSendError> {
        self.tx
            .try_send(Envelope::new(Frame::Peer {
                kind: kind.to_string(),
                body,
            }))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => PeerSendError::Full,
                mpsc::error::TrySendError::Closed(_) => PeerSendError::Gone,
            })
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
        Some(handler) => handler
            .on_peer_frame(sender.peer(), kind, body, sender)
            .map_err(|mut reason| {
                if !(4000..=4999).contains(&reason.code) {
                    reason.code = close::PROTOCOL_VIOLATION;
                }
                reason
            }),
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
    fn a_slow_peer_fills_its_queue_and_a_bad_close_code_is_not_sent() {
        let (sender, mut rx) = PeerSender::new(did(1));
        for _ in 0..PEER_QUEUE {
            sender.send("record", vec![]).unwrap();
        }
        assert_eq!(sender.send("record", vec![]), Err(PeerSendError::Full));
        rx.try_recv().unwrap();
        sender.send("record", vec![]).unwrap();
        drop(rx);
        assert_eq!(sender.send("record", vec![]), Err(PeerSendError::Gone));

        struct Closes(u16);
        impl PeerFrames for Closes {
            fn on_peer_frame(
                &self,
                _: &Did,
                _: &str,
                _: &[u8],
                _: &PeerSender,
            ) -> Result<(), CloseReason> {
                Err(CloseReason {
                    code: self.0,
                    reason: "no".into(),
                })
            }
        }
        for (asked, sent) in [
            (4010, 4010),
            (1000, close::PROTOCOL_VIOLATION),
            (1006, close::PROTOCOL_VIOLATION),
            (5000, close::PROTOCOL_VIOLATION),
        ] {
            let got = dispatch(Some(&Closes(asked)), &sender, "x", b"").unwrap_err();
            assert_eq!(got.code, sent, "{asked}");
        }
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
