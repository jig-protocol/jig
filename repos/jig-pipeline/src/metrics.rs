//! Process-wide count of accepted blocks, by where they came from.
//!
//! Counted once, at the end of [`crate::ingest::ingest`], so every surface that
//! ingests (WebSocket, REST, admin endpoints, federation, bridges) is covered,
//! including ones added later. The server renders these at `/metrics`.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::ingest::IngestSource;

static LOCAL: AtomicU64 = AtomicU64::new(0);
static FEDERATION: AtomicU64 = AtomicU64::new(0);
static ADMIN: AtomicU64 = AtomicU64::new(0);
static BRIDGE: AtomicU64 = AtomicU64::new(0);

/// Record one block accepted from `source`.
pub(crate) fn block_ingested(source: &IngestSource) {
    let counter = match source {
        IngestSource::LocalClient { .. } => &LOCAL,
        // A write a follower relayed arrived over federation too.
        IngestSource::FederatedPeer { .. } | IngestSource::Relayed { .. } => &FEDERATION,
        IngestSource::AdminEndpoint => &ADMIN,
        IngestSource::Bridge => &BRIDGE,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Blocks accepted since start, as `(source label, count)`. The labels are a
/// fixed set: `local` (WebSocket and REST clients), `federation`, `admin` and
/// `bridge`.
pub fn ingested_by_source() -> [(&'static str, u64); 4] {
    [
        ("local", LOCAL.load(Ordering::Relaxed)),
        ("federation", FEDERATION.load(Ordering::Relaxed)),
        ("admin", ADMIN.load(Ordering::Relaxed)),
        ("bridge", BRIDGE.load(Ordering::Relaxed)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(label: &str) -> u64 {
        ingested_by_source()
            .into_iter()
            .find(|(l, _)| *l == label)
            .unwrap()
            .1
    }

    #[test]
    fn each_source_lands_on_its_own_label() {
        // Counters are process-wide and other tests ingest concurrently, so
        // assert on growth, not on exact values.
        let sources = [
            (IngestSource::LocalClient { conn_id: 7 }, "local"),
            (
                IngestSource::FederatedPeer {
                    peer_did: jig_core::Did::from_ed25519_pubkey(&[1; 32]),
                    peer_url: "wss://peer.example".into(),
                },
                "federation",
            ),
            (IngestSource::AdminEndpoint, "admin"),
            (IngestSource::Bridge, "bridge"),
        ];
        for (source, label) in sources {
            let before = count(label);
            block_ingested(&source);
            assert!(count(label) > before, "{label} did not grow");
        }
    }
}
