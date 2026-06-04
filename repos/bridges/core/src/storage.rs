//! Backend-agnostic, namespaced key-value-with-TTL storage for bridges.
//!
//! Bridges never open their own database. The server implements this trait
//! over its canonical store (SQLite today; Postgres/CockroachDB later) and
//! hands an `Arc<dyn BridgeStorage>` to each bridge via `BridgeContext`.
//! Keys are scoped by `(bridge supplies ns, key)`; the server additionally
//! scopes by bridge name so two bridges can't collide.

use anyhow::Result;
use async_trait::async_trait;

/// Namespaced KV with optional per-entry expiry (unix seconds).
#[async_trait]
pub trait BridgeStorage: Send + Sync {
    /// Upsert `value` at `(ns, key)`. `expires_at` = unix-seconds deadline,
    /// or `None` for no expiry.
    async fn put(&self, ns: &str, key: &str, value: &[u8], expires_at: Option<i64>) -> Result<()>;

    /// Fetch the value at `(ns, key)`. Returns `None` if absent OR expired.
    async fn get(&self, ns: &str, key: &str) -> Result<Option<Vec<u8>>>;

    /// Remove `(ns, key)` if present (idempotent).
    async fn delete(&self, ns: &str, key: &str) -> Result<()>;

    /// Delete all expired entries in `ns`. Returns the count removed.
    async fn sweep_expired(&self, ns: &str) -> Result<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // (ns, key) -> (value, expires_at)
    type Entries = HashMap<(String, String), (Vec<u8>, Option<i64>)>;

    /// In-memory reference impl used to validate the trait shape + that the
    /// expiry contract is expressible. (The real impl lives in jig-server.)
    #[derive(Default)]
    struct MemStore {
        map: Mutex<Entries>,
        now: i64,
    }

    #[async_trait]
    impl BridgeStorage for MemStore {
        async fn put(
            &self,
            ns: &str,
            key: &str,
            value: &[u8],
            expires_at: Option<i64>,
        ) -> Result<()> {
            self.map
                .lock()
                .unwrap()
                .insert((ns.into(), key.into()), (value.to_vec(), expires_at));
            Ok(())
        }
        async fn get(&self, ns: &str, key: &str) -> Result<Option<Vec<u8>>> {
            let m = self.map.lock().unwrap();
            match m.get(&(ns.into(), key.into())) {
                Some((_v, Some(exp))) if *exp <= self.now => Ok(None),
                Some((v, _)) => Ok(Some(v.clone())),
                None => Ok(None),
            }
        }
        async fn delete(&self, ns: &str, key: &str) -> Result<()> {
            self.map.lock().unwrap().remove(&(ns.into(), key.into()));
            Ok(())
        }
        async fn sweep_expired(&self, ns: &str) -> Result<u64> {
            let mut m = self.map.lock().unwrap();
            let before = m.len();
            m.retain(|(n, _), (_, exp)| !(n == ns && matches!(exp, Some(e) if *e <= self.now)));
            Ok((before - m.len()) as u64)
        }
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        let s = MemStore::default();
        s.put("addrbook", "alice@example.com", b"did:jig:zShadow", None)
            .await
            .unwrap();
        assert_eq!(
            s.get("addrbook", "alice@example.com")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"did:jig:zShadow"[..])
        );
    }

    #[tokio::test]
    async fn expired_entry_reads_none() {
        let s = MemStore {
            now: 100,
            ..Default::default()
        };
        s.put("addrbook", "k", b"v", Some(50)).await.unwrap(); // expired (50 <= 100)
        assert!(s.get("addrbook", "k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let s = MemStore::default();
        s.delete("ns", "absent").await.unwrap(); // no panic
        s.put("ns", "k", b"v", None).await.unwrap();
        s.delete("ns", "k").await.unwrap();
        assert!(s.get("ns", "k").await.unwrap().is_none());
    }
}
