//! `BridgeStorage` impl over the pipeline's SQLite store. Scopes every key by
//! bridge name so two bridges can't collide. This is the only `BridgeStorage`
//! backend in v0.0.3 — hence the `naively_single_backend_bridge_storage`
//! limitation flag the server advertises when a bridge is loaded (task B6).

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use jig_bridge_core::BridgeStorage;
use jig_pipeline::persist::SqliteStore;

pub struct SqliteBridgeStorage {
    store: Arc<SqliteStore>,
    bridge_name: String,
}

impl SqliteBridgeStorage {
    pub fn new(store: Arc<SqliteStore>, bridge_name: impl Into<String>) -> Self {
        Self {
            store,
            bridge_name: bridge_name.into(),
        }
    }
    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }
}

#[async_trait]
impl BridgeStorage for SqliteBridgeStorage {
    async fn put(&self, ns: &str, key: &str, value: &[u8], expires_at: Option<i64>) -> Result<()> {
        self.store
            .bridge_kv_put(&self.bridge_name, ns, key, value, expires_at)?;
        Ok(())
    }
    async fn get(&self, ns: &str, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .store
            .bridge_kv_get(&self.bridge_name, ns, key, Self::now())?)
    }
    async fn delete(&self, ns: &str, key: &str) -> Result<()> {
        self.store.bridge_kv_delete(&self.bridge_name, ns, key)?;
        Ok(())
    }
    async fn sweep_expired(&self, ns: &str) -> Result<u64> {
        Ok(self
            .store
            .bridge_kv_sweep(&self.bridge_name, ns, Self::now())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_get_delete_roundtrip() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let s = SqliteBridgeStorage::new(store, "email");
        s.put("addrbook", "alice@example.com", b"did:jig:zS", None)
            .await
            .unwrap();
        assert_eq!(
            s.get("addrbook", "alice@example.com")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"did:jig:zS"[..])
        );
        s.delete("addrbook", "alice@example.com").await.unwrap();
        assert!(
            s.get("addrbook", "alice@example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn bridge_name_scoping_prevents_collision() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let email = SqliteBridgeStorage::new(store.clone(), "email");
        let slack = SqliteBridgeStorage::new(store, "slack");
        email.put("ns", "k", b"email-val", None).await.unwrap();
        slack.put("ns", "k", b"slack-val", None).await.unwrap();
        assert_eq!(
            email.get("ns", "k").await.unwrap().as_deref(),
            Some(&b"email-val"[..])
        );
        assert_eq!(
            slack.get("ns", "k").await.unwrap().as_deref(),
            Some(&b"slack-val"[..])
        );
    }
}
