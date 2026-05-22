//! In-memory hot backend (Tier 1)
//!
//! Simple HashMap-based hot storage with TTL support.
//! No persistence - data lost on restart.

use crate::error::Result;
use crate::hot::HotEntry;
use crate::hot::backend::{HotBackend, HotBackendCapabilities};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Type alias for nested hash map structure (field -> value mappings by key)
type HashesMap = HashMap<String, HashMap<String, Vec<u8>>>;

/// In-memory hot backend - uses HashMap with RwLock
#[derive(Debug)]
pub struct InMemoryHot {
    store: Arc<RwLock<HashMap<String, HotEntry<Vec<u8>>>>>,
    hashes: Arc<RwLock<HashesMap>>,
}

impl InMemoryHot {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            hashes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Remove expired entries (called internally on get)
    #[allow(dead_code)]
    async fn reap_expired(&self) {
        let mut store = self.store.write().await;
        store.retain(|_, entry| !entry.is_expired());
    }
}

impl Default for InMemoryHot {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HotBackend for InMemoryHot {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let store = self.store.read().await;
        if let Some(entry) = store.get(key) {
            if entry.is_expired() {
                return Ok(None);
            }
            Ok(Some(entry.value.clone()))
        } else {
            Ok(None)
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl_secs: Option<u64>) -> Result<()> {
        let entry = HotEntry::new(value, ttl_secs);
        let mut store = self.store.write().await;
        store.insert(key.to_string(), entry);
        Ok(())
    }

    async fn del(&self, key: &str) -> Result<bool> {
        let mut store = self.store.write().await;
        Ok(store.remove(key).is_some())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let store = self.store.read().await;
        if let Some(entry) = store.get(key) {
            Ok(!entry.is_expired())
        } else {
            Ok(false)
        }
    }

    async fn expire(&self, key: &str, ttl_secs: u64) -> Result<bool> {
        let mut store = self.store.write().await;
        if let Some(entry) = store.get_mut(key) {
            entry.expires_at =
                Some(chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64));
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn incr(&self, key: &str) -> Result<i64> {
        self.incr_by(key, 1).await
    }

    async fn incr_by(&self, key: &str, amount: i64) -> Result<i64> {
        let mut store = self.store.write().await;

        let current = if let Some(entry) = store.get(key) {
            if entry.is_expired() {
                0
            } else {
                // Parse as i64
                std::str::from_utf8(&entry.value)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0)
            }
        } else {
            0
        };

        let new_value = current + amount;
        let value_bytes = new_value.to_string().into_bytes();

        store.insert(key.to_string(), HotEntry::new(value_bytes, None));
        Ok(new_value)
    }

    async fn decr(&self, key: &str) -> Result<i64> {
        self.incr_by(key, -1).await
    }

    async fn hset(&self, key: &str, field: &str, value: Vec<u8>) -> Result<()> {
        let mut hashes = self.hashes.write().await;
        let hash = hashes.entry(key.to_string()).or_insert_with(HashMap::new);
        hash.insert(field.to_string(), value);
        Ok(())
    }

    async fn hget(&self, key: &str, field: &str) -> Result<Option<Vec<u8>>> {
        let hashes = self.hashes.read().await;
        Ok(hashes.get(key).and_then(|hash| hash.get(field).cloned()))
    }

    async fn hgetall(&self, key: &str) -> Result<HashMap<String, Vec<u8>>> {
        let hashes = self.hashes.read().await;
        Ok(hashes.get(key).cloned().unwrap_or_default())
    }

    async fn hdel(&self, key: &str, field: &str) -> Result<bool> {
        let mut hashes = self.hashes.write().await;
        if let Some(hash) = hashes.get_mut(key) {
            Ok(hash.remove(field).is_some())
        } else {
            Ok(false)
        }
    }

    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.get(key).await?);
        }
        Ok(results)
    }

    async fn mset(&self, pairs: &[(&str, Vec<u8>)]) -> Result<()> {
        for (key, value) in pairs {
            self.set(key, value.clone(), None).await?;
        }
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        let mut store = self.store.write().await;
        let mut hashes = self.hashes.write().await;
        store.clear();
        hashes.clear();
        Ok(())
    }

    fn capabilities(&self) -> HotBackendCapabilities {
        HotBackendCapabilities {
            persistent: false,
            ttl_support: true,
            atomic_ops: true,
            pubsub: false,
            distributed: false,
            latency_us: 100,      // ~0.1ms for HashMap lookup
            max_throughput: None, // Limited by single-threaded RwLock contention
        }
    }

    fn name(&self) -> &'static str {
        "memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_get_set() {
        let backend = InMemoryHot::new();

        backend.set("key1", b"value1".to_vec(), None).await.unwrap();
        let value = backend.get("key1").await.unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        let backend = InMemoryHot::new();

        backend
            .set("key1", b"value1".to_vec(), Some(1))
            .await
            .unwrap();
        assert!(backend.exists("key1").await.unwrap());

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(!backend.exists("key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_atomic_incr() {
        let backend = InMemoryHot::new();

        let val1 = backend.incr("counter").await.unwrap();
        assert_eq!(val1, 1);

        let val2 = backend.incr_by("counter", 5).await.unwrap();
        assert_eq!(val2, 6);

        let val3 = backend.decr("counter").await.unwrap();
        assert_eq!(val3, 5);
    }

    #[tokio::test]
    async fn test_hash_operations() {
        let backend = InMemoryHot::new();

        backend
            .hset("user:1", "name", b"Alice".to_vec())
            .await
            .unwrap();
        backend.hset("user:1", "age", b"30".to_vec()).await.unwrap();

        let name = backend.hget("user:1", "name").await.unwrap();
        assert_eq!(name, Some(b"Alice".to_vec()));

        let all = backend.hgetall("user:1").await.unwrap();
        assert_eq!(all.len(), 2);
    }
}
