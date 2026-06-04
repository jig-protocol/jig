//! Email <-> DID resolution with a BridgeStorage-backed TTL cache.
//!
//! resolve() checks the cache, then the nameserver, then falls back to a
//! deterministic shadow DID. Results are cached with a TTL. The nameserver
//! call is best-effort: any failure or absent mapping yields a shadow DID.

use std::sync::Arc;

use anyhow::Result;
use jig_bridge_core::BridgeStorage;

use crate::identity;

const NS: &str = "addrbook";

/// The resolution outcome for an external email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Email belongs to a registered Jig user — deliver natively.
    NativeJig(String), // real DID string
    /// No Jig alias — use the bridge's shadow DID + send email.
    EmailShadow(String), // shadow DID string
}

impl Resolution {
    /// The DID string regardless of variant.
    pub fn did(&self) -> &str {
        match self {
            Resolution::NativeJig(d) | Resolution::EmailShadow(d) => d,
        }
    }
}

pub struct AddressBook {
    storage: Arc<dyn BridgeStorage>,
    nameserver_url: Option<String>,
    bridge_secret: String,
    strip_plus_tags: bool,
    ttl_secs: i64,
    http: reqwest::Client,
}

impl AddressBook {
    pub fn new(
        storage: Arc<dyn BridgeStorage>,
        nameserver_url: Option<String>,
        bridge_secret: String,
        strip_plus_tags: bool,
        ttl_secs: i64,
    ) -> Self {
        Self {
            storage,
            nameserver_url,
            bridge_secret,
            strip_plus_tags,
            ttl_secs,
            http: reqwest::Client::new(),
        }
    }

    /// Resolve, consulting cache then nameserver. Caches the result with TTL.
    pub async fn resolve(&self, email: &str) -> Result<Resolution> {
        let norm = identity::normalize_email(email, self.strip_plus_tags);
        if let Some(bytes) = self.storage.get(NS, &norm).await?
            && let Ok(stored) = serde_json::from_slice::<StoredResolution>(&bytes)
        {
            return Ok(stored.into());
        }
        let resolution = self.resolve_uncached(&norm).await;
        let stored = StoredResolution::from(&resolution);
        let expires = chrono::Utc::now().timestamp() + self.ttl_secs;
        self.storage
            .put(NS, &norm, &serde_json::to_vec(&stored)?, Some(expires))
            .await?;
        Ok(resolution)
    }

    /// Expire a cached entry (e.g. after a native-route delivery failure).
    pub async fn invalidate(&self, email: &str) -> Result<()> {
        let norm = identity::normalize_email(email, self.strip_plus_tags);
        self.storage.delete(NS, &norm).await
    }

    /// Resolve without touching the cache. Best-effort nameserver lookup, then
    /// a deterministic shadow DID. Never errors — always yields a Resolution.
    async fn resolve_uncached(&self, norm_email: &str) -> Resolution {
        if let Some(ns) = &self.nameserver_url {
            let url = format!("{ns}/v1/resolve/{norm_email}");
            if let Ok(resp) = self.http.get(&url).send().await
                && resp.status().is_success()
                && let Ok(v) = resp.json::<serde_json::Value>().await
                && let Some(did) = v.get("did").and_then(|d| d.as_str())
            {
                return Resolution::NativeJig(did.to_string());
            }
        }
        let did = identity::shadow_did(&self.bridge_secret, norm_email, self.strip_plus_tags);
        Resolution::EmailShadow(did.to_did_jig_string())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredResolution {
    kind: String,
    did: String,
}
impl From<&Resolution> for StoredResolution {
    fn from(r: &Resolution) -> Self {
        match r {
            Resolution::NativeJig(d) => Self {
                kind: "native".into(),
                did: d.clone(),
            },
            Resolution::EmailShadow(d) => Self {
                kind: "shadow".into(),
                did: d.clone(),
            },
        }
    }
}
impl From<StoredResolution> for Resolution {
    fn from(s: StoredResolution) -> Self {
        if s.kind == "native" {
            Resolution::NativeJig(s.did)
        } else {
            Resolution::EmailShadow(s.did)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// HashMap-backed BridgeStorage for tests (expiry not exercised here).
    #[derive(Default)]
    struct MemStore {
        map: Mutex<HashMap<(String, String), Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl BridgeStorage for MemStore {
        async fn put(
            &self,
            ns: &str,
            key: &str,
            value: &[u8],
            _expires_at: Option<i64>,
        ) -> Result<()> {
            self.map
                .lock()
                .unwrap()
                .insert((ns.into(), key.into()), value.to_vec());
            Ok(())
        }
        async fn get(&self, ns: &str, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .get(&(ns.into(), key.into()))
                .cloned())
        }
        async fn delete(&self, ns: &str, key: &str) -> Result<()> {
            self.map.lock().unwrap().remove(&(ns.into(), key.into()));
            Ok(())
        }
        async fn sweep_expired(&self, _ns: &str) -> Result<u64> {
            Ok(0)
        }
    }
    fn test_storage() -> Arc<dyn BridgeStorage> {
        Arc::new(MemStore::default())
    }

    #[tokio::test]
    async fn no_nameserver_yields_shadow_and_caches() {
        let storage = test_storage();
        let ab = AddressBook::new(storage.clone(), None, "secret".into(), false, 3600);
        let r1 = ab.resolve("alice@example.com").await.unwrap();
        assert!(matches!(r1, Resolution::EmailShadow(_)));
        // Second resolve hits cache (same value).
        let r2 = ab.resolve("alice@example.com").await.unwrap();
        assert_eq!(r1, r2);
        // The entry is actually in storage under the addrbook ns.
        assert!(
            storage
                .get("addrbook", "alice@example.com")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn invalidate_forces_recompute() {
        let storage = test_storage();
        let ab = AddressBook::new(storage.clone(), None, "secret".into(), false, 3600);
        let _ = ab.resolve("alice@example.com").await.unwrap();
        ab.invalidate("alice@example.com").await.unwrap();
        assert!(
            storage
                .get("addrbook", "alice@example.com")
                .await
                .unwrap()
                .is_none()
        );
        // resolve again — still shadow (deterministic), exercising the miss path.
        let r = ab.resolve("alice@example.com").await.unwrap();
        assert!(matches!(r, Resolution::EmailShadow(_)));
    }

    #[tokio::test]
    async fn shadow_did_matches_identity_module() {
        let storage = test_storage();
        let ab = AddressBook::new(storage, None, "secret".into(), false, 3600);
        let r = ab.resolve("alice@example.com").await.unwrap();
        let expected =
            identity::shadow_did("secret", "alice@example.com", false).to_did_jig_string();
        assert_eq!(r.did(), expected);
    }
}
