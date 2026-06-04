//! `RouterMount` — the handle a bridge uses to register HTTP routes on the
//! server's axum app under `/_bridge/<name>/`. Only present with the `web`
//! feature. The server collects mounted routers after `Bridge::start` and
//! merges them into its main router before serving.

use std::sync::{Arc, Mutex};

/// Collects sub-routers contributed by bridges during `start()`. The server
/// owns the collector; each bridge gets a clone via `BridgeContext`.
#[derive(Clone, Default)]
pub struct RouterMount {
    inner: Arc<Mutex<Vec<(String, axum::Router)>>>,
}

impl RouterMount {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mount `router` under `/_bridge/<bridge_name>/`. Called by the bridge
    /// from `start()`. The server applies the nesting prefix when it drains.
    pub fn mount(&self, bridge_name: &str, router: axum::Router) {
        self.inner
            .lock()
            .expect("RouterMount poisoned")
            .push((bridge_name.to_string(), router));
    }

    /// Server-side: drain all mounted (name, router) pairs for merging.
    pub fn drain(&self) -> Vec<(String, axum::Router)> {
        std::mem::take(&mut *self.inner.lock().expect("RouterMount poisoned"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_then_drain_returns_pairs() {
        let m = RouterMount::new();
        m.mount("email", axum::Router::new());
        m.mount("slack", axum::Router::new());
        let drained = m.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].0, "email");
        assert_eq!(drained[1].0, "slack");
        // Drained collector is now empty.
        assert!(m.drain().is_empty());
    }
}
