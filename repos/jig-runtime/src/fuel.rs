//! Capability metering utilities.
//!
//! Tracks host-side fuel, byte usage, and status bins per capability scope so
//! receipts can surface pricing-compatible counters without exposing mutable
//! handles to guest code.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use jig_core::{CapabilityScopePattern, CapabilityUsageKey};

use crate::error::{Result, RuntimeError};

fn canonical_key(key: &CapabilityUsageKey) -> String {
    key.to_canonical_string()
}

#[derive(Debug)]
struct CapabilityScopeStats {
    calls: u64,
    fuel: u64,
    bytes_tx: u64,
    bytes_rx: u64,
    status_bins: HashMap<String, u32>,
}

impl CapabilityScopeStats {
    fn new() -> Self {
        Self {
            calls: 0,
            fuel: 0,
            bytes_tx: 0,
            bytes_rx: 0,
            status_bins: HashMap::new(),
        }
    }

    fn record(&mut self, fuel: u64, bytes_tx: u64, bytes_rx: u64, status: Option<&str>) {
        self.calls += 1;
        self.fuel += fuel;
        self.bytes_tx += bytes_tx;
        self.bytes_rx += bytes_rx;

        if let Some(status) = status.filter(|s| !s.is_empty()) {
            *self.status_bins.entry(status.to_string()).or_insert(0) += 1;
        }
    }
}

/// Internal meter state (non-thread-safe).
#[derive(Debug, Default)]
struct CapabilityMeter {
    scopes: HashMap<String, CapabilityScopeStats>,
    quota_overrides: HashMap<String, u64>,
    call_records: Vec<CapabilityCallRecord>,
    total_bytes_tx: u64,
    total_bytes_rx: u64,
}

impl CapabilityMeter {
    fn new() -> Self {
        Self::default()
    }

    fn with_quotas(quotas: HashMap<String, u64>) -> Self {
        Self {
            quota_overrides: quotas,
            ..Self::default()
        }
    }

    fn record_invocation(
        &mut self,
        key: &CapabilityUsageKey,
        operation: &str,
        fuel: u64,
        bytes_tx: u64,
        bytes_rx: u64,
        status: Option<&str>,
    ) -> Result<()> {
        let canonical = canonical_key(key);

        let entry = self
            .scopes
            .entry(canonical.clone())
            .or_insert_with(CapabilityScopeStats::new);

        if let Some(&quota) = self.quota_overrides.get(&canonical)
            && entry.fuel + fuel > quota
        {
            return Err(RuntimeError::CapabilityQuotaExceeded {
                capability: canonical,
            });
        }

        entry.record(fuel, bytes_tx, bytes_rx, status);
        self.total_bytes_tx += bytes_tx;
        self.total_bytes_rx += bytes_rx;

        self.call_records.push(CapabilityCallRecord {
            key: key.clone(),
            operation: operation.to_string(),
            fuel_used: fuel,
            bytes_transferred: bytes_tx.saturating_add(bytes_rx),
            status: status.map(|s| s.to_string()),
        });

        Ok(())
    }

    fn snapshot(&self) -> CapabilityMeterSnapshot {
        let mut fuel_by_capability = BTreeMap::new();
        let mut status_bins = BTreeMap::new();

        for (scope, stats) in &self.scopes {
            fuel_by_capability.insert(scope.clone(), stats.fuel);

            if !stats.status_bins.is_empty() {
                status_bins.insert(scope.clone(), stats.status_bins.clone());
            }
        }

        CapabilityMeterSnapshot {
            fuel_by_capability,
            bytes_tx: self.total_bytes_tx,
            bytes_rx: self.total_bytes_rx,
            call_records: self.call_records.clone(),
            status_bins,
        }
    }
}

/// Thread-safe handle shared between runtime components.
#[derive(Debug, Clone)]
pub struct CapabilityMeterHandle(Arc<Mutex<CapabilityMeter>>);

impl CapabilityMeterHandle {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(CapabilityMeter::new())))
    }

    pub fn with_quotas(quotas: HashMap<String, u64>) -> Self {
        Self(Arc::new(Mutex::new(CapabilityMeter::with_quotas(quotas))))
    }

    pub fn record_invocation(
        &self,
        key: CapabilityUsageKey,
        operation: &str,
        fuel: u64,
        bytes_tx: u64,
        bytes_rx: u64,
        status: Option<&str>,
    ) -> Result<()> {
        let mut meter = self.0.lock().expect("capability meter poisoned");
        meter.record_invocation(&key, operation, fuel, bytes_tx, bytes_rx, status)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_invocation_with_scope(
        &self,
        capability: &str,
        scope: &CapabilityScopePattern,
        operation: &str,
        fuel: u64,
        bytes_tx: u64,
        bytes_rx: u64,
        status: Option<&str>,
    ) -> Result<()> {
        let key = CapabilityUsageKey::with_scope(capability, scope.clone());
        self.record_invocation(key, operation, fuel, bytes_tx, bytes_rx, status)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_invocation_from_str(
        &self,
        capability: &str,
        scope: &str,
        operation: &str,
        fuel: u64,
        bytes_tx: u64,
        bytes_rx: u64,
        status: Option<&str>,
    ) -> Result<()> {
        let pattern = CapabilityScopePattern::parse(scope)
            .map_err(|e| RuntimeError::ValidationError(e.to_string()))?;
        self.record_invocation_with_scope(
            capability, &pattern, operation, fuel, bytes_tx, bytes_rx, status,
        )
    }

    pub fn snapshot(&self) -> CapabilityMeterSnapshot {
        let meter = self.0.lock().expect("capability meter poisoned");
        meter.snapshot()
    }
}

impl Default for CapabilityMeterHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Data returned when the meter is sampled after execution.
#[derive(Debug, Clone, Default)]
pub struct CapabilityMeterSnapshot {
    pub fuel_by_capability: BTreeMap<String, u64>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub call_records: Vec<CapabilityCallRecord>,
    pub status_bins: BTreeMap<String, HashMap<String, u32>>,
}

impl CapabilityMeterSnapshot {
    pub fn is_empty(&self) -> bool {
        self.call_records.is_empty()
            && self.fuel_by_capability.is_empty()
            && self.bytes_tx == 0
            && self.bytes_rx == 0
    }

    pub fn status_bins_btree(&self) -> BTreeMap<String, BTreeMap<String, u64>> {
        let mut outer = BTreeMap::new();
        for (scope, bins) in &self.status_bins {
            let mut inner = BTreeMap::new();
            for (status, count) in bins {
                inner.insert(status.clone(), *count as u64);
            }
            outer.insert(scope.clone(), inner);
        }
        outer
    }
}

/// Lightweight record of a single capability invocation.
#[derive(Debug, Clone)]
pub struct CapabilityCallRecord {
    pub key: CapabilityUsageKey,
    pub operation: String,
    pub fuel_used: u64,
    pub bytes_transferred: u64,
    pub status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_single_invocation() {
        let handle = CapabilityMeterHandle::new();
        let scope = CapabilityScopePattern::parse("https://api.example.com/*").unwrap();
        handle
            .record_invocation_with_scope(
                "net.fetch",
                &scope,
                "GET",
                150,
                1_024,
                2_048,
                Some("http.2xx"),
            )
            .unwrap();
        handle
            .record_invocation_with_scope(
                "net.fetch",
                &scope,
                "GET",
                50,
                512,
                1_024,
                Some("http.5xx"),
            )
            .unwrap();

        let snapshot = handle.snapshot();
        let key = "net.fetch|https://api.example.com/*";
        assert_eq!(snapshot.fuel_by_capability.get(key).copied(), Some(200));
        assert_eq!(snapshot.bytes_tx, 1_024 + 512);
        assert_eq!(snapshot.bytes_rx, 2_048 + 1_024);
        assert_eq!(snapshot.call_records.len(), 2);
    }

    #[test]
    fn enforce_quota() {
        let mut quotas = HashMap::new();
        let scope = CapabilityScopePattern::parse("mem://default/*").unwrap();
        quotas.insert(
            CapabilityUsageKey::with_scope("kv.read", scope.clone()).to_canonical_string(),
            150,
        );
        let handle = CapabilityMeterHandle::with_quotas(quotas);

        handle
            .record_invocation_with_scope("kv.read", &scope, "get", 100, 0, 0, None)
            .unwrap();
        let err = handle
            .record_invocation_with_scope("kv.read", &scope, "get", 100, 0, 0, None)
            .unwrap_err();
        matches!(err, RuntimeError::CapabilityQuotaExceeded { .. });
    }

    #[test]
    fn status_bins_recorded() {
        let handle = CapabilityMeterHandle::new();
        let scope = CapabilityScopePattern::parse("https://example.com/*").unwrap();
        handle
            .record_invocation_with_scope(
                "net.fetch",
                &scope,
                "GET",
                50,
                512,
                1_024,
                Some("http.5xx"),
            )
            .unwrap();
        handle
            .record_invocation_with_scope(
                "net.fetch",
                &scope,
                "GET",
                25,
                128,
                256,
                Some("http.5xx"),
            )
            .unwrap();
        handle
            .record_invocation_with_scope(
                "net.fetch",
                &scope,
                "GET",
                25,
                128,
                256,
                Some("http.2xx"),
            )
            .unwrap();

        let snapshot = handle.snapshot();
        let bins = snapshot.status_bins_btree();
        let entry = bins
            .get("net.fetch|https://example.com/*")
            .expect("status bins");
        assert_eq!(entry.get("http.5xx"), Some(&2));
        assert_eq!(entry.get("http.2xx"), Some(&1));
    }
}
