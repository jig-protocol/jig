# Phase D Configuration Audit: Hardcoded → Config-as-Code

## Executive Summary

**Goal:** Maximize TOML-driven control over nameserver behavior, minimizing hardcoded values and enabling operator customization without code changes.

**Current State:** ~60% config-driven
**Target State:** >90% config-driven

---

## Hardcoded Values Inventory

### 1. Cross-Nameserver Verification (anomaly.rs)

| Value | Location | Current | Should Be Config |
|-------|----------|---------|------------------|
| **HTTP client timeout** | anomaly.rs:57 | `5s` | `federation.validation_timeout_secs` |
| **Max peer requests** | anomaly.rs:243 | `3` | `federation.max_validation_peers` |
| **Fuel tolerance** | anomaly.rs:274 | `5.0%` | `anomaly_detection.cross_validation.fuel_tolerance_pct` |
| **Majority threshold** | anomaly.rs:302 | `>50%` | `anomaly_detection.cross_validation.consensus_threshold` |

### 2. Anomaly Detection (anomaly.rs)

| Value | Location | Current | jig-config Equivalent |
|-------|----------|---------|----------------------|
| **Fuel excessive multiplier** | anomaly.rs:31 | `3.0` | ✅ `anomaly_detection.fuel_anomaly.excessive_threshold` |
| **Fuel suspicious multiplier** | anomaly.rs:32 | `0.5` | ✅ `anomaly_detection.fuel_anomaly.suspicious_threshold` |
| **Max network fuel** | anomaly.rs:33 | `1_000_000` | ✅ `anomaly_detection.max_network_fuel` |
| **Hard fail threshold** | anomaly.rs:34 | `3` | ✅ `anomaly_detection.hard_failure.consecutive_threshold` |
| **Hard fail window** | anomaly.rs:35 | `3600s` | ✅ `anomaly_detection.hard_failure.time_window_secs` |
| **PoW penalty bits** | anomaly.rs:187-205 | Low:0, Med:2, High:4, Crit:8 | ⚠️ `anomaly_detection.auto_escalation.pow_penalties` |

### 3. Runtime Execution (runtime.rs)

| Value | Location | Current | jig-config Equivalent |
|-------|----------|---------|----------------------|
| **Fuel max** | runtime.rs (via config) | `5_000_000` | ✅ Defined in our config |
| **Memory max** | runtime.rs (via config) | `32MB` | ✅ Defined in our config |
| **Execution timeout** | runtime.rs (via config) | `250ms` | ✅ Defined in our config |
| **Allowed capabilities** | runtime.rs (via config) | 3 hardcoded strings | ✅ Defined in our config |

### 4. Configuration Duplication

| Our Config | jig-config Equivalent | Status |
|------------|----------------------|--------|
| `AnomalyDetectorConfig` | `jig_config::nameserver::AnomalyDetectionConfig` | ❌ **DUPLICATE** |
| `RuntimeConfig` | Partially in `jig_config::nameserver::NameserverConfig` | ⚠️ **MISSING** |

---

## Required jig-config Additions

### New: `CrossValidationConfig`

```rust
/// Cross-nameserver validation configuration
///
/// **Hot-reload:** Yes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CrossValidationConfig {
    /// Enable cross-validation for suspicious receipts
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// HTTP timeout for peer requests (seconds)
    #[serde(default = "default_validation_timeout")]
    pub validation_timeout_secs: u32,

    /// Maximum peers to query for validation
    #[serde(default = "default_max_validation_peers")]
    pub max_validation_peers: usize,

    /// Fuel tolerance percentage (e.g., 5.0 = ±5%)
    #[serde(default = "default_fuel_tolerance")]
    pub fuel_tolerance_pct: f64,

    /// Consensus threshold (e.g., 0.5 = >50% agreement required)
    #[serde(default = "default_consensus_threshold")]
    pub consensus_threshold: f64,

    /// Minimum peers required for validation
    #[serde(default = "default_min_validation_peers")]
    pub min_peers: usize,
}

fn default_validation_timeout() -> u32 { 5 }
fn default_max_validation_peers() -> usize { 3 }
fn default_fuel_tolerance() -> f64 { 5.0 }
fn default_consensus_threshold() -> f64 { 0.5 }
fn default_min_validation_peers() -> usize { 2 }
```

**Location:** Add to `jig-config/src/nameserver.rs` inside `AnomalyDetectionConfig`

---

## Implementation Plan

### Step 1: Extend jig-config (PR to jig-config repo)

```rust
// In jig-config/src/nameserver.rs
pub struct AnomalyDetectionConfig {
    pub enabled: bool,
    pub max_network_fuel: u64,
    pub fuel_anomaly: FuelAnomalyConfig,
    pub hard_failure: HardFailureConfig,
    pub auto_escalation: AutoEscalationConfig,
    pub cross_validation: CrossValidationConfig,  // ← NEW
}
```

### Step 2: Remove Duplicate Config (jig-nameserver)

**Delete:**
- `jig-nameserver/src/anomaly.rs:14-43` (AnomalyDetectorConfig struct)

**Replace with:**
```rust
use jig_config::nameserver::AnomalyDetectionConfig;
```

### Step 3: Wire Up Config in anomaly.rs

**Before:**
```rust
pub struct ReceiptAnomalyDetector {
    config: AnomalyDetectorConfig,  // Local hardcoded defaults
    http_client: Client,
}
```

**After:**
```rust
pub struct ReceiptAnomalyDetector {
    config: Arc<jig_config::nameserver::AnomalyDetectionConfig>,
    federation_config: Arc<jig_config::nameserver::FederationConfig>,
    http_client: Client,
}
```

### Step 4: Update Hardcoded Values

**anomaly.rs:57 - HTTP timeout:**
```rust
// Before: .timeout(Duration::from_secs(5))
.timeout(Duration::from_secs(
    config.cross_validation.validation_timeout_secs as u64
))
```

**anomaly.rs:243 - Max peers:**
```rust
// Before: .take(3)
.take(config.cross_validation.max_validation_peers)
```

**anomaly.rs:274 - Fuel tolerance:**
```rust
// Before: if fuel_diff_pct > 5.0
if fuel_diff_pct > config.cross_validation.fuel_tolerance_pct
```

**anomaly.rs:302 - Majority threshold:**
```rust
// Before: let majority = (total_peers / 2) + 1;
let required_agreement = (total_peers as f64 * config.cross_validation.consensus_threshold).ceil() as usize;
```

---

## Config Examples

### Example 1: Strict Cross-Validation (Production)

```toml
[anomaly_detection]
enabled = true
max_network_fuel = 500_000

[anomaly_detection.fuel_anomaly]
enabled = true
excessive_threshold = 2.5  # Stricter: 2.5x avg instead of 3.0x
suspicious_threshold = 0.4
min_sample_size = 20       # More samples for baseline

[anomaly_detection.hard_failure]
enabled = true
consecutive_threshold = 3
time_window_secs = 300

[anomaly_detection.auto_escalation]
enabled = true
severities = ["high", "critical"]

[anomaly_detection.auto_escalation.pow_penalties]
medium = 2
high = 4
critical = 8

[anomaly_detection.cross_validation]
enabled = true
validation_timeout_secs = 3     # Faster timeout for production
max_validation_peers = 5        # Query more peers
fuel_tolerance_pct = 3.0        # Stricter fuel matching
consensus_threshold = 0.67      # Require 67% agreement
min_peers = 3                   # Minimum 3 peers
```

### Example 2: Lenient Cross-Validation (Development)

```toml
[anomaly_detection]
enabled = true

[anomaly_detection.cross_validation]
enabled = true
validation_timeout_secs = 10    # Longer timeout for dev
max_validation_peers = 2
fuel_tolerance_pct = 10.0       # Allow 10% variance
consensus_threshold = 0.5       # Simple majority
min_peers = 1                   # Allow single peer validation
```

### Example 3: Disabled Cross-Validation (Isolated Mode)

```toml
[federation]
enabled = false
mode = "Isolated"

[anomaly_detection]
enabled = true

[anomaly_detection.cross_validation]
enabled = false  # No cross-validation in isolated mode
```

---

## Control Plane Parity Analysis

### Categories

| Category | Configurable | Hardcoded | % Config-Driven |
|----------|--------------|-----------|-----------------|
| **Anomaly Detection Rules** | 5/6 | 1/6 | 83% |
| **Cross-Validation Protocol** | 0/5 | 5/5 | 0% ⚠️ |
| **Runtime Execution** | 4/4 | 0/4 | 100% ✅ |
| **Auto-Escalation** | 3/4 | 1/4 | 75% |
| **Penalty Application** | 2/4 | 2/4 | 50% |
| **Transparency Logging** | 3/3 | 0/3 | 100% ✅ |

### Overall Metrics

**Current State:**
- **Configurable:** 17/26 (65%)
- **Hardcoded:** 9/26 (35%)

**After Implementation:**
- **Configurable:** 25/26 (96%)
- **Hardcoded:** 1/26 (4%)

**Remaining Hardcoded:**
- PoW penalty bit calculation logic (requires code change for new severity levels)

---

## Benefits of Config-as-Code

1. **Operator Tuning:** Admins can adjust thresholds without recompilation
2. **Environment Flexibility:** Dev/staging/prod can use different sensitivity
3. **A/B Testing:** Test different anomaly detection strategies via config
4. **Incident Response:** Quickly tighten security during attacks
5. **Federation Compatibility:** Different federations can have different standards
6. **GUI/CLI Unified:** Single source of truth for all control interfaces

---

## Migration Checklist

- [ ] Submit PR to jig-config: Add `CrossValidationConfig`
- [ ] Remove `AnomalyDetectorConfig` from jig-nameserver
- [ ] Update `ReceiptAnomalyDetector` constructor to accept jig-config types
- [ ] Replace hardcoded timeouts with `config.cross_validation.validation_timeout_secs`
- [ ] Replace hardcoded peer limit with `config.cross_validation.max_validation_peers`
- [ ] Replace hardcoded fuel tolerance with `config.cross_validation.fuel_tolerance_pct`
- [ ] Replace hardcoded majority with `config.cross_validation.consensus_threshold`
- [ ] Add config examples to `jig-config/examples/nameserver-*.toml`
- [ ] Update NAMESERVER_INTEGRATION.md with cross-validation config guide
- [ ] Add integration tests for config-driven behavior changes

---

## Post-Implementation Verification

```bash
# Test config-driven cross-validation
cargo test cross_validate_receipt

# Verify config hot-reload
curl -X POST http://localhost:7070/admin/reload-config

# Test different thresholds
JIG_NS_CONFIG=strict.toml cargo run
JIG_NS_CONFIG=lenient.toml cargo run
```

---

## Next Steps

1. **Immediate:** Implement Steps 2-4 (remove duplicates, wire up jig-config)
2. **Short-term:** Submit jig-config PR for `CrossValidationConfig`
3. **Medium-term:** Add hot-reload support for anomaly detection config
4. **Long-term:** GUI config editor for visual threshold tuning
