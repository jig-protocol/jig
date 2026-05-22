# Nameserver Configuration Integration Guide

## Purpose

This document provides guidance to the jig-nameserver team on integrating jig-config's nameserver configuration structures. It identifies:

1. **Config structures** that need to be consumed
2. **Hot-reload vs restart boundaries** for operational safety
3. **Config hooks** needed to replace hardcoded values
4. **Migration path** from current config to jig-config
5. **Testing strategy** for config integration

## Overview

jig-config v0.2.0 Phase 5 provides comprehensive nameserver and federation configuration covering three interaction scenarios:

- **Federated**: High-trust federation with shared parent organization
- **Shared Ruleset**: Medium-trust with explicit data contracts or network participation
- **Isolated**: Zero-trust, no federation

## Configuration Structures

### Root Configuration

```rust
use jig_config::nameserver::NameserverConfig;

// Load from TOML
let config = NameserverConfig::load_from_path("~/.jig/nameserver.toml")?;
```

### Key Sections

| Section | Purpose | Hot-Reload | Priority |
|---------|---------|------------|----------|
| `network` | Bind address, port, DNS discovery | ❌ No (restart) | P0 - Critical |
| `storage` | Database path, connections | ❌ No (restart) | P0 - Critical |
| `pow` | PoW secret, difficulty tiers | ⚠️ Partial | P0 - Critical |
| `rate_limits` | Per-key, per-IP, global limits | ✅ Yes | P1 - High |
| `penalties` | Decay, escalation thresholds | ✅ Yes | P1 - High |
| `anonymous` | Anonymous account policy | ✅ Yes | P1 - High |
| `federation` | Federation mode, peering | ⚠️ Partial | P0 - Critical |
| `reputation` | Rulesets, translation contracts | ⚠️ Partial | P1 - High |
| `automation` | Tribunal auto-escalation | ✅ Yes | P2 - Medium |
| `transparency` | Logging, merkle root publishing | ✅ Yes | P2 - Medium |
| `useful_work` | Assignment TTL, queue depth | ✅ Yes | P1 - High |
| `capabilities` | DNS TXT, .well-known endpoint | ✅ Yes | P2 - Medium |
| `anomaly_detection` | Receipt anomaly rules | ✅ Yes | P1 - High |

## Hot-Reload Implementation Strategy

### Phase 1: Read-Only Integration (Week 1)

**Goal**: jig-nameserver reads config but doesn't hot-reload

```rust
// In jig-nameserver/src/config.rs

use jig_config::nameserver::NameserverConfig;
use std::sync::Arc;

pub struct NameServer {
    config: Arc<NameserverConfig>,
    // ... existing fields
}

impl NameServer {
    pub fn new(config_path: &str) -> anyhow::Result<Self> {
        let config = NameserverConfig::load_from_path(config_path)?;

        // Validate config before using
        Self::validate_config(&config)?;

        Ok(Self {
            config: Arc::new(config),
            // ... initialize other fields from config
        })
    }

    fn validate_config(config: &NameserverConfig) -> anyhow::Result<()> {
        // Ensure PoW secret is not default
        if config.pow.secret.contains("change-me") {
            anyhow::bail!("PoW secret must be changed from default");
        }

        // Ensure difficulty ranges are valid
        if config.pow.base_difficulty < config.pow.min_difficulty {
            anyhow::bail!("base_difficulty must be >= min_difficulty");
        }

        Ok(())
    }
}
```

### Phase 2: Hot-Reload for Safe Parameters (Week 2-3)

**Goal**: Enable hot-reload for parameters that are safe to change at runtime

```rust
use std::sync::RwLock;

pub struct NameServer {
    // Immutable config (requires restart)
    immutable_config: Arc<ImmutableConfig>,

    // Mutable config (hot-reloadable)
    mutable_config: Arc<RwLock<MutableConfig>>,

    // ... existing fields
}

#[derive(Clone)]
struct ImmutableConfig {
    network: NetworkConfig,
    storage: StorageConfig,
    pow_secret: String,
    federation_mode: FederationMode,
}

#[derive(Clone)]
struct MutableConfig {
    pow_difficulty: PowDifficulty,
    rate_limits: RateLimitConfig,
    penalties: PenaltyConfig,
    anonymous: AnonymousPolicy,
    gossip: GossipConfig,
    // ... other hot-reloadable fields
}

impl NameServer {
    pub fn reload_config(&self, config_path: &str) -> anyhow::Result<()> {
        let new_config = NameserverConfig::load_from_path(config_path)?;

        // Verify immutable config hasn't changed
        self.verify_immutable_unchanged(&new_config)?;

        // Update mutable config
        let new_mutable = MutableConfig::from(&new_config);
        *self.mutable_config.write().unwrap() = new_mutable;

        tracing::info!("Config hot-reloaded successfully");
        Ok(())
    }

    fn verify_immutable_unchanged(&self, new: &NameserverConfig) -> anyhow::Result<()> {
        if new.network.bind_address != self.immutable_config.network.bind_address {
            anyhow::bail!("Cannot hot-reload network.bind_address (requires restart)");
        }
        if new.network.port != self.immutable_config.network.port {
            anyhow::bail!("Cannot hot-reload network.port (requires restart)");
        }
        if new.pow.secret != self.immutable_config.pow_secret {
            anyhow::bail!("Cannot hot-reload pow.secret (security critical)");
        }
        if new.federation.mode != self.immutable_config.federation_mode {
            anyhow::bail!("Cannot hot-reload federation.mode (requires restart)");
        }
        Ok(())
    }
}
```

### Phase 3: Config File Watcher (Week 4)

**Goal**: Automatically reload config when file changes

```rust
use notify::{Watcher, RecursiveMode, watcher};
use std::sync::mpsc::channel;
use std::time::Duration;

impl NameServer {
    pub fn watch_config(self: Arc<Self>, config_path: String) {
        let (tx, rx) = channel();

        let mut watcher = watcher(tx, Duration::from_secs(2))
            .expect("Failed to create file watcher");

        watcher.watch(&config_path, RecursiveMode::NonRecursive)
            .expect("Failed to watch config file");

        tokio::spawn(async move {
            loop {
                match rx.recv() {
                    Ok(notify::DebouncedEvent::Write(_)) => {
                        match self.reload_config(&config_path) {
                            Ok(()) => tracing::info!("Config auto-reloaded"),
                            Err(e) => tracing::error!("Config reload failed: {e}"),
                        }
                    }
                    Err(e) => {
                        tracing::error!("Watch error: {e}");
                        break;
                    }
                    _ => {}
                }
            }
        });
    }
}
```

## Config Hook Migration Map

### Current jig-nameserver Config → jig-config Mapping

| Current Field | jig-config Path | Type | Notes |
|---------------|----------------|------|-------|
| `NetworkConfig::bind` | `network.bind_address` | String | No change |
| `NetworkConfig::port` | `network.port` | u16 | No change |
| `PowConfig::secret` | `pow.secret` | String | **Security**: Never log |
| `PowConfig::base_difficulty` | `pow.base_difficulty` | u16 | Hot-reload safe |
| `RateLimitConfig::per_key_limit` | `rate_limits.per_key_limit` | u32 | Hot-reload safe |
| `FederationConfig::enabled` | `federation.enabled` | bool | Requires restart |
| `FederationConfig::allow_domains` | `federation.allow_list` | Vec<String> | Hot-reload safe (atomic swap) |
| `FederationConfig::seed_peers` | `federation.seed_peers` | Vec<String> | Hot-reload safe |
| `ReputationConfig::rulesets` | `reputation.rulesets` | Vec<RulesetConfig> | Requires restart |
| `AutomationPolicy` | `automation` | AutomationPolicy | Hot-reload safe |

### New Fields (Not in Current Config)

These fields are **new** in jig-config and need integration:

1. **Federation Mode** (`federation.mode`): Enum distinguishing Federated/SharedRuleset/Isolated
2. **Parent Org Config** (`federation.parent_org`): Parent organization verification
3. **Shared Ruleset Config** (`federation.shared_ruleset`): Data contract configuration
4. **Zone Overrides** (`pow.zone_overrides`): Per-zone PoW difficulty
5. **Anomaly Detection** (`anomaly_detection`): Receipt anomaly rules
6. **Useful Work Validators** (`useful_work.validator_requirements`): Per-work-type requirements

## Implementation Checklist

### P0 - Critical (Must Have for v0.2.0)

- [ ] **Replace `NameServerConfig` with jig-config types**
  - `src/config.rs`: Import `jig_config::nameserver::*`
  - Remove duplicate type definitions
  - Update `from_env()` and `merge_env()` to use jig-config types

- [ ] **Implement config loading**
  - `NameServerConfig::load_from_path()` integration
  - Environment variable override support
  - Validation on startup

- [ ] **Update PoW challenge generation**
  - `src/pow.rs`: Use `config.pow.secret` instead of hardcoded
  - `src/pow.rs`: Use `config.pow.base_difficulty` + penalty calculation
  - Support zone overrides: `config.pow.zone_overrides.get(zone)`

- [ ] **Update rate limiting**
  - `src/rate_limit.rs`: Use `config.rate_limits.per_key_limit`
  - `src/rate_limit.rs`: Use `config.rate_limits.per_ip_limit`
  - `src/rate_limit.rs`: Use `config.rate_limits.global_limit`

- [ ] **Update federation discovery**
  - `src/federation.rs`: Use `config.federation.mode` to determine behavior
  - `src/federation.rs`: Use `config.federation.seed_peers` for bootstrapping
  - `src/federation.rs`: Use `config.federation.allow_list` / `deny_list`

### P1 - High (Should Have for v0.2.0)

- [ ] **Implement hot-reload for safe parameters**
  - Rate limits (atomic swap with `Arc<RwLock<RateLimitConfig>>`)
  - Penalties (atomic swap)
  - Gossip interval (atomic swap)
  - Allow/deny lists (atomic swap)

- [ ] **Integrate anomaly detection config**
  - `src/anomaly.rs`: Replace hardcoded thresholds with `config.anomaly_detection.*`
  - Support fuel anomaly thresholds
  - Support hard failure detection config

- [ ] **Integrate reputation config**
  - `src/reputation.rs`: Load rulesets from `config.reputation.rulesets`
  - Support translation contracts
  - Support zone thresholds

- [ ] **Integrate useful work config**
  - Load validator requirements from `config.useful_work.validator_requirements`
  - Support assignment TTL
  - Support queue depth limits

### P2 - Medium (Nice to Have)

- [ ] **Implement config file watcher**
  - Auto-reload on config file change
  - Log reload success/failure
  - Validate before applying

- [ ] **Add config validation command**
  - `jig-ns config validate /path/to/config.toml`
  - Check for common mistakes
  - Verify secret is not default

- [ ] **Add config diff command**
  - `jig-ns config diff current /path/to/new.toml`
  - Show what would change
  - Indicate if restart required

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_federated_config() {
        let config = NameserverConfig::load_from_path(
            "tests/fixtures/federated.toml"
        ).unwrap();

        assert_eq!(config.federation.mode, FederationMode::Federated);
        assert!(config.federation.parent_org.is_some());
    }

    #[test]
    fn test_hot_reload_rate_limits() {
        let server = NameServer::new("tests/fixtures/test.toml").unwrap();

        // Modify config file
        std::fs::write(
            "tests/fixtures/test.toml",
            b"[rate_limits]\nper_key_limit = 200"
        ).unwrap();

        // Hot-reload
        server.reload_config("tests/fixtures/test.toml").unwrap();

        // Verify new limits applied
        assert_eq!(server.get_rate_limit().per_key_limit, 200);
    }

    #[test]
    fn test_reject_immutable_changes() {
        let server = NameServer::new("tests/fixtures/test.toml").unwrap();

        // Modify immutable field
        std::fs::write(
            "tests/fixtures/test.toml",
            b"[network]\nbind_address = \"0.0.0.0\""
        ).unwrap();

        // Should reject hot-reload
        assert!(server.reload_config("tests/fixtures/test.toml").is_err());
    }
}
```

### Integration Tests

```bash
# Test federated scenario
cargo test --test integration_federated -- --nocapture

# Test shared ruleset scenario
cargo test --test integration_shared_ruleset -- --nocapture

# Test isolated scenario
cargo test --test integration_isolated -- --nocapture

# Test hot-reload
cargo test --test integration_hot_reload -- --nocapture
```

### Manual Testing

```bash
# 1. Start nameserver with federated config
jig-ns start --config examples/nameserver-federated.toml

# 2. Verify federation mode
curl http://localhost:7070/.well-known/jig-ns/capabilities | jq '.federation_mode'

# 3. Test hot-reload
# Edit config: change rate_limits.per_key_limit from 120 to 200
echo '[rate_limits]' > /tmp/test.toml
echo 'per_key_limit = 200' >> /tmp/test.toml

# Send reload signal
kill -HUP $(pgrep jig-ns)

# 4. Verify new limits applied
curl http://localhost:7070/admin/config | jq '.rate_limits.per_key_limit'
# Should return 200
```

## Migration Timeline

### Week 1: Foundation
- Day 1-2: Import jig-config types, remove duplicates
- Day 3-4: Update config loading, validation
- Day 5: Basic integration tests

### Week 2: Core Integration
- Day 1-2: PoW config integration
- Day 3-4: Rate limiting config integration
- Day 5: Federation config integration

### Week 3: Advanced Features
- Day 1-2: Reputation config integration
- Day 3-4: Anomaly detection config integration
- Day 5: Useful work config integration

### Week 4: Hot-Reload
- Day 1-2: Implement hot-reload infrastructure
- Day 3-4: Config file watcher
- Day 5: End-to-end testing

## Config Security Considerations

### Secrets Management

**CRITICAL**: Never log `config.pow.secret`

```rust
// ❌ BAD: Logs secret
tracing::debug!("Config: {:?}", config);

// ✅ GOOD: Redact secrets
tracing::debug!("Config: {:?}", config.redacted());

impl NameserverConfig {
    pub fn redacted(&self) -> String {
        format!(
            "NameserverConfig {{ network: {:?}, pow_secret: <REDACTED>, ... }}",
            self.network
        )
    }
}
```

### Environment Variable Overrides

Support environment variable overrides for secrets:

```bash
# Override PoW secret from env
export JIG_NS_POW_SECRET="production-secret-from-vault"
jig-ns start --config nameserver.toml
```

```rust
impl NameserverConfig {
    pub fn load_with_env_overrides(path: &str) -> anyhow::Result<Self> {
        let mut config = Self::load_from_path(path)?;

        // Override from env vars
        if let Ok(secret) = std::env::var("JIG_NS_POW_SECRET") {
            config.pow.secret = secret;
        }

        Ok(config)
    }
}
```

## Config Examples

jig-config provides three complete examples:

1. **`examples/nameserver-federated.toml`**: Parent organization federation
2. **`examples/nameserver-shared-ruleset.toml`**: Data contract or network participation
3. **`examples/nameserver-isolated.toml`**: Zero-trust isolated operation

Use these as templates for deployment configurations.

## Questions & Support

For questions about jig-config integration:

1. **Config structure questions**: See `jig-config/src/nameserver.rs` inline documentation
2. **Hot-reload boundaries**: See module-level comments with `**Hot-reload:**` annotations
3. **Integration help**: File issue at `jig-config` repo with `[nameserver]` tag

## Appendix: Complete Type Reference

```rust
pub struct NameserverConfig {
    pub network: NameserverNetworkConfig,
    pub storage: NameserverStorageConfig,
    pub pow: PowConfig,
    pub rate_limits: RateLimitConfig,
    pub penalties: PenaltyConfig,
    pub anonymous: AnonymousPolicy,
    pub federation: FederationConfig,
    pub reputation: ReputationConfig,
    pub automation: AutomationPolicy,
    pub transparency: TransparencyConfig,
    pub useful_work: UsefulWorkConfig,
    pub capabilities: CapabilitiesConfig,
    pub anomaly_detection: AnomalyDetectionConfig,
}

pub enum FederationMode {
    Federated,      // High trust: parent org
    SharedRuleset,  // Medium trust: data contract
    Isolated,       // Zero trust: no federation
}
```

Full type definitions: `jig-config/src/nameserver.rs`
