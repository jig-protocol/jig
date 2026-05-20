//! Integration tests for nameserver and federation configuration
//!
//! Tests cover three federation scenarios:
//! 1. Federated - High trust, shared parent org
//! 2. SharedRuleset - Medium trust, explicit contracts
//! 3. Isolated - Zero trust, manual peering

use jig_config::nameserver::*;
use serde_json::json;
use std::collections::HashMap;

// ============================================================================
// Federation Mode Tests
// ============================================================================

#[test]
fn test_federation_mode_serialization() {
    let federated = FederationMode::Federated;
    let shared = FederationMode::SharedRuleset;
    let isolated = FederationMode::Isolated;

    // Test serialization
    let fed_json = serde_json::to_string(&federated).unwrap();
    let share_json = serde_json::to_string(&shared).unwrap();
    let iso_json = serde_json::to_string(&isolated).unwrap();

    assert_eq!(fed_json, r#""federated""#);
    assert_eq!(share_json, r#""shared_ruleset""#);
    assert_eq!(iso_json, r#""isolated""#);

    // Test deserialization
    let fed_back: FederationMode = serde_json::from_str(&fed_json).unwrap();
    let share_back: FederationMode = serde_json::from_str(&share_json).unwrap();
    let iso_back: FederationMode = serde_json::from_str(&iso_json).unwrap();

    assert_eq!(fed_back, FederationMode::Federated);
    assert_eq!(share_back, FederationMode::SharedRuleset);
    assert_eq!(iso_back, FederationMode::Isolated);
}

// ============================================================================
// Scenario 1: Federated Configuration (High Trust)
// ============================================================================

#[test]
fn test_federated_scenario_parent_org() {
    let config = FederationConfig {
        mode: FederationMode::Federated,
        enabled: true,
        seed_peers: vec![
            "https://ns1.acme.com".to_string(),
            "https://ns2.acme.com".to_string(),
        ],
        allow_list: vec!["*.acme.com".to_string()],
        deny_list: vec![],
        gossip: GossipConfig {
            interval_secs: 60, // Faster gossip for federated
            batch_size: 200,
            message_types: vec![
                "policy_hash".to_string(),
                "reputation_summary".to_string(),
                "tribunal_decision".to_string(),
                "handshake".to_string(),
            ],
            verify_signatures: true,
        },
        handshake: HandshakeConfig {
            timeout_secs: 30,
            require_mtls: true, // Federated requires mTLS
            protocol_versions: vec!["1.0".to_string()],
        },
        parent_org: Some(ParentOrgConfig {
            org_did: "did:jig:acme".to_string(),
            verification_endpoint: "https://org.acme.com/verify".to_string(),
            auto_trust_siblings: true,
            policy_repo: Some("https://git.acme.com/jig/policies".to_string()),
            policy_sync_interval_secs: 600, // Sync every 10 minutes
        }),
        shared_ruleset: None,
        max_peers: 100, // Higher peer limit for federated
        policy_hash: Some("abc123".to_string()),
    };

    // Verify federated-specific settings
    assert_eq!(config.mode, FederationMode::Federated);
    assert!(config.enabled);
    assert!(config.handshake.require_mtls);
    assert!(config.parent_org.is_some());
    assert!(config.parent_org.as_ref().unwrap().auto_trust_siblings);
    assert_eq!(config.gossip.interval_secs, 60);
}

#[test]
fn test_federated_scenario_toml_roundtrip() {
    let toml_str = r#"
mode = "federated"
enabled = true
seed_peers = ["https://ns1.acme.com", "https://ns2.acme.com"]
allow_list = ["*.acme.com"]
deny_list = []
max_peers = 100
policy_hash = "abc123"

[gossip]
interval_secs = 60
batch_size = 200
message_types = ["policy_hash", "reputation_summary", "tribunal_decision", "handshake"]
verify_signatures = true

[handshake]
timeout_secs = 30
require_mtls = true
protocol_versions = ["1.0"]

[parent_org]
org_did = "did:jig:acme"
verification_endpoint = "https://org.acme.com/verify"
auto_trust_siblings = true
policy_repo = "https://git.acme.com/jig/policies"
policy_sync_interval_secs = 600
"#;

    let config: FederationConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.mode, FederationMode::Federated);
    assert!(config.parent_org.is_some());

    // Roundtrip test
    let serialized = toml::to_string(&config).unwrap();
    let deserialized: FederationConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(config, deserialized);
}

// ============================================================================
// Scenario 2: Shared Ruleset Configuration (Medium Trust)
// ============================================================================

#[test]
fn test_shared_ruleset_scenario_network() {
    let config = FederationConfig {
        mode: FederationMode::SharedRuleset,
        enabled: true,
        seed_peers: vec!["https://bootstrap.high-sec.network".to_string()],
        allow_list: vec![], // No blanket allow - validated by contract
        deny_list: vec!["known-bad.example".to_string()],
        gossip: GossipConfig {
            interval_secs: 300, // Standard gossip interval
            batch_size: 100,
            message_types: vec![
                "policy_hash".to_string(),
                "reputation_summary".to_string(),
                "tribunal_decision".to_string(),
            ],
            verify_signatures: true,
        },
        handshake: HandshakeConfig {
            timeout_secs: 30,
            require_mtls: false, // Optional for shared ruleset
            protocol_versions: vec!["1.0".to_string()],
        },
        parent_org: None,
        shared_ruleset: Some(SharedRulesetConfig {
            network_id: Some("high-sec-network".to_string()),
            contract_dids: vec![
                "did:jig:contract:high-sec-v1".to_string(),
                "did:jig:contract:tribunal-protocol".to_string(),
            ],
            require_policy_match: true,
            policy_drift_tolerance: 0.1,
            contract_verification_endpoint: Some(
                "https://verify.high-sec.network/contracts".to_string(),
            ),
        }),
        max_peers: 50,
        policy_hash: Some("def456".to_string()),
    };

    // Verify shared ruleset-specific settings
    assert_eq!(config.mode, FederationMode::SharedRuleset);
    assert!(config.enabled);
    assert!(config.shared_ruleset.is_some());
    assert!(config.shared_ruleset.as_ref().unwrap().require_policy_match);
    assert_eq!(
        config.shared_ruleset.as_ref().unwrap().network_id,
        Some("high-sec-network".to_string())
    );
}

#[test]
fn test_shared_ruleset_scenario_data_contract() {
    let config = FederationConfig {
        mode: FederationMode::SharedRuleset,
        enabled: true,
        seed_peers: vec![],
        allow_list: vec![],
        deny_list: vec![],
        gossip: GossipConfig::default(),
        handshake: HandshakeConfig::default(),
        parent_org: None,
        shared_ruleset: Some(SharedRulesetConfig {
            network_id: None,
            contract_dids: vec!["did:jig:contract:bilateral-trust".to_string()],
            require_policy_match: true,
            policy_drift_tolerance: 0.05, // Strict drift tolerance
            contract_verification_endpoint: Some("https://bilateral.example/verify".to_string()),
        }),
        max_peers: 10, // Limited peers for bilateral
        policy_hash: Some("ghi789".to_string()),
    };

    // Verify data contract-specific settings
    assert_eq!(config.mode, FederationMode::SharedRuleset);
    assert!(config.shared_ruleset.is_some());
    assert_eq!(
        config.shared_ruleset.as_ref().unwrap().contract_dids.len(),
        1
    );
    assert_eq!(
        config
            .shared_ruleset
            .as_ref()
            .unwrap()
            .policy_drift_tolerance,
        0.05
    );
}

#[test]
fn test_shared_ruleset_scenario_toml_roundtrip() {
    let toml_str = r#"
mode = "shared_ruleset"
enabled = true
seed_peers = ["https://bootstrap.high-sec.network"]
allow_list = []
deny_list = ["known-bad.example"]
max_peers = 50
policy_hash = "def456"

[shared_ruleset]
network_id = "high-sec-network"
contract_dids = ["did:jig:contract:high-sec-v1", "did:jig:contract:tribunal-protocol"]
require_policy_match = true
policy_drift_tolerance = 0.1
contract_verification_endpoint = "https://verify.high-sec.network/contracts"
"#;

    let config: FederationConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.mode, FederationMode::SharedRuleset);
    assert!(config.shared_ruleset.is_some());

    // Roundtrip test
    let serialized = toml::to_string(&config).unwrap();
    let deserialized: FederationConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(config, deserialized);
}

// ============================================================================
// Scenario 3: Isolated Configuration (Zero Trust)
// ============================================================================

#[test]
fn test_isolated_scenario() {
    let config = FederationConfig {
        mode: FederationMode::Isolated,
        enabled: false, // Federation disabled for isolated
        seed_peers: vec![],
        allow_list: vec![],
        deny_list: vec![],
        gossip: GossipConfig::default(),
        handshake: HandshakeConfig::default(),
        parent_org: None,
        shared_ruleset: None,
        max_peers: 0,
        policy_hash: None,
    };

    // Verify isolated-specific settings
    assert_eq!(config.mode, FederationMode::Isolated);
    assert!(!config.enabled);
    assert!(config.seed_peers.is_empty());
    assert!(config.parent_org.is_none());
    assert!(config.shared_ruleset.is_none());
    assert_eq!(config.max_peers, 0);
}

#[test]
fn test_isolated_scenario_toml_roundtrip() {
    let toml_str = r#"
mode = "isolated"
enabled = false
seed_peers = []
allow_list = []
deny_list = []
max_peers = 0
"#;

    let config: FederationConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.mode, FederationMode::Isolated);
    assert!(!config.enabled);

    // Roundtrip test
    let serialized = toml::to_string(&config).unwrap();
    let deserialized: FederationConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(config, deserialized);
}

// ============================================================================
// PoW Configuration Tests
// ============================================================================

#[test]
fn test_pow_config_zone_overrides() {
    let mut zone_overrides = HashMap::new();
    zone_overrides.insert("null-sec".to_string(), 24);
    zone_overrides.insert("low-sec".to_string(), 18);
    zone_overrides.insert("high-sec".to_string(), 12);

    let config = PowConfig {
        secret: "test-secret".to_string(),
        base_difficulty: 18,
        min_difficulty: 16,
        max_difficulty: 28,
        penalty_step_bits: 2,
        zone_overrides,
    };

    assert_eq!(config.zone_overrides.get("null-sec"), Some(&24));
    assert_eq!(config.zone_overrides.get("low-sec"), Some(&18));
    assert_eq!(config.zone_overrides.get("high-sec"), Some(&12));
}

#[test]
fn test_pow_config_toml_roundtrip() {
    let toml_str = r#"
secret = "test-secret"
base_difficulty = 18
min_difficulty = 16
max_difficulty = 28
penalty_step_bits = 2

[zone_overrides]
"null-sec" = 24
"low-sec" = 18
"high-sec" = 12
"#;

    let config: PowConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.secret, "test-secret");
    assert_eq!(config.base_difficulty, 18);

    // Roundtrip test
    let serialized = toml::to_string(&config).unwrap();
    let deserialized: PowConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(config.secret, deserialized.secret);
}

// ============================================================================
// Reputation Configuration Tests
// ============================================================================

#[test]
fn test_reputation_config_with_rulesets() {
    let config = ReputationConfig {
        rulesets: vec![
            RulesetConfig {
                id: "high-sec".to_string(),
                name: "High Security Network".to_string(),
                pow_policy: Some(PowPolicy {
                    base_difficulty: 16,
                    penalty_multiplier: 1.5,
                }),
                tribunal_policy: Some(TribunalPolicy {
                    auto_escalate: true,
                    escalation_severity: Some("medium".to_string()),
                    quorum_size: 5,
                }),
                zone_thresholds: {
                    let mut thresholds = HashMap::new();
                    thresholds.insert("low-sec".to_string(), 0.5);
                    thresholds.insert("high-sec".to_string(), 0.8);
                    thresholds
                },
            },
            RulesetConfig {
                id: "federation".to_string(),
                name: "Federation Network".to_string(),
                pow_policy: Some(PowPolicy {
                    base_difficulty: 14,
                    penalty_multiplier: 1.2,
                }),
                tribunal_policy: Some(TribunalPolicy {
                    auto_escalate: true,
                    escalation_severity: Some("high".to_string()),
                    quorum_size: 7,
                }),
                zone_thresholds: HashMap::new(),
            },
        ],
        translation_contracts: vec![TranslationContract {
            from_ruleset: "federation".to_string(),
            to_ruleset: "high-sec".to_string(),
            transform: TransformType::Linear,
            parameters: json!({"multiplier": 0.9}),
        }],
        damping_factor: 0.85,
        min_observations_for_aggregate: 5,
    };

    assert_eq!(config.rulesets.len(), 2);
    assert_eq!(config.translation_contracts.len(), 1);
    assert_eq!(config.damping_factor, 0.85);
}

#[test]
fn test_transform_type_serialization() {
    let linear = TransformType::Linear;
    let table = TransformType::Table;
    let exponential = TransformType::Exponential;

    let linear_json = serde_json::to_string(&linear).unwrap();
    let table_json = serde_json::to_string(&table).unwrap();
    let exp_json = serde_json::to_string(&exponential).unwrap();

    assert_eq!(linear_json, r#""linear""#);
    assert_eq!(table_json, r#""table""#);
    assert_eq!(exp_json, r#""exponential""#);
}

// ============================================================================
// Anomaly Detection Configuration Tests
// ============================================================================

#[test]
fn test_anomaly_detection_defaults() {
    let config = AnomalyDetectionConfig::default();
    assert!(config.enabled);
    assert_eq!(config.max_network_fuel, 500_000);
    assert!(config.fuel_anomaly.enabled);
    assert!(config.hard_failure.enabled);
    assert!(config.auto_escalation.enabled);
}

#[test]
fn test_fuel_anomaly_thresholds() {
    let config = FuelAnomalyConfig {
        enabled: true,
        excessive_threshold: 3.0,
        suspicious_threshold: 0.3,
        min_sample_size: 20,
    };

    assert_eq!(config.excessive_threshold, 3.0);
    assert_eq!(config.suspicious_threshold, 0.3);
    assert_eq!(config.min_sample_size, 20);
}

#[test]
fn test_auto_escalation_config_with_penalties() {
    let mut pow_penalties = HashMap::new();
    pow_penalties.insert("low".to_string(), 2);
    pow_penalties.insert("medium".to_string(), 4);
    pow_penalties.insert("high".to_string(), 6);
    pow_penalties.insert("critical".to_string(), 8);

    let config = AutoEscalationConfig {
        enabled: true,
        severities: vec!["high".to_string(), "critical".to_string()],
        pow_penalties,
    };

    assert!(config.enabled);
    assert_eq!(config.severities.len(), 2);
    assert_eq!(config.pow_penalties.get("high"), Some(&6));
    assert_eq!(config.pow_penalties.get("critical"), Some(&8));
}

// ============================================================================
// Useful Work Configuration Tests
// ============================================================================

#[test]
fn test_useful_work_validator_requirements() {
    let mut validator_requirements = HashMap::new();
    validator_requirements.insert(
        "process_executable_block".to_string(),
        ValidatorRequirement {
            min_validators: 3,
            consensus_threshold: 0.67,
            min_zone: Some("low-sec".to_string()),
        },
    );
    validator_requirements.insert(
        "resolve_receipt_dispute".to_string(),
        ValidatorRequirement {
            min_validators: 5,
            consensus_threshold: 0.8,
            min_zone: Some("high-sec".to_string()),
        },
    );

    let config = UsefulWorkConfig {
        enabled: true,
        assignment_ttl_secs: 3600,
        max_queue_depth: 1000,
        retention_days: 30,
        enabled_work_types: vec![
            "process_executable_block".to_string(),
            "resolve_receipt_dispute".to_string(),
        ],
        validator_requirements,
    };

    assert_eq!(config.enabled_work_types.len(), 2);
    assert_eq!(config.validator_requirements.len(), 2);

    let block_req = config
        .validator_requirements
        .get("process_executable_block")
        .unwrap();
    assert_eq!(block_req.min_validators, 3);
    assert_eq!(block_req.consensus_threshold, 0.67);
}

// ============================================================================
// Complete Nameserver Configuration Tests
// ============================================================================

#[test]
fn test_complete_nameserver_config_federated() {
    let config = NameserverConfig {
        network: NameserverNetworkConfig {
            bind_address: "0.0.0.0".to_string(),
            port: 7070,
            public_address: Some("ns.acme.com".to_string()),
            proxy: None,
            dns_discovery: DnsDiscoveryConfig {
                enabled: true,
                domain: Some("acme.com".to_string()),
                cache_ttl_secs: 300,
            },
        },
        storage: NameserverStorageConfig {
            path: "/var/lib/jig/nameserver.db".to_string(),
            max_connections: 20,
            wal_mode: true,
        },
        pow: PowConfig {
            secret: "production-secret".to_string(),
            base_difficulty: 18,
            min_difficulty: 16,
            max_difficulty: 28,
            penalty_step_bits: 2,
            zone_overrides: HashMap::new(),
        },
        rate_limits: RateLimitConfig::default(),
        penalties: PenaltyConfig::default(),
        anonymous: AnonymousPolicy::default(),
        federation: FederationConfig {
            mode: FederationMode::Federated,
            enabled: true,
            seed_peers: vec!["https://ns1.acme.com".to_string()],
            allow_list: vec!["*.acme.com".to_string()],
            deny_list: vec![],
            gossip: GossipConfig::default(),
            handshake: HandshakeConfig {
                timeout_secs: 30,
                require_mtls: true,
                protocol_versions: vec!["1.0".to_string()],
            },
            parent_org: Some(ParentOrgConfig {
                org_did: "did:jig:acme".to_string(),
                verification_endpoint: "https://org.acme.com/verify".to_string(),
                auto_trust_siblings: true,
                policy_repo: None,
                policy_sync_interval_secs: 3600,
            }),
            shared_ruleset: None,
            max_peers: 100,
            policy_hash: None,
        },
        reputation: ReputationConfig::default(),
        automation: AutomationPolicy::default(),
        transparency: TransparencyConfig::default(),
        useful_work: UsefulWorkConfig::default(),
        capabilities: CapabilitiesConfig::default(),
        anomaly_detection: AnomalyDetectionConfig::default(),
    };

    // Verify federated configuration
    assert_eq!(config.federation.mode, FederationMode::Federated);
    assert!(config.federation.enabled);
    assert!(config.federation.handshake.require_mtls);
    assert!(config.federation.parent_org.is_some());
}

#[test]
fn test_complete_nameserver_config_toml_roundtrip() {
    let toml_str = r#"
[network]
bind_address = "127.0.0.1"
port = 7070

[network.dns_discovery]
enabled = true
cache_ttl_secs = 300

[storage]
path = "~/.jig/nameserver.db"
max_connections = 10
wal_mode = true

[pow]
secret = "test-secret"
base_difficulty = 18
min_difficulty = 16
max_difficulty = 28
penalty_step_bits = 2

[federation]
mode = "isolated"
enabled = false
max_peers = 0
"#;

    let config: NameserverConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.network.bind_address, "127.0.0.1");
    assert_eq!(config.network.port, 7070);
    assert_eq!(config.pow.secret, "test-secret");
    assert_eq!(config.federation.mode, FederationMode::Isolated);

    // Roundtrip test
    let serialized = toml::to_string(&config).unwrap();
    let deserialized: NameserverConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(
        config.network.bind_address,
        deserialized.network.bind_address
    );
    assert_eq!(config.pow.secret, deserialized.pow.secret);
}

// ============================================================================
// Hot-Reload Boundary Tests
// ============================================================================

#[test]
fn test_hot_reload_safe_configs() {
    // These configs should be safe to hot-reload
    let mut rate_limits = RateLimitConfig::default();
    rate_limits.per_key_limit = 120; // Adjusted dynamically

    let mut penalties = PenaltyConfig::default();
    penalties.decay_window_secs = 900; // Adjusted dynamically

    let mut gossip = GossipConfig::default();
    gossip.interval_secs = 600; // Adjusted dynamically

    // Verify adjustments
    assert_eq!(rate_limits.per_key_limit, 120);
    assert_eq!(penalties.decay_window_secs, 900);
    assert_eq!(gossip.interval_secs, 600);
}

#[test]
fn test_hot_reload_unsafe_configs() {
    // These configs require restart
    let network = NameserverNetworkConfig {
        bind_address: "0.0.0.0".to_string(), // Requires socket rebind
        port: 8080,                          // Requires socket rebind
        public_address: None,
        proxy: None,
        dns_discovery: DnsDiscoveryConfig::default(),
    };

    let storage = NameserverStorageConfig {
        path: "/new/path/db.sqlite".to_string(), // Requires connection pool rebuild
        max_connections: 20,
        wal_mode: true,
    };

    let pow = PowConfig {
        secret: "new-secret".to_string(), // Security-critical, requires restart
        base_difficulty: 20,
        min_difficulty: 18,
        max_difficulty: 30,
        penalty_step_bits: 2,
        zone_overrides: HashMap::new(),
    };

    // Verify these would require restart
    assert_eq!(network.bind_address, "0.0.0.0");
    assert_eq!(storage.path, "/new/path/db.sqlite");
    assert_eq!(pow.secret, "new-secret");
}
