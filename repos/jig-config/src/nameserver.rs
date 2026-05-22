//! Nameserver and Federation Configuration
//!
//! This module provides configuration for jig-nameserver instances across three
//! federation scenarios:
//! 1. **Federated** - Share parent organization (high trust)
//! 2. **Shared Ruleset** - Same network or data contract link (medium trust)
//! 3. **Isolated** - No federation (zero trust)
//!
//! Configuration is designed with hot-reload capabilities where safe, requiring
//! restart only for security-critical or foundational changes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Network Configuration
// ============================================================================

/// Network binding and discovery configuration
///
/// **Hot-reload:** No (requires restart)
/// **Reason:** Bind address/port changes require socket rebinding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NameserverNetworkConfig {
    /// Address to bind nameserver on
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Port to listen on
    #[serde(default = "default_nameserver_port")]
    pub port: u16,

    /// Public address for federation advertising
    #[serde(default)]
    pub public_address: Option<String>,

    /// Proxy configuration for outbound federation requests
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,

    /// DNS discovery configuration
    #[serde(default)]
    pub dns_discovery: DnsDiscoveryConfig,
}

fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}

fn default_nameserver_port() -> u16 {
    7070
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyConfig {
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsDiscoveryConfig {
    /// Enable DNS-based peer discovery (_jig-ns._tcp SRV records)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Domain for SRV record publishing
    #[serde(default)]
    pub domain: Option<String>,

    /// Cache TTL for DNS lookups (seconds)
    #[serde(default = "default_dns_cache_ttl")]
    pub cache_ttl_secs: u32,
}

fn default_dns_cache_ttl() -> u32 {
    300
}

// ============================================================================
// Storage Configuration
// ============================================================================

/// Storage backend configuration
///
/// **Hot-reload:** No (requires restart)
/// **Reason:** Database connection changes require connection pool rebuild
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameserverStorageConfig {
    /// SQLite database path
    #[serde(default = "default_storage_path")]
    pub path: String,

    /// Maximum database connections
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Enable WAL mode for better concurrency
    #[serde(default = "default_true")]
    pub wal_mode: bool,
}

fn default_storage_path() -> String {
    "~/.jig/nameserver.db".to_string()
}

fn default_max_connections() -> u32 {
    10
}

// ============================================================================
// Proof-of-Work Configuration
// ============================================================================

/// Adaptive PoW configuration with penalty-based scaling
///
/// **Hot-reload:** Partial (difficulty tiers yes, secret no)
/// **Reason:** Secret is security-critical and affects all challenge generation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PowConfig {
    /// Secret for keyed hashing (NEVER hot-reload)
    ///
    /// **Hot-reload:** No
    /// **Security:** Critical - changing this invalidates all outstanding challenges
    pub secret: String,

    /// Base difficulty for new accounts (leading zero bits)
    ///
    /// **Hot-reload:** Yes (applied to new challenges only)
    #[serde(default = "default_base_difficulty")]
    pub base_difficulty: u16,

    /// Minimum difficulty floor
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_min_difficulty")]
    pub min_difficulty: u16,

    /// Maximum difficulty ceiling
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_max_difficulty")]
    pub max_difficulty: u16,

    /// Penalty step size (bits added per penalty point)
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_penalty_step")]
    pub penalty_step_bits: u16,

    /// Zone-specific difficulty overrides
    ///
    /// **Hot-reload:** Yes
    #[serde(default)]
    pub zone_overrides: HashMap<String, u16>,
}

fn default_base_difficulty() -> u16 {
    18
}

fn default_min_difficulty() -> u16 {
    16
}

fn default_max_difficulty() -> u16 {
    28
}

fn default_penalty_step() -> u16 {
    2
}

// ============================================================================
// Rate Limiting Configuration
// ============================================================================

/// Multi-tier rate limiting configuration
///
/// **Hot-reload:** Yes
/// **Reason:** Safe to adjust limits dynamically using atomic updates
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RateLimitConfig {
    /// Per-key rate limit (requests/minute)
    #[serde(default = "default_per_key_limit")]
    pub per_key_limit: u32,

    /// Per-IP rate limit (requests/minute)
    #[serde(default = "default_per_ip_limit")]
    pub per_ip_limit: u32,

    /// Global circuit breaker (requests/second)
    #[serde(default = "default_global_limit")]
    pub global_limit: u32,

    /// Burst allowance multiplier
    #[serde(default = "default_burst_multiplier")]
    pub burst_multiplier: f64,

    /// Zone-specific overrides
    #[serde(default)]
    pub zone_overrides: HashMap<String, ZoneRateLimits>,
}

fn default_per_key_limit() -> u32 {
    60
}

fn default_per_ip_limit() -> u32 {
    120
}

fn default_global_limit() -> u32 {
    1000
}

fn default_burst_multiplier() -> f64 {
    1.5
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZoneRateLimits {
    pub per_key_limit: u32,
    pub per_ip_limit: u32,
}

// ============================================================================
// Penalty Configuration
// ============================================================================

/// Penalty accumulation and decay configuration
///
/// **Hot-reload:** Yes
/// **Reason:** Penalty parameters can be safely adjusted dynamically
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PenaltyConfig {
    /// Penalty decay time window (seconds)
    #[serde(default = "default_decay_window")]
    pub decay_window_secs: u32,

    /// Maximum penalty points before auto-suspension
    #[serde(default = "default_max_penalty_points")]
    pub max_penalty_points: f64,

    /// Penalty floor (minimum time before first decay)
    #[serde(default = "default_penalty_floor")]
    pub penalty_floor_secs: u32,

    /// Auto-escalate to tribunal at this threshold
    #[serde(default = "default_tribunal_threshold")]
    pub tribunal_escalation_threshold: f64,

    /// Penalty weights by anomaly kind
    #[serde(default)]
    pub anomaly_weights: HashMap<String, f64>,
}

fn default_decay_window() -> u32 {
    600 // 10 minutes
}

fn default_max_penalty_points() -> f64 {
    100.0
}

fn default_penalty_floor() -> u32 {
    60
}

fn default_tribunal_threshold() -> f64 {
    50.0
}

// ============================================================================
// Anonymous Policy Configuration
// ============================================================================

/// Anonymous account policy (null-sec zone)
///
/// **Hot-reload:** Yes
/// **Reason:** Policy changes can be applied to new sessions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnonymousPolicy {
    /// Enable anonymous accounts
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Minimum PoW difficulty for anonymous accounts
    #[serde(default = "default_anon_difficulty")]
    pub min_difficulty: u16,

    /// Token TTL for anonymous sessions (seconds)
    #[serde(default = "default_anon_ttl")]
    pub token_ttl_secs: u32,

    /// Maximum concurrent anonymous sessions per IP
    #[serde(default = "default_anon_sessions")]
    pub max_sessions_per_ip: u32,
}

fn default_anon_difficulty() -> u16 {
    24
}

fn default_anon_ttl() -> u32 {
    3600 // 1 hour
}

fn default_anon_sessions() -> u32 {
    5
}

// ============================================================================
// Federation Configuration (Three Scenarios)
// ============================================================================

/// Federation mode selector
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FederationMode {
    /// Fully federated with parent organization (high trust)
    Federated,
    /// Shared ruleset via network or data contract (medium trust)
    SharedRuleset,
    /// Isolated operation (zero trust)
    Isolated,
}

/// Federation configuration for nameserver peering
///
/// **Hot-reload:** Partial (peer lists yes, mode no)
/// **Reason:** Mode changes affect discovery mechanism; peer lists can update dynamically
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationConfig {
    /// Federation mode
    ///
    /// **Hot-reload:** No (requires restart to change discovery mechanism)
    #[serde(default)]
    pub mode: FederationMode,

    /// Enable federation
    #[serde(default)]
    pub enabled: bool,

    /// Seed peers for discovery (URLs)
    ///
    /// **Hot-reload:** Yes
    #[serde(default)]
    pub seed_peers: Vec<String>,

    /// Allow list (domain patterns)
    ///
    /// **Hot-reload:** Yes (using atomic swap)
    #[serde(default)]
    pub allow_list: Vec<String>,

    /// Deny list (domain patterns)
    ///
    /// **Hot-reload:** Yes (using atomic swap)
    #[serde(default)]
    pub deny_list: Vec<String>,

    /// Gossip protocol settings
    #[serde(default)]
    pub gossip: GossipConfig,

    /// Handshake protocol settings
    #[serde(default)]
    pub handshake: HandshakeConfig,

    /// Parent organization configuration (for Federated mode)
    #[serde(default)]
    pub parent_org: Option<ParentOrgConfig>,

    /// Ruleset sharing configuration (for SharedRuleset mode)
    #[serde(default)]
    pub shared_ruleset: Option<SharedRulesetConfig>,

    /// Maximum peers to maintain
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,

    /// Policy hash for federation compatibility
    ///
    /// **Hot-reload:** Yes (new hash computed on config change)
    #[serde(default)]
    pub policy_hash: Option<String>,
}

impl Default for FederationMode {
    fn default() -> Self {
        Self::Isolated
    }
}

fn default_max_peers() -> usize {
    50
}

/// Gossip protocol configuration
///
/// **Hot-reload:** Yes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GossipConfig {
    /// Gossip round interval (seconds)
    #[serde(default = "default_gossip_interval")]
    pub interval_secs: u32,

    /// Maximum messages per gossip batch
    #[serde(default = "default_gossip_batch_size")]
    pub batch_size: usize,

    /// Message types to gossip
    #[serde(default = "default_gossip_types")]
    pub message_types: Vec<String>,

    /// Enable signature verification
    #[serde(default = "default_true")]
    pub verify_signatures: bool,
}

fn default_gossip_interval() -> u32 {
    300 // 5 minutes
}

fn default_gossip_batch_size() -> usize {
    100
}

fn default_gossip_types() -> Vec<String> {
    vec![
        "policy_hash".to_string(),
        "reputation_summary".to_string(),
        "tribunal_decision".to_string(),
    ]
}

/// Handshake protocol configuration
///
/// **Hot-reload:** Partial (timeout yes, TLS config no)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandshakeConfig {
    /// Handshake timeout (seconds)
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_handshake_timeout")]
    pub timeout_secs: u32,

    /// Require mutual TLS
    ///
    /// **Hot-reload:** No (affects connection establishment)
    #[serde(default)]
    pub require_mtls: bool,

    /// Supported protocol versions
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_protocol_versions")]
    pub protocol_versions: Vec<String>,
}

fn default_handshake_timeout() -> u32 {
    30
}

fn default_protocol_versions() -> Vec<String> {
    vec!["1.0".to_string()]
}

/// Parent organization configuration (Federated mode)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParentOrgConfig {
    /// Parent organization DID
    pub org_did: String,

    /// Org verification endpoint
    pub verification_endpoint: String,

    /// Auto-trust peers in same org
    #[serde(default = "default_true")]
    pub auto_trust_siblings: bool,

    /// Shared policy repository URL
    #[serde(default)]
    pub policy_repo: Option<String>,

    /// Automatic policy sync interval (seconds)
    #[serde(default = "default_policy_sync_interval")]
    pub policy_sync_interval_secs: u32,
}

fn default_policy_sync_interval() -> u32 {
    3600 // 1 hour
}

/// Shared ruleset configuration (SharedRuleset mode)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SharedRulesetConfig {
    /// Network ID (for high-sec network participation)
    #[serde(default)]
    pub network_id: Option<String>,

    /// Data contract DIDs (for data contract links)
    #[serde(default)]
    pub contract_dids: Vec<String>,

    /// Require policy hash match for peering
    #[serde(default = "default_true")]
    pub require_policy_match: bool,

    /// Acceptable policy drift (hash difference tolerance)
    #[serde(default)]
    pub policy_drift_tolerance: f64,

    /// Contract verification endpoint
    #[serde(default)]
    pub contract_verification_endpoint: Option<String>,
}

// ============================================================================
// Reputation Configuration
// ============================================================================

/// Reputation system configuration
///
/// **Hot-reload:** Partial (weights yes, rulesets no)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReputationConfig {
    /// Local rulesets
    ///
    /// **Hot-reload:** No (requires re-initialization)
    #[serde(default)]
    pub rulesets: Vec<RulesetConfig>,

    /// Translation contracts between rulesets
    ///
    /// **Hot-reload:** Yes
    #[serde(default)]
    pub translation_contracts: Vec<TranslationContract>,

    /// PageRank damping factor
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_damping_factor")]
    pub damping_factor: f64,

    /// Minimum observations for aggregate
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_min_observations")]
    pub min_observations_for_aggregate: usize,
}

fn default_damping_factor() -> f64 {
    0.85
}

fn default_min_observations() -> usize {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RulesetConfig {
    /// Ruleset identifier
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// PoW policy for this ruleset
    #[serde(default)]
    pub pow_policy: Option<PowPolicy>,

    /// Tribunal policy for this ruleset
    #[serde(default)]
    pub tribunal_policy: Option<TribunalPolicy>,

    /// Reputation thresholds for zone transitions
    #[serde(default)]
    pub zone_thresholds: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PowPolicy {
    /// Base difficulty for this ruleset
    pub base_difficulty: u16,

    /// Penalty multiplier
    #[serde(default = "default_penalty_multiplier")]
    pub penalty_multiplier: f64,
}

fn default_penalty_multiplier() -> f64 {
    1.0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TribunalPolicy {
    /// Auto-escalate on threshold
    #[serde(default = "default_true")]
    pub auto_escalate: bool,

    /// Escalation severity threshold
    #[serde(default)]
    pub escalation_severity: Option<String>,

    /// Quorum size
    #[serde(default = "default_quorum_size")]
    pub quorum_size: usize,
}

fn default_quorum_size() -> usize {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TranslationContract {
    /// Source ruleset
    pub from_ruleset: String,

    /// Target ruleset
    pub to_ruleset: String,

    /// Translation function type
    pub transform: TransformType,

    /// Weighted multiplier or lookup table
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransformType {
    Linear,
    Table,
    Exponential,
}

// ============================================================================
// Automation Policy Configuration
// ============================================================================

/// Automation policy for tribunal and penalty enforcement
///
/// **Hot-reload:** Yes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutomationPolicy {
    /// Power law witness amplification exponent
    #[serde(default = "default_power_law_exponent")]
    pub power_law_exponent: f64,

    /// Pile-on factor for coordinated penalties
    #[serde(default = "default_pile_on_factor")]
    pub pile_on_factor: f64,

    /// Quorum requirement for tribunal auto-escalation
    #[serde(default = "default_quorum_requirement")]
    pub quorum_requirement: usize,

    /// Evidence window for case aggregation (seconds)
    #[serde(default = "default_evidence_window")]
    pub evidence_window_secs: u32,

    /// Maximum auto-escalations per hour
    #[serde(default = "default_max_escalations")]
    pub max_escalations_per_hour: u32,
}

fn default_power_law_exponent() -> f64 {
    1.5
}

fn default_pile_on_factor() -> f64 {
    0.8
}

fn default_quorum_requirement() -> usize {
    3
}

fn default_evidence_window() -> u32 {
    300 // 5 minutes
}

fn default_max_escalations() -> u32 {
    10
}

// ============================================================================
// Transparency Configuration
// ============================================================================

/// Transparency logging configuration
///
/// **Hot-reload:** Yes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparencyConfig {
    /// Enable transparency logging
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Log file path
    #[serde(default = "default_transparency_log_path")]
    pub log_path: String,

    /// Publish interval for merkle root (seconds)
    #[serde(default = "default_publish_interval")]
    pub publish_interval_secs: u32,

    /// Events to log
    #[serde(default = "default_transparency_events")]
    pub events: Vec<String>,

    /// Enable public HTTP endpoint for log queries
    #[serde(default)]
    pub public_endpoint: bool,
}

fn default_transparency_log_path() -> String {
    "~/.jig/transparency.log".to_string()
}

fn default_publish_interval() -> u32 {
    3600 // 1 hour
}

fn default_transparency_events() -> Vec<String> {
    vec![
        "tribunal_decision".to_string(),
        "reputation_update".to_string(),
        "penalty_applied".to_string(),
        "identity_claimed".to_string(),
    ]
}

// ============================================================================
// Useful Work Configuration
// ============================================================================

/// Useful work assignment configuration
///
/// **Hot-reload:** Yes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsefulWorkConfig {
    /// Enable useful work system
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Assignment TTL (seconds)
    #[serde(default = "default_assignment_ttl")]
    pub assignment_ttl_secs: u32,

    /// Maximum queue depth
    #[serde(default = "default_queue_depth")]
    pub max_queue_depth: usize,

    /// Work retention after completion (days)
    #[serde(default = "default_work_retention")]
    pub retention_days: u32,

    /// Work types enabled
    #[serde(default = "default_work_types")]
    pub enabled_work_types: Vec<String>,

    /// Validator requirements per work type
    #[serde(default)]
    pub validator_requirements: HashMap<String, ValidatorRequirement>,
}

fn default_assignment_ttl() -> u32 {
    3600 // 1 hour
}

fn default_queue_depth() -> usize {
    1000
}

fn default_work_retention() -> u32 {
    30
}

fn default_work_types() -> Vec<String> {
    vec![
        "validate_block".to_string(),
        "verify_observation".to_string(),
        "process_executable_block".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorRequirement {
    /// Minimum validators required
    pub min_validators: usize,

    /// Consensus threshold (e.g., 0.67 for 2/3)
    pub consensus_threshold: f64,

    /// Minimum zone requirement
    #[serde(default)]
    pub min_zone: Option<String>,
}

// ============================================================================
// Capabilities Configuration
// ============================================================================

/// Capabilities advertisement configuration
///
/// **Hot-reload:** Yes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilitiesConfig {
    /// Enable capabilities advertisement
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// DNS TXT record content
    #[serde(default)]
    pub dns_txt_record: Option<String>,

    /// .well-known endpoint path
    #[serde(default = "default_capabilities_endpoint")]
    pub endpoint_path: String,

    /// Capabilities to advertise
    #[serde(default)]
    pub advertised_capabilities: Vec<String>,

    /// Affordances to advertise
    #[serde(default)]
    pub affordances: Vec<String>,
}

fn default_capabilities_endpoint() -> String {
    "/.well-known/jig-ns/capabilities".to_string()
}

// ============================================================================
// Anomaly Detection Configuration
// ============================================================================

/// Receipt anomaly detection configuration
///
/// **Hot-reload:** Yes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnomalyDetectionConfig {
    /// Enable anomaly detection
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum fuel threshold for network operations
    #[serde(default = "default_max_network_fuel")]
    pub max_network_fuel: u64,

    /// Fuel usage anomaly detection settings
    #[serde(default)]
    pub fuel_anomaly: FuelAnomalyConfig,

    /// Hard failure detection settings
    #[serde(default)]
    pub hard_failure: HardFailureConfig,

    /// Auto-escalation settings
    #[serde(default)]
    pub auto_escalation: AutoEscalationConfig,
}

fn default_max_network_fuel() -> u64 {
    500_000
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FuelAnomalyConfig {
    /// Enable fuel anomaly detection
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Excessive threshold multiplier (vs historical avg)
    #[serde(default = "default_excessive_threshold")]
    pub excessive_threshold: f64,

    /// Suspicious threshold multiplier (vs historical avg)
    #[serde(default = "default_suspicious_threshold")]
    pub suspicious_threshold: f64,

    /// Minimum sample size for baseline
    #[serde(default = "default_min_sample_size")]
    pub min_sample_size: usize,
}

fn default_excessive_threshold() -> f64 {
    3.0
}

fn default_suspicious_threshold() -> f64 {
    0.3
}

fn default_min_sample_size() -> usize {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HardFailureConfig {
    /// Enable hard failure detection
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Consecutive failures to trigger alert
    #[serde(default = "default_failure_threshold")]
    pub consecutive_threshold: u32,

    /// Time window for failure counting (seconds)
    #[serde(default = "default_failure_window")]
    pub time_window_secs: u32,
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_failure_window() -> u32 {
    300 // 5 minutes
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutoEscalationConfig {
    /// Enable auto-escalation to tribunal
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Severity levels that trigger auto-escalation
    #[serde(default = "default_escalation_severities")]
    pub severities: Vec<String>,

    /// PoW penalty bits for each severity
    #[serde(default)]
    pub pow_penalties: HashMap<String, u32>,
}

fn default_escalation_severities() -> Vec<String> {
    vec!["high".to_string(), "critical".to_string()]
}

// ============================================================================
// Root Nameserver Configuration
// ============================================================================

/// Complete nameserver configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NameserverConfig {
    /// Network configuration
    #[serde(default)]
    pub network: NameserverNetworkConfig,

    /// Storage configuration
    #[serde(default)]
    pub storage: NameserverStorageConfig,

    /// Proof-of-Work configuration
    pub pow: PowConfig,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limits: RateLimitConfig,

    /// Penalty configuration
    #[serde(default)]
    pub penalties: PenaltyConfig,

    /// Anonymous account policy
    #[serde(default)]
    pub anonymous: AnonymousPolicy,

    /// Federation configuration
    #[serde(default)]
    pub federation: FederationConfig,

    /// Reputation configuration
    #[serde(default)]
    pub reputation: ReputationConfig,

    /// Automation policy
    #[serde(default)]
    pub automation: AutomationPolicy,

    /// Transparency logging
    #[serde(default)]
    pub transparency: TransparencyConfig,

    /// Useful work configuration
    #[serde(default)]
    pub useful_work: UsefulWorkConfig,

    /// Capabilities advertisement
    #[serde(default)]
    pub capabilities: CapabilitiesConfig,

    /// Anomaly detection
    #[serde(default)]
    pub anomaly_detection: AnomalyDetectionConfig,
}

impl Default for NameserverNetworkConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            port: default_nameserver_port(),
            public_address: None,
            proxy: None,
            dns_discovery: DnsDiscoveryConfig::default(),
        }
    }
}

impl Default for DnsDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            domain: None,
            cache_ttl_secs: default_dns_cache_ttl(),
        }
    }
}

impl Default for NameserverStorageConfig {
    fn default() -> Self {
        Self {
            path: default_storage_path(),
            max_connections: default_max_connections(),
            wal_mode: default_true(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_key_limit: default_per_key_limit(),
            per_ip_limit: default_per_ip_limit(),
            global_limit: default_global_limit(),
            burst_multiplier: default_burst_multiplier(),
            zone_overrides: HashMap::new(),
        }
    }
}

impl Default for PenaltyConfig {
    fn default() -> Self {
        Self {
            decay_window_secs: default_decay_window(),
            max_penalty_points: default_max_penalty_points(),
            penalty_floor_secs: default_penalty_floor(),
            tribunal_escalation_threshold: default_tribunal_threshold(),
            anomaly_weights: HashMap::new(),
        }
    }
}

impl Default for AnonymousPolicy {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            min_difficulty: default_anon_difficulty(),
            token_ttl_secs: default_anon_ttl(),
            max_sessions_per_ip: default_anon_sessions(),
        }
    }
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            mode: FederationMode::default(),
            enabled: false,
            seed_peers: Vec::new(),
            allow_list: Vec::new(),
            deny_list: Vec::new(),
            gossip: GossipConfig::default(),
            handshake: HandshakeConfig::default(),
            parent_org: None,
            shared_ruleset: None,
            max_peers: default_max_peers(),
            policy_hash: None,
        }
    }
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_gossip_interval(),
            batch_size: default_gossip_batch_size(),
            message_types: default_gossip_types(),
            verify_signatures: default_true(),
        }
    }
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_handshake_timeout(),
            require_mtls: false,
            protocol_versions: default_protocol_versions(),
        }
    }
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            rulesets: Vec::new(),
            translation_contracts: Vec::new(),
            damping_factor: default_damping_factor(),
            min_observations_for_aggregate: default_min_observations(),
        }
    }
}

impl Default for AutomationPolicy {
    fn default() -> Self {
        Self {
            power_law_exponent: default_power_law_exponent(),
            pile_on_factor: default_pile_on_factor(),
            quorum_requirement: default_quorum_requirement(),
            evidence_window_secs: default_evidence_window(),
            max_escalations_per_hour: default_max_escalations(),
        }
    }
}

impl Default for TransparencyConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            log_path: default_transparency_log_path(),
            publish_interval_secs: default_publish_interval(),
            events: default_transparency_events(),
            public_endpoint: false,
        }
    }
}

impl Default for UsefulWorkConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            assignment_ttl_secs: default_assignment_ttl(),
            max_queue_depth: default_queue_depth(),
            retention_days: default_work_retention(),
            enabled_work_types: default_work_types(),
            validator_requirements: HashMap::new(),
        }
    }
}

impl Default for CapabilitiesConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            dns_txt_record: None,
            endpoint_path: default_capabilities_endpoint(),
            advertised_capabilities: Vec::new(),
            affordances: Vec::new(),
        }
    }
}

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_network_fuel: default_max_network_fuel(),
            fuel_anomaly: FuelAnomalyConfig::default(),
            hard_failure: HardFailureConfig::default(),
            auto_escalation: AutoEscalationConfig::default(),
        }
    }
}

impl Default for FuelAnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            excessive_threshold: default_excessive_threshold(),
            suspicious_threshold: default_suspicious_threshold(),
            min_sample_size: default_min_sample_size(),
        }
    }
}

impl Default for HardFailureConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            consecutive_threshold: default_failure_threshold(),
            time_window_secs: default_failure_window(),
        }
    }
}

impl Default for AutoEscalationConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            severities: default_escalation_severities(),
            pow_penalties: HashMap::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federation_modes() {
        let federated = FederationMode::Federated;
        let shared = FederationMode::SharedRuleset;
        let isolated = FederationMode::Isolated;

        assert_ne!(federated, shared);
        assert_ne!(shared, isolated);
        assert_ne!(isolated, federated);
    }

    #[test]
    fn test_default_nameserver_network_config() {
        let config = NameserverNetworkConfig::default();
        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.port, 7070);
        assert!(config.dns_discovery.enabled);
    }

    #[test]
    fn test_default_pow_config_values() {
        let base = default_base_difficulty();
        let min = default_min_difficulty();
        let max = default_max_difficulty();

        assert!(min <= base);
        assert!(base <= max);
    }

    #[test]
    fn test_rate_limit_defaults() {
        let config = RateLimitConfig::default();
        assert!(config.per_key_limit > 0);
        assert!(config.per_ip_limit > config.per_key_limit);
        assert!(config.global_limit > config.per_ip_limit);
        assert!(config.burst_multiplier >= 1.0);
    }

    #[test]
    fn test_federation_config_isolated_default() {
        let config = FederationConfig::default();
        assert_eq!(config.mode, FederationMode::Isolated);
        assert!(!config.enabled);
    }
}
