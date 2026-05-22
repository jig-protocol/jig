//! Bridge-specific configuration types for jig-config.
//!
//! This module defines explicit configuration for named bridges (IRC, Email, etc.)
//! and template configurations for bridge categories (enterprise messengers, etc.).
//!
//! # Architecture
//!
//! - **Named Bridges**: Explicit configs for specific integrations (IRC, Email, ATProto, etc.)
//! - **Category Bridges**: Generic templates for classes of bridges (Slack-like, Discord-like, etc.)
//! - All bridges build on the generic `BridgeConfig` from `interop.rs`
//!
//! # Native vs. External Bridges
//!
//! - **Native**: IRC, Email, WebSocket, Federation (implemented in jig-server)
//! - **External**: ATProto, ActivityPub, enterprise messengers (community-implemented)

use crate::interop::{BridgeConfig, TransformConfig, TransformType};
use crate::profiles::Profile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// IRC Bridge (Native Protocol)
// ============================================================================

/// IRC bridge configuration (native jig-server protocol).
///
/// IRC is a native protocol in jig-server (RFC 1459 compliant).
/// Maps IRC commands (PRIVMSG, JOIN, etc.) to Jig blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IrcBridgeConfig {
    /// Enable IRC server
    pub enabled: bool,

    /// IRC server name (default: "jig.irc.local")
    pub server_name: String,

    /// TCP port for IRC connections (default: 6667)
    pub port: u16,

    /// Bind address (default: "127.0.0.1" for potato, "0.0.0.0" for hyperscale)
    pub bind_address: String,

    /// Auto-join channels on connect
    #[serde(default)]
    pub auto_join_channels: Vec<String>,

    /// Nick validation rules
    #[serde(default)]
    pub nick_validation: NickValidation,

    /// Block wrapping configuration
    #[serde(default)]
    pub block_wrapper: BlockWrapperConfig,

    /// Generic bridge settings (rate limits, fuel, monitoring)
    #[serde(default)]
    pub bridge: BridgeConfig,
}

/// Nick validation rules for IRC
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NickValidation {
    /// Max nickname length (default: 30, per RFC 1459)
    pub max_length: usize,

    /// Allowed characters (default: alphanumeric + []\\`_^{|}- )
    pub allowed_chars: String,

    /// Require unique nicks (default: true)
    pub require_unique: bool,
}

/// Block wrapping configuration (IRC → Jig block)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockWrapperConfig {
    /// Wrap IRC messages as Jig blocks (default: true)
    pub enabled: bool,

    /// Fuel budget for wrapping (default: 10,000)
    pub fuel_budget: u64,

    /// Preserve IRC metadata in block (default: true)
    pub preserve_metadata: bool,
}

impl Default for IrcBridgeConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl IrcBridgeConfig {
    pub fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                enabled: true,
                server_name: "jig.irc.local".to_string(),
                port: 6667,
                bind_address: "127.0.0.1".to_string(),
                auto_join_channels: vec![],
                nick_validation: NickValidation::default(),
                block_wrapper: BlockWrapperConfig::default(),
                bridge: BridgeConfig::default_for_profile(Profile::Potato),
            },
            Profile::Standard => Self {
                enabled: true,
                server_name: "jig.irc.local".to_string(),
                port: 6667,
                bind_address: "0.0.0.0".to_string(),
                auto_join_channels: vec!["#general".to_string()],
                nick_validation: NickValidation::default(),
                block_wrapper: BlockWrapperConfig::default(),
                bridge: BridgeConfig::default_for_profile(Profile::Standard),
            },
            Profile::Hyperscale => Self {
                enabled: true,
                server_name: "jig.irc.network".to_string(),
                port: 6667,
                bind_address: "0.0.0.0".to_string(),
                auto_join_channels: vec!["#jig".to_string(), "#jig-dev".to_string()],
                nick_validation: NickValidation::default(),
                block_wrapper: BlockWrapperConfig::default(),
                bridge: BridgeConfig::default_for_profile(Profile::Hyperscale),
            },
            Profile::Custom => Self {
                enabled: false,
                server_name: "jig.irc.local".to_string(),
                port: 6667,
                bind_address: "127.0.0.1".to_string(),
                auto_join_channels: vec![],
                nick_validation: NickValidation::default(),
                block_wrapper: BlockWrapperConfig::default(),
                bridge: BridgeConfig::default_for_profile(Profile::Custom),
            },
        }
    }
}

impl Default for NickValidation {
    fn default() -> Self {
        Self {
            max_length: 30,
            allowed_chars:
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[]\\`_^{|}-"
                    .to_string(),
            require_unique: true,
        }
    }
}

impl Default for BlockWrapperConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fuel_budget: 10_000,
            preserve_metadata: true,
        }
    }
}

// ============================================================================
// Email Bridge (Native Protocol)
// ============================================================================

/// Email bridge configuration (native jig-server protocol).
///
/// Provides SMTP/IMAP interfaces for email client compatibility.
/// Maps email messages to Jig blocks with relay support.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmailBridgeConfig {
    /// Enable email bridge
    pub enabled: bool,

    /// SMTP server configuration
    #[serde(default)]
    pub smtp: SmtpConfig,

    /// IMAP server configuration (optional)
    #[serde(default)]
    pub imap: ImapConfig,

    /// Relay configuration (for outbound email)
    #[serde(default)]
    pub relay: RelayConfig,

    /// Deliverability tracking and analytics
    #[serde(default)]
    pub deliverability: DeliverabilityConfig,

    /// Generic bridge settings
    #[serde(default)]
    pub bridge: BridgeConfig,
}

/// SMTP server configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmtpConfig {
    /// Enable SMTP server
    pub enabled: bool,

    /// SMTP port (default: 2525 for dev, 25 for production)
    pub port: u16,

    /// Submission port (default: 587)
    pub submission_port: u16,

    /// Bind address
    pub bind_address: String,

    /// MX domains for this server
    #[serde(default)]
    pub mx_domains: Vec<String>,

    /// Enable STARTTLS (default: true)
    pub starttls: bool,

    /// Require authentication for submission (default: true)
    pub require_auth: bool,
}

/// IMAP server configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImapConfig {
    /// Enable IMAP server (default: false for potato)
    pub enabled: bool,

    /// IMAP port (default: 143, 993 for IMAPS)
    pub port: u16,

    /// Bind address
    pub bind_address: String,

    /// Enable STARTTLS (default: true)
    pub starttls: bool,
}

/// Relay configuration for outbound email
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Primary relay method
    pub method: RelayMethod,

    /// Community relay participation (donate bandwidth)
    pub community_relay: bool,

    /// Donated relay quota per day (bytes)
    pub donated_quota_bytes: u64,

    /// Daily sending quota (emails per day)
    pub relay_quota_per_day: u32,

    /// DNS discovery for Jig-to-Jig delivery
    pub dns_discovery: bool,

    /// SPF/DKIM enforcement level
    pub spf_dkim_enforcement: EnforcementLevel,
}

/// Relay method for outbound email
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayMethod {
    /// Use SendGrid (free tier: 100 emails/day)
    SendGrid { api_key: Option<String> },

    /// Use community relay network
    Community,

    /// Direct send (requires clean IP reputation)
    Direct,

    /// Custom SMTP relay
    Custom {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
}

/// SPF/DKIM enforcement level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementLevel {
    /// No enforcement (accept all)
    None,
    /// Log failures but accept
    Lenient,
    /// Reject on hard fails only
    Moderate,
    /// Strict enforcement (reject all failures)
    Strict,
}

/// Deliverability tracking configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliverabilityConfig {
    /// Enable deliverability tracking
    pub enabled: bool,

    /// Analytics backend (default: "duckdb" for potato)
    pub analytics_backend: String,

    /// Track email opens (default: false for privacy)
    pub track_opens: bool,

    /// Track bounces (default: true)
    pub track_bounces: bool,

    /// Track clicks (default: false for privacy)
    pub track_clicks: bool,
}

impl Default for EmailBridgeConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl EmailBridgeConfig {
    pub fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                enabled: false, // Disabled by default for potato
                smtp: SmtpConfig::default_for_profile(Profile::Potato),
                imap: ImapConfig::default_for_profile(Profile::Potato),
                relay: RelayConfig::default_for_profile(Profile::Potato),
                deliverability: DeliverabilityConfig::default_for_profile(Profile::Potato),
                bridge: BridgeConfig::default_for_profile(Profile::Potato),
            },
            Profile::Standard => Self {
                enabled: true,
                smtp: SmtpConfig::default_for_profile(Profile::Standard),
                imap: ImapConfig::default_for_profile(Profile::Standard),
                relay: RelayConfig::default_for_profile(Profile::Standard),
                deliverability: DeliverabilityConfig::default_for_profile(Profile::Standard),
                bridge: BridgeConfig::default_for_profile(Profile::Standard),
            },
            Profile::Hyperscale => Self {
                enabled: true,
                smtp: SmtpConfig::default_for_profile(Profile::Hyperscale),
                imap: ImapConfig::default_for_profile(Profile::Hyperscale),
                relay: RelayConfig::default_for_profile(Profile::Hyperscale),
                deliverability: DeliverabilityConfig::default_for_profile(Profile::Hyperscale),
                bridge: BridgeConfig::default_for_profile(Profile::Hyperscale),
            },
            Profile::Custom => Self {
                enabled: false,
                smtp: SmtpConfig::default(),
                imap: ImapConfig::default(),
                relay: RelayConfig::default(),
                deliverability: DeliverabilityConfig::default(),
                bridge: BridgeConfig::default_for_profile(Profile::Custom),
            },
        }
    }
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl SmtpConfig {
    fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                enabled: false,
                port: 2525,
                submission_port: 587,
                bind_address: "127.0.0.1".to_string(),
                mx_domains: vec![],
                starttls: true,
                require_auth: true,
            },
            Profile::Standard | Profile::Hyperscale => Self {
                enabled: true,
                port: 25,
                submission_port: 587,
                bind_address: "0.0.0.0".to_string(),
                mx_domains: vec![],
                starttls: true,
                require_auth: true,
            },
            Profile::Custom => Self {
                enabled: false,
                port: 2525,
                submission_port: 587,
                bind_address: "127.0.0.1".to_string(),
                mx_domains: vec![],
                starttls: true,
                require_auth: true,
            },
        }
    }
}

impl Default for ImapConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl ImapConfig {
    fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                enabled: false,
                port: 143,
                bind_address: "127.0.0.1".to_string(),
                starttls: true,
            },
            Profile::Standard | Profile::Hyperscale => Self {
                enabled: true,
                port: 143,
                bind_address: "0.0.0.0".to_string(),
                starttls: true,
            },
            Profile::Custom => Self {
                enabled: false,
                port: 143,
                bind_address: "127.0.0.1".to_string(),
                starttls: true,
            },
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl RelayConfig {
    fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                method: RelayMethod::Community,
                community_relay: false,
                donated_quota_bytes: 0,
                relay_quota_per_day: 100,
                dns_discovery: true,
                spf_dkim_enforcement: EnforcementLevel::Lenient,
            },
            Profile::Standard => Self {
                method: RelayMethod::Community,
                community_relay: true,
                donated_quota_bytes: 10_737_418_240, // 10 GB/day
                relay_quota_per_day: 1_000,
                dns_discovery: true,
                spf_dkim_enforcement: EnforcementLevel::Moderate,
            },
            Profile::Hyperscale => Self {
                method: RelayMethod::Direct,
                community_relay: true,
                donated_quota_bytes: 107_374_182_400, // 100 GB/day
                relay_quota_per_day: 10_000,
                dns_discovery: true,
                spf_dkim_enforcement: EnforcementLevel::Strict,
            },
            Profile::Custom => Self {
                method: RelayMethod::Community,
                community_relay: false,
                donated_quota_bytes: 0,
                relay_quota_per_day: 100,
                dns_discovery: true,
                spf_dkim_enforcement: EnforcementLevel::Lenient,
            },
        }
    }
}

impl Default for DeliverabilityConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl DeliverabilityConfig {
    fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                enabled: false,
                analytics_backend: "duckdb".to_string(),
                track_opens: false,
                track_bounces: true,
                track_clicks: false,
            },
            Profile::Standard => Self {
                enabled: true,
                analytics_backend: "duckdb".to_string(),
                track_opens: false,
                track_bounces: true,
                track_clicks: false,
            },
            Profile::Hyperscale => Self {
                enabled: true,
                analytics_backend: "clickhouse".to_string(),
                track_opens: false,
                track_bounces: true,
                track_clicks: false,
            },
            Profile::Custom => Self {
                enabled: false,
                analytics_backend: "duckdb".to_string(),
                track_opens: false,
                track_bounces: false,
                track_clicks: false,
            },
        }
    }
}

// ============================================================================
// WebSocket Bridge (Native Protocol)
// ============================================================================

/// WebSocket bridge configuration (native jig-server protocol).
///
/// Provides real-time bidirectional communication for web clients.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebSocketBridgeConfig {
    /// Enable WebSocket server
    pub enabled: bool,

    /// WebSocket port (default: 8080, 443 for WSS)
    pub port: u16,

    /// Bind address
    pub bind_address: String,

    /// Enable TLS (WSS instead of WS)
    pub tls_enabled: bool,

    /// Max concurrent connections
    pub max_connections: u32,

    /// Ping interval (seconds, for keepalive)
    pub ping_interval_sec: u32,

    /// Enable compression (permessage-deflate)
    pub compression: bool,

    /// Max message size (bytes)
    pub max_message_size_bytes: u64,

    /// Generic bridge settings
    #[serde(default)]
    pub bridge: BridgeConfig,
}

impl Default for WebSocketBridgeConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl WebSocketBridgeConfig {
    pub fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                enabled: false,
                port: 8080,
                bind_address: "127.0.0.1".to_string(),
                tls_enabled: false,
                max_connections: 100,
                ping_interval_sec: 60,
                compression: false,
                max_message_size_bytes: 1_048_576, // 1 MB
                bridge: BridgeConfig::default_for_profile(Profile::Potato),
            },
            Profile::Standard => Self {
                enabled: true,
                port: 8080,
                bind_address: "0.0.0.0".to_string(),
                tls_enabled: true,
                max_connections: 10_000,
                ping_interval_sec: 30,
                compression: true,
                max_message_size_bytes: 10_485_760, // 10 MB
                bridge: BridgeConfig::default_for_profile(Profile::Standard),
            },
            Profile::Hyperscale => Self {
                enabled: true,
                port: 8080,
                bind_address: "0.0.0.0".to_string(),
                tls_enabled: true,
                max_connections: 100_000,
                ping_interval_sec: 30,
                compression: true,
                max_message_size_bytes: 52_428_800, // 50 MB
                bridge: BridgeConfig::default_for_profile(Profile::Hyperscale),
            },
            Profile::Custom => Self {
                enabled: false,
                port: 8080,
                bind_address: "127.0.0.1".to_string(),
                tls_enabled: false,
                max_connections: 100,
                ping_interval_sec: 60,
                compression: false,
                max_message_size_bytes: 1_048_576,
                bridge: BridgeConfig::default_for_profile(Profile::Custom),
            },
        }
    }
}

// ============================================================================
// Federation Bridge (Native Protocol)
// ============================================================================

/// Federation bridge configuration (native jig-server protocol).
///
/// Server-to-server communication for federated Jig instances.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationBridgeConfig {
    /// Enable federation
    pub enabled: bool,

    /// Federation port (default: 7117)
    pub port: u16,

    /// Bind address
    pub bind_address: String,

    /// Public address for this server (for discovery)
    pub public_address: String,

    /// Require TLS for federation traffic (default: true)
    pub require_tls: bool,

    /// Discovery configuration
    #[serde(default)]
    pub discovery: DiscoveryConfig,

    /// Identity verification configuration
    #[serde(default)]
    pub identity: IdentityConfig,

    /// Trust policy configuration
    #[serde(default)]
    pub trust: TrustConfig,

    /// Generic bridge settings
    #[serde(default)]
    pub bridge: BridgeConfig,
}

/// Server discovery configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable automatic server discovery
    pub enabled: bool,

    /// Discovery method
    pub method: DiscoveryMethod,

    /// Known federation endpoints
    #[serde(default)]
    pub known_endpoints: Vec<String>,
}

/// Discovery method for federation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMethod {
    /// DNS-based discovery (TXT records)
    Dns,
    /// WebFinger-based discovery
    WebFinger,
    /// Manual configuration only
    Manual,
}

/// Identity verification configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Require cryptographic proof of identity
    pub require_proof: bool,

    /// Public key algorithm (default: "ed25519")
    pub key_algorithm: String,

    /// Identity verification level
    pub verification_level: VerificationLevel,
}

/// Identity verification level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationLevel {
    /// No verification (accept all)
    None,
    /// Self-signed certificates OK
    SelfSigned,
    /// Require known CA
    Ca,
    /// Require known CA + transparency log
    CaWithTransparency,
}

/// Trust policy configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustConfig {
    /// Default trust policy for unknown servers
    pub default_policy: TrustPolicy,

    /// Known trusted servers
    #[serde(default)]
    pub trusted_servers: Vec<String>,

    /// Blocked servers
    #[serde(default)]
    pub blocked_servers: Vec<String>,
}

/// Trust policy for federation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustPolicy {
    /// Block all unknown servers
    BlockAll,
    /// Allow but mark suspicious
    AllowWithWarning,
    /// Allow all (trust on first use)
    AllowAll,
}

impl Default for FederationBridgeConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl FederationBridgeConfig {
    pub fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                enabled: false,
                port: 7117,
                bind_address: "127.0.0.1".to_string(),
                public_address: "".to_string(),
                require_tls: false,
                discovery: DiscoveryConfig::default_for_profile(Profile::Potato),
                identity: IdentityConfig::default_for_profile(Profile::Potato),
                trust: TrustConfig::default_for_profile(Profile::Potato),
                bridge: BridgeConfig::default_for_profile(Profile::Potato),
            },
            Profile::Standard => Self {
                enabled: false,
                port: 7117,
                bind_address: "0.0.0.0".to_string(),
                public_address: "".to_string(),
                require_tls: true,
                discovery: DiscoveryConfig::default_for_profile(Profile::Standard),
                identity: IdentityConfig::default_for_profile(Profile::Standard),
                trust: TrustConfig::default_for_profile(Profile::Standard),
                bridge: BridgeConfig::default_for_profile(Profile::Standard),
            },
            Profile::Hyperscale => Self {
                enabled: true,
                port: 7117,
                bind_address: "0.0.0.0".to_string(),
                public_address: "jig.example.com".to_string(),
                require_tls: true,
                discovery: DiscoveryConfig::default_for_profile(Profile::Hyperscale),
                identity: IdentityConfig::default_for_profile(Profile::Hyperscale),
                trust: TrustConfig::default_for_profile(Profile::Hyperscale),
                bridge: BridgeConfig::default_for_profile(Profile::Hyperscale),
            },
            Profile::Custom => Self {
                enabled: false,
                port: 7117,
                bind_address: "127.0.0.1".to_string(),
                public_address: "".to_string(),
                require_tls: true,
                discovery: DiscoveryConfig::default(),
                identity: IdentityConfig::default(),
                trust: TrustConfig::default(),
                bridge: BridgeConfig::default_for_profile(Profile::Custom),
            },
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl DiscoveryConfig {
    fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato | Profile::Custom => Self {
                enabled: false,
                method: DiscoveryMethod::Manual,
                known_endpoints: vec![],
            },
            Profile::Standard => Self {
                enabled: true,
                method: DiscoveryMethod::Dns,
                known_endpoints: vec![],
            },
            Profile::Hyperscale => Self {
                enabled: true,
                method: DiscoveryMethod::WebFinger,
                known_endpoints: vec![],
            },
        }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl IdentityConfig {
    fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato | Profile::Custom => Self {
                require_proof: false,
                key_algorithm: "ed25519".to_string(),
                verification_level: VerificationLevel::None,
            },
            Profile::Standard => Self {
                require_proof: true,
                key_algorithm: "ed25519".to_string(),
                verification_level: VerificationLevel::SelfSigned,
            },
            Profile::Hyperscale => Self {
                require_proof: true,
                key_algorithm: "ed25519".to_string(),
                verification_level: VerificationLevel::CaWithTransparency,
            },
        }
    }
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl TrustConfig {
    fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato | Profile::Custom => Self {
                default_policy: TrustPolicy::BlockAll,
                trusted_servers: vec![],
                blocked_servers: vec![],
            },
            Profile::Standard => Self {
                default_policy: TrustPolicy::AllowWithWarning,
                trusted_servers: vec![],
                blocked_servers: vec![],
            },
            Profile::Hyperscale => Self {
                default_policy: TrustPolicy::AllowAll,
                trusted_servers: vec![],
                blocked_servers: vec![],
            },
        }
    }
}

// ============================================================================
// ATProto Bridge (External - Bluesky)
// ============================================================================

/// AT Protocol bridge configuration (Bluesky/AT Protocol network).
///
/// Bridges Jig blocks to/from the AT Protocol (Bluesky ecosystem).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AtProtoBridgeConfig {
    /// Enable ATProto bridge
    pub enabled: bool,

    /// PDS (Personal Data Server) endpoint
    pub pds_endpoint: String,

    /// DID (Decentralized Identifier) for this server
    pub server_did: Option<String>,

    /// Resolve DIDs to handles
    pub did_resolution: bool,

    /// Subscribe to ATProto firehose
    pub firehose_enabled: bool,

    /// Transform pipeline (ATProto records → Jig blocks)
    #[serde(default)]
    pub ingest_transforms: Vec<TransformConfig>,

    /// Transform pipeline (Jig blocks → ATProto records)
    #[serde(default)]
    pub export_transforms: Vec<TransformConfig>,

    /// Generic bridge settings
    #[serde(default)]
    pub bridge: BridgeConfig,
}

impl Default for AtProtoBridgeConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl AtProtoBridgeConfig {
    pub fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato | Profile::Custom => Self {
                enabled: false,
                pds_endpoint: "https://bsky.social".to_string(),
                server_did: None,
                did_resolution: true,
                firehose_enabled: false,
                ingest_transforms: vec![],
                export_transforms: vec![],
                bridge: BridgeConfig::default_for_profile(profile),
            },
            Profile::Standard => Self {
                enabled: false, // Opt-in for Standard
                pds_endpoint: "https://bsky.social".to_string(),
                server_did: None,
                did_resolution: true,
                firehose_enabled: false,
                ingest_transforms: vec![TransformConfig {
                    transform_type: TransformType::Custom("atproto_to_jig".to_string()),
                    fuel_budget: 50_000,
                    fuel_max: 500_000,
                    required_capabilities: vec!["atproto.read".to_string()],
                    validate_determinism: true,
                    preserve_provenance: true,
                }],
                export_transforms: vec![TransformConfig {
                    transform_type: TransformType::Custom("jig_to_atproto".to_string()),
                    fuel_budget: 50_000,
                    fuel_max: 500_000,
                    required_capabilities: vec!["atproto.write".to_string()],
                    validate_determinism: true,
                    preserve_provenance: true,
                }],
                bridge: BridgeConfig::default_for_profile(Profile::Standard),
            },
            Profile::Hyperscale => Self {
                enabled: true,
                pds_endpoint: "https://bsky.social".to_string(),
                server_did: Some("did:plc:example123".to_string()),
                did_resolution: true,
                firehose_enabled: true,
                ingest_transforms: vec![TransformConfig {
                    transform_type: TransformType::Custom("atproto_to_jig".to_string()),
                    fuel_budget: 200_000,
                    fuel_max: 2_000_000,
                    required_capabilities: vec!["atproto.read".to_string(), "net.http".to_string()],
                    validate_determinism: true,
                    preserve_provenance: true,
                }],
                export_transforms: vec![TransformConfig {
                    transform_type: TransformType::Custom("jig_to_atproto".to_string()),
                    fuel_budget: 200_000,
                    fuel_max: 2_000_000,
                    required_capabilities: vec![
                        "atproto.write".to_string(),
                        "net.http".to_string(),
                    ],
                    validate_determinism: true,
                    preserve_provenance: true,
                }],
                bridge: BridgeConfig::default_for_profile(Profile::Hyperscale),
            },
        }
    }
}

// ============================================================================
// ActivityPub Bridge (External - Fediverse)
// ============================================================================

/// ActivityPub bridge configuration (Mastodon, Fediverse).
///
/// Bridges Jig blocks to/from the ActivityPub protocol (Mastodon, Pleroma, etc.).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActivityPubBridgeConfig {
    /// Enable ActivityPub bridge
    pub enabled: bool,

    /// Actor name for this server (e.g., "@jig@example.com")
    pub actor_name: String,

    /// Public inbox endpoint
    pub inbox_endpoint: String,

    /// Public outbox endpoint
    pub outbox_endpoint: String,

    /// Enable WebFinger for actor discovery
    pub webfinger_enabled: bool,

    /// Accept follows from remote actors
    pub accept_follows: bool,

    /// Transform pipeline (ActivityPub activities → Jig blocks)
    #[serde(default)]
    pub ingest_transforms: Vec<TransformConfig>,

    /// Transform pipeline (Jig blocks → ActivityPub activities)
    #[serde(default)]
    pub export_transforms: Vec<TransformConfig>,

    /// Generic bridge settings
    #[serde(default)]
    pub bridge: BridgeConfig,
}

impl Default for ActivityPubBridgeConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl ActivityPubBridgeConfig {
    pub fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato | Profile::Custom => Self {
                enabled: false,
                actor_name: "@jig@localhost".to_string(),
                inbox_endpoint: "/inbox".to_string(),
                outbox_endpoint: "/outbox".to_string(),
                webfinger_enabled: false,
                accept_follows: false,
                ingest_transforms: vec![],
                export_transforms: vec![],
                bridge: BridgeConfig::default_for_profile(profile),
            },
            Profile::Standard => Self {
                enabled: false, // Opt-in for Standard
                actor_name: "@jig@example.com".to_string(),
                inbox_endpoint: "/inbox".to_string(),
                outbox_endpoint: "/outbox".to_string(),
                webfinger_enabled: true,
                accept_follows: true,
                ingest_transforms: vec![TransformConfig {
                    transform_type: TransformType::Custom("activitypub_to_jig".to_string()),
                    fuel_budget: 50_000,
                    fuel_max: 500_000,
                    required_capabilities: vec!["activitypub.read".to_string()],
                    validate_determinism: true,
                    preserve_provenance: true,
                }],
                export_transforms: vec![TransformConfig {
                    transform_type: TransformType::Custom("jig_to_activitypub".to_string()),
                    fuel_budget: 50_000,
                    fuel_max: 500_000,
                    required_capabilities: vec!["activitypub.write".to_string()],
                    validate_determinism: true,
                    preserve_provenance: true,
                }],
                bridge: BridgeConfig::default_for_profile(Profile::Standard),
            },
            Profile::Hyperscale => Self {
                enabled: true,
                actor_name: "@jig@example.com".to_string(),
                inbox_endpoint: "/inbox".to_string(),
                outbox_endpoint: "/outbox".to_string(),
                webfinger_enabled: true,
                accept_follows: true,
                ingest_transforms: vec![TransformConfig {
                    transform_type: TransformType::Custom("activitypub_to_jig".to_string()),
                    fuel_budget: 200_000,
                    fuel_max: 2_000_000,
                    required_capabilities: vec![
                        "activitypub.read".to_string(),
                        "net.http".to_string(),
                    ],
                    validate_determinism: true,
                    preserve_provenance: true,
                }],
                export_transforms: vec![TransformConfig {
                    transform_type: TransformType::Custom("jig_to_activitypub".to_string()),
                    fuel_budget: 200_000,
                    fuel_max: 2_000_000,
                    required_capabilities: vec![
                        "activitypub.write".to_string(),
                        "net.http".to_string(),
                    ],
                    validate_determinism: true,
                    preserve_provenance: true,
                }],
                bridge: BridgeConfig::default_for_profile(Profile::Hyperscale),
            },
        }
    }
}

// ============================================================================
// Bridge Categories (Shell Configs for Taxonomy)
// ============================================================================

/// Enterprise messenger bridge template (Slack, Mattermost, etc.).
///
/// This is a shell config to prime the taxonomy for community-built bridges.
/// Actual implementation will be provided by OSS contributors via bounties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnterpriseMessengerBridge {
    /// Bridge type (e.g., "slack", "mattermost", "teams")
    pub bridge_type: String,

    /// API endpoint
    pub api_endpoint: String,

    /// Authentication token
    pub auth_token: Option<String>,

    /// Workspace/team ID
    pub workspace_id: Option<String>,

    /// Transform pipeline (enterprise format → Jig blocks)
    #[serde(default)]
    pub ingest_transforms: Vec<TransformConfig>,

    /// Transform pipeline (Jig blocks → enterprise format)
    #[serde(default)]
    pub export_transforms: Vec<TransformConfig>,

    /// Generic bridge settings
    #[serde(default)]
    pub bridge: BridgeConfig,
}

/// Consumer messenger bridge template (Discord, Matrix, Telegram, etc.).
///
/// Shell config for community-built consumer messenger bridges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsumerMessengerBridge {
    /// Bridge type (e.g., "discord", "matrix", "telegram", "signal")
    pub bridge_type: String,

    /// Bot token or credentials
    pub credentials: HashMap<String, String>,

    /// Server/guild/room identifiers
    #[serde(default)]
    pub identifiers: Vec<String>,

    /// Transform pipeline (consumer format → Jig blocks)
    #[serde(default)]
    pub ingest_transforms: Vec<TransformConfig>,

    /// Transform pipeline (Jig blocks → consumer format)
    #[serde(default)]
    pub export_transforms: Vec<TransformConfig>,

    /// Generic bridge settings
    #[serde(default)]
    pub bridge: BridgeConfig,
}

/// Video codec bridge template (H.264, VP9, AV1, etc.).
///
/// Shell config for video codec transform bridges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VideoCodecBridge {
    /// Source codec (e.g., "h264", "vp9", "av1")
    pub source_codec: String,

    /// Target codec (e.g., "h264", "vp9", "av1")
    pub target_codec: String,

    /// Quality settings
    #[serde(default)]
    pub quality: VideoQuality,

    /// Transform pipeline (decode → process → encode)
    #[serde(default)]
    pub transforms: Vec<TransformConfig>,

    /// Generic bridge settings
    #[serde(default)]
    pub bridge: BridgeConfig,
}

/// Video quality settings
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VideoQuality {
    /// Target bitrate (bps)
    pub bitrate: u32,

    /// Resolution (e.g., "1920x1080", "1280x720")
    pub resolution: String,

    /// Frame rate (fps)
    pub fps: u32,
}

impl Default for VideoQuality {
    fn default() -> Self {
        Self {
            bitrate: 2_000_000, // 2 Mbps
            resolution: "1280x720".to_string(),
            fps: 30,
        }
    }
}

/// Audio codec bridge template (MP3, Opus, AAC, etc.).
///
/// Shell config for audio codec transform bridges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AudioCodecBridge {
    /// Source codec (e.g., "mp3", "opus", "aac", "flac")
    pub source_codec: String,

    /// Target codec (e.g., "mp3", "opus", "aac", "flac")
    pub target_codec: String,

    /// Quality settings
    #[serde(default)]
    pub quality: AudioQuality,

    /// Transform pipeline (decode → process → encode)
    #[serde(default)]
    pub transforms: Vec<TransformConfig>,

    /// Generic bridge settings
    #[serde(default)]
    pub bridge: BridgeConfig,
}

/// Audio quality settings
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AudioQuality {
    /// Target bitrate (bps)
    pub bitrate: u32,

    /// Sample rate (Hz)
    pub sample_rate: u32,

    /// Channels (1 = mono, 2 = stereo)
    pub channels: u32,
}

impl Default for AudioQuality {
    fn default() -> Self {
        Self {
            bitrate: 128_000, // 128 kbps
            sample_rate: 48_000,
            channels: 2,
        }
    }
}

/// Transport/API bridge template (HTTPS, SSH, gRPC, etc.).
///
/// Shell config for API/transport-level bridges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransportBridge {
    /// Transport type (e.g., "https", "ssh", "grpc", "websocket")
    pub transport_type: String,

    /// Endpoint configuration
    pub endpoint: String,

    /// Authentication method
    pub auth_method: AuthMethod,

    /// Transform pipeline (transport-specific → Jig blocks)
    #[serde(default)]
    pub ingest_transforms: Vec<TransformConfig>,

    /// Transform pipeline (Jig blocks → transport-specific)
    #[serde(default)]
    pub export_transforms: Vec<TransformConfig>,

    /// Generic bridge settings
    #[serde(default)]
    pub bridge: BridgeConfig,
}

/// Authentication method for transport bridges
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// No authentication
    None,
    /// API key authentication
    ApiKey { key: String },
    /// OAuth 2.0
    OAuth2 {
        client_id: String,
        client_secret: String,
    },
    /// SSH key-based
    SshKey { private_key_path: String },
    /// TLS client certificate
    TlsCert { cert_path: String, key_path: String },
}

/// Document bridge template (PDF, Office docs, etc.).
///
/// Shell config for document format bridges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentBridge {
    /// Document type (e.g., "pdf", "docx", "odt", "markdown")
    pub document_type: String,

    /// Enable OCR for scanned documents
    pub ocr_enabled: bool,

    /// Extract metadata
    pub extract_metadata: bool,

    /// Transform pipeline (document → Jig blocks)
    #[serde(default)]
    pub ingest_transforms: Vec<TransformConfig>,

    /// Transform pipeline (Jig blocks → document)
    #[serde(default)]
    pub export_transforms: Vec<TransformConfig>,

    /// Generic bridge settings
    #[serde(default)]
    pub bridge: BridgeConfig,
}

// ============================================================================
// Root Bridge Configuration
// ============================================================================

/// Root bridge configuration container.
///
/// Contains all named bridges and category bridge templates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BridgesConfig {
    // Named bridges (explicit configs)
    #[serde(default)]
    pub irc: IrcBridgeConfig,

    #[serde(default)]
    pub email: EmailBridgeConfig,

    #[serde(default)]
    pub websocket: WebSocketBridgeConfig,

    #[serde(default)]
    pub federation: FederationBridgeConfig,

    #[serde(default)]
    pub atproto: AtProtoBridgeConfig,

    #[serde(default)]
    pub activitypub: ActivityPubBridgeConfig,

    // Category bridges (shell configs)
    #[serde(default)]
    pub enterprise_messengers: HashMap<String, EnterpriseMessengerBridge>,

    #[serde(default)]
    pub consumer_messengers: HashMap<String, ConsumerMessengerBridge>,

    #[serde(default)]
    pub video_codecs: HashMap<String, VideoCodecBridge>,

    #[serde(default)]
    pub audio_codecs: HashMap<String, AudioCodecBridge>,

    #[serde(default)]
    pub transports: HashMap<String, TransportBridge>,

    #[serde(default)]
    pub documents: HashMap<String, DocumentBridge>,
}

impl Default for BridgesConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::Potato)
    }
}

impl BridgesConfig {
    pub fn default_for_profile(profile: Profile) -> Self {
        Self {
            irc: IrcBridgeConfig::default_for_profile(profile),
            email: EmailBridgeConfig::default_for_profile(profile),
            websocket: WebSocketBridgeConfig::default_for_profile(profile),
            federation: FederationBridgeConfig::default_for_profile(profile),
            atproto: AtProtoBridgeConfig::default_for_profile(profile),
            activitypub: ActivityPubBridgeConfig::default_for_profile(profile),
            enterprise_messengers: HashMap::new(),
            consumer_messengers: HashMap::new(),
            video_codecs: HashMap::new(),
            audio_codecs: HashMap::new(),
            transports: HashMap::new(),
            documents: HashMap::new(),
        }
    }
}
