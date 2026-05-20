//! Integration tests for bridge-specific configuration.

use jig_config::bridges::*;
use jig_config::profiles::Profile;

// ============================================================================
// IRC Bridge Tests
// ============================================================================

#[test]
fn test_irc_bridge_potato_defaults() {
    let config = IrcBridgeConfig::default_for_profile(Profile::Potato);

    assert!(config.enabled);
    assert_eq!(config.server_name, "jig.irc.local");
    assert_eq!(config.port, 6667);
    assert_eq!(config.bind_address, "127.0.0.1");
    assert!(config.auto_join_channels.is_empty());
    assert_eq!(config.nick_validation.max_length, 30);
    assert!(config.nick_validation.require_unique);
    assert!(config.block_wrapper.enabled);
    assert_eq!(config.block_wrapper.fuel_budget, 10_000);
}

#[test]
fn test_irc_bridge_hyperscale_defaults() {
    let config = IrcBridgeConfig::default_for_profile(Profile::Hyperscale);

    assert!(config.enabled);
    assert_eq!(config.server_name, "jig.irc.network");
    assert_eq!(config.bind_address, "0.0.0.0");
    assert_eq!(config.auto_join_channels.len(), 2);
    assert!(config.auto_join_channels.contains(&"#jig".to_string()));
    assert!(config.auto_join_channels.contains(&"#jig-dev".to_string()));
}

#[test]
fn test_irc_nick_validation_defaults() {
    let nick_val = NickValidation::default();

    assert_eq!(nick_val.max_length, 30);
    assert!(nick_val.allowed_chars.contains('a'));
    assert!(nick_val.allowed_chars.contains('Z'));
    assert!(nick_val.allowed_chars.contains('0'));
    assert!(nick_val.allowed_chars.contains('['));
    assert!(nick_val.require_unique);
}

#[test]
fn test_irc_toml_deserialization() {
    let toml = r##"
        enabled = true
        server_name = "test.irc.local"
        port = 6667
        bind_address = "0.0.0.0"
        auto_join_channels = ["#test"]

        [nick_validation]
        max_length = 20
        allowed_chars = "abc123"
        require_unique = false

        [block_wrapper]
        enabled = true
        fuel_budget = 5000
        preserve_metadata = false
    "##;

    let config: IrcBridgeConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.server_name, "test.irc.local");
    assert_eq!(config.auto_join_channels.len(), 1);
    assert_eq!(config.nick_validation.max_length, 20);
    assert_eq!(config.nick_validation.allowed_chars, "abc123");
    assert!(!config.nick_validation.require_unique);
    assert_eq!(config.block_wrapper.fuel_budget, 5000);
    assert!(!config.block_wrapper.preserve_metadata);
}

// ============================================================================
// Email Bridge Tests
// ============================================================================

#[test]
fn test_email_bridge_potato_defaults() {
    let config = EmailBridgeConfig::default_for_profile(Profile::Potato);

    assert!(!config.enabled); // Disabled by default for potato
    assert!(!config.smtp.enabled);
    assert_eq!(config.smtp.port, 2525); // Dev port
    assert_eq!(config.smtp.bind_address, "127.0.0.1");
    assert!(!config.imap.enabled);
    assert_eq!(config.relay.relay_quota_per_day, 100);
}

#[test]
fn test_email_bridge_hyperscale_defaults() {
    let config = EmailBridgeConfig::default_for_profile(Profile::Hyperscale);

    assert!(config.enabled);
    assert!(config.smtp.enabled);
    assert_eq!(config.smtp.port, 25); // Production port
    assert_eq!(config.smtp.bind_address, "0.0.0.0");
    assert!(config.imap.enabled);
    assert_eq!(config.relay.relay_quota_per_day, 10_000);
    assert_eq!(config.deliverability.analytics_backend, "clickhouse");
}

#[test]
fn test_relay_method_serialization() {
    let sendgrid = RelayMethod::SendGrid {
        api_key: Some("test123".to_string()),
    };
    let json = serde_json::to_string(&sendgrid).unwrap();
    assert!(json.contains("send_grid"));

    let community = RelayMethod::Community;
    let json = serde_json::to_string(&community).unwrap();
    assert_eq!(json, r#""community""#);

    let custom = RelayMethod::Custom {
        host: "smtp.example.com".to_string(),
        port: 587,
        username: Some("user".to_string()),
        password: None,
    };
    let json = serde_json::to_string(&custom).unwrap();
    assert!(json.contains("smtp.example.com"));
}

#[test]
fn test_enforcement_level_serialization() {
    assert_eq!(
        serde_json::to_string(&EnforcementLevel::None).unwrap(),
        r#""none""#
    );
    assert_eq!(
        serde_json::to_string(&EnforcementLevel::Lenient).unwrap(),
        r#""lenient""#
    );
    assert_eq!(
        serde_json::to_string(&EnforcementLevel::Moderate).unwrap(),
        r#""moderate""#
    );
    assert_eq!(
        serde_json::to_string(&EnforcementLevel::Strict).unwrap(),
        r#""strict""#
    );
}

#[test]
fn test_email_toml_deserialization() {
    let toml = r#"
        enabled = true

        [smtp]
        enabled = true
        port = 25
        submission_port = 587
        bind_address = "0.0.0.0"
        mx_domains = ["example.com"]
        starttls = true
        require_auth = true

        [relay]
        method = { custom = { host = "smtp.relay.com", port = 587 } }
        community_relay = false
        donated_quota_bytes = 1000000
        relay_quota_per_day = 500
        dns_discovery = true
        spf_dkim_enforcement = "strict"
    "#;

    let config: EmailBridgeConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert!(config.enabled);
    assert_eq!(config.smtp.mx_domains.len(), 1);
    assert_eq!(config.relay.relay_quota_per_day, 500);
}

// ============================================================================
// WebSocket Bridge Tests
// ============================================================================

#[test]
fn test_websocket_bridge_potato_defaults() {
    let config = WebSocketBridgeConfig::default_for_profile(Profile::Potato);

    assert!(!config.enabled);
    assert_eq!(config.port, 8080);
    assert_eq!(config.bind_address, "127.0.0.1");
    assert!(!config.tls_enabled);
    assert_eq!(config.max_connections, 100);
    assert_eq!(config.ping_interval_sec, 60);
    assert!(!config.compression);
}

#[test]
fn test_websocket_bridge_hyperscale_defaults() {
    let config = WebSocketBridgeConfig::default_for_profile(Profile::Hyperscale);

    assert!(config.enabled);
    assert_eq!(config.bind_address, "0.0.0.0");
    assert!(config.tls_enabled);
    assert_eq!(config.max_connections, 100_000);
    assert_eq!(config.ping_interval_sec, 30);
    assert!(config.compression);
}

#[test]
fn test_websocket_toml_deserialization() {
    let toml = r#"
        enabled = true
        port = 8443
        bind_address = "0.0.0.0"
        tls_enabled = true
        max_connections = 50000
        ping_interval_sec = 45
        compression = true
        max_message_size_bytes = 5242880
    "#;

    let config: WebSocketBridgeConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.port, 8443);
    assert_eq!(config.max_connections, 50_000);
    assert_eq!(config.ping_interval_sec, 45);
    assert_eq!(config.max_message_size_bytes, 5_242_880);
}

// ============================================================================
// Federation Bridge Tests
// ============================================================================

#[test]
fn test_federation_bridge_potato_defaults() {
    let config = FederationBridgeConfig::default_for_profile(Profile::Potato);

    assert!(!config.enabled);
    assert_eq!(config.port, 7117);
    assert_eq!(config.bind_address, "127.0.0.1");
    assert!(config.public_address.is_empty());
    assert!(!config.require_tls);
    assert!(!config.discovery.enabled);
    assert!(!config.identity.require_proof);
    assert_eq!(config.trust.default_policy, TrustPolicy::BlockAll);
}

#[test]
fn test_federation_bridge_hyperscale_defaults() {
    let config = FederationBridgeConfig::default_for_profile(Profile::Hyperscale);

    assert!(config.enabled);
    assert_eq!(config.bind_address, "0.0.0.0");
    assert_eq!(config.public_address, "jig.example.com");
    assert!(config.require_tls);
    assert!(config.discovery.enabled);
    assert!(config.identity.require_proof);
    assert_eq!(
        config.identity.verification_level,
        VerificationLevel::CaWithTransparency
    );
    assert_eq!(config.trust.default_policy, TrustPolicy::AllowAll);
}

#[test]
fn test_discovery_method_serialization() {
    assert_eq!(
        serde_json::to_string(&DiscoveryMethod::Dns).unwrap(),
        r#""dns""#
    );
    assert_eq!(
        serde_json::to_string(&DiscoveryMethod::WebFinger).unwrap(),
        r#""web_finger""#
    );
    assert_eq!(
        serde_json::to_string(&DiscoveryMethod::Manual).unwrap(),
        r#""manual""#
    );
}

#[test]
fn test_verification_level_serialization() {
    assert_eq!(
        serde_json::to_string(&VerificationLevel::None).unwrap(),
        r#""none""#
    );
    assert_eq!(
        serde_json::to_string(&VerificationLevel::SelfSigned).unwrap(),
        r#""self_signed""#
    );
    assert_eq!(
        serde_json::to_string(&VerificationLevel::Ca).unwrap(),
        r#""ca""#
    );
    assert_eq!(
        serde_json::to_string(&VerificationLevel::CaWithTransparency).unwrap(),
        r#""ca_with_transparency""#
    );
}

#[test]
fn test_trust_policy_serialization() {
    assert_eq!(
        serde_json::to_string(&TrustPolicy::BlockAll).unwrap(),
        r#""block_all""#
    );
    assert_eq!(
        serde_json::to_string(&TrustPolicy::AllowWithWarning).unwrap(),
        r#""allow_with_warning""#
    );
    assert_eq!(
        serde_json::to_string(&TrustPolicy::AllowAll).unwrap(),
        r#""allow_all""#
    );
}

#[test]
fn test_federation_toml_deserialization() {
    let toml = r#"
        enabled = true
        port = 7117
        bind_address = "0.0.0.0"
        public_address = "jig.test.com"
        require_tls = true

        [discovery]
        enabled = true
        method = "dns"
        known_endpoints = ["jig1.com", "jig2.com"]

        [identity]
        require_proof = true
        key_algorithm = "ed25519"
        verification_level = "ca"

        [trust]
        default_policy = "allow_with_warning"
        trusted_servers = ["trusted.com"]
        blocked_servers = ["blocked.com"]
    "#;

    let config: FederationBridgeConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.public_address, "jig.test.com");
    assert_eq!(config.discovery.known_endpoints.len(), 2);
    assert_eq!(config.identity.verification_level, VerificationLevel::Ca);
    assert_eq!(config.trust.trusted_servers.len(), 1);
    assert_eq!(config.trust.blocked_servers.len(), 1);
}

// ============================================================================
// ATProto Bridge Tests
// ============================================================================

#[test]
fn test_atproto_bridge_potato_defaults() {
    let config = AtProtoBridgeConfig::default_for_profile(Profile::Potato);

    assert!(!config.enabled);
    assert_eq!(config.pds_endpoint, "https://bsky.social");
    assert!(config.server_did.is_none());
    assert!(config.did_resolution);
    assert!(!config.firehose_enabled);
    assert!(config.ingest_transforms.is_empty());
}

#[test]
fn test_atproto_bridge_hyperscale_defaults() {
    let config = AtProtoBridgeConfig::default_for_profile(Profile::Hyperscale);

    assert!(config.enabled);
    assert_eq!(config.server_did, Some("did:plc:example123".to_string()));
    assert!(config.firehose_enabled);
    assert_eq!(config.ingest_transforms.len(), 1);
    assert_eq!(config.export_transforms.len(), 1);

    // Check transform config
    let ingest = &config.ingest_transforms[0];
    assert_eq!(ingest.fuel_budget, 200_000);
    assert_eq!(ingest.fuel_max, 2_000_000);
    assert!(ingest.validate_determinism);
    assert!(ingest.preserve_provenance);
}

#[test]
fn test_atproto_toml_deserialization() {
    let toml = r#"
        enabled = true
        pds_endpoint = "https://custom.pds"
        server_did = "did:plc:abc123"
        did_resolution = true
        firehose_enabled = true
    "#;

    let config: AtProtoBridgeConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert!(config.enabled);
    assert_eq!(config.pds_endpoint, "https://custom.pds");
    assert_eq!(config.server_did, Some("did:plc:abc123".to_string()));
}

// ============================================================================
// ActivityPub Bridge Tests
// ============================================================================

#[test]
fn test_activitypub_bridge_potato_defaults() {
    let config = ActivityPubBridgeConfig::default_for_profile(Profile::Potato);

    assert!(!config.enabled);
    assert_eq!(config.actor_name, "@jig@localhost");
    assert_eq!(config.inbox_endpoint, "/inbox");
    assert!(!config.webfinger_enabled);
    assert!(!config.accept_follows);
    assert!(config.ingest_transforms.is_empty());
}

#[test]
fn test_activitypub_bridge_hyperscale_defaults() {
    let config = ActivityPubBridgeConfig::default_for_profile(Profile::Hyperscale);

    assert!(config.enabled);
    assert_eq!(config.actor_name, "@jig@example.com");
    assert!(config.webfinger_enabled);
    assert!(config.accept_follows);
    assert_eq!(config.ingest_transforms.len(), 1);
    assert_eq!(config.export_transforms.len(), 1);
}

#[test]
fn test_activitypub_toml_deserialization() {
    let toml = r#"
        enabled = true
        actor_name = "@test@example.org"
        inbox_endpoint = "/ap/inbox"
        outbox_endpoint = "/ap/outbox"
        webfinger_enabled = true
        accept_follows = true
    "#;

    let config: ActivityPubBridgeConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.actor_name, "@test@example.org");
    assert_eq!(config.inbox_endpoint, "/ap/inbox");
    assert_eq!(config.outbox_endpoint, "/ap/outbox");
}

// ============================================================================
// Category Bridge Tests
// ============================================================================

#[test]
fn test_video_quality_defaults() {
    let quality = VideoQuality::default();

    assert_eq!(quality.bitrate, 2_000_000);
    assert_eq!(quality.resolution, "1280x720");
    assert_eq!(quality.fps, 30);
}

#[test]
fn test_audio_quality_defaults() {
    let quality = AudioQuality::default();

    assert_eq!(quality.bitrate, 128_000);
    assert_eq!(quality.sample_rate, 48_000);
    assert_eq!(quality.channels, 2);
}

#[test]
fn test_auth_method_serialization() {
    let none = AuthMethod::None;
    let json = serde_json::to_string(&none).unwrap();
    assert_eq!(json, r#""none""#);

    let api_key = AuthMethod::ApiKey {
        key: "secret123".to_string(),
    };
    let json = serde_json::to_string(&api_key).unwrap();
    assert!(json.contains("api_key"));
    assert!(json.contains("secret123"));
}

#[test]
fn test_enterprise_messenger_bridge_toml() {
    let toml = r#"
        bridge_type = "slack"
        api_endpoint = "https://slack.com/api"
        auth_token = "xoxb-123"
        workspace_id = "T12345"
    "#;

    let config: EnterpriseMessengerBridge = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.bridge_type, "slack");
    assert_eq!(config.api_endpoint, "https://slack.com/api");
    assert_eq!(config.auth_token, Some("xoxb-123".to_string()));
    assert_eq!(config.workspace_id, Some("T12345".to_string()));
}

#[test]
fn test_video_codec_bridge_toml() {
    let toml = r#"
        source_codec = "h264"
        target_codec = "av1"

        [quality]
        bitrate = 5000000
        resolution = "1920x1080"
        fps = 60
    "#;

    let config: VideoCodecBridge = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.source_codec, "h264");
    assert_eq!(config.target_codec, "av1");
    assert_eq!(config.quality.bitrate, 5_000_000);
    assert_eq!(config.quality.resolution, "1920x1080");
    assert_eq!(config.quality.fps, 60);
}

#[test]
fn test_audio_codec_bridge_toml() {
    let toml = r#"
        source_codec = "mp3"
        target_codec = "opus"

        [quality]
        bitrate = 256000
        sample_rate = 48000
        channels = 2
    "#;

    let config: AudioCodecBridge = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.source_codec, "mp3");
    assert_eq!(config.target_codec, "opus");
    assert_eq!(config.quality.bitrate, 256_000);
}

#[test]
fn test_document_bridge_toml() {
    let toml = r#"
        document_type = "pdf"
        ocr_enabled = true
        extract_metadata = true
    "#;

    let config: DocumentBridge = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.document_type, "pdf");
    assert!(config.ocr_enabled);
    assert!(config.extract_metadata);
}

// ============================================================================
// Root BridgesConfig Tests
// ============================================================================

#[test]
fn test_bridges_config_potato_defaults() {
    let config = BridgesConfig::default_for_profile(Profile::Potato);

    // Named bridges
    assert!(config.irc.enabled);
    assert!(!config.email.enabled);
    assert!(!config.websocket.enabled);
    assert!(!config.federation.enabled);
    assert!(!config.atproto.enabled);
    assert!(!config.activitypub.enabled);

    // Category bridges (all empty by default)
    assert!(config.enterprise_messengers.is_empty());
    assert!(config.consumer_messengers.is_empty());
    assert!(config.video_codecs.is_empty());
    assert!(config.audio_codecs.is_empty());
    assert!(config.transports.is_empty());
    assert!(config.documents.is_empty());
}

#[test]
fn test_bridges_config_hyperscale_defaults() {
    let config = BridgesConfig::default_for_profile(Profile::Hyperscale);

    // Named bridges (most enabled for hyperscale)
    assert!(config.irc.enabled);
    assert!(config.email.enabled);
    assert!(config.websocket.enabled);
    assert!(config.federation.enabled);
    assert!(config.atproto.enabled);
    assert!(config.activitypub.enabled);
}

#[test]
fn test_bridges_config_toml_deserialization() {
    let toml = r#"
        [irc]
        enabled = true
        server_name = "test.irc"
        port = 6667
        bind_address = "0.0.0.0"

        [email]
        enabled = true

        [websocket]
        enabled = true
        port = 8080
        bind_address = "0.0.0.0"
        tls_enabled = false
        max_connections = 1000
        ping_interval_sec = 30
        compression = true
        max_message_size_bytes = 1048576

        [federation]
        enabled = false
        port = 7117
        bind_address = "127.0.0.1"
        public_address = ""
        require_tls = true
    "#;

    let config: BridgesConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.irc.server_name, "test.irc");
    assert!(config.email.enabled);
    assert!(config.websocket.enabled);
    assert!(!config.federation.enabled);
}

#[test]
fn test_bridges_config_toml_serialization_roundtrip() {
    let config = BridgesConfig::default_for_profile(Profile::Standard);

    // Serialize to TOML
    let toml_str = toml::to_string(&config).expect("failed to serialize");

    // Deserialize back
    let parsed: BridgesConfig = toml::from_str(&toml_str).expect("failed to deserialize");

    // Spot check a few values
    assert_eq!(config.irc.enabled, parsed.irc.enabled);
    assert_eq!(config.email.enabled, parsed.email.enabled);
    assert_eq!(config.websocket.enabled, parsed.websocket.enabled);
    assert_eq!(config.federation.enabled, parsed.federation.enabled);
}

#[test]
fn test_bridges_config_with_category_bridges() {
    let toml = r#"
        [enterprise_messengers.slack]
        bridge_type = "slack"
        api_endpoint = "https://slack.com/api"

        [consumer_messengers.discord]
        bridge_type = "discord"
        [consumer_messengers.discord.credentials]
        token = "discord_bot_token"

        [video_codecs.h264_to_av1]
        source_codec = "h264"
        target_codec = "av1"
    "#;

    let config: BridgesConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert_eq!(config.enterprise_messengers.len(), 1);
    assert!(config.enterprise_messengers.contains_key("slack"));

    assert_eq!(config.consumer_messengers.len(), 1);
    assert!(config.consumer_messengers.contains_key("discord"));

    assert_eq!(config.video_codecs.len(), 1);
    assert!(config.video_codecs.contains_key("h264_to_av1"));
}
