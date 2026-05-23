//! Integration tests for three-pronged email bridge routing
//!
//! Tests all three routing paths:
//! 1. Jig <> Jig: Native protocol via DNS discovery
//! 2. Jig -> Email: SMTP with viral block signature  
//! 3. Email -> Jig: Convert to block and forward

use jig_bridge_email::router::{MessageRouter, RouteDecision};
use jig_bridge_email::types::EmailMessage;

#[tokio::test]
async fn test_prong_1_jig_to_jig_no_discovery() {
    // PRONG 1: Jig <> Jig routing
    // When DNS discovery finds no _jig records, should fall back to email
    let router = MessageRouter::new("http://localhost:7117".to_string());

    let msg = EmailMessage::new(
        "alice@example.com".to_string(),
        "bob@example.com".to_string(),
        "Test Subject".to_string(),
        "Test body".to_string(),
    );

    let decision = router.route_message(&msg).await.unwrap();

    // Should fall back to email since example.com has no _jig records
    assert!(matches!(decision, RouteDecision::ToEmail));
}

#[tokio::test]
async fn test_prong_2_email_to_jig_direct_address() {
    // PRONG 2: Email -> Jig routing
    // Direct Jig address (no @) should route to default server
    let router = MessageRouter::new("http://localhost:7117".to_string());

    let msg = EmailMessage::new(
        "alice@example.com".to_string(),
        "bob".to_string(), // No @ sign - direct Jig address
        "Test Subject".to_string(),
        "Test body".to_string(),
    );

    let decision = router.route_message(&msg).await.unwrap();

    match decision {
        RouteDecision::ToJigServer { server_url } => {
            assert_eq!(server_url, "http://localhost:7117");
        }
        _ => panic!("Expected ToJigServer decision"),
    }
}

#[tokio::test]
async fn test_prong_3_jig_to_email_fallback() {
    // PRONG 3: Jig -> Email routing
    // When recipient has @ but no _jig records, route via SMTP
    let router = MessageRouter::new("http://localhost:7117".to_string());

    let msg = EmailMessage::new(
        "alice@jig.local".to_string(),
        "external@gmail.com".to_string(),
        "External Email".to_string(),
        "Sending to external email".to_string(),
    );

    let decision = router.route_message(&msg).await.unwrap();

    // Should route to email with viral signature
    assert!(matches!(decision, RouteDecision::ToEmail));
}

#[test]
fn test_email_message_block_conversion() {
    // Test bidirectional email <-> block conversion
    let mut email = EmailMessage::new(
        "alice@example.com".to_string(),
        "bob@example.com".to_string(),
        "Test Subject".to_string(),
        "Test body content".to_string(),
    );

    // Add DKIM/SPF metadata
    email.dkim_result = Some("pass".to_string());
    email.spf_result = Some("pass".to_string());
    email.dmarc_result = Some("pass".to_string());

    // Convert to block
    let manifest = email
        .to_block_manifest("did:jig:alice")
        .expect("Should convert to manifest");

    // Verify metadata is preserved
    assert_eq!(
        manifest.metadata.get("type").and_then(|v| v.as_str()),
        Some("email")
    );
    assert_eq!(
        manifest.metadata.get("from").and_then(|v| v.as_str()),
        Some("alice@example.com")
    );
    assert_eq!(
        manifest.metadata.get("to").and_then(|v| v.as_str()),
        Some("bob@example.com")
    );
    assert_eq!(
        manifest.metadata.get("subject").and_then(|v| v.as_str()),
        Some("Test Subject")
    );
    assert_eq!(
        manifest.metadata.get("content").and_then(|v| v.as_str()),
        Some("Test body content")
    );

    // Verify DKIM/SPF/DMARC metadata
    assert_eq!(
        manifest
            .metadata
            .get("dkim_result")
            .and_then(|v| v.as_str()),
        Some("pass")
    );
    assert_eq!(
        manifest.metadata.get("spf_result").and_then(|v| v.as_str()),
        Some("pass")
    );
    assert_eq!(
        manifest
            .metadata
            .get("dmarc_result")
            .and_then(|v| v.as_str()),
        Some("pass")
    );

    // Convert back from block
    let recovered =
        EmailMessage::from_block_manifest(&manifest).expect("Should extract from manifest");

    assert_eq!(recovered.from, email.from);
    assert_eq!(recovered.to, email.to);
    assert_eq!(recovered.subject, email.subject);
    assert_eq!(recovered.body, email.body);
    assert_eq!(recovered.dkim_result, email.dkim_result);
    assert_eq!(recovered.spf_result, email.spf_result);
    assert_eq!(recovered.dmarc_result, email.dmarc_result);
}

#[test]
fn test_viral_signature_with_block_cid() {
    use jig_bridge_email::config::FormattingConfig;
    use jig_bridge_email::formatter::format_text_body_with_cid;

    let config = FormattingConfig {
        signature: "\n--\nSent via Jig".to_string(),
        html_template: None,
        wrap_at: 0,
        add_signature: true,
        add_x_jig_header: true,
        add_thread_headers: true,
    };

    let body = "Hello, this is a test message.";
    let cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

    let formatted = format_text_body_with_cid(body, &config, Some(cid));

    // Should contain original message
    assert!(formatted.contains("Hello, this is a test message"));

    // Should contain signature
    assert!(formatted.contains("Sent via Jig"));

    // Should contain viral block signature
    assert!(formatted.contains("📦 Secured by Jig Block"));
    assert!(formatted.contains(&format!("Block ID: {}", cid)));
    assert!(formatted.contains("https://jig.onl/block/"));
}

#[test]
fn test_thread_info_generation() {
    use jig_bridge_email::types::ThreadInfo;

    let message_id = ThreadInfo::generate_message_id("example.com");

    // Should be RFC-compliant format: <...@domain>
    assert!(message_id.starts_with("<jig-"));
    assert!(message_id.ends_with("@example.com>"));
    assert!(message_id.contains("-")); // Should have timestamp and UUID
}

#[tokio::test]
async fn test_dns_discovery_invalid_email() {
    use jig_bridge_email::discovery::JigDiscovery;

    let discovery = JigDiscovery::new().unwrap();
    let result = discovery.discover("not-an-email").await;

    // Should error on invalid email format
    assert!(result.is_err());
}

#[tokio::test]
async fn test_dns_discovery_no_records() {
    use jig_bridge_email::discovery::JigDiscovery;

    let discovery = JigDiscovery::new().unwrap();
    let result = discovery.discover("alice@example.com").await.unwrap();

    // example.com has no _jig records, should return None
    assert!(result.is_none());
}
