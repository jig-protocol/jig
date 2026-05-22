//! Type definitions for email bridge that adapt between email and block-based messaging
//!
//! This module provides the adapter types that bridge traditional email (SMTP/IMAP)
//! with the Jig block-based executable internet protocol.

use jig_core::BlockManifest;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// A simplified message representation for email bridge operations
/// This sits between raw email and BlockManifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMessage {
    /// Email sender address
    pub from: String,
    /// Email recipient address
    pub to: String,
    /// Subject line
    pub subject: String,
    /// Plain text body
    pub body: String,
    /// Optional HTML body
    pub html: Option<String>,
    /// Thread identifiers for email threading
    pub thread_info: Option<ThreadInfo>,
    /// Optional channel/topic for routing
    pub channel: Option<String>,
    /// DKIM signature validation result
    pub dkim_result: Option<String>,
    /// SPF validation result
    pub spf_result: Option<String>,
    /// DMARC validation result
    pub dmarc_result: Option<String>,
    /// Block CID if this email was converted from/to a block
    pub block_cid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    /// Message-ID header value
    pub message_id: Option<String>,
    /// In-Reply-To header value
    pub in_reply_to: Option<String>,
    /// References header values
    pub references: Vec<String>,
}

impl EmailMessage {
    pub fn new(from: String, to: String, subject: String, body: String) -> Self {
        Self {
            from,
            to,
            subject,
            body,
            html: None,
            thread_info: None,
            channel: None,
            dkim_result: None,
            spf_result: None,
            dmarc_result: None,
            block_cid: None,
        }
    }

    /// Convert this email message into a BlockManifest for storage/transport
    /// The manifest embeds the message content in metadata with semantic structure
    pub fn to_block_manifest(&self, author_did: &str) -> anyhow::Result<BlockManifest> {
        use jig_core::{Author, BlockManifest};
        use semver::Version;

        let mut builder = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: author_did.into(),
                public_key: None,
                roles: vec!["email-bridge".to_string()],
            });

        // Embed email-specific metadata
        builder = builder
            .metadata_entry("type", json!("email"))
            .metadata_entry("from", json!(self.from))
            .metadata_entry("to", json!(self.to))
            .metadata_entry("subject", json!(self.subject))
            .metadata_entry("content", json!(self.body));

        if let Some(html) = &self.html {
            builder = builder.metadata_entry("html", json!(html));
        }

        if let Some(channel) = &self.channel {
            builder = builder.metadata_entry("channel", json!(channel));
        }

        // Embed DKIM/SPF/DMARC metadata for deliverability tracking
        if let Some(dkim) = &self.dkim_result {
            builder = builder.metadata_entry("dkim_result", json!(dkim));
        }
        if let Some(spf) = &self.spf_result {
            builder = builder.metadata_entry("spf_result", json!(spf));
        }
        if let Some(dmarc) = &self.dmarc_result {
            builder = builder.metadata_entry("dmarc_result", json!(dmarc));
        }
        if let Some(cid) = &self.block_cid {
            builder = builder.metadata_entry("block_cid", json!(cid));
        }

        // Embed threading information
        if let Some(thread) = &self.thread_info {
            if let Some(msg_id) = &thread.message_id {
                builder = builder.metadata_entry("email_message_id", json!(msg_id));
            }
            if let Some(reply_to) = &thread.in_reply_to {
                builder = builder.metadata_entry("in_reply_to", json!(reply_to));
            }
            if !thread.references.is_empty() {
                builder = builder.metadata_entry("references", json!(thread.references));
            }
        }

        Ok(builder.build()?)
    }

    /// Extract an EmailMessage from a BlockManifest
    /// This reverses the process of to_block_manifest
    pub fn from_block_manifest(manifest: &BlockManifest) -> Option<Self> {
        // Only process blocks with email type
        let msg_type = manifest.metadata.get("type")?.as_str()?;
        if msg_type != "email" {
            return None;
        }

        let from = manifest.metadata.get("from")?.as_str()?.to_string();
        let to = manifest.metadata.get("to")?.as_str()?.to_string();
        let subject = manifest.metadata.get("subject")?.as_str()?.to_string();
        let body = manifest.metadata.get("content")?.as_str()?.to_string();

        let html = manifest
            .metadata
            .get("html")
            .and_then(|v| v.as_str())
            .map(String::from);

        let channel = manifest
            .metadata
            .get("channel")
            .and_then(|v| v.as_str())
            .map(String::from);

        let thread_info = ThreadInfo::from_manifest(manifest);

        let dkim_result = manifest
            .metadata
            .get("dkim_result")
            .and_then(|v| v.as_str())
            .map(String::from);

        let spf_result = manifest
            .metadata
            .get("spf_result")
            .and_then(|v| v.as_str())
            .map(String::from);

        let dmarc_result = manifest
            .metadata
            .get("dmarc_result")
            .and_then(|v| v.as_str())
            .map(String::from);

        let block_cid = manifest
            .metadata
            .get("block_cid")
            .and_then(|v| v.as_str())
            .map(String::from);

        Some(Self {
            from,
            to,
            subject,
            body,
            html,
            thread_info,
            channel,
            dkim_result,
            spf_result,
            dmarc_result,
            block_cid,
        })
    }
}

impl ThreadInfo {
    fn from_manifest(manifest: &BlockManifest) -> Option<Self> {
        let message_id = manifest
            .metadata
            .get("email_message_id")
            .and_then(|v| v.as_str())
            .map(String::from);

        let in_reply_to = manifest
            .metadata
            .get("in_reply_to")
            .and_then(|v| v.as_str())
            .map(String::from);

        let references: Vec<String> = manifest
            .metadata
            .get("references")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        if message_id.is_none() && in_reply_to.is_none() && references.is_empty() {
            None
        } else {
            Some(Self {
                message_id,
                in_reply_to,
                references,
            })
        }
    }

    pub fn generate_message_id(domain: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!("<jig-{}-{}@{}>", timestamp, uuid::Uuid::new_v4(), domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_to_manifest_roundtrip() {
        let email = EmailMessage::new(
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
            "Test Subject".to_string(),
            "Test body content".to_string(),
        );

        let manifest = email
            .to_block_manifest("did:jig:alice")
            .expect("should build manifest");
        let recovered = EmailMessage::from_block_manifest(&manifest).expect("should extract");

        assert_eq!(recovered.from, email.from);
        assert_eq!(recovered.to, email.to);
        assert_eq!(recovered.subject, email.subject);
        assert_eq!(recovered.body, email.body);
    }
}
