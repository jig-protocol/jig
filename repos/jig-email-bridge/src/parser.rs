//! Email parser - RFC822 to EmailMessage

use crate::types::{EmailMessage, ThreadInfo};
use anyhow::Result;

/// Parse raw RFC822 email bytes into an `EmailMessage`.
///
/// Extracts sender, recipient, subject, body, and thread headers.
pub fn parse_email(raw_email: &[u8]) -> Result<EmailMessage> {
    let parser = mail_parser::MessageParser::default();
    let email = parser
        .parse(raw_email)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse email"))?;

    // Extract basic headers
    let from = email
        .from()
        .and_then(|addrs| addrs.first())
        .and_then(|addr| addr.address())
        .unwrap_or("unknown@unknown")
        .to_string();

    let to = email
        .to()
        .and_then(|addrs| addrs.first())
        .and_then(|addr| addr.address())
        .unwrap_or("unknown@unknown")
        .to_string();

    let subject = email.subject().unwrap_or("No Subject").to_string();
    let body = email.body_text(0).unwrap_or_default().trim().to_string();
    let html = email.body_html(0).map(|h| h.to_string());

    // Extract threading headers
    let thread_info = extract_thread_info(&email);

    Ok(EmailMessage {
        from,
        to,
        subject,
        body,
        html,
        thread_info,
        channel: None,
        dkim_result: None,  // TODO: Parse DKIM-Signature header
        spf_result: None,   // TODO: Parse Received-SPF header
        dmarc_result: None, // TODO: Parse Authentication-Results header
        block_cid: None,    // Set when converting to block
    })
}

/// Extract thread information from email headers
fn extract_thread_info(email: &mail_parser::Message) -> Option<ThreadInfo> {
    let message_id = email.message_id().map(|id| format!("<{}>", id));

    // mail-parser in_reply_to() returns &HeaderValue (or empty)
    // We need to check if it's actually present
    let in_reply_to = match email.in_reply_to() {
        mail_parser::HeaderValue::Text(txt) if !txt.is_empty() => Some(format!("<{}>", txt)),
        mail_parser::HeaderValue::TextList(list) if !list.is_empty() => {
            Some(format!("<{}>", list[0]))
        }
        _ => None,
    };

    let references: Vec<String> = Vec::new(); // TODO: Parse References header properly

    if message_id.is_none() && in_reply_to.is_none() && references.is_empty() {
        None
    } else {
        Some(ThreadInfo {
            message_id,
            in_reply_to,
            references,
        })
    }
}
