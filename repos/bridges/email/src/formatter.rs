//! EmailMessage to SMTP message formatter

use crate::types::EmailMessage;
use anyhow::Result;
use lettre::message::Message;
use lettre::message::header::{Header, HeaderName, HeaderValue, InReplyTo, MessageId};

/// Format EmailMessage as SMTP message with headers and signature
pub fn email_to_smtp(
    msg: &EmailMessage,
    from: &str,
    fmt: &crate::config::FormattingConfig,
) -> Result<Message> {
    let body = format_text_body(&msg.body, fmt);

    let mut builder = Message::builder()
        .from(from.parse()?)
        .to(msg.to.parse()?)
        .subject(&msg.subject);

    // Add Message-ID if available
    if let Some(thread) = &msg.thread_info {
        if let Some(msg_id) = &thread.message_id {
            builder = builder.header(MessageId::from(msg_id.clone()));
        }
        if let Some(reply_to) = &thread.in_reply_to {
            builder = builder.header(InReplyTo::from(reply_to.clone()));
        }
        if !thread.references.is_empty() {
            let refs = thread.references.join(" ");
            builder = builder.header(lettre::message::header::References::from(refs));
        }
    }

    if fmt.add_x_jig_header {
        let x_jig_value = "v=1; link=https://jig.onl; type=email-bridge".to_string();
        builder = builder.header(XJigProtocol(x_jig_value));
    }

    let email = builder.body(body)?;
    Ok(email)
}

pub fn format_text_body(content: &str, fmt: &crate::config::FormattingConfig) -> String {
    format_text_body_with_cid(content, fmt, None)
}

/// Format text body with optional block CID for viral signature
pub fn format_text_body_with_cid(
    content: &str,
    fmt: &crate::config::FormattingConfig,
    block_cid: Option<&str>,
) -> String {
    // Optionally wrap at configured width (simple greedy wrap)
    let wrapped = if fmt.wrap_at > 0 {
        wrap_text(content, fmt.wrap_at)
    } else {
        content.to_string()
    };

    let mut result = wrapped;

    if fmt.add_signature && !fmt.signature.trim().is_empty() {
        // Ensure a newline before signature if needed
        if !result.ends_with('\n') && !fmt.signature.starts_with('\n') {
            result.push('\n');
        }
        result.push_str(&fmt.signature);
    }

    // Add viral block signature with CID
    if let Some(cid) = block_cid {
        if !result.ends_with('\n') {
            result.push('\n');
        }
        result.push_str("\n");
        result.push_str("—\n"); // em dash separator
        result.push_str("📦 Secured by Jig Block\n");
        result.push_str(&format!("Block ID: {}\n", cid));
        result.push_str("Verify at: https://jig.onl/block/");
        result.push_str(cid);
    }

    result
}

/// Custom header for X-Jig-Protocol
#[derive(Clone)]
struct XJigProtocol(String);

impl Header for XJigProtocol {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("X-Jig-Protocol")
    }
    fn display(&self) -> HeaderValue {
        HeaderValue::new(Self::name(), self.0.clone())
    }
    fn parse(_value: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
    where
        Self: Sized,
    {
        // Parsing is not used for outbound construction; provide a minimal impl.
        Ok(XJigProtocol(String::new()))
    }
}

fn wrap_text(input: &str, width: usize) -> String {
    if width == 0 {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    for line in input.lines() {
        let mut current = 0usize;
        for word in line.split_whitespace() {
            let wlen = word.chars().count();
            if current == 0 {
                out.push_str(word);
                current = wlen;
            } else if current + 1 + wlen > width {
                out.push('\n');
                out.push_str(word);
                current = wlen;
            } else {
                out.push(' ');
                out.push_str(word);
                current += 1 + wlen;
            }
        }
        out.push('\n');
    }
    // Remove the final newline if the original didn't end with one
    if !input.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}
