//! Resend (https://resend.com) email provider.
//!
//! Outbound: POST https://api.resend.com/emails with a Bearer API key.
//! Inbound: Resend signs webhooks with the Svix scheme — verify the `svix-*`
//! headers (HMAC-SHA256 over `{id}.{timestamp}.{body}`, base64-encoded, key =
//! base64-decoded webhook secret), then parse the event into an
//! `InboundNotification` (metadata only — Resend webhooks carry no body). The
//! body is fetched separately via `fetch_inbound` (GET /emails/receiving/{id}).
//! Non-deliverable events (delivery status, bounces) -> Ok(None).

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::provider::{EmailProvider, InboundEmail, InboundNotification, OutboundEmail, ProviderMessageId};

type HmacSha256 = Hmac<Sha256>;

pub struct ResendProvider {
    api_key: String,
    webhook_secret: String,
    http: reqwest::Client,
}

impl ResendProvider {
    pub fn new(api_key: String, webhook_secret: String) -> Self {
        Self {
            api_key,
            webhook_secret,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl EmailProvider for ResendProvider {
    async fn send(&self, msg: &OutboundEmail) -> Result<ProviderMessageId> {
        let resp = self
            .http
            .post("https://api.resend.com/emails")
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({
                "from": msg.from,
                "to": [&msg.to],
                "subject": msg.subject,
                "text": msg.body,
            }))
            .send()
            .await
            .context("resend send request")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("resend send failed: {status}: {body}");
        }
        let v: serde_json::Value = resp.json().await.context("resend send response json")?;
        v.get("id")
            .and_then(|i| i.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("resend send response missing id"))
    }

    fn verify_webhook(&self, headers: &HeaderMap, body: &[u8]) -> Result<()> {
        let id = header_str(headers, "svix-id")?;
        let ts = header_str(headers, "svix-timestamp")?;
        let sig_header = header_str(headers, "svix-signature")?;

        // NOTE(alpha.email follow-up): the svix-timestamp is bound into the
        // signed content (replay of a tampered timestamp fails verification),
        // but we do NOT yet reject timestamps outside the Svix-recommended
        // ±5min window — so a *verbatim* captured webhook can be replayed.
        // Add a tolerance check against wall-clock before live Resend use.

        let secret_b64 = self
            .webhook_secret
            .strip_prefix("whsec_")
            .unwrap_or(&self.webhook_secret);
        let key = B64.decode(secret_b64).context("decoding webhook secret")?;

        let body_str = std::str::from_utf8(body).context("webhook body utf8")?;
        let signed = format!("{id}.{ts}.{body_str}");
        let mac = {
            let mut m = HmacSha256::new_from_slice(&key).context("hmac key")?;
            m.update(signed.as_bytes());
            m
        };

        // Accept if ANY candidate signature matches — Svix may include multiple
        // (e.g. during key rotation). `verify_slice` consumes the Mac and is
        // constant-time (prevents timing oracles), so clone it per candidate.
        let matched = sig_header
            .split(' ')
            .filter_map(|entry| entry.strip_prefix("v1,"))
            .filter_map(|s| B64.decode(s).ok())
            .any(|candidate| mac.clone().verify_slice(&candidate).is_ok());

        if matched {
            Ok(())
        } else {
            bail!("svix signature mismatch")
        }
    }

    fn parse_webhook(
        &self,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Option<InboundNotification>> {
        let v: serde_json::Value = serde_json::from_slice(body).context("webhook json")?;
        let event_type = v.get("type").and_then(|t| t.as_str()).unwrap_or_default();
        if event_type != "email.received" && event_type != "inbound.email.received" {
            return Ok(None);
        }
        let data = v.get("data").unwrap_or(&v);
        let provider_message_id = data
            .get("email_id")
            .or_else(|| data.get("id"))
            .and_then(|i| i.as_str())
            .unwrap_or_default()
            .to_string();
        let from = data.get("from").and_then(value_as_email).unwrap_or_default();
        let to = data.get("to").and_then(value_as_email).unwrap_or_default();
        let subject = data
            .get("subject")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string();
        if provider_message_id.is_empty() || from.is_empty() || to.is_empty() {
            bail!("resend email.received missing email_id/from/to");
        }
        Ok(Some(InboundNotification {
            provider_message_id,
            from,
            to,
            subject,
        }))
    }

    async fn fetch_inbound(&self, n: &InboundNotification) -> Result<InboundEmail> {
        let url = format!(
            "https://api.resend.com/emails/receiving/{}",
            n.provider_message_id
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.api_key)
            // data_uri (Resend's default) inlines images as base64 so the html
            // fallback is self-contained — no broken `cid:` refs once we drop the
            // (unfetched) attachments.
            .query(&[("html_format", "data_uri")])
            .send()
            .await
            .context("resend fetch received email")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("resend fetch received email failed: {status}: {body}");
        }
        let bytes = resp.bytes().await.context("resend fetch body")?;
        let body = parse_received_email_json(&bytes)?;
        Ok(InboundEmail {
            from: n.from.clone(),
            to: n.to.clone(),
            subject: n.subject.clone(),
            body,
            provider_message_id: n.provider_message_id.clone(),
        })
    }
}

/// Map a Resend "retrieve received email" response into the message body:
/// prefer `text`, fall back to raw `html` (proper HTML->text is a later
/// refinement), and append a footer when attachments are present (we do not
/// fetch attachment content in this iteration). Pure — unit-testable.
fn parse_received_email_json(bytes: &[u8]) -> Result<String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).context("received-email json")?;
    let text = v.get("text").and_then(|t| t.as_str()).unwrap_or("");
    let html = v.get("html").and_then(|h| h.as_str()).unwrap_or("");
    let mut body = if !text.trim().is_empty() {
        text.to_string()
    } else {
        html.to_string()
    };
    let n_attach = v
        .get("attachments")
        .and_then(|a| a.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    // Intentional: an attachment-only email (blank text + html) yields a
    // footer-only body, which passes the inbound empty-body guard and is
    // forwarded — telling the recipient something arrived but wasn't delivered,
    // rather than silently dropping it.
    if n_attach > 0 {
        body.push_str(&format!("\n\n[{n_attach} attachment(s) not delivered]"));
    }
    Ok(body)
}

fn header_str(headers: &HeaderMap, name: &str) -> Result<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("missing or invalid header: {name}"))
}

/// Resend may represent an address as a plain string, an array, or `{ "email": ... }`.
fn value_as_email(v: &serde_json::Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    if let Some(arr) = v.as_array() {
        return arr.first().and_then(value_as_email);
    }
    v.get("email")
        .and_then(|e| e.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const TEST_SECRET: &str = "whsec_dGVzdHNlY3JldA=="; // base64("testsecret")

    /// Build a valid `v1,<base64>` Svix signature for the given inputs.
    fn sign(secret_b64: &str, id: &str, ts: &str, body: &[u8]) -> String {
        let key_b64 = secret_b64.strip_prefix("whsec_").unwrap_or(secret_b64);
        let key = B64.decode(key_b64).expect("decode test secret");
        let body_str = std::str::from_utf8(body).expect("body utf8");
        let signed = format!("{id}.{ts}.{body_str}");
        let mut m = HmacSha256::new_from_slice(&key).expect("hmac key");
        m.update(signed.as_bytes());
        let sig_bytes = m.finalize().into_bytes();
        format!("v1,{}", B64.encode(sig_bytes))
    }

    /// Build a `HeaderMap` with the three required svix headers.
    fn svix_headers(id: &str, ts: &str, sig: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert("svix-id", HeaderValue::from_str(id).unwrap());
        m.insert("svix-timestamp", HeaderValue::from_str(ts).unwrap());
        m.insert("svix-signature", HeaderValue::from_str(sig).unwrap());
        m
    }

    fn provider() -> ResendProvider {
        ResendProvider::new("test_api_key".into(), TEST_SECRET.into())
    }

    #[test]
    fn verify_accepts_good_signature() {
        let body = b"{\"type\":\"email.delivered\"}";
        let id = "msg_01abc";
        let ts = "1700000000";
        let sig = sign(TEST_SECRET, id, ts, body);
        let headers = svix_headers(id, ts, &sig);
        provider()
            .verify_webhook(&headers, body)
            .expect("should verify");
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let body = b"{\"type\":\"email.delivered\"}";
        let id = "msg_01abc";
        let ts = "1700000000";
        // Sign over different body content — signature won't match the actual body.
        let sig = sign(TEST_SECRET, id, ts, b"tampered body");
        let headers = svix_headers(id, ts, &sig);
        assert!(
            provider().verify_webhook(&headers, body).is_err(),
            "tampered body should fail"
        );
    }

    #[test]
    fn verify_rejects_missing_headers() {
        let body = b"{\"type\":\"email.delivered\"}";
        assert!(
            provider().verify_webhook(&HeaderMap::new(), body).is_err(),
            "empty headers should fail"
        );
    }

    #[test]
    fn parse_received_event_yields_inbound() {
        let fixture = br#"{
            "type": "email.received",
            "data": {
                "from": "alice@example.com",
                "to": ["bridge@jig.onl"],
                "subject": "Hi",
                "text": "hello",
                "email_id": "m_1"
            }
        }"#;
        let result = provider()
            .parse_webhook(&HeaderMap::new(), fixture)
            .unwrap();
        // parse_webhook now returns InboundNotification (no body — body is fetched separately)
        let notif = result.expect("should be Some for email.received");
        assert_eq!(notif.provider_message_id, "m_1");
        assert_eq!(notif.from, "alice@example.com");
        assert_eq!(notif.to, "bridge@jig.onl");
        assert_eq!(notif.subject, "Hi");
    }

    #[test]
    fn parse_received_prefers_text() {
        let j = br#"{"text":"hello","html":"<p>hello</p>"}"#;
        assert_eq!(parse_received_email_json(j).unwrap(), "hello");
    }

    #[test]
    fn parse_received_falls_back_to_html() {
        let j = br#"{"text":null,"html":"<p>hi</p>"}"#;
        assert_eq!(parse_received_email_json(j).unwrap(), "<p>hi</p>");
    }

    #[test]
    fn parse_received_empty_when_both_blank_no_attachments() {
        let j = br#"{"text":"","html":""}"#;
        assert_eq!(parse_received_email_json(j).unwrap(), "");
    }

    #[test]
    fn parse_received_appends_attachment_footer() {
        let j = br#"{"text":"body","attachments":[{"id":"a"},{"id":"b"}]}"#;
        assert_eq!(
            parse_received_email_json(j).unwrap(),
            "body\n\n[2 attachment(s) not delivered]"
        );
    }
    #[test]
    fn parse_received_attachment_only_produces_footer_body() {
        // Blank text + html but an attachment: the footer is the whole body and
        // (after trim) is non-empty, so the inbound guard forwards it.
        let j = br#"{"text":"","html":"","attachments":[{"id":"a"}]}"#;
        let body = parse_received_email_json(j).unwrap();
        assert_eq!(body, "\n\n[1 attachment(s) not delivered]");
        assert!(!body.trim().is_empty());
    }

    #[test]
    fn parse_delivery_status_event_yields_none() {
        let fixture = br#"{
            "type": "email.delivered",
            "data": {
                "email_id": "m_2",
                "from": "sender@example.com",
                "to": "recipient@example.com"
            }
        }"#;
        let result = provider()
            .parse_webhook(&HeaderMap::new(), fixture)
            .unwrap();
        assert!(result.is_none(), "delivery-status events should yield None");
    }

    #[test]
    fn parse_bounce_event_yields_none() {
        // A bounce is non-deliverable: it must not be forwarded as a message,
        // even though it carries the same id/from/to fields a received event has.
        let fixture = br#"{
            "type": "email.bounced",
            "data": {
                "email_id": "m_3",
                "from": "sender@example.com",
                "to": "recipient@example.com",
                "subject": "Undelivered",
                "text": "bounce notification"
            }
        }"#;
        let result = provider()
            .parse_webhook(&HeaderMap::new(), fixture)
            .unwrap();
        assert!(result.is_none(), "bounce events should yield None");
    }

    /// Live smoke against real Resend. Ignored by default (no network in CI).
    /// Run manually with credentials from 1Password, e.g.:
    ///   RESEND_API_KEY=$(op read 'op://...') RESEND_TEST_TO=you@example.com \
    ///     cargo test -p jig-bridge-email resend_live_send -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "live: needs RESEND_API_KEY + RESEND_TEST_TO"]
    async fn resend_live_send() {
        let api_key = std::env::var("RESEND_API_KEY").expect("set RESEND_API_KEY");
        let to = std::env::var("RESEND_TEST_TO").expect("set RESEND_TEST_TO");
        let from =
            std::env::var("RESEND_TEST_FROM").unwrap_or_else(|_| "onboarding@resend.dev".into());
        let p = ResendProvider::new(api_key, String::new());
        let id = p
            .send(&OutboundEmail {
                to,
                from,
                subject: "jig live smoke".into(),
                body: "hello from the jig email bridge".into(),
            })
            .await
            .expect("live send should succeed");
        assert!(!id.is_empty(), "Resend returned an empty message id");
    }
}
