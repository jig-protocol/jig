//! Resend outbound transport

use crate::config::{FormattingConfig, ResendClientConfig};
use crate::formatter::format_text_body;
use crate::storage::{EmailStorage, OutboundEmail};
use anyhow::{Context, Result};
use tracing::{error, info};

const RESEND_ENDPOINT: &str = "https://api.resend.com/emails";

/// Background worker: pull from outbound_queue and send via Resend
pub async fn run(
    config: ResendClientConfig,
    storage: EmailStorage,
    fmt: FormattingConfig,
) -> Result<()> {
    if !config.enabled {
        info!("Resend client disabled");
        return Ok(());
    }

    let api_key = std::env::var(&config.api_key_env)
        .with_context(|| format!("{} not set in environment", config.api_key_env))?;

    let client = reqwest::Client::new();
    info!("Starting Resend client worker");

    loop {
        if let Some(out) = storage.next_outbound()? {
            match send_queued(&client, &config, &api_key, &out, &fmt).await {
                Ok(_) => {
                    let _ = storage.mark_outbound_sent(out.id);
                }
                Err(e) => {
                    error!("Failed sending via Resend {}: {}", out.id, e);
                }
            }
        } else {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}

/// One-shot send for CLI direct send
pub async fn send_once(
    config: &ResendClientConfig,
    api_key: &str,
    to: &str,
    subject: &str,
    text: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    send_via_resend(&client, config, api_key, to, subject, text, None).await
}

async fn send_queued(
    client: &reqwest::Client,
    config: &ResendClientConfig,
    api_key: &str,
    out: &OutboundEmail,
    fmt: &FormattingConfig,
) -> Result<()> {
    // Build a JigMessage for consistent formatting
    let email_msg = out.to_email_message();
    let subject = &email_msg.subject;
    let text = format_text_body(&email_msg.body, fmt);

    // Optionally include custom headers (X-Jig-Protocol, thread headers) later if desired.
    send_via_resend(client, config, api_key, &out.to, &subject, &text, None).await
}

async fn send_via_resend(
    client: &reqwest::Client,
    config: &ResendClientConfig,
    api_key: &str,
    to: &str,
    subject: &str,
    text: &str,
    headers: Option<serde_json::Value>,
) -> Result<()> {
    let mut body = serde_json::json!({
        "from": config.from_address,
        "to": [to],
        "subject": subject,
        "text": text,
    });

    if let Some(h) = headers {
        body["headers"] = h;
    }

    let resp = client
        .post(RESEND_ENDPOINT)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Resend API error: {} - {}", status, err_text);
    }

    Ok(())
}
