//! SMTP client implementation

use crate::config::{FormattingConfig, SmtpClientConfig};
use crate::formatter::email_to_smtp;
use crate::storage::{EmailStorage, OutboundEmail};
use anyhow::Result;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::response::Response;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use tracing::{error, info};

pub async fn run(
    config: SmtpClientConfig,
    storage: EmailStorage,
    fmt: FormattingConfig,
) -> Result<()> {
    if !config.enabled {
        info!("SMTP client disabled");
        return Ok(());
    }

    info!("Starting SMTP client worker");

    let mut builder =
        AsyncSmtpTransport::<Tokio1Executor>::relay(&config.relay_host)?.port(config.relay_port);
    if let (Some(u), Some(p)) = (config.username.as_ref(), config.password.as_ref()) {
        builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
    }
    let mailer = builder.build();

    loop {
        if let Some(out) = storage.next_outbound()? {
            match send_email(&mailer, &config.from_address, &out, &fmt).await {
                Ok(_) => {
                    let _ = storage.mark_outbound_sent(out.id);
                }
                Err(e) => {
                    error!("Failed sending email {}: {}", out.id, e);
                }
            }
        } else {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}

async fn send_email(
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &str,
    out: &OutboundEmail,
    fmt: &FormattingConfig,
) -> Result<Response> {
    // Convert OutboundEmail to EmailMessage
    let mut email_msg = out.to_email_message();
    email_msg.from = from.to_string();

    // Convert EmailMessage to SMTP Message
    let smtp_msg = email_to_smtp(&email_msg, from, fmt)?;
    Ok(mailer.send(smtp_msg).await?)
}
