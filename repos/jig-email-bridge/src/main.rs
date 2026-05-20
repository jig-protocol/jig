//! Jig Email Bridge - Bidirectional email gateway
//!
//! Bridges email (SMTP/IMAP) with Jig protocol messages

mod config;
mod discovery;
mod formatter;
mod parser;
mod resend_client;
mod smtp_client;
mod smtp_server;
mod storage;
mod types;

use anyhow::Context;
use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "jig-email-bridge")]
#[command(about = "Email bridge for Jig protocol", long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "email-bridge.toml")]
    config: std::path::PathBuf,

    /// Database path
    #[arg(short, long, default_value = "/var/lib/jig/email.db")]
    database: std::path::PathBuf,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Subcommands
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Send a Jig message as an email directly (bypasses queue)
    SendEmail {
        /// Recipient email address
        #[arg(long)]
        to: String,
        /// Subject line (fallbacks to first line of body if omitted)
        #[arg(long)]
        subject: Option<String>,
        /// Body text for the message
        #[arg(long)]
        body: String,
    },
    /// Enqueue a Jig message for sending via the SMTP worker
    EnqueueEmail {
        /// Recipient email address
        #[arg(long)]
        to: String,
        /// Subject line (fallbacks to first line of body if omitted)
        #[arg(long)]
        subject: Option<String>,
        /// Body text for the message
        #[arg(long)]
        body: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Load configuration
    let config = config::load_config(&cli.config)?;

    // Handle subcommands before starting services
    if let Some(cmd) = &cli.command {
        match cmd {
            Commands::SendEmail { to, subject, body } => {
                // Create EmailMessage
                let email_msg = types::EmailMessage::new(
                    config.smtp_client.from_address.clone(),
                    to.clone(),
                    subject.clone().unwrap_or_else(|| {
                        body.lines()
                            .next()
                            .unwrap_or("Jig Message")
                            .chars()
                            .take(100)
                            .collect()
                    }),
                    body.clone(),
                );

                match config.outbound_transport {
                    crate::config::OutboundTransport::Smtp => {
                        use lettre::transport::smtp::authentication::Credentials;
                        use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

                        // Build mailer from config
                        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(
                            &config.smtp_client.relay_host,
                        )?
                        .port(config.smtp_client.relay_port);
                        if let (Some(u), Some(p)) = (
                            config.smtp_client.username.as_ref(),
                            config.smtp_client.password.as_ref(),
                        ) {
                            builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
                        }
                        let mailer = builder.build();

                        // Transform to SMTP message and send
                        let smtp_msg = formatter::email_to_smtp(
                            &email_msg,
                            &config.smtp_client.from_address,
                            &config.formatting,
                        )?;
                        let response = mailer.send(smtp_msg).await?;
                        info!("Email sent via SMTP: {:?}", response);
                        return Ok(());
                    }
                    crate::config::OutboundTransport::Resend => {
                        let api_key = std::env::var(&config.resend_client.api_key_env)
                            .with_context(|| {
                                format!(
                                    "{} not set in environment",
                                    config.resend_client.api_key_env
                                )
                            })?;
                        let formatted_body =
                            formatter::format_text_body(&email_msg.body, &config.formatting);
                        resend_client::send_once(
                            &config.resend_client,
                            &api_key,
                            &email_msg.to,
                            &email_msg.subject,
                            &formatted_body,
                        )
                        .await?;
                        info!("Email sent via Resend");
                        return Ok(());
                    }
                }
            }
            Commands::EnqueueEmail { to, subject, body } => {
                // Create storage and enqueue
                let storage = storage::EmailStorage::new(&cli.database)?;
                let message_id = uuid::Uuid::new_v4().to_string();
                // Fallback subject from first line of body
                let subj_value = subject.clone().unwrap_or_else(|| {
                    body.lines()
                        .next()
                        .unwrap_or("Jig Message")
                        .chars()
                        .take(100)
                        .collect()
                });
                storage.queue_outbound(&message_id, to, &subj_value, body)?;
                info!(
                    "Enqueued email to {} with subject '{}' (msg_id={})",
                    to, subj_value, message_id
                );
                return Ok(());
            }
        }
    }

    info!("Starting Jig Email Bridge services");

    // Initialize storage
    let storage = storage::EmailStorage::new(&cli.database)?;

    // Clone for each task
    let storage_for_server = storage.clone();
    let storage_for_client = storage.clone();

    // Start SMTP server (inbound) — still a stub; optional
    let smtp_handle = tokio::spawn(async move {
        if let Err(e) = smtp_server::run(config.smtp_server, storage_for_server).await {
            error!("SMTP server error: {}", e);
        }
    });

    // Start outbound worker based on transport
    let fmt = config.formatting.clone();
    let outbound = config.outbound_transport.clone();
    let smtp_cfg = config.smtp_client.clone();
    let resend_cfg = config.resend_client.clone();
    let client_handle = tokio::spawn(async move {
        match outbound {
            crate::config::OutboundTransport::Smtp => {
                if let Err(e) = smtp_client::run(smtp_cfg, storage_for_client, fmt).await {
                    error!("SMTP client error: {}", e);
                }
            }
            crate::config::OutboundTransport::Resend => {
                if let Err(e) = resend_client::run(resend_cfg, storage_for_client, fmt).await {
                    error!("Resend client error: {}", e);
                }
            }
        }
    });

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    smtp_handle.abort();
    client_handle.abort();

    Ok(())
}
