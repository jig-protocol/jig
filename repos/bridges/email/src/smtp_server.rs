//! SMTP server implementation

use crate::config::SmtpServerConfig;
use crate::parser::parse_email;
use crate::storage::EmailStorage;
use anyhow::Result;
use tokio::io::AsyncReadExt;
use tracing::{error, info};

pub async fn run(config: SmtpServerConfig, storage: EmailStorage) -> Result<()> {
    if !config.enabled {
        info!("SMTP server disabled");
        return Ok(());
    }

    let addr = format!("{}:{}", config.listen_addr, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Listening for SMTP connections on {}", addr);

    loop {
        let (mut stream, peer) = listener.accept().await?;
        let storage = storage.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            if stream.read_to_end(&mut buf).await.is_ok() {
                match parse_email(&buf) {
                    Ok(email_msg) => {
                        // For now just log the inbound message.
                        info!(
                            "Received email from {} to {} ({} bytes)",
                            email_msg.from,
                            email_msg.to,
                            buf.len()
                        );
                        // TODO: Convert to BlockManifest and store or forward to jig-server
                        let _ = storage; // storage reserved for future persistence
                    }
                    Err(e) => error!("Failed to parse email from {}: {}", peer, e),
                }
            }
        });
    }
}
