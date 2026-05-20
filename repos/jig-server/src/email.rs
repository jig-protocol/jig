// jig-server/src/modules/email.rs
// License: AGPL-3.0 (core server functionality)
// CRITICAL: This file contains core server logic - AGPL prevents competitor forks

use crate::core::JigServer;
use anyhow::Result;
use tokio::net::TcpListener;

/// Email module for JigServer
/// Provides SMTP, IMAP, and HTTP email interfaces
pub struct EmailModule {
    smtp_server: SmtpServer,
    imap_server: Option<ImapServer>, // Optional for lighter installs
    discovery: JigDiscovery,
    router: MessageRouter,
}

impl EmailModule {
    pub async fn new(config: &EmailConfig) -> Result<Self> {
        Ok(Self {
            smtp_server: SmtpServer::new(config)?,
            imap_server: if config.imap_enabled {
                Some(ImapServer::new(config)?)
            } else {
                None
            },
            discovery: JigDiscovery::new(),
            router: MessageRouter::new(config)?,
        })
    }

    /// Start all email services
    pub async fn start(&self, jig_server: &JigServer) -> Result<()> {
        // Start SMTP on port 25 (receive) and 587 (submit)
        tokio::spawn(self.clone().run_smtp_server());

        // Start IMAP if enabled
        if self.imap_server.is_some() {
            tokio::spawn(self.clone().run_imap_server());
        }

        // Start MX responder for incoming email
        tokio::spawn(self.clone().run_mx_receiver());

        Ok(())
    }

    async fn run_smtp_server(self) -> Result<()> {
        let listener = TcpListener::bind("0.0.0.0:25").await?;
        log::info!("SMTP server listening on :25");

        loop {
            let (stream, addr) = listener.accept().await?;
            let handler = self.clone();

            tokio::spawn(async move {
                if let Err(e) = handler.handle_smtp_connection(stream, addr).await {
                    log::error!("SMTP error from {}: {}", addr, e);
                }
            });
        }
    }

    async fn handle_smtp_connection(&self, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        let mut session = SmtpSession::new(stream);

        // Banner
        session.send(220, "Jig ESMTP Ready").await?;

        while let Some(cmd) = session.read_command().await? {
            match cmd {
                SmtpCommand::Ehlo(domain) => {
                    session
                        .send_multiline(
                            250,
                            vec![
                                "Hello",
                                "SIZE 52428800",
                                "8BITMIME",
                                "PIPELINING",
                                "STARTTLS",
                                "AUTH PLAIN LOGIN",
                                // SENSITIVE: Commercial features
                                #[cfg(feature = "commercial")]
                                "X-JIG-GIGUE",
                            ],
                        )
                        .await?;
                }
                SmtpCommand::Mail { from } => {
                    // Check if sender is Jig user
                    if self.is_jig_sender(&from).await? {
                        session.jig_enhanced = true;
                    }
                    session.send(250, "OK").await?;
                }
                SmtpCommand::Rcpt { to } => {
                    // Check if recipient is local or remote
                    match self.check_recipient(&to).await? {
                        RecipientType::LocalJig => {
                            session.send(250, "OK - Jig user").await?;
                        }
                        RecipientType::RemoteJig(endpoint) => {
                            session
                                .send(250, &format!("OK - Will relay via Jig to {}", endpoint))
                                .await?;
                        }
                        RecipientType::Email => {
                            session.send(250, "OK - Will relay via email").await?;
                        }
                    }
                }
                SmtpCommand::Data => {
                    session.send(354, "End data with <CR><LF>.<CR><LF>").await?;
                    let data = session.read_data().await?;

                    // Process the message
                    self.process_smtp_message(data, session.jig_enhanced)
                        .await?;

                    session.send(250, "Message accepted for delivery").await?;
                }
                SmtpCommand::Quit => {
                    session.send(221, "Bye").await?;
                    break;
                }
            }
        }

        Ok(())
    }

    async fn process_smtp_message(&self, data: Vec<u8>, jig_enhanced: bool) -> Result<()> {
        // Parse email
        let email = parse_email(&data)?;

        // Convert to Jig message
        let mut jig_msg = email_to_jig_message(email)?;

        // If sender is Jig user, preserve rich features
        if jig_enhanced {
            jig_msg.preserve_jig_features = true;
        }

        // Route the message
        match self.router.route_message(&jig_msg).await? {
            RouteDecision::NativeJig { endpoint } => {
                // Send directly via Jig protocol
                self.send_via_jig(jig_msg, endpoint).await?;
            }
            RouteDecision::JigToEmail { to, .. } => {
                // Send as email with enhancements
                self.router.send_as_email(&jig_msg, &to).await?;
            }
            _ => {}
        }

        Ok(())
    }
}

/// IMAP server for email client compatibility
pub struct ImapServer {
    storage: JigStorage,
}

impl ImapServer {
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind("0.0.0.0:143").await?;
        log::info!("IMAP server listening on :143");

        loop {
            let (stream, addr) = listener.accept().await?;
            let handler = self.clone();

            tokio::spawn(async move {
                if let Err(e) = handler.handle_imap_connection(stream).await {
                    log::error!("IMAP error: {}", e);
                }
            });
        }
    }

    async fn handle_imap_connection(&self, stream: TcpStream) -> Result<()> {
        // IMAP session that makes Jig messages appear as emails
        let session = ImapSession::new(stream, self.storage.clone());

        session.send_greeting().await?;

        while let Some(cmd) = session.read_command().await? {
            match cmd {
                ImapCommand::List => {
                    // Show Jig channels as IMAP folders
                    let channels = self.storage.get_channels().await?;
                    for channel in channels {
                        session.send_list_response(&channel).await?;
                    }
                }
                ImapCommand::Select(folder) => {
                    // Map folder to Jig channel
                    let channel = self.folder_to_channel(&folder);
                    session.select_channel(channel).await?;
                }
                ImapCommand::Fetch(range) => {
                    // Return Jig messages as emails
                    let messages = self.storage.get_messages(range).await?;
                    for msg in messages {
                        let email_view = self.jig_to_email_view(msg);
                        session.send_fetch_response(email_view).await?;
                    }
                } // ... other IMAP commands
            }
        }

        Ok(())
    }

    fn jig_to_email_view(&self, msg: JigMessage) -> EmailView {
        // Convert Jig message to email representation
        // This allows Thunderbird/Outlook to work with Jig
        EmailView {
            from: format!("{}@jig.local", msg.sender),
            to: msg.recipient.unwrap_or_default(),
            subject: msg.thread_id.unwrap_or_else(|| "Jig Message".to_string()),
            body: msg.content.to_text(),
            headers: self.generate_email_headers(msg),
        }
    }
}

/// Configuration for email module
#[derive(Debug, Deserialize, Clone)]
pub struct EmailConfig {
    /// Enable SMTP server (receive email)
    pub smtp_enabled: bool,

    /// Enable IMAP server (email client access)
    pub imap_enabled: bool,

    /// MX record handling
    pub mx_domains: Vec<String>,

    /// Relay configuration
    pub relay: RelayConfig,

    // SENSITIVE: Commercial features
    #[cfg(feature = "commercial")]
    pub gigue_features: GigueEmailConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RelayConfig {
    /// Primary relay method
    pub primary: RelayMethod,

    /// Community relay participation
    pub community_relay: bool,

    /// Donated quota (if participating)
    pub donated_quota: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub enum RelayMethod {
    /// Use SendGrid (free tier)
    SendGrid { api_key: Option<String> },

    /// Use community relay network
    Community,

    /// Direct send (requires clean IP)
    Direct,

    /// Custom SMTP relay
    Custom {
        host: String,
        port: u16,
        auth: Option<(String, String)>,
    },
}
