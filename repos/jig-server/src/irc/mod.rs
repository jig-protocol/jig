//! IRC server implementation for Jig
//!
//! Full IRC compatibility - respect 35 years of muscle memory

mod handler;
mod parser;
mod protocol;
mod session;

pub use protocol::{IrcCommand, IrcMessage, IrcReply};
pub use session::IrcSession;

use crate::error::Result;
use crate::storage::SqliteBackend;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// IRC Server that maps to Jig protocol
pub struct IrcServer {
    storage: Arc<SqliteBackend>,
    sessions: Arc<RwLock<HashMap<String, Arc<IrcSession>>>>,
    channels: Arc<RwLock<HashMap<String, Vec<String>>>>,
    server_name: String,
}

impl IrcServer {
    /// Create new IRC server
    pub fn new(storage: Arc<SqliteBackend>) -> Self {
        Self {
            storage,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            channels: Arc::new(RwLock::new(HashMap::new())),
            server_name: "jig.irc.local".to_string(),
        }
    }

    /// Start IRC server on specified port
    pub async fn start(&self, bind_addr: &str, port: u16) -> Result<()> {
        let listener = TcpListener::bind(format!("{}:{}", bind_addr, port)).await?;
        info!("IRC server listening on {}:{}", bind_addr, port);

        loop {
            let (stream, addr) = listener.accept().await?;
            info!("New IRC connection from {}", addr);

            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.handle_client(stream).await {
                    warn!("Error handling IRC client: {}", e);
                }
            });
        }
    }

    /// Handle individual IRC client connection
    async fn handle_client(&self, stream: TcpStream) -> Result<()> {
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let writer = Arc::new(tokio::sync::Mutex::new(writer));

        let mut session = IrcSession::new(writer.clone());
        let session_id = session.id.clone();

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), Arc::new(session.clone()));
        }

        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // Connection closed
                    info!("IRC client {} disconnected", session_id);
                    break;
                }
                Ok(_) => {
                    let line = line.trim_end();
                    if !line.is_empty() {
                        debug!("IRC recv: {}", line);
                        match self.handle_line(&mut session, line).await {
                            Err(crate::error::ServerError::ConnectionClosed) => {
                                info!("Client requested disconnect");
                                break;
                            }
                            Err(e) => {
                                warn!("Error handling IRC command: {}", e);
                            }
                            Ok(_) => {}
                        }
                    }
                }
                Err(e) => {
                    warn!("Error reading from IRC client: {}", e);
                    break;
                }
            }
        }

        // Clean up session
        {
            let mut sessions = self.sessions.write().await;
            sessions.remove(&session_id);
        }

        // Remove from channels
        let _ = self.remove_from_all_channels(&session.nick).await;

        // Properly close the TCP connection
        let _ = session.shutdown().await;

        Ok(())
    }

    /// Handle a single IRC command line
    async fn handle_line(&self, session: &mut IrcSession, line: &str) -> Result<()> {
        let msg = parser::parse_irc_message(line)?;
        let res = handler::handle_command(self, session, msg).await;
        if res.is_ok() {
            // keep stored snapshot in sync for broadcasting and lookups
            self.update_session(session).await?;
        }
        res
    }

    /// Send message to all users in a channel
    pub async fn broadcast_to_channel(
        &self,
        channel: &str,
        message: &str,
        exclude: Option<&str>,
    ) -> Result<()> {
        let channels = self.channels.read().await;
        if let Some(users) = channels.get(channel) {
            let sessions = self.sessions.read().await;
            for nick in users {
                if exclude.is_some() && exclude == Some(nick.as_str()) {
                    continue;
                }
                if let Some(session) = sessions.values().find(|s| s.nick == *nick) {
                    session.send_raw(message).await?;
                }
            }
        }
        Ok(())
    }

    /// Add user to channel
    pub async fn add_to_channel(&self, channel: &str, nick: &str) -> Result<()> {
        let mut channels = self.channels.write().await;
        channels
            .entry(channel.to_string())
            .or_insert_with(Vec::new)
            .push(nick.to_string());
        Ok(())
    }

    /// Remove user from channel
    pub async fn remove_from_channel(&self, channel: &str, nick: &str) -> Result<()> {
        let mut channels = self.channels.write().await;
        if let Some(users) = channels.get_mut(channel) {
            users.retain(|u| u != nick);
        }
        Ok(())
    }

    /// Remove user from all channels
    async fn remove_from_all_channels(&self, nick: &str) -> Result<()> {
        let mut channels = self.channels.write().await;
        for users in channels.values_mut() {
            users.retain(|u| u != nick);
        }
        Ok(())
    }

    /// Update a session snapshot stored by the server (to reflect latest nick/user)
    pub async fn update_session(&self, session: &IrcSession) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.id.clone(), Arc::new(session.clone()));
        Ok(())
    }

    /// Rename a user's nick across all channels
    pub async fn rename_nick_in_channels(&self, old_nick: &str, new_nick: &str) -> Result<()> {
        let mut channels = self.channels.write().await;
        for users in channels.values_mut() {
            for u in users.iter_mut() {
                if u == old_nick {
                    *u = new_nick.to_string();
                }
            }
        }
        Ok(())
    }

    /// Get list of users in channel
    pub async fn get_channel_users(&self, channel: &str) -> Vec<String> {
        let channels = self.channels.read().await;
        channels.get(channel).cloned().unwrap_or_default()
    }
}

impl Clone for IrcServer {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            sessions: self.sessions.clone(),
            channels: self.channels.clone(),
            server_name: self.server_name.clone(),
        }
    }
}
