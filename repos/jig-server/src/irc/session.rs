//! IRC client session management

use crate::error::Result;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;

/// IRC client session
#[derive(Clone)]
pub struct IrcSession {
    pub id: String,
    pub nick: String,
    pub user: Option<String>,
    pub realname: Option<String>,
    pub registered: bool,
    pub channels: Vec<String>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
}

impl IrcSession {
    /// Create new IRC session
    pub fn new(writer: Arc<Mutex<OwnedWriteHalf>>) -> Self {
        Self {
            id: uuid::Uuid::now_v7().to_string(),
            nick: String::new(),
            user: None,
            realname: None,
            registered: false,
            channels: Vec::new(),
            writer,
        }
    }

    /// Send raw IRC message
    pub async fn send_raw(&self, message: &str) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer.write_all(message.as_bytes()).await?;
        writer.write_all(b"\r\n").await?;
        writer.flush().await?;
        Ok(())
    }

    /// Shutdown the TCP connection
    pub async fn shutdown(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer.shutdown().await?;
        Ok(())
    }

    /// Send IRC reply
    pub async fn send_reply(
        &self,
        code: super::protocol::IrcReply,
        params: Vec<&str>,
    ) -> Result<()> {
        let mut message = format!(":jig.irc.local {} ", code.as_str());

        // Add nick or * if not set
        if !self.nick.is_empty() {
            message.push_str(&self.nick);
        } else {
            message.push('*');
        }

        // Add parameters
        for (i, param) in params.iter().enumerate() {
            message.push(' ');
            if i == params.len() - 1 && param.contains(' ') {
                message.push(':');
            }
            message.push_str(param);
        }

        self.send_raw(&message).await
    }

    /// Send error reply
    pub async fn send_error(&self, code: super::protocol::IrcReply, message: &str) -> Result<()> {
        self.send_reply(code, vec![message]).await
    }

    /// Check if session is fully registered
    pub fn is_registered(&self) -> bool {
        self.registered && !self.nick.is_empty() && self.user.is_some()
    }

    /// Set nickname
    pub fn set_nick(&mut self, nick: String) {
        self.nick = nick;
        self.check_registration();
    }

    /// Set user info
    pub fn set_user(&mut self, user: String, realname: String) {
        self.user = Some(user);
        self.realname = Some(realname);
        self.check_registration();
    }

    /// Check and update registration status
    fn check_registration(&mut self) {
        if !self.nick.is_empty() && self.user.is_some() {
            self.registered = true;
        }
    }

    /// Join channel
    pub fn join_channel(&mut self, channel: String) {
        if !self.channels.contains(&channel) {
            self.channels.push(channel);
        }
    }

    /// Leave channel
    pub fn leave_channel(&mut self, channel: &str) {
        self.channels.retain(|c| c != channel);
    }

    /// Get user prefix (nick!user@host)
    pub fn get_prefix(&self) -> String {
        if let Some(ref user) = self.user {
            format!("{}!{}@jig.local", self.nick, user)
        } else {
            self.nick.clone()
        }
    }
}
