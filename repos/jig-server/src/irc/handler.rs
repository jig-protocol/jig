//! IRC command handlers

use super::protocol::{IrcCommand, IrcMessage, IrcReply};
use super::session::IrcSession;
use super::IrcServer;
use crate::error::Result;
use jig_core::message::RoutingHeader;
use jig_core::{JigMessage, MessageContent, StorageBackend};
use tracing::{debug, info};

/// Handle IRC command
pub async fn handle_command(
    server: &IrcServer,
    session: &mut IrcSession,
    msg: IrcMessage,
) -> Result<()> {
    match msg.command {
        IrcCommand::Nick(nick) => handle_nick(server, session, nick).await,
        IrcCommand::User(user, _host, _server, realname) => {
            handle_user(session, user, realname).await
        }
        IrcCommand::Pass(_pass) => {
            // We don't require passwords for now
            Ok(())
        }
        IrcCommand::Cap(subcommand, params) => handle_cap(session, subcommand, params).await,
        IrcCommand::Join(channels) => handle_join(server, session, channels).await,
        IrcCommand::Part(channels, msg) => handle_part(server, session, channels, msg).await,
        IrcCommand::Privmsg(target, text) => handle_privmsg(server, session, target, text).await,
        IrcCommand::Notice(target, text) => handle_notice(server, session, target, text).await,
        IrcCommand::Quit(msg) => handle_quit(server, session, msg).await,
        IrcCommand::Ping(s1, s2) => handle_ping(session, s1, s2).await,
        IrcCommand::Pong(_s1, _s2) => {
            // Client PONG response, just acknowledge
            Ok(())
        }
        IrcCommand::Topic(channel, topic) => handle_topic(server, session, channel, topic).await,
        IrcCommand::Names(channels) => handle_names(server, session, channels).await,
        IrcCommand::List(channels) => handle_list(server, session, channels).await,
        IrcCommand::Who(mask) => handle_who(server, session, mask).await,
        IrcCommand::Whois(nicks) => handle_whois(server, session, nicks).await,
        IrcCommand::Mode(target, mode, params) => handle_mode(session, target, mode, params).await,
        IrcCommand::Unknown(cmd, _params) => {
            session
                .send_error(
                    IrcReply::UnknownCommand,
                    &format!("{} :Unknown command", cmd),
                )
                .await
        }
    }
}

async fn handle_nick(server: &IrcServer, session: &mut IrcSession, nick: String) -> Result<()> {
    // Validate nickname
    if nick.is_empty() {
        return session
            .send_error(IrcReply::NoNicknameGiven, "No nickname given")
            .await;
    }

    if !is_valid_nick(&nick) {
        return session
            .send_error(
                IrcReply::ErroneousNickname,
                &format!("{} :Erroneous nickname", nick),
            )
            .await;
    }

    // Check if nick is in use (simplified - real IRC would check all sessions)
    // For now we'll allow it

    let old_nick = session.nick.clone();
    session.set_nick(nick.clone());
    // Update server snapshot of session and channel nick references
    if !old_nick.is_empty() && old_nick != nick {
        server.rename_nick_in_channels(&old_nick, &nick).await?;
    }
    server.update_session(session).await?;

    // If already registered, broadcast nick change
    if session.is_registered() && !old_nick.is_empty() {
        let message = format!(":{} NICK :{}", session.get_prefix(), nick);
        for channel in &session.channels.clone() {
            server.broadcast_to_channel(channel, &message, None).await?;
        }
    }

    // Send welcome messages if just registered
    if session.is_registered() && old_nick.is_empty() {
        send_welcome(session).await?;
    }

    Ok(())
}

async fn handle_user(session: &mut IrcSession, user: String, realname: String) -> Result<()> {
    if session.registered {
        return session
            .send_error(IrcReply::AlreadyRegistered, "You may not reregister")
            .await;
    }

    session.set_user(user, realname);

    // Send welcome if now registered
    if session.is_registered() {
        send_welcome(session).await?;
    }

    Ok(())
}

async fn send_welcome(session: &IrcSession) -> Result<()> {
    info!("User {} registered", session.nick);

    session
        .send_reply(
            IrcReply::Welcome,
            vec![&format!(
                "Welcome to the Jig IRC Network {}",
                session.get_prefix()
            )],
        )
        .await?;

    session
        .send_reply(
            IrcReply::YourHost,
            vec!["Your host is jig.irc.local, running version 0.1.0"],
        )
        .await?;

    session
        .send_reply(IrcReply::Created, vec!["This server was created recently"])
        .await?;

    session
        .send_reply(IrcReply::MyInfo, vec!["jig.irc.local", "0.1.0", "iw", "nt"])
        .await?;

    Ok(())
}

async fn handle_cap(
    session: &mut IrcSession,
    subcommand: String,
    _params: Vec<String>,
) -> Result<()> {
    // Basic CAP support - we don't actually support any capabilities
    // but we need to respond properly so clients like irssi work
    match subcommand.as_str() {
        "LS" => {
            // List available capabilities (we have none)
            session.send_raw("CAP * LS :").await?;
        }
        "REQ" => {
            // Client requesting capabilities - NAK them all
            session.send_raw("CAP * NAK :").await?;
        }
        "END" => {
            // Client ending negotiation - just acknowledge
            // No response needed for END
        }
        _ => {
            // Unknown CAP subcommand - ignore
        }
    }
    Ok(())
}

async fn handle_join(
    server: &IrcServer,
    session: &mut IrcSession,
    channels: Vec<String>,
) -> Result<()> {
    if !session.is_registered() {
        return session
            .send_error(IrcReply::NotRegistered, "You have not registered")
            .await;
    }

    for mut channel in channels {
        // Auto-prefix channels without valid prefix for better compatibility
        if !channel.starts_with('#') && !channel.starts_with('&') {
            // Auto-prefix with # for user convenience
            channel = format!("#{}", channel);
        }

        // Add to channel
        session.join_channel(channel.clone());
        server.add_to_channel(&channel, &session.nick).await?;

        // Send JOIN confirmation to all users
        let join_msg = format!(":{} JOIN {}", session.get_prefix(), channel);
        server
            .broadcast_to_channel(&channel, &join_msg, None)
            .await?;

        // Send topic if exists (for now, no topic)
        session
            .send_reply(IrcReply::NoTopic, vec![&channel, "No topic is set"])
            .await?;

        // Send names list
        let users = server.get_channel_users(&channel).await;
        let names = users.join(" ");
        session
            .send_reply(IrcReply::NamesReply, vec!["=", &channel, &names])
            .await?;
        session
            .send_reply(IrcReply::EndOfNames, vec![&channel, "End of /NAMES list"])
            .await?;
    }

    Ok(())
}

async fn handle_part(
    server: &IrcServer,
    session: &mut IrcSession,
    channels: Vec<String>,
    msg: Option<String>,
) -> Result<()> {
    if !session.is_registered() {
        return session
            .send_error(IrcReply::NotRegistered, "You have not registered")
            .await;
    }

    let part_msg = msg.unwrap_or_else(|| "Leaving".to_string());

    for channel in channels {
        if !session.channels.contains(&channel) {
            session
                .send_error(
                    IrcReply::NotOnChannel,
                    &format!("{} :You're not on that channel", channel),
                )
                .await?;
            continue;
        }

        // Send PART message to channel
        let msg = format!(":{} PART {} :{}", session.get_prefix(), channel, part_msg);
        server.broadcast_to_channel(&channel, &msg, None).await?;

        // Remove from channel
        session.leave_channel(&channel);
        server.remove_from_channel(&channel, &session.nick).await?;
    }

    Ok(())
}

async fn handle_privmsg(
    server: &IrcServer,
    session: &mut IrcSession,
    target: String,
    text: String,
) -> Result<()> {
    if !session.is_registered() {
        return session
            .send_error(IrcReply::NotRegistered, "You have not registered")
            .await;
    }

    if text.is_empty() {
        return session
            .send_error(IrcReply::NoTextToSend, "No text to send")
            .await;
    }

    // Store in Jig storage
    let jig_msg = JigMessage {
        id: jig_core::MessageId::new(),
        version: 1,
        content: MessageContent::Text {
            content: text.clone(),
        },
        routing: RoutingHeader {
            from: Some(session.nick.clone()),
            to: if target.starts_with('#') {
                None
            } else {
                Some(target.clone())
            },
            channel: if target.starts_with('#') {
                Some(target.clone())
            } else {
                None
            },
            thread: None,
            reply_to: None,
        },
        signatures: vec![],
        extensions: std::collections::HashMap::new(),
        timestamp: chrono::Utc::now(),
    };

    // Store message
    info!(
        "Storing message to channel {} from {}: {}",
        jig_msg.routing.channel.as_deref().unwrap_or("none"),
        session.nick,
        text
    );
    server.storage.store_message(&jig_msg).await?;

    // Send to channel or user
    if target.starts_with('#') || target.starts_with('&') {
        // Channel message
        if !session.channels.contains(&target) {
            return session
                .send_error(
                    IrcReply::CannotSendToChan,
                    &format!("{} :Cannot send to channel", target),
                )
                .await;
        }

        let msg = format!(":{} PRIVMSG {} :{}", session.get_prefix(), target, text);
        server
            .broadcast_to_channel(&target, &msg, Some(&session.nick))
            .await?;
    } else {
        // Direct message - find target session and send
        // For now, we'll just store it
        debug!(
            "Direct message from {} to {}: {}",
            session.nick, target, text
        );
    }

    Ok(())
}

async fn handle_notice(
    server: &IrcServer,
    session: &mut IrcSession,
    target: String,
    text: String,
) -> Result<()> {
    // Similar to PRIVMSG but no automatic replies
    if !session.is_registered() {
        return Ok(()); // Silently ignore for NOTICE
    }

    if target.starts_with('#') || target.starts_with('&') {
        let msg = format!(":{} NOTICE {} :{}", session.get_prefix(), target, text);
        server
            .broadcast_to_channel(&target, &msg, Some(&session.nick))
            .await?;
    }

    Ok(())
}

async fn handle_quit(
    _server: &IrcServer,
    session: &mut IrcSession,
    msg: Option<String>,
) -> Result<()> {
    let quit_msg = msg.unwrap_or_else(|| "Client quit".to_string());
    info!("User {} quit: {}", session.nick, quit_msg);

    // Send ERROR message to client before closing
    let error_msg = format!(
        "ERROR :Closing Link: {} ({})",
        session.get_prefix(),
        quit_msg
    );
    let _ = session.send_raw(&error_msg).await;

    // Signal that connection should be closed
    Err(crate::error::ServerError::ConnectionClosed)
}

async fn handle_ping(session: &IrcSession, s1: String, s2: Option<String>) -> Result<()> {
    let response = if let Some(s2) = s2 {
        format!("PONG {} {}", s1, s2)
    } else {
        format!("PONG {}", s1)
    };
    session.send_raw(&response).await
}

async fn handle_topic(
    _server: &IrcServer,
    session: &mut IrcSession,
    channel: String,
    _topic: Option<String>,
) -> Result<()> {
    if !session.is_registered() {
        return session
            .send_error(IrcReply::NotRegistered, "You have not registered")
            .await;
    }

    // For now, no topic support
    session
        .send_reply(IrcReply::NoTopic, vec![&channel, "No topic is set"])
        .await
}

async fn handle_names(
    server: &IrcServer,
    session: &mut IrcSession,
    channels: Vec<String>,
) -> Result<()> {
    if !session.is_registered() {
        return session
            .send_error(IrcReply::NotRegistered, "You have not registered")
            .await;
    }

    let channels = if channels.is_empty() {
        session.channels.clone()
    } else {
        channels
    };

    for channel in channels {
        let users = server.get_channel_users(&channel).await;
        if !users.is_empty() {
            let names = users.join(" ");
            session
                .send_reply(IrcReply::NamesReply, vec!["=", &channel, &names])
                .await?;
        }
        session
            .send_reply(IrcReply::EndOfNames, vec![&channel, "End of /NAMES list"])
            .await?;
    }

    Ok(())
}

async fn handle_list(
    _server: &IrcServer,
    session: &mut IrcSession,
    _channels: Option<Vec<String>>,
) -> Result<()> {
    if !session.is_registered() {
        return session
            .send_error(IrcReply::NotRegistered, "You have not registered")
            .await;
    }

    // Simple implementation - just show joined channels
    session
        .send_reply(IrcReply::ListStart, vec!["Channel", "Users Name"])
        .await?;

    for channel in &session.channels {
        session
            .send_reply(IrcReply::List, vec![channel, "1", ""])
            .await?;
    }

    session
        .send_reply(IrcReply::ListEnd, vec!["End of /LIST"])
        .await
}

async fn handle_who(
    _server: &IrcServer,
    session: &mut IrcSession,
    mask: Option<String>,
) -> Result<()> {
    if !session.is_registered() {
        return session
            .send_error(IrcReply::NotRegistered, "You have not registered")
            .await;
    }

    // Simplified - just return end of WHO
    let name = mask.as_deref().unwrap_or("*");
    session
        .send_reply(IrcReply::EndOfWho, vec![name, "End of /WHO list"])
        .await
}

async fn handle_whois(
    _server: &IrcServer,
    session: &mut IrcSession,
    nicks: Vec<String>,
) -> Result<()> {
    if !session.is_registered() {
        return session
            .send_error(IrcReply::NotRegistered, "You have not registered")
            .await;
    }

    for nick in nicks {
        // Simplified - just show if it's the requesting user
        if nick == session.nick {
            session
                .send_reply(
                    IrcReply::WhoisUser,
                    vec![
                        &nick,
                        &session.user.as_ref().unwrap_or(&"*".to_string()),
                        "jig.local",
                        "*",
                        session.realname.as_ref().unwrap_or(&"".to_string()),
                    ],
                )
                .await?;

            if !session.channels.is_empty() {
                let channels = session.channels.join(" ");
                session
                    .send_reply(IrcReply::WhoisChannels, vec![&nick, &channels])
                    .await?;
            }
        } else {
            session
                .send_error(IrcReply::NoSuchNick, &format!("{} :No such nick", nick))
                .await?;
        }
    }

    session
        .send_reply(IrcReply::EndOfWhois, vec!["End of /WHOIS list"])
        .await
}

async fn handle_mode(
    session: &mut IrcSession,
    target: String,
    mode: Option<String>,
    _params: Vec<String>,
) -> Result<()> {
    if !session.is_registered() {
        return session
            .send_error(IrcReply::NotRegistered, "You have not registered")
            .await;
    }

    if mode.is_none() {
        // Query mode
        if target == session.nick {
            session.send_reply(IrcReply::UserModeIs, vec!["+i"]).await?;
        }
    }

    Ok(())
}

fn is_valid_nick(nick: &str) -> bool {
    if nick.is_empty() || nick.len() > 30 {
        return false;
    }

    // Must start with letter or special char
    let first = nick.chars().next().unwrap();
    if !first.is_alphabetic() && !"[]\\`_^{|}".contains(first) {
        return false;
    }

    // Rest can be alphanumeric or special
    nick.chars()
        .all(|c| c.is_alphanumeric() || "[]\\`_^{|}-".contains(c))
}
