//! IRC message parser

use super::protocol::{IrcCommand, IrcMessage};
use crate::error::{Result, ServerError};

/// Parse IRC message from raw line
pub fn parse_irc_message(line: &str) -> Result<IrcMessage> {
    let line = line.trim_end_matches(&['\r', '\n'][..]);

    if line.is_empty() {
        return Err(ServerError::IrcProtocol("Empty IRC message".to_string()));
    }

    // Extract optional prefix
    let (prefix_opt, rest) = if let Some(rest) = line.strip_prefix(':') {
        let mut iter = rest.splitn(2, ' ');
        let prefix = iter
            .next()
            .ok_or_else(|| ServerError::IrcProtocol("Missing prefix".to_string()))?;
        let after = iter
            .next()
            .ok_or_else(|| ServerError::IrcProtocol("Missing command after prefix".to_string()))?;
        (Some(prefix.to_string()), after)
    } else {
        (None, line)
    };

    // Split command and parameters
    let mut iter = rest.splitn(2, ' ');
    let command_str = iter.next().unwrap();
    let params = iter.next().unwrap_or("");

    let command = parse_command(command_str, params)?;
    Ok(IrcMessage {
        prefix: prefix_opt,
        command,
    })
}

fn parse_command(cmd: &str, params: &str) -> Result<IrcCommand> {
    let cmd = cmd.to_uppercase();

    match cmd.as_str() {
        "NICK" => {
            if params.is_empty() {
                return Err(ServerError::IrcProtocol(
                    "NICK requires a nickname".to_string(),
                ));
            }
            let nick = params.trim_start_matches(':');
            Ok(IrcCommand::Nick(nick.to_string()))
        }

        "USER" => {
            let parts: Vec<&str> = params.splitn(4, ' ').collect();
            if parts.len() < 4 {
                return Err(ServerError::IrcProtocol(
                    "USER requires 4 parameters".to_string(),
                ));
            }
            let realname = parts[3].trim_start_matches(':');
            Ok(IrcCommand::User(
                parts[0].to_string(),
                parts[1].to_string(),
                parts[2].to_string(),
                realname.to_string(),
            ))
        }

        "PASS" => {
            if params.is_empty() {
                return Err(ServerError::IrcProtocol(
                    "PASS requires a password".to_string(),
                ));
            }
            Ok(IrcCommand::Pass(params.to_string()))
        }

        "CAP" => {
            let parts: Vec<&str> = params.splitn(2, ' ').collect();
            if parts.is_empty() {
                return Err(ServerError::IrcProtocol(
                    "CAP requires subcommand".to_string(),
                ));
            }
            let subcommand = parts[0].to_uppercase();
            let cap_params = if parts.len() > 1 {
                parts[1].split_whitespace().map(|s| s.to_string()).collect()
            } else {
                vec![]
            };
            Ok(IrcCommand::Cap(subcommand, cap_params))
        }

        "JOIN" => {
            if params.is_empty() {
                return Err(ServerError::IrcProtocol(
                    "JOIN requires channels".to_string(),
                ));
            }
            let channels: Vec<String> = params
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            Ok(IrcCommand::Join(channels))
        }

        "PART" => {
            let (channels_str, msg) = if let Some(colon_pos) = params.find(" :") {
                let (ch, m) = params.split_at(colon_pos);
                (ch, Some(m[2..].to_string()))
            } else {
                (params, None)
            };

            let channels: Vec<String> = channels_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if channels.is_empty() {
                return Err(ServerError::IrcProtocol(
                    "PART requires channels".to_string(),
                ));
            }

            Ok(IrcCommand::Part(channels, msg))
        }

        "PRIVMSG" => {
            let (target, message) = parse_target_and_message(params)?;
            Ok(IrcCommand::Privmsg(target, message))
        }

        "NOTICE" => {
            let (target, message) = parse_target_and_message(params)?;
            Ok(IrcCommand::Notice(target, message))
        }

        "QUIT" => {
            let msg = if let Some(rest) = params.strip_prefix(':') {
                Some(rest.to_string())
            } else if !params.is_empty() {
                Some(params.to_string())
            } else {
                None
            };
            Ok(IrcCommand::Quit(msg))
        }

        "PING" => {
            let parts: Vec<&str> = params.split_whitespace().collect();
            if parts.is_empty() {
                return Err(ServerError::IrcProtocol(
                    "PING requires at least one parameter".to_string(),
                ));
            }
            let server1 = parts[0].to_string();
            let server2 = parts.get(1).map(|s| s.to_string());
            Ok(IrcCommand::Ping(server1, server2))
        }

        "PONG" => {
            let parts: Vec<&str> = params.split_whitespace().collect();
            if parts.is_empty() {
                return Err(ServerError::IrcProtocol(
                    "PONG requires at least one parameter".to_string(),
                ));
            }
            let server1 = parts[0].to_string();
            let server2 = parts.get(1).map(|s| s.to_string());
            Ok(IrcCommand::Pong(server1, server2))
        }

        "TOPIC" => {
            if params.is_empty() {
                return Err(ServerError::IrcProtocol(
                    "TOPIC requires a channel".to_string(),
                ));
            }

            let (channel, topic) = if let Some(colon_pos) = params.find(" :") {
                let (ch, t) = params.split_at(colon_pos);
                (ch.to_string(), Some(t[2..].to_string()))
            } else {
                let parts: Vec<&str> = params.splitn(2, ' ').collect();
                (parts[0].to_string(), parts.get(1).map(|s| s.to_string()))
            };

            Ok(IrcCommand::Topic(channel, topic))
        }

        "NAMES" => {
            let channels = if params.is_empty() {
                vec![]
            } else {
                params
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            };
            Ok(IrcCommand::Names(channels))
        }

        "LIST" => {
            let channels = if params.is_empty() {
                None
            } else {
                Some(
                    params
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                )
            };
            Ok(IrcCommand::List(channels))
        }

        "WHO" => {
            let mask = if params.is_empty() {
                None
            } else {
                Some(params.to_string())
            };
            Ok(IrcCommand::Who(mask))
        }

        "WHOIS" => {
            if params.is_empty() {
                return Err(ServerError::IrcProtocol(
                    "WHOIS requires nicknames".to_string(),
                ));
            }
            let nicks: Vec<String> = params
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            Ok(IrcCommand::Whois(nicks))
        }

        "MODE" => {
            let parts: Vec<&str> = params.split_whitespace().collect();
            if parts.is_empty() {
                return Err(ServerError::IrcProtocol(
                    "MODE requires a target".to_string(),
                ));
            }

            let target = parts[0].to_string();
            let mode = parts.get(1).map(|s| s.to_string());
            let params = parts.iter().skip(2).map(|s| s.to_string()).collect();

            Ok(IrcCommand::Mode(target, mode, params))
        }

        _ => {
            let params: Vec<String> = if params.is_empty() {
                vec![]
            } else {
                params.split_whitespace().map(|s| s.to_string()).collect()
            };
            Ok(IrcCommand::Unknown(cmd, params))
        }
    }
}

fn parse_target_and_message(params: &str) -> Result<(String, String)> {
    if let Some(colon_pos) = params.find(" :") {
        let (target, msg) = params.split_at(colon_pos);
        Ok((target.to_string(), msg[2..].to_string()))
    } else {
        let parts: Vec<&str> = params.splitn(2, ' ').collect();
        if parts.len() < 2 {
            return Err(ServerError::IrcProtocol(
                "Message requires target and text".to_string(),
            ));
        }
        Ok((parts[0].to_string(), parts[1].to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nick() {
        let msg = parse_irc_message("NICK alice").unwrap();
        assert_eq!(msg.command, IrcCommand::Nick("alice".to_string()));
    }

    #[test]
    fn test_parse_privmsg() {
        let msg = parse_irc_message("PRIVMSG #channel :Hello, world!").unwrap();
        match msg.command {
            IrcCommand::Privmsg(target, text) => {
                assert_eq!(target, "#channel");
                assert_eq!(text, "Hello, world!");
            }
            _ => panic!("Expected PRIVMSG"),
        }
    }

    #[test]
    fn test_parse_with_prefix() {
        let msg = parse_irc_message(":alice!user@host PRIVMSG #channel :Hi").unwrap();
        assert_eq!(msg.prefix, Some("alice!user@host".to_string()));
        match msg.command {
            IrcCommand::Privmsg(target, text) => {
                assert_eq!(target, "#channel");
                assert_eq!(text, "Hi");
            }
            _ => panic!("Expected PRIVMSG"),
        }
    }
}
