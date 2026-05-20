//! IRC protocol types and definitions (RFC 1459)

use std::fmt;

/// IRC command types
#[derive(Debug, Clone, PartialEq)]
pub enum IrcCommand {
    // Connection registration
    Nick(String),
    User(String, String, String, String), // username, hostname, servername, realname
    Pass(String),
    Cap(String, Vec<String>), // subcommand (LS, REQ, END, etc), params

    // Channel operations
    Join(Vec<String>),                 // channels
    Part(Vec<String>, Option<String>), // channels, part message
    Topic(String, Option<String>),     // channel, topic
    Names(Vec<String>),                // channels
    List(Option<Vec<String>>),         // optional channels

    // Messages
    Privmsg(String, String), // target, message
    Notice(String, String),  // target, message

    // Server queries
    Who(Option<String>),                       // optional mask
    Whois(Vec<String>),                        // nicknames
    Mode(String, Option<String>, Vec<String>), // target, mode string, params

    // Control
    Quit(Option<String>),         // quit message
    Ping(String, Option<String>), // server1, server2
    Pong(String, Option<String>), // server1, server2

    // Unknown/unhandled
    Unknown(String, Vec<String>), // command, params
}

/// IRC numeric reply codes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IrcReply {
    // Standard replies
    Welcome = 1,
    YourHost = 2,
    Created = 3,
    MyInfo = 4,

    // Channel replies
    NoTopic = 331,
    Topic = 332,
    NamesReply = 353,
    EndOfNames = 366,

    // WHOIS replies
    WhoisUser = 311,
    WhoisServer = 312,
    WhoisIdle = 317,
    EndOfWhois = 318,
    WhoisChannels = 319,
    // WHO replies
    EndOfWho = 315,

    // User mode
    UserModeIs = 221,

    // List replies
    ListStart = 321,
    List = 322,
    ListEnd = 323,

    // Errors
    NoSuchNick = 401,
    NoSuchServer = 402,
    NoSuchChannel = 403,
    CannotSendToChan = 404,
    TooManyChannels = 405,
    NoRecipient = 411,
    NoTextToSend = 412,
    UnknownCommand = 421,
    NoMotd = 422,
    NoNicknameGiven = 431,
    ErroneousNickname = 432,
    NicknameInUse = 433,
    NickCollision = 436,
    NotOnChannel = 442,
    UserOnChannel = 443,
    NeedMoreParams = 461,
    AlreadyRegistered = 462,
    NotRegistered = 451,
    ChannelIsFull = 471,
    UnknownMode = 472,
    InviteOnlyChan = 473,
    BannedFromChan = 474,
    BadChannelKey = 475,
}

impl IrcReply {
    pub fn as_str(&self) -> &'static str {
        match self {
            IrcReply::Welcome => "001",
            IrcReply::YourHost => "002",
            IrcReply::Created => "003",
            IrcReply::MyInfo => "004",
            IrcReply::NoTopic => "331",
            IrcReply::Topic => "332",
            IrcReply::NamesReply => "353",
            IrcReply::EndOfNames => "366",
            IrcReply::WhoisUser => "311",
            IrcReply::WhoisServer => "312",
            IrcReply::WhoisIdle => "317",
            IrcReply::EndOfWhois => "318",
            IrcReply::WhoisChannels => "319",
            IrcReply::EndOfWho => "315",
            IrcReply::UserModeIs => "221",
            IrcReply::ListStart => "321",
            IrcReply::List => "322",
            IrcReply::ListEnd => "323",
            IrcReply::NoSuchNick => "401",
            IrcReply::NoSuchServer => "402",
            IrcReply::NoSuchChannel => "403",
            IrcReply::CannotSendToChan => "404",
            IrcReply::TooManyChannels => "405",
            IrcReply::NoRecipient => "411",
            IrcReply::NoTextToSend => "412",
            IrcReply::UnknownCommand => "421",
            IrcReply::NoMotd => "422",
            IrcReply::NoNicknameGiven => "431",
            IrcReply::ErroneousNickname => "432",
            IrcReply::NicknameInUse => "433",
            IrcReply::NickCollision => "436",
            IrcReply::NotOnChannel => "442",
            IrcReply::UserOnChannel => "443",
            IrcReply::NeedMoreParams => "461",
            IrcReply::AlreadyRegistered => "462",
            IrcReply::NotRegistered => "451",
            IrcReply::ChannelIsFull => "471",
            IrcReply::UnknownMode => "472",
            IrcReply::InviteOnlyChan => "473",
            IrcReply::BannedFromChan => "474",
            IrcReply::BadChannelKey => "475",
        }
    }
}

/// IRC message structure
#[derive(Debug, Clone)]
pub struct IrcMessage {
    pub prefix: Option<String>,
    pub command: IrcCommand,
}

impl IrcMessage {
    pub fn new(command: IrcCommand) -> Self {
        Self {
            prefix: None,
            command,
        }
    }

    pub fn with_prefix(mut self, prefix: String) -> Self {
        self.prefix = Some(prefix);
        self
    }
}

impl fmt::Display for IrcMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref prefix) = self.prefix {
            write!(f, ":{} ", prefix)?;
        }

        match &self.command {
            IrcCommand::Nick(nick) => write!(f, "NICK {}", nick),
            IrcCommand::User(user, host, server, real) => {
                write!(f, "USER {} {} {} :{}", user, host, server, real)
            }
            IrcCommand::Pass(pass) => write!(f, "PASS {}", pass),
            IrcCommand::Cap(subcmd, params) => {
                write!(f, "CAP {}", subcmd)?;
                if !params.is_empty() {
                    write!(f, " {}", params.join(" "))?;
                }
                Ok(())
            }
            IrcCommand::Join(channels) => write!(f, "JOIN {}", channels.join(",")),
            IrcCommand::Part(channels, msg) => {
                write!(f, "PART {}", channels.join(","))?;
                if let Some(msg) = msg {
                    write!(f, " :{}", msg)?;
                }
                Ok(())
            }
            IrcCommand::Privmsg(target, msg) => write!(f, "PRIVMSG {} :{}", target, msg),
            IrcCommand::Notice(target, msg) => write!(f, "NOTICE {} :{}", target, msg),
            IrcCommand::Quit(msg) => {
                write!(f, "QUIT")?;
                if let Some(msg) = msg {
                    write!(f, " :{}", msg)?;
                }
                Ok(())
            }
            IrcCommand::Ping(s1, s2) => {
                write!(f, "PING {}", s1)?;
                if let Some(s2) = s2 {
                    write!(f, " {}", s2)?;
                }
                Ok(())
            }
            IrcCommand::Pong(s1, s2) => {
                write!(f, "PONG {}", s1)?;
                if let Some(s2) = s2 {
                    write!(f, " {}", s2)?;
                }
                Ok(())
            }
            IrcCommand::Topic(channel, topic) => {
                write!(f, "TOPIC {}", channel)?;
                if let Some(topic) = topic {
                    write!(f, " :{}", topic)?;
                }
                Ok(())
            }
            IrcCommand::Names(channels) => write!(f, "NAMES {}", channels.join(",")),
            IrcCommand::List(channels) => {
                write!(f, "LIST")?;
                if let Some(channels) = channels {
                    write!(f, " {}", channels.join(","))?;
                }
                Ok(())
            }
            IrcCommand::Who(mask) => {
                write!(f, "WHO")?;
                if let Some(mask) = mask {
                    write!(f, " {}", mask)?;
                }
                Ok(())
            }
            IrcCommand::Whois(nicks) => write!(f, "WHOIS {}", nicks.join(",")),
            IrcCommand::Mode(target, mode, params) => {
                write!(f, "MODE {}", target)?;
                if let Some(mode) = mode {
                    write!(f, " {}", mode)?;
                    for param in params {
                        write!(f, " {}", param)?;
                    }
                }
                Ok(())
            }
            IrcCommand::Unknown(cmd, params) => {
                write!(f, "{}", cmd)?;
                for param in params {
                    write!(f, " {}", param)?;
                }
                Ok(())
            }
        }
    }
}
