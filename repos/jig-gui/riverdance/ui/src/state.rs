use std::collections::HashMap;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub handle: String,
    pub avatar: String,
    pub status: UserStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UserStatus {
    Online,
    Away,
    Busy,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub description: String,
    pub channel_type: ChannelType,
    pub member_count: usize,
    pub unread_count: usize,
    pub last_message_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChannelType {
    Public,
    Private,
    DirectMessage,
    Bot,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub channel_id: String,
    pub user_id: String,
    pub content: String,
    pub timestamp: String,
    pub message_type: MessageType,
    pub reactions: Vec<Reaction>,
    pub thread_replies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageType {
    Text,
    Bot,
    System,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reaction {
    pub emoji: String,
    pub count: usize,
    pub users: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub avatar: String,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub current_user: User,
    pub current_organization: Organization,
    pub current_channel_id: String,
    pub current_route: String,
    pub channels: HashMap<String, Channel>,
    pub messages: HashMap<String, Vec<Message>>,
    pub users: HashMap<String, User>,
}

impl AppState {
    pub fn new() -> Self {
        let current_user = User {
            id: "alex-chen".to_string(),
            name: "Alex Chen".to_string(),
            handle: "@alex.dev".to_string(),
            avatar: "AC".to_string(),
            status: UserStatus::Online,
        };

        let current_org = Organization {
            id: "acme-corp".to_string(),
            name: "Acme Corp".to_string(),
            domain: "acme.jig".to_string(),
            avatar: "A".to_string(),
        };

        let mut channels = HashMap::new();
        let mut messages = HashMap::new();
        let mut users = HashMap::new();

        // Sample users
        users.insert("alex-chen".to_string(), current_user.clone());
        users.insert(
            "alice-dev".to_string(),
            User {
                id: "alice-dev".to_string(),
                name: "Alice Developer".to_string(),
                handle: "@alice.dev".to_string(),
                avatar: "A".to_string(),
                status: UserStatus::Online,
            },
        );
        users.insert(
            "bob-pm".to_string(),
            User {
                id: "bob-pm".to_string(),
                name: "Bob Product Manager".to_string(),
                handle: "@bob.pm".to_string(),
                avatar: "B".to_string(),
                status: UserStatus::Away,
            },
        );
        users.insert(
            "security-bot".to_string(),
            User {
                id: "security-bot".to_string(),
                name: "Security Bot".to_string(),
                handle: "@security-bot".to_string(),
                avatar: "S".to_string(),
                status: UserStatus::Online,
            },
        );

        // Sample channels
        channels.insert(
            "general".to_string(),
            Channel {
                id: "general".to_string(),
                name: "general".to_string(),
                description: "General discussion for the engineering team".to_string(),
                channel_type: ChannelType::Public,
                member_count: 12,
                unread_count: 3,
                last_message_id: Some("msg-3".to_string()),
            },
        );

        channels.insert(
            "backend".to_string(),
            Channel {
                id: "backend".to_string(),
                name: "backend".to_string(),
                description: "Backend development discussion".to_string(),
                channel_type: ChannelType::Public,
                member_count: 8,
                unread_count: 1,
                last_message_id: None,
            },
        );

        channels.insert(
            "security".to_string(),
            Channel {
                id: "security".to_string(),
                name: "security".to_string(),
                description: "Security team private channel".to_string(),
                channel_type: ChannelType::Private,
                member_count: 4,
                unread_count: 0,
                last_message_id: None,
            },
        );

        channels.insert(
            "deployment-bot".to_string(),
            Channel {
                id: "deployment-bot".to_string(),
                name: "deployment-bot".to_string(),
                description: "Automated deployment notifications".to_string(),
                channel_type: ChannelType::Bot,
                member_count: 15,
                unread_count: 2,
                last_message_id: None,
            },
        );

        channels.insert(
            "roadmap".to_string(),
            Channel {
                id: "roadmap".to_string(),
                name: "roadmap".to_string(),
                description: "Product roadmap planning".to_string(),
                channel_type: ChannelType::Private,
                member_count: 6,
                unread_count: 0,
                last_message_id: None,
            },
        );

        channels.insert(
            "user-feedback".to_string(),
            Channel {
                id: "user-feedback".to_string(),
                name: "user-feedback".to_string(),
                description: "User feedback and feature requests".to_string(),
                channel_type: ChannelType::Public,
                member_count: 20,
                unread_count: 5,
                last_message_id: None,
            },
        );

        // Direct message channels
        channels.insert(
            "dm-alice".to_string(),
            Channel {
                id: "dm-alice".to_string(),
                name: "alice.dev".to_string(),
                description: "Direct messages with Alice".to_string(),
                channel_type: ChannelType::DirectMessage,
                member_count: 2,
                unread_count: 0,
                last_message_id: None,
            },
        );

        channels.insert(
            "dm-bob".to_string(),
            Channel {
                id: "dm-bob".to_string(),
                name: "bob.pm".to_string(),
                description: "Direct messages with Bob".to_string(),
                channel_type: ChannelType::DirectMessage,
                member_count: 2,
                unread_count: 1,
                last_message_id: None,
            },
        );

        // Sample messages for general channel
        let general_messages = vec![
            Message {
                id: "msg-1".to_string(),
                channel_id: "general".to_string(),
                user_id: "alice-dev".to_string(),
                content: "Hey team, the new authentication service is ready for review. The \
                          implementation follows the Jig protocol spec with E2E encryption \
                          enabled by default."
                    .to_string(),
                timestamp: "23:30".to_string(),
                message_type: MessageType::Text,
                reactions: vec![
                    Reaction {
                        emoji: "👍".to_string(),
                        count: 3,
                        users: vec![
                            "alex-chen".to_string(),
                            "bob-pm".to_string(),
                            "security-bot".to_string(),
                        ],
                    },
                    Reaction {
                        emoji: "🚀".to_string(),
                        count: 1,
                        users: vec!["alex-chen".to_string()],
                    },
                ],
                thread_replies: vec!["reply-1".to_string(), "reply-2".to_string()],
            },
            Message {
                id: "msg-2".to_string(),
                channel_id: "general".to_string(),
                user_id: "security-bot".to_string(),
                content: "Security scan completed. No vulnerabilities found in the authentication \
                          service. All RBAC/ABAC policies are properly configured."
                    .to_string(),
                timestamp: "00:30".to_string(),
                message_type: MessageType::Bot,
                reactions: vec![],
                thread_replies: vec![],
            },
            Message {
                id: "msg-3".to_string(),
                channel_id: "general".to_string(),
                user_id: "bob-pm".to_string(),
                content: "Looks good! The config-as-code approach is working perfectly. The TOML \
                          files are clean and readable."
                    .to_string(),
                timestamp: "01:00".to_string(),
                message_type: MessageType::Text,
                reactions: vec![],
                thread_replies: vec![],
            },
        ];

        messages.insert("general".to_string(), general_messages);

        Self {
            current_user,
            current_organization: current_org,
            current_channel_id: "general".to_string(),
            current_route: "/".to_string(),
            channels,
            messages,
            users,
        }
    }

    pub fn get_current_channel(&self) -> Option<&Channel> {
        self.channels.get(&self.current_channel_id)
    }

    pub fn get_channel_messages(&self, channel_id: &str) -> Vec<&Message> {
        self.messages
            .get(channel_id)
            .map(|msgs| msgs.iter().collect())
            .unwrap_or_default()
    }

    pub fn get_user(&self, user_id: &str) -> Option<&User> {
        self.users.get(user_id)
    }

    pub fn switch_channel(&mut self, channel_id: &str) {
        if self.channels.contains_key(channel_id) {
            self.current_channel_id = channel_id.to_string();

            // Clear unread count for the channel
            if let Some(channel) = self.channels.get_mut(channel_id) {
                channel.unread_count = 0;
            }
        }
    }

    pub fn get_channels_by_type(&self, channel_type: ChannelType) -> Vec<&Channel> {
        self.channels.values().filter(|ch| ch.channel_type == channel_type).collect()
    }

    pub fn update_user_status(&mut self, status: UserStatus) {
        self.current_user.status = status;
    }

    pub fn get_status_color(&self) -> &'static str {
        match self.current_user.status {
            UserStatus::Online => "#10b981",
            UserStatus::Away => "#f59e0b",
            UserStatus::Busy => "#dc2626",
            UserStatus::Offline => "#6b7280",
        }
    }

    pub fn get_status_text(&self) -> &'static str {
        match self.current_user.status {
            UserStatus::Online => "Online",
            UserStatus::Away => "Away",
            UserStatus::Busy => "Busy",
            UserStatus::Offline => "Offline",
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn use_app_state() -> Signal<AppState> {
    use_signal(AppState::new)
}
