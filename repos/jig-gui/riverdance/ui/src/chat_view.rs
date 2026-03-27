use dioxus::prelude::*;

use crate::{use_app_state, MessageType};

#[component]
pub fn ChatView() -> Element {
    let app_state = use_app_state();
    rsx! {
        div { style: "display: flex; flex-direction: column; height: 100%;",
            // Messages area
            div { style: "flex: 1; padding: 20px; overflow-y: auto;",
                for message in app_state.read().get_channel_messages(&app_state.read().current_channel_id) {
                    if let Some(user) = app_state.read().get_user(&message.user_id) {
                        MessageBlock {
                            key: "{message.id}",
                            message: message.clone(),
                            user: user.clone(),
                        }
                    }
                }
            }

            // Message input area
            div { style: "border-top: 1px solid #e5e5e5; padding: 16px;",
                div { style: "display: flex; align-items: center; gap: 8px; margin-bottom: 8px;",
                    button {
                        style: "padding: 6px; border: none; background: none; cursor: pointer; font-weight: 600;",
                        "B"
                    }
                    button {
                        style: "padding: 6px; border: none; background: none; cursor: pointer; font-style: italic;",
                        "I"
                    }
                    button {
                        style: "padding: 6px; border: none; background: none; cursor: pointer;",
                        "🔗"
                    }
                    button {
                        style: "padding: 6px; border: none; background: none; cursor: pointer;",
                        "<>"
                    }

                    div { style: "flex: 1;" }

                    button {
                        style: "padding: 6px; border: none; background: none; cursor: pointer;",
                        "📎"
                    }
                    button {
                        style: "padding: 6px; border: none; background: none; cursor: pointer;",
                        "😊"
                    }
                }

                div { style: "display: flex; align-items: flex-end; gap: 12px;",
                    textarea {
                        style: "flex: 1; padding: 12px; border: 1px solid #d4d4d4; border-radius: 8px; resize: none; min-height: 44px; font-family: inherit;",
                        placeholder: "Type a message...",
                        rows: "1"
                    }

                    button {
                        style: "padding: 10px 16px; background-color: #737373; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 500;",
                        "Send"
                    }
                }
            }
        }
    }
}

#[component]
fn MessageBlock(message: crate::Message, user: crate::User) -> Element {
    let is_bot = message.message_type == MessageType::Bot;
    rsx! {
        div {
            class: "message-block",
            style: "margin-bottom: 16px; display: flex; gap: 12px;",
            // Avatar
            div {
                style: format!(
                    "width: 36px; height: 36px; border-radius: 50%; {} display: flex; align-items: center; justify-content: center; color: white; font-weight: 600; font-size: 14px; flex-shrink: 0;",
                    if is_bot { "background-color: #f59e0b;" } else { "background-color: #3b82f6;" }
                ),
                "{user.avatar}"
            }

            // Message content
            div { style: "flex: 1; min-width: 0;",
                // Header
                div { style: "display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px;",
                    span { style: "font-weight: 600; color: #171717;", "{user.name}" }
                    if is_bot {
                        span {
                            style: "background-color: #f59e0b; color: white; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 500;",
                            "BOT"
                        }
                    }
                    span { style: "font-size: 13px; color: #737373;", "{message.timestamp}" }
                }

                // Message text
                div { style: "color: #171717; line-height: 1.5;",
                    "{message.content}"
                }

                // Message actions (shown on hover)
                div { style: "margin-top: 8px; display: flex; gap: 4px;",
                    button {
                        style: "padding: 4px 8px; border: none; background-color: #f5f5f5; border-radius: 4px; cursor: pointer; font-size: 12px;",
                        title: "React with thumbs up",
                        "👍"
                    }
                    button {
                        style: "padding: 4px 8px; border: none; background-color: #f5f5f5; border-radius: 4px; cursor: pointer; font-size: 12px;",
                        title: "React with rocket",
                        "🚀"
                    }
                    button {
                        style: "padding: 4px 8px; border: none; background-color: #f5f5f5; border-radius: 4px; cursor: pointer; font-size: 12px;",
                        title: "React with fire",
                        "🔥"
                    }
                    button {
                        style: "padding: 4px 8px; border: none; background-color: #f5f5f5; border-radius: 4px; cursor: pointer; font-size: 12px;",
                        title: "Reply in thread",
                        "💬"
                    }
                }

                // Existing reactions
                if !message.reactions.is_empty() {
                    div { style: "margin-top: 6px; display: flex; gap: 4px;",
                        for reaction in &message.reactions {
                            div {
                                style: "display: flex; align-items: center; gap: 2px; padding: 2px 6px; background-color: #eff6ff; border: 1px solid #bfdbfe; border-radius: 12px; font-size: 12px;",
                                span { "{reaction.emoji}" }
                                span { style: "color: #3b82f6; font-weight: 500;", "{reaction.count}" }
                            }
                        }
                    }
                }

                // Thread replies indicator
                if !message.thread_replies.is_empty() {
                    div { style: "margin-top: 8px; font-size: 13px; color: #3b82f6; cursor: pointer;",
                        "{message.thread_replies.len()} replies"
                    }
                }
            }
        }
    }
}
