use dioxus::prelude::*;

use crate::use_app_state;

#[component]
pub fn RiverdanceLayout(children: Element) -> Element {
    rsx! {
        div { class: "riverdance-layout",
            LeftNavigation {}
            Sidebar {}
            div { class: "riverdance-main",
                Header {}
                div { class: "riverdance-content",
                    {children}
                }
            }
        }
    }
}

#[component]
fn LeftNavigation() -> Element {
    let navigator = use_navigator();
    let mut active_route = use_signal(|| String::from("/"));

    rsx! {
        div { class: "riverdance-left-nav",
            // Chat icon
            div {
                class: if active_route() == "/" { "nav-icon active" } else { "nav-icon" },
                title: "Chat",
                onclick: move |_| {
                    navigator.push("/");
                    active_route.set("/".to_string());
                },
                "💬"
            }

            // DMs icon
            div {
                class: if active_route() == "/dms" { "nav-icon active" } else { "nav-icon" },
                title: "Direct Messages",
                onclick: move |_| {
                    navigator.push("/dms");
                    active_route.set("/dms".to_string());
                },
                "👤"
            }

            // Threads icon
            div {
                class: if active_route() == "/threads" { "nav-icon active" } else { "nav-icon" },
                title: "Threads",
                onclick: move |_| {
                    navigator.push("/threads");
                    active_route.set("/threads".to_string());
                },
                "🧵"
            }

            // Saved items icon
            div {
                class: if active_route() == "/saved" { "nav-icon active" } else { "nav-icon" },
                title: "Saved Items",
                onclick: move |_| {
                    navigator.push("/saved");
                    active_route.set("/saved".to_string());
                },
                "⭐"
            }

            // Drafts icon
            div {
                class: if active_route() == "/drafts" { "nav-icon active" } else { "nav-icon" },
                title: "Drafts",
                onclick: move |_| {
                    navigator.push("/drafts");
                    active_route.set("/drafts".to_string());
                },
                "📝"
            }

            // Notifications icon
            div {
                class: if active_route() == "/notifications" { "nav-icon active" } else { "nav-icon" },
                title: "Notifications",
                onclick: move |_| {
                    navigator.push("/notifications");
                    active_route.set("/notifications".to_string());
                },
                "🔔"
            }

            // Settings icon
            div {
                class: if active_route() == "/settings" { "nav-icon active" } else { "nav-icon" },
                title: "Settings",
                onclick: move |_| {
                    navigator.push("/settings");
                    active_route.set("/settings".to_string());
                },
                "⚙️"
            }

            // Spacer
            div { style: "flex: 1;" }

            // Status indicators
            div {
                class: "nav-icon",
                title: "Connection Status: Connected",
                style: "background-color: #10b981;",
                "📶"
            }

            div {
                class: "nav-icon",
                title: "Sync Status: Synced",
                style: "background-color: #10b981;",
                "🔄"
            }
        }
    }
}

#[component]
fn Sidebar() -> Element {
    let navigator = use_navigator();
    let mut app_state = use_app_state();

    rsx! {
        div { class: "riverdance-sidebar",
            // Organization switcher
            div { class: "org-switcher",
                div { class: "dropdown-button",
                    div {
                        div { style: "font-weight: 600;", "{app_state.read().current_organization.name}" }
                        div { style: "font-size: 12px; color: #737373;", "{app_state.read().current_organization.domain}" }
                    }
                    div { "⌄" }
                }
            }

            // Profile switcher
            div { class: "profile-switcher",
                div { class: "dropdown-button",
                    div { style: "display: flex; align-items: center; gap: 8px;",
                        div { style: "position: relative;",
                            div {
                                style: "width: 24px; height: 24px; border-radius: 50%; background-color: #3b82f6; display: flex; align-items: center; justify-content: center; color: white; font-size: 12px; font-weight: 600;",
                                "{app_state.read().current_user.avatar}"
                            }
                            div {
                                style: format!(
                                    "position: absolute; bottom: -1px; right: -1px; width: 8px; height: 8px; border-radius: 50%; background-color: {}; border: 2px solid white;",
                                    app_state.read().get_status_color()
                                ),
                            }
                        }
                        div {
                            div { style: "font-weight: 500;", "{app_state.read().current_user.name}" }
                            div {
                                style: "font-size: 12px; color: #737373;",
                                "{app_state.read().current_user.handle} • {app_state.read().get_status_text()}"
                            }
                        }
                    }
                    div { "⌄" }
                }
            }

            // Search bar
            div { style: "padding: 12px 16px;",
                input {
                    style: "width: 100%; padding: 8px 12px; border: 1px solid #d4d4d4; border-radius: 6px; font-size: 14px;",
                    placeholder: "Search channels, messages...",
                }
            }

            // Channels section
            div { class: "sidebar-section",
                div { class: "section-header",
                    span { "Channels" }
                    div { style: "display: flex; gap: 4px;",
                        button {
                            style: "width: 20px; height: 20px; border: none; background-color: #e5e5e5; border-radius: 4px; display: flex; align-items: center; justify-content: center; cursor: pointer;",
                            title: "Add channel or section",
                            "+"
                        }
                        button {
                            style: "width: 20px; height: 20px; border: none; background-color: #e5e5e5; border-radius: 4px; display: flex; align-items: center; justify-content: center; cursor: pointer;",
                            title: "Channel settings",
                            "⚙"
                        }
                    }
                }

                // Engineering section
                div { style: "margin-bottom: 12px;",
                    div { style: "font-size: 13px; color: #737373; margin-bottom: 4px; display: flex; align-items: center;",
                        span { style: "margin-right: 4px;", "🔽" }
                        span { "ENGINEERING" }
                    }

                    div { class: "channel-list",
                        div {
                            class: if app_state.read().current_channel_id == "general" { "channel-item active" } else { "channel-item" },
                            onclick: move |_| {
                                navigator.push("/");
                                app_state.write().switch_channel("general");
                            },
                            span { class: "channel-icon", "#" }
                            span { class: "channel-name", "general" }
                            if let Some(channel) = app_state.read().channels.get("general") {
                                if channel.unread_count > 0 {
                                    span { class: "channel-badge", "{channel.unread_count}" }
                                }
                            }
                        }
                        div {
                            class: if app_state.read().current_channel_id == "backend" { "channel-item active" } else { "channel-item" },
                            onclick: move |_| {
                                app_state.write().switch_channel("backend");
                            },
                            span { class: "channel-icon", "#" }
                            span { class: "channel-name", "backend" }
                            if let Some(channel) = app_state.read().channels.get("backend") {
                                if channel.unread_count > 0 {
                                    span { class: "channel-badge", "{channel.unread_count}" }
                                }
                            }
                        }
                        div {
                            class: if app_state.read().current_channel_id == "security" { "channel-item active" } else { "channel-item" },
                            onclick: move |_| {
                                app_state.write().switch_channel("security");
                            },
                            span { class: "channel-icon", "🔒" }
                            span { class: "channel-name", "security" }
                        }
                        div {
                            class: if app_state.read().current_channel_id == "deployment-bot" { "channel-item active" } else { "channel-item" },
                            onclick: move |_| {
                                app_state.write().switch_channel("deployment-bot");
                            },
                            span { class: "channel-icon", "🤖" }
                            span { class: "channel-name", "deployment-bot" }
                            if let Some(channel) = app_state.read().channels.get("deployment-bot") {
                                if channel.unread_count > 0 {
                                    span { class: "channel-badge", "{channel.unread_count}" }
                                }
                            }
                        }
                    }
                }

                // Product section
                div { style: "margin-bottom: 12px;",
                    div { style: "font-size: 13px; color: #737373; margin-bottom: 4px; display: flex; align-items: center;",
                        span { style: "margin-right: 4px;", "🔽" }
                        span { "PRODUCT" }
                    }

                    div { class: "channel-list",
                        div {
                            class: if app_state.read().current_channel_id == "roadmap" { "channel-item active" } else { "channel-item" },
                            onclick: move |_| {
                                app_state.write().switch_channel("roadmap");
                            },
                            span { class: "channel-icon", "🔒" }
                            span { class: "channel-name", "roadmap" }
                        }
                        div {
                            class: if app_state.read().current_channel_id == "user-feedback" { "channel-item active" } else { "channel-item" },
                            onclick: move |_| {
                                app_state.write().switch_channel("user-feedback");
                            },
                            span { class: "channel-icon", "#" }
                            span { class: "channel-name", "user-feedback" }
                            if let Some(channel) = app_state.read().channels.get("user-feedback") {
                                if channel.unread_count > 0 {
                                    span { class: "channel-badge", "{channel.unread_count}" }
                                }
                            }
                        }
                    }
                }

                // Direct Messages section
                div {
                    div { style: "font-size: 13px; color: #737373; margin-bottom: 4px; display: flex; align-items: center;",
                        span { style: "margin-right: 4px;", "🔽" }
                        span { "DIRECT MESSAGES" }
                    }

                    div { class: "channel-list",
                        div {
                            class: if app_state.read().current_channel_id == "dm-alice" { "channel-item active" } else { "channel-item" },
                            onclick: move |_| {
                                navigator.push("/dms");
                                app_state.write().switch_channel("dm-alice");
                            },
                            span { class: "channel-icon", "👤" }
                            span { class: "channel-name", "alice.dev" }
                        }
                        div {
                            class: if app_state.read().current_channel_id == "dm-bob" { "channel-item active" } else { "channel-item" },
                            onclick: move |_| {
                                navigator.push("/dms");
                                app_state.write().switch_channel("dm-bob");
                            },
                            span { class: "channel-icon", "👤" }
                            span { class: "channel-name", "bob.pm" }
                            if let Some(channel) = app_state.read().channels.get("dm-bob") {
                                if channel.unread_count > 0 {
                                    span { class: "channel-badge", "{channel.unread_count}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn Header() -> Element {
    let app_state = use_app_state();

    rsx! {
        div { class: "riverdance-header",
            div { style: "display: flex; align-items: center; gap: 12px;",
                if let Some(channel) = app_state.read().get_current_channel() {
                    span {
                        style: "font-size: 20px;",
                        match channel.channel_type {
                            crate::ChannelType::Public => "#",
                            crate::ChannelType::Private => "🔒",
                            crate::ChannelType::DirectMessage => "👤",
                            crate::ChannelType::Bot => "🤖",
                        }
                    }
                    div {
                        div { style: "font-weight: 600; font-size: 16px;", "{channel.name}" }
                        div { style: "font-size: 14px; color: #737373;", "{channel.description} • {channel.member_count} members" }
                    }
                } else {
                    span { style: "font-size: 20px;", "#" }
                    div {
                        div { style: "font-weight: 600; font-size: 16px;", "No channel selected" }
                        div { style: "font-size: 14px; color: #737373;", "Select a channel from the sidebar" }
                    }
                }
            }

            div { style: "display: flex; align-items: center; gap: 8px;",
                button {
                    style: "padding: 6px 12px; border: 1px solid #d4d4d4; background-color: #ffffff; border-radius: 6px; cursor: pointer;",
                    "Search in channel"
                }

                div {
                    style: format!(
                        "width: 32px; height: 32px; border-radius: 50%; background-color: {}; display: flex; align-items: center; justify-content: center; color: white; font-size: 14px; font-weight: 600; cursor: pointer;",
                        app_state.read().get_status_color()
                    ),
                    title: "{app_state.read().current_user.name} - {app_state.read().get_status_text()}",
                    "{app_state.read().current_user.avatar}"
                }
            }
        }
    }
}
