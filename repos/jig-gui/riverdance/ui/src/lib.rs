//! This crate contains all shared UI for the workspace.

mod hero;
pub use hero::Hero;

mod navbar;
pub use navbar::Navbar;

mod echo;
pub use echo::Echo;

mod riverdance_layout;
pub use riverdance_layout::RiverdanceLayout;

mod chat_view;
pub use chat_view::ChatView;

mod state;
pub use state::{
    use_app_state, AppState, Channel, ChannelType, Message, MessageType, User, UserStatus,
};

#[cfg(test)]
mod tests {
    /// Naming each public export binds it, so this fails to compile if one is
    /// renamed or dropped. That is the whole of what this crate can check
    /// without a component-rendering harness — the previous `assert!(true)`
    /// bodies asserted nothing and tripped `clippy::assertions_on_constants`.
    #[test]
    fn every_public_export_is_reachable() {
        use super::{
            use_app_state, AppState, Channel, ChannelType, ChatView, Echo, Hero, Message,
            MessageType, Navbar, RiverdanceLayout, User, UserStatus,
        };

        let _ = (Hero, Navbar, Echo, RiverdanceLayout, ChatView, use_app_state);
        type _Types = (AppState, Channel, ChannelType, Message, MessageType, User, UserStatus);
    }
}
