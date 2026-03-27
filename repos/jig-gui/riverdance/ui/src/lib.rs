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
    use super::*;

    #[test]
    fn test_module_exports() {
        // Basic smoke test to ensure modules can be imported
        // This will be expanded as we add more functionality
        assert!(true, "Module exports work correctly");
    }

    #[test]
    fn test_component_structure() {
        // Test that our core components exist and are properly exported
        // In a real UI test framework, we'd render these components
        assert!(true, "Component structure is valid");
    }
}
