//! Jig Email Bridge Library
//!
//! Provides email bridge functionality for the Jig protocol,
//! bridging traditional email (SMTP/IMAP) with block-based messaging.

pub mod config;
pub mod discovery;
pub mod formatter;
pub mod parser;
pub mod router;
pub mod types;

// Re-export commonly used types
pub use config::{Config, FormattingConfig};
pub use discovery::{JigDiscovery, JigEndpoint};
pub use router::{MessageRouter, RouteDecision};
pub use types::{EmailMessage, ThreadInfo};
