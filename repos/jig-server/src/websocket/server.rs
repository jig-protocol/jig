use std::net::SocketAddr;
use std::sync::Arc;

use axum::{Router, extract::ws::WebSocketUpgrade, routing::get};
use tower_http::trace::TraceLayer;

use crate::config::WebSocketConfig;
use crate::error::{Result, ServerError};

use super::handler::ws_handler;
use super::state::SharedState;

/// WebSocket server implementation
pub struct WebSocketServer {
    config: WebSocketConfig,
    state: SharedState,
}

impl WebSocketServer {
    /// Create a new WebSocket server
    pub fn new(config: WebSocketConfig) -> Self {
        Self {
            config,
            state: Arc::new(super::state::State::default()),
        }
    }

    /// Start the WebSocket server
    pub async fn start(self: Arc<Self>, bind: String) -> Result<()> {
        let state = self.state.clone();
        let app = Router::new()
            .route(
                "/ws",
                get(move |ws: WebSocketUpgrade| async move {
                    ws.on_upgrade(|socket| ws_handler(socket, state))
                }),
            )
            .layer(TraceLayer::new_for_http());

        let addr: SocketAddr = format!("{}:{}", bind, self.config.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| ServerError::Server(e.to_string()))?;

        let listener = tokio::net::TcpListener::bind(addr).await
            .map_err(|e| ServerError::Server(e.to_string()))?;
        
        axum::serve(listener, app)
            .await
            .map_err(|e| ServerError::Server(e.to_string()))
    }
}
