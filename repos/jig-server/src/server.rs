//! Main Jig server orchestration.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;

use crate::config::ServerConfig;
use crate::error::{Result, ServerError};
use crate::handler::{self, AppState};
use crate::runtime::BlockRuntime;
use crate::storage::SqliteBlockStore;

pub struct JigServer {
    config: ServerConfig,
    store: Arc<SqliteBlockStore>,
    runtime: Arc<BlockRuntime>,
}

impl JigServer {
    pub fn new(config: ServerConfig) -> Result<Self> {
        let store = Arc::new(SqliteBlockStore::new(&config.database_path)?);
        store.health_check()?;

        let runtime = Arc::new(BlockRuntime::new(config.execution_config())?);

        Ok(Self {
            config,
            store,
            runtime,
        })
    }

    pub async fn start(&self) -> Result<()> {
        tracing::info!(
            "Starting Jig server on {}:{}",
            self.config.bind_address,
            self.config.port
        );

        #[cfg(feature = "analytics_clickhouse")]
        let dispatcher = {
            use crate::analytics::clickhouse::ClickHouseSink;
            use crate::analytics::dispatcher::AnalyticsDispatcher;
            if let Some(ch) = self.config.clickhouse_settings() {
                let sink =
                    std::sync::Arc::new(ClickHouseSink::new(&ch.url, &ch.database, &ch.table)?);
                Some(AnalyticsDispatcher::new(
                    sink,
                    ch.queue_capacity,
                    ch.batch_size,
                    std::time::Duration::from_millis(ch.flush_interval_ms),
                ))
            } else {
                None
            }
        };

        let app_state = AppState {
            store: self.store.clone(),
            runtime: self.runtime.clone(),
            config: self.config.clone(),
            #[cfg(feature = "analytics_clickhouse")]
            dispatcher,
        };

        let router: Router = handler::build_router(app_state);

        let addr: SocketAddr = format!("{}:{}", self.config.bind_address, self.config.port)
            .parse()
            .map_err(|e| ServerError::Config(format!("invalid bind address: {e}")))?;

        let listener = TcpListener::bind(addr).await?;
        tracing::info!("HTTP API listening on http://{}", listener.local_addr()?);

        axum::serve(listener, router)
            .await
            .map_err(|e| ServerError::Server(format!("HTTP server error: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn server_initializes() {
        let dir = tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.database_path = dir.path().join("test.db");
        config.bind_address = "127.0.0.1".into();

        config.port = 0;

        let server = JigServer::new(config.clone()).expect("server");

        let handle = tokio::spawn(async move { server.start().await });

        tokio::time::sleep(Duration::from_millis(50)).await;

        if handle.is_finished() {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(ServerError::Io(err)))
                    if err.kind() == std::io::ErrorKind::PermissionDenied => {}
                Ok(Err(err)) => panic!("server failed to start: {err:?}"),
                Err(join_err) => panic!("server task join error: {join_err:?}"),
            }
        } else {
            handle.abort();
            if let Err(join_err) = handle.await {
                assert!(
                    join_err.is_cancelled(),
                    "server task unexpected state: {join_err:?}"
                );
            }
        }
    }
}
