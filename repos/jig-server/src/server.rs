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
    /// v0.0.2 pipeline state. `None` when only running v0.0.1 routes.
    v0_0_2: Option<Arc<crate::v0_0_2::AppState>>,
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
            v0_0_2: None,
        })
    }

    /// Construct a JigServer with the v0.0.2 pipeline state wired in. When
    /// `v0_0_2` is `Some(...)`, the `/.well-known/jig` handler emits the
    /// v0.0.2 discovery fields (server_did, unsafe_options_active,
    /// allowed_block_kinds, peers) so federated peers can detect
    /// misconfigured neighbors (spec §6.6).
    pub fn new_with_v0_0_2(
        config: ServerConfig,
        v0_0_2: Option<Arc<crate::v0_0_2::AppState>>,
    ) -> Result<Self> {
        let store = Arc::new(SqliteBlockStore::new(&config.database_path)?);
        store.health_check()?;

        let runtime = Arc::new(BlockRuntime::new(config.execution_config())?);

        Ok(Self {
            config,
            store,
            runtime,
            v0_0_2,
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
            v0_0_2: self.v0_0_2.clone(),
        };

        let main_router: Router = handler::build_router(app_state);

        // Merge the v0.0.2 WSS router when the pipeline state is present.
        // The v0.0.2 routes have their own AppState (Arc<v0_0_2::AppState>)
        // and do not conflict with any existing v0.0.1 routes.
        let router = if let Some(v002_state) = &self.v0_0_2 {
            main_router.merge(crate::v0_0_2_ws::build_v0_0_2_router(v002_state.clone()))
        } else {
            main_router
        };

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
