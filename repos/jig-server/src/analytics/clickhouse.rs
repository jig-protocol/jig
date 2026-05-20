//! ClickHouse analytics sink (hyperscale) for jig-server.
//! Feature-gated with `analytics_clickhouse`.

use clickhouse::Client;

use crate::error::{Result, ServerError};

use super::dispatcher::{AnalyticsRow, AnalyticsSink};

pub struct ClickHouseSink {
    client: Client,
    table: String,
}

impl ClickHouseSink {
    pub fn new(url: &str, database: &str, table: &str) -> Result<Self> {
        let client = Client::default().with_url(url).with_database(database);
        let sink = Self {
            client,
            table: table.to_string(),
        };
        sink.init_schema()?;
        Ok(sink)
    }

    fn init_schema(&self) -> Result<()> {
        let ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {table} (
                block_id String,
                executed_at Int64,
                fuel_used UInt64,
                outcome LowCardinality(String),
                host String,
                capability Nullable(String)
            )
            ENGINE = MergeTree
            ORDER BY (executed_at)
            "#,
            table = self.table
        );
        tokio_block_on_ok(self.client.query(&ddl).execute())?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl AnalyticsSink for ClickHouseSink {
    async fn insert_batch(&self, rows: &[AnalyticsRow]) -> Result<()> {
        #[derive(serde::Serialize, clickhouse::Row)]
        struct Row<'a> {
            block_id: &'a str,
            executed_at: i64,
            fuel_used: u64,
            outcome: &'a str,
            host: &'a str,
            capability: Option<&'a str>,
        }

        let mut inserter = self
            .client
            .insert(self.table.as_str())
            .map_err(|e| ServerError::Server(format!("ClickHouse insert open error: {e}")))?;
        for r in rows {
            let row = Row {
                block_id: &r.block_id,
                executed_at: r.executed_at,
                fuel_used: r.fuel_used,
                outcome: &r.outcome,
                host: &r.host,
                capability: r.capability.as_deref(),
            };
            inserter
                .write(&row)
                .await
                .map_err(|e| ServerError::Server(format!("ClickHouse insert error: {e}")))?;
        }
        inserter
            .end()
            .await
            .map_err(|e| ServerError::Server(format!("ClickHouse insert end error: {e}")))?;
        Ok(())
    }
}

// Minimal block_on helper to perform schema init synchronously during construction.
fn tokio_block_on_ok<F, E>(fut: F) -> Result<()>
where
    F: std::future::Future<Output = std::result::Result<(), E>>,
    E: std::fmt::Display,
{
    use tokio::runtime::Builder;
    // Use a lightweight current_thread runtime to avoid stealing global runtime
    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ServerError::Server(format!("tokio runtime init error: {e}")))?;
    match rt.block_on(fut) {
        Ok(()) => Ok(()),
        Err(e) => Err(ServerError::Server(format!("ClickHouse error: {e}"))),
    }
}
