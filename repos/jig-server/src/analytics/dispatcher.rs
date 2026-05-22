use std::sync::Arc;

use tokio::sync::mpsc;

use crate::error::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalyticsRow {
    pub block_id: String,
    pub executed_at: i64,
    pub fuel_used: u64,
    pub outcome: String,
    pub host: String,
    pub capability: Option<String>,
}

#[async_trait::async_trait]
pub trait AnalyticsSink: Send + Sync {
    async fn insert_batch(&self, rows: &[AnalyticsRow]) -> Result<()>;

    async fn insert_row(&self, row: &AnalyticsRow) -> Result<()> {
        self.insert_batch(std::slice::from_ref(row)).await
    }
}

#[derive(Clone)]
pub struct AnalyticsDispatcher {
    tx: mpsc::Sender<AnalyticsRow>,
}

impl AnalyticsDispatcher {
    pub fn new(
        sink: Arc<dyn AnalyticsSink>,
        capacity: usize,
        batch_size: usize,
        flush_interval: std::time::Duration,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<AnalyticsRow>(capacity.max(1));
        tokio::spawn(async move {
            let mut batch: Vec<AnalyticsRow> = Vec::with_capacity(batch_size.max(1));
            let mut interval = tokio::time::interval(flush_interval);
            loop {
                tokio::select! {
                    maybe_row = rx.recv() => {
                        match maybe_row {
                            Some(row) => {
                                batch.push(row);
                                if batch.len() >= batch_size {
                                    let to_flush = std::mem::take(&mut batch);
                                    let _ = sink.insert_batch(&to_flush).await;
                                }
                            }
                            None => {
                                if !batch.is_empty() {
                                    let _ = sink.insert_batch(&batch).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            let to_flush = std::mem::take(&mut batch);
                            let _ = sink.insert_batch(&to_flush).await;
                        }
                    }
                }
            }
        });
        Self { tx }
    }

    pub fn enqueue(&self, row: AnalyticsRow) -> bool {
        self.tx.try_send(row).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct TestSink {
        rows: Mutex<Vec<AnalyticsRow>>,
    }

    #[async_trait::async_trait]
    impl AnalyticsSink for TestSink {
        async fn insert_batch(&self, rows: &[AnalyticsRow]) -> Result<()> {
            self.rows.lock().unwrap().extend_from_slice(rows);
            Ok(())
        }
    }

    #[tokio::test]
    async fn dispatcher_drops_when_full_and_flushes_batches() {
        let sink = Arc::new(TestSink {
            rows: Mutex::new(Vec::new()),
        });
        let dispatcher =
            AnalyticsDispatcher::new(sink.clone(), 1, 8, std::time::Duration::from_millis(10));

        let mut ok = 0usize;
        for i in 0..100 {
            let sent = dispatcher.enqueue(AnalyticsRow {
                block_id: format!("cid-{i}"),
                executed_at: 0,
                fuel_used: 1,
                outcome: "ok".into(),
                host: "did:jig:server:test".into(),
                capability: None,
            });
            if sent {
                ok += 1;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let received = sink.rows.lock().unwrap().len();
        assert!(received <= ok);
        assert!(received > 0);
    }
}
