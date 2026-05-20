//! Parquet exporter (standard tier) for jig-server analytics.
//! Feature-gated with `analytics_parquet`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow::array::{ArrayRef, Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::arrow_writer::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;

use chrono::{TimeZone, Utc};

use crate::analytics::TimeRange;
use crate::error::{Result, ServerError};
use crate::storage::SqliteBlockStore;

/// Write-only exporter that serializes receipt projections to a Parquet file.
pub struct ParquetExporter {
    export_path: PathBuf,
    compression: Compression,
}

impl ParquetExporter {
    /// Create a new exporter. If `compression` is None, defaults to zstd.
    pub fn new(export_path: impl AsRef<Path>, compression: Option<&str>) -> Result<Self> {
        let export_path = export_path.as_ref().to_path_buf();
        if let Some(parent) = export_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ServerError::Server(format!("failed to create export dir: {e}")))?;
        }
        let compression = match compression.unwrap_or("zstd").to_ascii_lowercase().as_str() {
            "zstd" => Compression::ZSTD(ZstdLevel::default()),
            "snappy" => Compression::SNAPPY,
            "gzip" => Compression::GZIP(Default::default()),
            "lz4" => Compression::LZ4,
            "uncompressed" => Compression::UNCOMPRESSED,
            _ => Compression::ZSTD(ZstdLevel::default()),
        };
        Ok(Self {
            export_path,
            compression,
        })
    }

    fn receipts_schema() -> Schema {
        Schema::new(vec![
            Field::new("block_id", DataType::Utf8, false),
            Field::new("executed_at", DataType::Int64, false),
            Field::new("fuel_used", DataType::Int64, false),
            Field::new("outcome", DataType::Utf8, false),
            Field::new("host", DataType::Utf8, false),
            Field::new("capability", DataType::Utf8, true),
        ])
    }

    /// Query the SQLite truth store for receipts in `range` and write to a Parquet file.
    pub fn write_receipts_from_store(
        &self,
        store: &SqliteBlockStore,
        range: TimeRange,
    ) -> Result<()> {
        let (start_ts, end_ts) = range.to_timestamp_range();
        let start = Utc
            .timestamp_opt(start_ts, 0)
            .single()
            .unwrap_or_else(Utc::now);
        let end = Utc
            .timestamp_opt(end_ts, 0)
            .single()
            .unwrap_or_else(Utc::now);
        let receipts = store.list_receipts_in_range(Some(start), Some(end), None)?;

        let block_ids: Vec<String> = receipts.iter().map(|r| r.cid.to_string()).collect();
        let executed_ats: Vec<i64> = receipts
            .iter()
            .map(|r| r.receipt.executed_at.unix_timestamp())
            .collect();
        let fuel_useds: Vec<i64> = receipts
            .iter()
            .map(|r| r.receipt.fuel_used as i64)
            .collect();
        let outcomes: Vec<String> = receipts
            .iter()
            .map(|r| {
                r.receipt
                    .outcome
                    .as_ref()
                    .map(|o| format!("{:?}", o.status))
                    .unwrap_or_else(|| "ok".to_string())
            })
            .collect();
        let hosts: Vec<String> = receipts.iter().map(|r| r.receipt.host.clone()).collect();
        let capabilities: Vec<Option<String>> = receipts
            .iter()
            .map(|r| {
                r.receipt.counters.as_ref().and_then(|c| {
                    c.fuel_by_capability
                        .iter()
                        .max_by_key(|(_, v)| *v)
                        .map(|(k, _)| k.clone())
                })
            })
            .collect();

        // Build Arrow arrays and RecordBatch
        let schema = Arc::new(Self::receipts_schema());
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(StringArray::from(block_ids)) as ArrayRef,
                Arc::new(Int64Array::from(executed_ats)) as ArrayRef,
                Arc::new(Int64Array::from(fuel_useds)) as ArrayRef,
                Arc::new(StringArray::from(outcomes)) as ArrayRef,
                Arc::new(StringArray::from(hosts)) as ArrayRef,
                Arc::new(StringArray::from(capabilities)) as ArrayRef,
            ],
        )
        .map_err(|e| ServerError::Server(format!("arrow RecordBatch error: {e}")))?;

        let file = std::fs::File::create(&self.export_path)
            .map_err(|e| ServerError::Server(format!("failed to create parquet file: {e}")))?;
        let props = WriterProperties::builder()
            .set_compression(self.compression)
            .build();
        let mut writer = ArrowWriter::try_new(file, schema, Some(props))
            .map_err(|e| ServerError::Server(format!("parquet writer error: {e}")))?;
        writer
            .write(&batch)
            .map_err(|e| ServerError::Server(format!("parquet write error: {e}")))?;
        writer
            .close()
            .map_err(|e| ServerError::Server(format!("parquet close error: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{SqliteBlockStore, StoredBlock, StoredReceipt, StoredResource};
    use chrono::Utc;
    use jig_core::bundle::BlockBundle;
    use jig_core::manifest::{Author, BlockManifest};
    use jig_core::receipt::CountersBuilder;
    use semver::Version;
    use time::OffsetDateTime;

    fn sample_block_manifest() -> BlockManifest {
        BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                ..Default::default()
            })
            .build()
            .unwrap()
    }

    #[test]
    fn writes_parquet_from_store() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("parquet_test.db");
        let store = SqliteBlockStore::new(&db_path).unwrap();

        // Insert one OK receipt with a capability
        let manifest = sample_block_manifest();
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &[],
            resources: vec![],
        };
        let cid = bundle.block_cid().unwrap();
        store
            .store_block(&StoredBlock {
                cid,
                manifest: manifest.clone(),
                code: vec![],
                resources: Vec::<StoredResource>::new(),
                created_at: Utc::now(),
            })
            .unwrap();

        let executed_at = OffsetDateTime::now_utc();
        let usage = jig_core::capability_scope::CapabilityUsageKey::without_scope("core:compute");
        let counters = CountersBuilder::new()
            .fuel_total(100)
            .add_fuel(&usage, 100)
            .build();
        let receipt_ok = jig_core::receipt::BlockReceipt::builder(cid)
            .host("did:jig:server:local")
            .executed_at(executed_at)
            .render_hash("sha256:abcd")
            .fuel_used(100)
            .counters(counters)
            .build()
            .unwrap();
        store
            .store_receipt(&StoredReceipt {
                cid,
                receipt: receipt_ok,
                created_at: Utc::now(),
            })
            .unwrap();

        // Export to parquet
        let out_path = dir.path().join("export.receipts.parquet");
        let exporter = ParquetExporter::new(&out_path, Some("zstd")).unwrap();
        exporter
            .write_receipts_from_store(&store, TimeRange::LastDay)
            .unwrap();

        let meta = std::fs::metadata(&out_path).unwrap();
        assert!(meta.is_file());
        assert!(meta.len() > 0);
    }
}
