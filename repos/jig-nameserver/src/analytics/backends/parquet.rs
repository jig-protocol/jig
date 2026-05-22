//! Parquet file exporter backend (Tier 2)
//!
//! Exports analytics data to Parquet files for archival, data lake integration,
//! or external analytics tools. Feature-gated behind `tier2-analytics`.

#[cfg(feature = "tier2-analytics")]
use crate::analytics::backend::*;
#[cfg(feature = "tier2-analytics")]
use crate::error::{NameServerError, Result};
#[cfg(feature = "tier2-analytics")]
use async_trait::async_trait;
#[cfg(feature = "tier2-analytics")]
use std::collections::HashMap;
#[cfg(feature = "tier2-analytics")]
use std::path::PathBuf;
#[cfg(feature = "tier2-analytics")]
use std::sync::Arc;

#[cfg(feature = "tier2-analytics")]
use arrow::array::{ArrayRef, Int64Array, StringArray};
#[cfg(feature = "tier2-analytics")]
use arrow::datatypes::{DataType, Field, Schema};
#[cfg(feature = "tier2-analytics")]
use arrow::record_batch::RecordBatch;
#[cfg(feature = "tier2-analytics")]
use parquet::arrow::arrow_writer::ArrowWriter;
#[cfg(feature = "tier2-analytics")]
use parquet::basic::{Compression, ZstdLevel};
#[cfg(feature = "tier2-analytics")]
use parquet::file::properties::WriterProperties;

#[cfg(feature = "tier2-analytics")]
/// Parquet exporter - write-only analytics backend for archival
pub struct ParquetExporter {
    export_path: PathBuf,
    compression: Compression,
}

#[cfg(feature = "tier2-analytics")]
impl ParquetExporter {
    pub fn new(export_path: PathBuf, compression: String) -> Result<Self> {
        // Ensure export directory exists
        if let Some(parent) = export_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("Failed to create export directory: {}", e))
            })?;
        }

        // Parse compression type
        let compression = match compression.to_lowercase().as_str() {
            "zstd" => Compression::ZSTD(ZstdLevel::default()),
            "snappy" => Compression::SNAPPY,
            "gzip" => Compression::GZIP(Default::default()),
            "lz4" => Compression::LZ4,
            "uncompressed" => Compression::UNCOMPRESSED,
            _ => Compression::ZSTD(ZstdLevel::default()), // Default to zstd
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

    fn write_receipts_parquet(&self, receipts: Vec<ReceiptRecord>) -> Result<()> {
        let schema = Arc::new(Self::receipts_schema());

        // Convert records to Arrow arrays
        let block_ids: Vec<String> = receipts.iter().map(|r| r.block_id.clone()).collect();
        let executed_ats: Vec<i64> = receipts.iter().map(|r| r.executed_at).collect();
        let fuel_useds: Vec<i64> = receipts.iter().map(|r| r.fuel_used as i64).collect();
        let outcomes: Vec<String> = receipts.iter().map(|r| r.outcome.clone()).collect();
        let hosts: Vec<String> = receipts.iter().map(|r| r.host.clone()).collect();
        let capabilities: Vec<Option<String>> =
            receipts.iter().map(|r| r.capability.clone()).collect();

        let block_id_array = Arc::new(StringArray::from(block_ids)) as ArrayRef;
        let executed_at_array = Arc::new(Int64Array::from(executed_ats)) as ArrayRef;
        let fuel_used_array = Arc::new(Int64Array::from(fuel_useds)) as ArrayRef;
        let outcome_array = Arc::new(StringArray::from(outcomes)) as ArrayRef;
        let host_array = Arc::new(StringArray::from(hosts)) as ArrayRef;
        let capability_array = Arc::new(StringArray::from(capabilities)) as ArrayRef;

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                block_id_array,
                executed_at_array,
                fuel_used_array,
                outcome_array,
                host_array,
                capability_array,
            ],
        )
        .map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to create RecordBatch: {}", e))
        })?;

        // Write to Parquet file
        let file = std::fs::File::create(&self.export_path).map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to create Parquet file: {}", e))
        })?;

        let props = WriterProperties::builder()
            .set_compression(self.compression)
            .build();

        let mut writer = ArrowWriter::try_new(file, schema, Some(props)).map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to create Parquet writer: {}", e))
        })?;

        writer.write(&batch).map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to write Parquet batch: {}", e))
        })?;

        writer.close().map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to close Parquet writer: {}", e))
        })?;

        Ok(())
    }

    /// Public method to write receipts to Parquet file
    /// This is the main entry point for using the Parquet exporter
    pub fn write_receipts_to_file(&self, receipts: Vec<ReceiptRecord>) -> Result<()> {
        self.write_receipts_parquet(receipts)
    }
}

#[cfg(feature = "tier2-analytics")]
#[async_trait]
impl AnalyticsBackend for ParquetExporter {
    async fn query_receipts(&self, _range: TimeRange) -> Result<Vec<ReceiptRecord>> {
        // Parquet is write-only for now (could add read support later)
        Err(NameServerError::Other(anyhow::anyhow!(
            "Parquet backend is write-only (export) - use for archival, not queries"
        )))
    }

    async fn query_anomalies(&self, _range: TimeRange) -> Result<Vec<AnomalyRecord>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Parquet backend is write-only"
        )))
    }

    async fn query_penalties(&self, _range: TimeRange) -> Result<Vec<PenaltyRecord>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Parquet backend is write-only"
        )))
    }

    async fn query_useful_work(&self, _range: TimeRange) -> Result<Vec<UsefulWorkRecord>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Parquet backend is write-only"
        )))
    }

    async fn query_cross_validations(
        &self,
        _range: TimeRange,
    ) -> Result<Vec<CrossValidationRecord>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Parquet backend is write-only"
        )))
    }

    async fn export(&self, _range: TimeRange, format: ExportFormat) -> Result<Vec<u8>> {
        match format {
            ExportFormat::Parquet => {
                // Parquet backend is write-only for archival
                // Use write_receipts_to_file() method to write data from another source
                Err(NameServerError::Other(anyhow::anyhow!(
                    "Parquet backend is write-only. Use ParquetExporter::write_receipts_to_file() with data from another backend"
                )))
            }
            ExportFormat::Json | ExportFormat::Csv => Err(NameServerError::Other(anyhow::anyhow!(
                "Parquet backend only supports Parquet format"
            ))),
        }
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_streaming: false,
            supports_aggregations: false, // Write-only
            max_query_size: None,
            columnar_storage: true,
            time_series_optimized: false, // Not optimized for querying
        }
    }

    fn name(&self) -> &'static str {
        "parquet"
    }
}

#[cfg(feature = "tier2-analytics")]
/// Factory for creating Parquet exporter backends
pub struct ParquetExporterFactory;

#[cfg(feature = "tier2-analytics")]
impl AnalyticsBackendFactory for ParquetExporterFactory {
    fn create(&self, config: &HashMap<String, String>) -> Result<Box<dyn AnalyticsBackend>> {
        let export_path = config
            .get("export_path")
            .ok_or_else(|| {
                NameServerError::Other(anyhow::anyhow!(
                    "Parquet backend requires 'export_path' config"
                ))
            })?
            .into();

        let compression = config
            .get("compression")
            .cloned()
            .unwrap_or_else(|| "zstd".to_string());

        Ok(Box::new(ParquetExporter::new(export_path, compression)?))
    }

    fn name(&self) -> &'static str {
        "parquet"
    }
}

// Placeholder stubs for non-tier2 builds
#[cfg(not(feature = "tier2-analytics"))]
pub struct ParquetExporter;

#[cfg(not(feature = "tier2-analytics"))]
impl ParquetExporter {
    pub fn new(
        _export_path: std::path::PathBuf,
        _compression: String,
    ) -> crate::error::Result<Self> {
        Err(crate::error::NameServerError::Other(anyhow::anyhow!(
            "Parquet backend requires tier2-analytics feature"
        )))
    }
}
