//! Block storage built on SQLite.

use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use cid::Cid;
use jig_core::{BlockManifest, BlockReceipt};
use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::error::{Result, ServerError};

#[derive(Clone)]
pub struct StoredResource {
    pub name: String,
    pub mime: String,
    pub data: Vec<u8>,
}

#[derive(Clone)]
pub struct StoredBlock {
    pub cid: Cid,
    pub manifest: BlockManifest,
    pub code: Vec<u8>,
    pub resources: Vec<StoredResource>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct StoredReceipt {
    pub cid: Cid,
    pub receipt: BlockReceipt,
    pub created_at: DateTime<Utc>,
}

/// SQLite-backed block store.
pub struct SqliteBlockStore {
    conn: Arc<Mutex<Connection>>,
    _path: PathBuf,
}

impl SqliteBlockStore {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            _path: path,
        };

        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS blocks (
                cid TEXT PRIMARY KEY,
                manifest TEXT NOT NULL,
                code BLOB,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS block_resources (
                block_cid TEXT NOT NULL,
                name TEXT NOT NULL,
                mime TEXT NOT NULL,
                data BLOB NOT NULL,
                PRIMARY KEY (block_cid, name),
                FOREIGN KEY(block_cid) REFERENCES blocks(cid) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS receipts (
                block_cid TEXT PRIMARY KEY,
                receipt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(block_cid) REFERENCES blocks(cid) ON DELETE CASCADE
            );
            "#,
        )?;
        Ok(())
    }

    pub fn store_block(&self, block: &StoredBlock) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT OR REPLACE INTO blocks (cid, manifest, code, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                block.cid.to_string(),
                serde_json::to_string(&block.manifest)?,
                if block.code.is_empty() { None } else { Some(&block.code) },
                block.created_at.to_rfc3339(),
            ],
        )?;

        tx.execute(
            "DELETE FROM block_resources WHERE block_cid = ?1",
            params![block.cid.to_string()],
        )?;

        for resource in &block.resources {
            tx.execute(
                "INSERT INTO block_resources (block_cid, name, mime, data) VALUES (?1, ?2, ?3, ?4)",
                params![
                    block.cid.to_string(),
                    &resource.name,
                    &resource.mime,
                    &resource.data,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn store_receipt(&self, receipt: &StoredReceipt) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO receipts (block_cid, receipt, created_at) VALUES (?1, ?2, ?3)",
            params![
                receipt.cid.to_string(),
                serde_json::to_string(&receipt.receipt)?,
                receipt.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_block(&self, cid: &Cid) -> Result<Option<StoredBlock>> {
        let conn = self.conn.lock().unwrap();

        let block = conn
            .query_row(
                "SELECT manifest, code, created_at FROM blocks WHERE cid = ?1",
                params![cid.to_string()],
                |row| {
                    let manifest_json: String = row.get(0)?;
                    let manifest = parse_manifest(&manifest_json)?;
                    let code: Option<Vec<u8>> = row.get(1)?;
                    let created_at: String = row.get(2)?;
                    let created_at = parse_datetime(&created_at)?;

                    Ok((manifest, code.unwrap_or_default(), created_at))
                },
            )
            .optional()?;

        let Some((manifest, code, created_at)) = block else {
            return Ok(None);
        };

        let mut stmt = conn.prepare(
            "SELECT name, mime, data FROM block_resources WHERE block_cid = ?1 ORDER BY name",
        )?;
        let resources = stmt
            .query_map(params![cid.to_string()], |row| {
                Ok(StoredResource {
                    name: row.get(0)?,
                    mime: row.get(1)?,
                    data: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(Some(StoredBlock {
            cid: *cid,
            manifest,
            code,
            resources,
            created_at,
        }))
    }

    pub fn get_receipt(&self, cid: &Cid) -> Result<Option<StoredReceipt>> {
        let conn = self.conn.lock().unwrap();
        let receipt = conn
            .query_row(
                "SELECT receipt, created_at FROM receipts WHERE block_cid = ?1",
                params![cid.to_string()],
                |row| {
                    let receipt_json: String = row.get(0)?;
                    let receipt = parse_receipt(&receipt_json)?;
                    let created_at: String = row.get(1)?;
                    let created_at = parse_datetime(&created_at)?;
                    Ok((receipt, created_at))
                },
            )
            .optional()?;

        Ok(receipt.map(|(receipt, created_at)| StoredReceipt {
            cid: *cid,
            receipt,
            created_at,
        }))
    }

    pub fn list_receipts_in_range(
        &self,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<StoredReceipt>> {
        let conn = self.conn.lock().unwrap();

        let mut sql = String::from("SELECT block_cid, receipt, created_at FROM receipts");
        let mut params_vec: Vec<String> = Vec::new();
        let mut where_clauses: Vec<&str> = Vec::new();
        if let Some(s) = start {
            where_clauses.push("datetime(created_at) >= datetime(?)");
            params_vec.push(s.to_rfc3339());
        }
        if let Some(e) = end {
            where_clauses.push("datetime(created_at) <= datetime(?)");
            params_vec.push(e.to_rfc3339());
        }
        if !where_clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY created_at DESC");
        if let Some(l) = limit {
            sql.push_str(&format!(" LIMIT {l}"));
        }

        let map_row = |row: &rusqlite::Row| -> rusqlite::Result<StoredReceipt> {
            let cid_str: String = row.get(0)?;
            let receipt_json: String = row.get(1)?;
            let created_at_str: String = row.get(2)?;
            let cid: Cid = cid_str.parse().map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(e))
            })?;
            let receipt = parse_receipt(&receipt_json)?;
            let created_at = parse_datetime(&created_at_str)?;
            Ok(StoredReceipt {
                cid,
                receipt,
                created_at,
            })
        };

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params_vec.iter()), map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn list_blocks(&self, limit: usize) -> Result<Vec<StoredBlockSummary>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT cid, manifest, created_at FROM blocks ORDER BY created_at DESC LIMIT ?1",
        )?;

        let rows = stmt
            .query_map(params![limit as i64], |row| {
                let cid_str: String = row.get(0)?;
                let manifest_json: String = row.get(1)?;
                let created_at: String = row.get(2)?;

                let manifest = parse_manifest(&manifest_json)?;
                let created_at = parse_datetime(&created_at)?;

                Ok(StoredBlockSummary {
                    cid: cid_str.parse().map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(e))
                    })?,
                    manifest,
                    created_at,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(rows)
    }

    pub fn health_check(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT 1", [], |_| Ok(()))
            .map_err(ServerError::from)
    }
}

#[derive(Clone)]
pub struct StoredBlockSummary {
    pub cid: Cid,
    pub manifest: BlockManifest,
    pub created_at: DateTime<Utc>,
}

/// Helper used by HTTP layer to encode resource bodies as base64.
pub fn encode_resource_data(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

fn parse_manifest(json: &str) -> rusqlite::Result<BlockManifest> {
    serde_json::from_str(json)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(e)))
}

fn parse_receipt(json: &str) -> rusqlite::Result<BlockReceipt> {
    serde_json::from_str(json)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(e)))
}

fn parse_datetime(value: &str) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn encodes_resource_base64() {
        let out = encode_resource_data(b"abc");
        assert_eq!(out, "YWJj");
    }

    #[test]
    fn parse_helpers_error_paths() {
        assert!(parse_manifest("}").is_err());
        assert!(parse_receipt("{").is_err());
        assert!(parse_datetime("not-a-time").is_err());
    }

    #[test]
    fn health_check_ok() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("test.db");
        let store = SqliteBlockStore::new(&db).unwrap();
        assert!(store.health_check().is_ok());
    }

    #[test]
    fn store_and_get_block_roundtrip() {
        use blake3::hash;
        use jig_core::manifest::{Author, RenderDescriptor};
        let dir = tempdir().unwrap();
        let db = dir.path().join("test.db");
        let store = SqliteBlockStore::new(&db).unwrap();

        let code: Vec<u8> = vec![1, 2, 3, 4];
        let module_hash = hash(&code).to_hex().to_string();
        let manifest = BlockManifest::builder()
            .version(semver::Version::new(1, 0, 0))
            .author(Author {
                did: "did:jig:test".into(),
                ..Default::default()
            })
            .render(RenderDescriptor {
                entry: "index.html".into(),
                expected_hash: module_hash,
                output_type: "application/wasm".into(),
            })
            .build()
            .unwrap();
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = jig_core::BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &code,
            resources: vec![],
        };
        let cid = bundle.block_cid().unwrap();

        let block = StoredBlock {
            cid,
            manifest: manifest.clone(),
            code: code.clone(),
            resources: vec![StoredResource {
                name: "a.txt".into(),
                mime: "text/plain".into(),
                data: b"hi".to_vec(),
            }],
            created_at: Utc::now(),
        };
        store.store_block(&block).unwrap();

        let got = store.get_block(&cid).unwrap().unwrap();
        assert_eq!(got.cid, cid);
        assert_eq!(got.code, code);
        assert_eq!(got.resources.len(), 1);
        assert_eq!(got.resources[0].name, "a.txt");
    }

    #[test]
    fn store_and_get_receipt_roundtrip_and_list_filters() {
        use jig_core::receipt::BlockReceipt;
        use time::OffsetDateTime;

        let dir = tempdir().unwrap();
        let db = dir.path().join("test.db");
        let store = SqliteBlockStore::new(&db).unwrap();

        let mut cids = Vec::new();
        for i in 0..3 {
            let manifest = BlockManifest::builder()
                .version(semver::Version::new(1, 0, i))
                .author(jig_core::manifest::Author {
                    did: format!("did:jig:test-{i}"),
                    ..Default::default()
                })
                .render(jig_core::manifest::RenderDescriptor {
                    entry: "index.html".into(),
                    expected_hash: format!("h{i}"),
                    output_type: "application/wasm".into(),
                })
                .build()
                .unwrap();
            let manifest_bytes = manifest.to_canonical_bytes().unwrap();
            let bundle = jig_core::BlockBundle {
                manifest_bytes: &manifest_bytes,
                code_bytes: &[],
                resources: vec![],
            };
            let cid = bundle.block_cid().unwrap();
            store
                .store_block(&StoredBlock {
                    cid,
                    manifest,
                    code: vec![],
                    resources: vec![],
                    created_at: Utc::now(),
                })
                .unwrap();
            cids.push(cid);
        }

        let t0 = Utc::now() - chrono::Duration::hours(2);
        let t1 = Utc::now() - chrono::Duration::minutes(30);
        let t2 = Utc::now();

        let r0 = BlockReceipt::builder(cids[0])
            .host("h")
            .executed_at(OffsetDateTime::from_unix_timestamp(t0.timestamp()).unwrap())
            .render_hash("r0")
            .fuel_used(1)
            .build()
            .unwrap();
        store
            .store_receipt(&StoredReceipt {
                cid: cids[0],
                receipt: r0,
                created_at: t0,
            })
            .unwrap();

        let r1 = BlockReceipt::builder(cids[1])
            .host("h")
            .executed_at(OffsetDateTime::from_unix_timestamp(t1.timestamp()).unwrap())
            .render_hash("r1")
            .fuel_used(2)
            .build()
            .unwrap();
        store
            .store_receipt(&StoredReceipt {
                cid: cids[1],
                receipt: r1,
                created_at: t1,
            })
            .unwrap();

        let r2 = BlockReceipt::builder(cids[2])
            .host("h")
            .executed_at(OffsetDateTime::from_unix_timestamp(t2.timestamp()).unwrap())
            .render_hash("r2")
            .fuel_used(3)
            .build()
            .unwrap();
        store
            .store_receipt(&StoredReceipt {
                cid: cids[2],
                receipt: r2,
                created_at: t2,
            })
            .unwrap();

        let all = store.list_receipts_in_range(None, None, None).unwrap();
        assert_eq!(all.len(), 3);
        assert!(all[0].created_at >= all[1].created_at);

        let recent = store
            .list_receipts_in_range(Some(t1), None, Some(1))
            .unwrap();
        assert_eq!(recent.len(), 1);

        let window = store
            .list_receipts_in_range(
                Some(t0 + chrono::Duration::minutes(1)),
                Some(t2 - chrono::Duration::minutes(1)),
                None,
            )
            .unwrap();
        assert_eq!(window.len(), 1);
        assert_eq!(window[0].created_at, t1);
    }
}
