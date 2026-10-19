//! SQLite persist layer for jig-pipeline.
//!
//! Schema per v0.0.2 spec §4.1. The 8 tables capture block-shaped state
//! mutations (`blocks` + `receipts`), denormalized derived state for fast
//! reads (`channels`, `memberships`, `peers`, `alias_attestations`,
//! `tofu_keys`), and federation catch-up state (`subscription_cursors`).
//!
//! `bundle_bytes` and `receipt_bytes` are stored as canonical bytes — the
//! denormalized columns (`render_hash`, `sender_did`, `block_kind`, etc.)
//! are read-optimization indexes whose source of truth is the canonical bytes.

use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;

use crate::ingest_record::{GENESIS_PREV, IngestRecord, RecordSigner};

#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A stored value this version cannot read back.
    #[error("corrupt store: {0}")]
    Corrupt(String),
    /// [`SqliteStore::normalize_alias_case`] would hand one alias to two DIDs.
    #[error(
        "lowercasing aliases would give `{0}` to more than one DID; \
         resolve the conflicting alias_attestations rows by hand"
    )]
    AliasCaseClash(String),
}

pub type Result<T> = std::result::Result<T, PersistError>;

/// SQLite-backed store. Internally serializes all access via `Mutex<Connection>`.
/// For higher concurrency in v0.0.3+ consider replacing with a connection pool.
pub struct SqliteStore {
    pub(crate) conn: Mutex<Connection>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoredBlock {
    pub cid: String,
    pub channel_id: Option<String>,
    pub block_kind: String,
    pub sender_did: String,
    pub sender_sig: Vec<u8>,
    pub bundle_bytes: Vec<u8>,
    pub is_synthetic: bool,
    pub hlc_wall_ms: u64,
    pub hlc_logical: u32,
    pub hlc_origin: String,
    pub posted_at: i64,
    pub origin_server: String,
    pub federated_from: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoredReceipt {
    pub cid: String,
    pub block_cid: String,
    pub server_id: String,
    pub receipt_bytes: Vec<u8>,
    pub render_hash: Option<String>,
    pub produced_at: i64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoredChannel {
    pub id: String,
    pub slug: String,
    pub visibility: String,
    pub created_at: i64,
    pub owner_did: String,
    /// The encryption suite fixed at creation (`none` or `mls`). Every post
    /// is checked against it; see `jig_pipeline::mls_gate`.
    pub suite: String,
}

/// An encrypted channel's MLS public state, as the delivery service tracks it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoredMlsGroup {
    pub slug: String,
    pub group_id: Vec<u8>,
    /// `jig_mls::snapshot` bytes of the channel's `PublicGroup`.
    pub state: Vec<u8>,
    pub epoch: u64,
    /// The newest group info a committer published, for external joiners.
    pub group_info: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoredMembership {
    pub channel_id: String,
    pub member_did: String,
    pub role: String,
    pub joined_at: i64,
    pub source_block_cid: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoredPeer {
    pub server_url: String,
    pub server_did: String,
    pub last_handshake_cid: Option<String>,
    pub status: String,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoredAliasAttestation {
    pub did: String,
    pub alias: String,
    pub ns_did: String,
    pub valid_from: i64,
    pub valid_until: i64,
    pub attestation_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoredTofuKey {
    pub local_nickname: String,
    pub did: String,
    pub first_seen_at: i64,
    pub locked: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StoredCursor {
    pub peer_server_url: String,
    pub origin_did: String,
    pub last_hlc_wall_ms: i64,
    pub last_hlc_logical: i64,
}

/// Hard ceiling on how many blocks one history read returns, matching the
/// v0.0.1 store's clamp. Callers pass a caller-supplied `limit` straight
/// through from a query string, so the clamp lives here rather than at the
/// edge — no REST handler can turn `?limit=` into a whole-channel dump.
pub const MAX_HISTORY_LIMIT: usize = 200;

/// A point on a channel's HLC timeline, used as an exclusive read cursor by
/// [`SqliteStore::list_blocks_by_channel`].
///
/// `hlc_origin` is deliberately absent: it only breaks ties between blocks
/// that share a `(wall_ms, logical)` pair, and a cursor that resumes from
/// "strictly after this point" does not need that resolution.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct HlcPoint {
    pub wall_ms: u64,
    pub logical: u32,
}

/// Every column of `blocks`, in the order [`row_to_stored_block`] reads them.
const BLOCK_COLUMNS: &str = "cid, channel_id, block_kind, sender_did, sender_sig, \
     bundle_bytes, is_synthetic, hlc_wall_ms, hlc_logical, hlc_origin, posted_at, \
     origin_server, federated_from";

fn row_to_stored_block(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredBlock> {
    Ok(StoredBlock {
        cid: r.get(0)?,
        channel_id: r.get(1)?,
        block_kind: r.get(2)?,
        sender_did: r.get(3)?,
        sender_sig: r.get(4)?,
        bundle_bytes: r.get(5)?,
        is_synthetic: r.get::<_, i64>(6)? != 0,
        hlc_wall_ms: r.get::<_, i64>(7)? as u64,
        hlc_logical: r.get::<_, i64>(8)? as u32,
        hlc_origin: r.get(9)?,
        posted_at: r.get(10)?,
        origin_server: r.get(11)?,
        federated_from: r.get(12)?,
    })
}

/// The statement behind [`SqliteStore::list_blocks_by_channel`]. Factored out
/// so the `EXPLAIN QUERY PLAN` test asserts against the exact SQL that runs
/// and cannot drift away from it.
///
/// Both variants are shaped to ride the `blocks_channel_hlc_cid` index end to
/// end: equality on the leading `channel_id`, then an ordered walk of the
/// trailing columns (backwards for the no-cursor case) so SQLite never
/// materialises a sort.
///
/// History order is (HLC wall, logical, origin, CID). The CID makes it total:
/// one author's blocks in the same millisecond share the rest, and without it
/// a page boundary between two of them could skip one.
fn history_sql(with_cursor: bool) -> String {
    if with_cursor {
        format!(
            "SELECT {BLOCK_COLUMNS} FROM blocks \
             WHERE channel_id = ?1 AND (hlc_wall_ms, hlc_logical) > (?2, ?3) \
             ORDER BY hlc_wall_ms ASC, hlc_logical ASC, hlc_origin ASC, cid ASC \
             LIMIT ?4"
        )
    } else {
        format!(
            "SELECT {BLOCK_COLUMNS} FROM blocks \
             WHERE channel_id = ?1 \
             ORDER BY hlc_wall_ms DESC, hlc_logical DESC, hlc_origin DESC, cid DESC \
             LIMIT ?2"
        )
    }
}

/// History of a sequenced channel, newest first: by the sequencer's `seq`,
/// not the authors' clocks (TM-02). `before_seq` bounds it for paging.
fn sequenced_history_sql(with_before: bool) -> String {
    let columns = BLOCK_COLUMNS
        .split(", ")
        .map(|c| format!("b.{}", c.trim()))
        .collect::<Vec<_>>()
        .join(", ");
    let bound = if with_before { "AND r.seq < ?3" } else { "" };
    format!(
        "SELECT {columns} FROM ingest_records r JOIN blocks b ON b.cid = r.block_cid \
         WHERE r.slug = ?1 {bound} ORDER BY r.seq DESC LIMIT ?2"
    )
}

/// The statement behind [`SqliteStore::list_blocks_before`]: the page just
/// older than a cursor block, newest first, on the same index and order.
fn history_before_sql() -> String {
    format!(
        "SELECT {BLOCK_COLUMNS} FROM blocks \
         WHERE channel_id = ?1 \
           AND (hlc_wall_ms, hlc_logical, hlc_origin, cid) < (?2, ?3, ?4, ?5) \
         ORDER BY hlc_wall_ms DESC, hlc_logical DESC, hlc_origin DESC, cid DESC \
         LIMIT ?6"
    )
}

/// Additively add `column` to `table` when an older database predates it.
///
/// SQLite has no `ADD COLUMN IF NOT EXISTS`, so probe `pragma_table_info`
/// first. Only nullable / defaulted columns are safe to add this way, which is
/// all v0.0.2 needs.
fn add_column_if_missing(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<bool> {
    let present: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
        params![table, column],
        |r| r.get(0),
    )?;
    if present {
        return Ok(false);
    }
    // Table/column names are compile-time constants at every call site, so the
    // format! is not an injection vector — SQLite forbids binding identifiers.
    conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))?;
    Ok(true)
}

/// The suffix an `alias_attestations` row is keyed by: the lowercased text
/// after the last `@` of its alias, or `''` for a bare alias (an ingested
/// `ns-attestation` block may carry one). Lowercased so `Bob@B.example` and
/// `bob@b.example` share one key: one name per DID per suffix whatever the
/// case.
fn alias_suffix_of(alias: &str) -> String {
    alias
        .rsplit_once('@')
        .map_or("", |(_, suffix)| suffix)
        .to_ascii_lowercase()
}

/// Re-key `alias_attestations` from `(did, ns_did)` to `(did, ns_did, suffix)`
/// so one DID can hold a name under each suffix a nameserver serves.
///
/// SQLite cannot change a primary key in place, so a database that predates
/// the `suffix` column has its table rebuilt in one transaction, with each
/// row's suffix derived from its alias. A table that already has the column is
/// left alone, which makes this idempotent.
fn rebuild_alias_attestations_with_suffix(conn: &Connection) -> Result<bool> {
    let present: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('alias_attestations') WHERE name = 'suffix')",
        [],
        |r| r.get(0),
    )?;
    if present {
        return Ok(false);
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "CREATE TABLE alias_attestations_new (
             did                  TEXT NOT NULL,
             alias                TEXT NOT NULL,
             ns_did               TEXT NOT NULL,
             valid_from           INTEGER NOT NULL,
             valid_until          INTEGER NOT NULL,
             attestation_bytes    BLOB NOT NULL,
             suffix               TEXT NOT NULL DEFAULT '',
             PRIMARY KEY (did, ns_did, suffix)
         );",
    )?;
    {
        let mut read = tx.prepare(
            "SELECT did, alias, ns_did, valid_from, valid_until, attestation_bytes
             FROM alias_attestations",
        )?;
        let mut write = tx.prepare(
            "INSERT INTO alias_attestations_new
                 (did, alias, ns_did, valid_from, valid_until, attestation_bytes, suffix)
             VALUES (?,?,?,?,?,?,?)",
        )?;
        let rows = read
            .query_map([], row_to_stored_alias_attestation)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for a in rows {
            write.execute(params![
                a.did,
                a.alias,
                a.ns_did,
                a.valid_from,
                a.valid_until,
                a.attestation_bytes,
                alias_suffix_of(&a.alias)
            ])?;
        }
    }
    tx.execute_batch(
        "DROP TABLE alias_attestations;
         ALTER TABLE alias_attestations_new RENAME TO alias_attestations;",
    )?;
    tx.commit()?;
    Ok(true)
}

fn row_to_stored_alias_attestation(
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredAliasAttestation> {
    Ok(StoredAliasAttestation {
        did: r.get(0)?,
        alias: r.get(1)?,
        ns_did: r.get(2)?,
        valid_from: r.get(3)?,
        valid_until: r.get(4)?,
        attestation_bytes: r.get(5)?,
    })
}

fn row_to_stored_channel(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredChannel> {
    Ok(StoredChannel {
        id: r.get(0)?,
        slug: r.get(1)?,
        visibility: r.get(2)?,
        created_at: r.get(3)?,
        owner_did: r.get(4)?,
        suite: r.get(5)?,
    })
}

const CHANNEL_COLUMNS: &str = "id, slug, visibility, created_at, owner_did, suite";

/// The membership change a commit-carrying block makes, applied inside
/// [`SqliteStore::land_mls_commit`]'s transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipChange {
    None,
    Upsert(StoredMembership),
    Remove {
        channel_id: String,
        member_did: String,
    },
}

/// Give `block_cid` the next entry of its channel's chain, signed by
/// `signer`, inside the caller's transaction. `seq` and `prev` are read from
/// the chain as stored under the same lock, so two blocks can never share one.
fn sequence_on(
    conn: &Connection,
    slug: &str,
    block_cid: &str,
    signer: &RecordSigner<'_>,
) -> Result<IngestRecord> {
    let last: Option<Vec<u8>> = conn
        .query_row(
            "SELECT record FROM ingest_records WHERE channel_id = ? ORDER BY seq DESC LIMIT 1",
            [signer.channel_id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let (seq, prev) = match last {
        None => (0, GENESIS_PREV),
        Some(bytes) => {
            let last = IngestRecord::decode(&bytes)
                .map_err(|e| PersistError::Corrupt(format!("ingest record: {e}")))?;
            (last.seq + 1, last.hash())
        }
    };
    let record = signer.sign(seq, block_cid, prev);
    conn.execute(
        "INSERT INTO ingest_records (block_cid, channel_id, slug, seq, record)
         VALUES (?,?,?,?,?)",
        params![
            block_cid,
            record.channel_id,
            slug,
            seq as i64,
            record.encode()
        ],
    )?;
    Ok(record)
}

fn insert_block_on(conn: &Connection, b: &StoredBlock) -> Result<()> {
    conn.execute(
        "INSERT INTO blocks
         (cid, channel_id, block_kind, sender_did, sender_sig, bundle_bytes,
          is_synthetic, hlc_wall_ms, hlc_logical, hlc_origin, posted_at,
          origin_server, federated_from)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            b.cid,
            b.channel_id,
            b.block_kind,
            b.sender_did,
            b.sender_sig,
            b.bundle_bytes,
            b.is_synthetic as i64,
            b.hlc_wall_ms as i64,
            b.hlc_logical as i64,
            b.hlc_origin,
            b.posted_at,
            b.origin_server,
            b.federated_from,
        ],
    )?;
    Ok(())
}

fn insert_receipt_on(conn: &Connection, r: &StoredReceipt) -> Result<()> {
    conn.execute(
        "INSERT INTO receipts (cid, block_cid, server_id, receipt_bytes, render_hash, produced_at)
         VALUES (?,?,?,?,?,?)",
        params![
            r.cid,
            r.block_cid,
            r.server_id,
            r.receipt_bytes,
            r.render_hash,
            r.produced_at
        ],
    )?;
    Ok(())
}

fn upsert_membership_on(conn: &Connection, m: &StoredMembership) -> Result<()> {
    conn.execute(
        "INSERT INTO memberships (channel_id, member_did, role, joined_at, source_block_cid)
         VALUES (?,?,?,?,?)
         ON CONFLICT(channel_id, member_did) DO UPDATE SET
            role = excluded.role,
            joined_at = excluded.joined_at,
            source_block_cid = excluded.source_block_cid",
        params![
            m.channel_id,
            m.member_did,
            m.role,
            m.joined_at,
            m.source_block_cid
        ],
    )?;
    Ok(())
}

fn row_to_stored_mls_group(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMlsGroup> {
    Ok(StoredMlsGroup {
        slug: r.get(0)?,
        group_id: r.get(1)?,
        state: r.get(2)?,
        epoch: r.get::<_, i64>(3)? as u64,
        group_info: r.get(4)?,
    })
}

impl SqliteStore {
    /// Open (or create) a SQLite file at `path` and run migrations.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        // WAL so the history readers (REST replay, CLI catch-up) and the
        // ingest writer can hold the same file open concurrently; the busy
        // timeout absorbs the brief writer-vs-writer overlap that remains.
        // The v0.0.1 store (jig-server/src/storage.rs) has done this since
        // day one — without it, concurrent readers hit SQLITE_BUSY.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;
        Self::migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory store (used for tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn migrate(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS blocks (
                cid            TEXT PRIMARY KEY,
                channel_id     TEXT,
                block_kind     TEXT NOT NULL,
                sender_did     TEXT NOT NULL,
                sender_sig     BLOB NOT NULL,
                bundle_bytes   BLOB NOT NULL,
                is_synthetic   INTEGER NOT NULL,
                hlc_wall_ms    INTEGER NOT NULL,
                hlc_logical    INTEGER NOT NULL,
                hlc_origin     TEXT NOT NULL,
                posted_at      INTEGER NOT NULL,
                origin_server  TEXT NOT NULL,
                federated_from TEXT
            );
            DROP INDEX IF EXISTS blocks_channel_hlc;
            CREATE INDEX IF NOT EXISTS blocks_channel_hlc_cid
                ON blocks(channel_id, hlc_wall_ms, hlc_logical, hlc_origin, cid);

            CREATE TABLE IF NOT EXISTS receipts (
                cid            TEXT PRIMARY KEY,
                block_cid      TEXT NOT NULL REFERENCES blocks(cid),
                server_id      TEXT NOT NULL,
                receipt_bytes  BLOB NOT NULL,
                render_hash    TEXT,
                produced_at    INTEGER NOT NULL,
                UNIQUE(block_cid, server_id)
            );
            CREATE INDEX IF NOT EXISTS receipts_block_hash
                ON receipts(block_cid, render_hash);

            CREATE TABLE IF NOT EXISTS channels (
                id          TEXT PRIMARY KEY,
                slug        TEXT UNIQUE NOT NULL,
                visibility  TEXT NOT NULL,
                created_at  INTEGER NOT NULL,
                owner_did   TEXT NOT NULL,
                -- NULL = live. Set by the channel-archive effect (soft delete);
                -- see `add_column_if_missing` below for why it is also applied
                -- as an ALTER for databases created before this column existed.
                archived_at INTEGER,
                -- Encryption suite fixed at creation. Same ALTER story.
                suite       TEXT NOT NULL DEFAULT 'none'
            );

            -- One row per encrypted channel: the delivery service's view of
            -- its MLS group. `epoch` is duplicated out of `state` so a commit
            -- can be applied with a compare-and-swap on it.
            CREATE TABLE IF NOT EXISTS mls_groups (
                slug        TEXT PRIMARY KEY,
                group_id    BLOB NOT NULL,
                state       BLOB NOT NULL,
                epoch       INTEGER NOT NULL,
                group_info  BLOB
            );

            -- Published MLS key packages. Consumed rows are kept (with
            -- `consumed_at`) so the same package cannot be uploaded again
            -- after it was handed out.
            CREATE TABLE IF NOT EXISTS mls_key_packages (
                reference     BLOB PRIMARY KEY,
                did           TEXT NOT NULL,
                package       BLOB NOT NULL,
                last_resort   INTEGER NOT NULL,
                published_at  INTEGER NOT NULL,
                consumed_at   INTEGER
            );
            CREATE INDEX IF NOT EXISTS mls_key_packages_did
                ON mls_key_packages(did, consumed_at, last_resort);

            -- DIDs that did this server's admission proof of work, and how
            -- much. Kept for good: the work was the price of being known.
            CREATE TABLE IF NOT EXISTS admission_proofs (
                did        TEXT PRIMARY KEY,
                bits       INTEGER NOT NULL,
                proven_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS memberships (
                channel_id        TEXT NOT NULL,
                member_did        TEXT NOT NULL,
                role              TEXT NOT NULL,
                joined_at         INTEGER NOT NULL,
                source_block_cid  TEXT NOT NULL,
                PRIMARY KEY (channel_id, member_did)
            );

            CREATE TABLE IF NOT EXISTS peers (
                server_url           TEXT PRIMARY KEY,
                server_did           TEXT NOT NULL,
                last_handshake_cid   TEXT,
                status               TEXT NOT NULL,
                alias                TEXT
            );

            CREATE TABLE IF NOT EXISTS alias_attestations (
                did                  TEXT NOT NULL,
                alias                TEXT NOT NULL,
                ns_did               TEXT NOT NULL,
                valid_from           INTEGER NOT NULL,
                valid_until          INTEGER NOT NULL,
                attestation_bytes    BLOB NOT NULL,
                suffix               TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (did, ns_did, suffix)
            );

            CREATE TABLE IF NOT EXISTS tofu_keys (
                local_nickname  TEXT PRIMARY KEY,
                did             TEXT NOT NULL,
                first_seen_at   INTEGER NOT NULL,
                locked          INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS subscription_cursors (
                peer_server_url  TEXT NOT NULL,
                origin_did       TEXT NOT NULL,
                last_hlc_wall_ms INTEGER NOT NULL,
                last_hlc_logical INTEGER NOT NULL,
                PRIMARY KEY (peer_server_url, origin_did)
            );

            CREATE TABLE IF NOT EXISTS bridge_kv (
                bridge_name  TEXT NOT NULL,
                ns           TEXT NOT NULL,
                key          TEXT NOT NULL,
                value        BLOB NOT NULL,
                expires_at   INTEGER,
                PRIMARY KEY (bridge_name, ns, key)
            );
            "#,
        )?;

        // One signed record per block of a channel this server sequences
        // (JEP-0002 rule 9). `slug` is how blocks name their channel;
        // `channel_id` is the channel-create CID the record signs.
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS ingest_records (
                block_cid  TEXT PRIMARY KEY REFERENCES blocks(cid),
                channel_id TEXT NOT NULL,
                slug       TEXT NOT NULL,
                seq        INTEGER NOT NULL,
                record     BLOB NOT NULL,
                UNIQUE (channel_id, seq)
            );
            CREATE INDEX IF NOT EXISTS ingest_records_slug_seq ON ingest_records(slug, seq);
            "#,
        )?;

        // `CREATE TABLE IF NOT EXISTS` is a no-op on a table that already
        // exists, so columns added after a database was first created must be
        // ALTERed in. Every already-deployed server has a `channels` table
        // without `archived_at`.
        add_column_if_missing(conn, "channels", "archived_at", "INTEGER")?;
        // Every channel created before v0.2 was unencrypted.
        add_column_if_missing(conn, "channels", "suite", "TEXT NOT NULL DEFAULT 'none'")?;
        rebuild_alias_attestations_with_suffix(conn)?;
        Ok(())
    }

    /// List all table names. Used by tests and diagnostic tooling.
    pub fn list_tables(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("SqliteStore mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // --- blocks ---

    pub fn insert_block(&self, b: &StoredBlock) -> Result<()> {
        insert_block_on(&self.conn.lock().expect("poisoned"), b)
    }

    /// Store `b` and the next record of its channel's chain in one
    /// transaction. `b.channel_id` must be the channel's slug.
    pub fn insert_block_sequenced(
        &self,
        b: &StoredBlock,
        signer: &RecordSigner<'_>,
    ) -> Result<IngestRecord> {
        let slug = b
            .channel_id
            .as_deref()
            .ok_or_else(|| PersistError::Corrupt("a sequenced block names no channel".into()))?;
        let mut conn = self.conn.lock().expect("poisoned");
        let tx = conn.transaction()?;
        insert_block_on(&tx, b)?;
        let record = sequence_on(&tx, slug, &b.cid, signer)?;
        tx.commit()?;
        Ok(record)
    }

    /// The record of `block_cid`, when this server sequenced it.
    pub fn get_ingest_record(&self, block_cid: &str) -> Result<Option<IngestRecord>> {
        let conn = self.conn.lock().expect("poisoned");
        let bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT record FROM ingest_records WHERE block_cid = ?",
                [block_cid],
                |r| r.get(0),
            )
            .optional()?;
        bytes
            .map(|b| {
                IngestRecord::decode(&b)
                    .map_err(|e| PersistError::Corrupt(format!("ingest record: {e}")))
            })
            .transpose()
    }

    /// Records of `slug` from `from_seq`, in order, at most `limit`
    /// ([`MAX_HISTORY_LIMIT`] at most). Records carry no content, so a client
    /// can check a whole chain without fetching every block.
    pub fn list_ingest_records(
        &self,
        slug: &str,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<IngestRecord>> {
        let limit = limit.min(MAX_HISTORY_LIMIT) as i64;
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT record FROM ingest_records WHERE slug = ?1 AND seq >= ?2
             ORDER BY seq ASC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![slug, from_seq as i64, limit], |r| {
                r.get::<_, Vec<u8>>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.iter()
            .map(|b| {
                IngestRecord::decode(b)
                    .map_err(|e| PersistError::Corrupt(format!("ingest record: {e}")))
            })
            .collect()
    }

    /// Give every block of a channel this server holds that has no record
    /// one, signed by `key`, continuing each channel's chain: the
    /// channel-create first, then the rest in their old history order.
    /// Returns how many records it wrote. Run at boot, so a store from
    /// before records existed is sequenced once.
    pub fn backfill_ingest_records(&self, key: &ed25519_dalek::SigningKey) -> Result<usize> {
        let mut conn = self.conn.lock().expect("poisoned");
        let tx = conn.transaction()?;
        let channels: Vec<(String, String)> = {
            let mut stmt = tx.prepare("SELECT id, slug FROM channels")?;
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut written = 0;
        for (channel_id, slug) in channels {
            let unsequenced: Vec<(String, i64)> = {
                let mut stmt = tx.prepare(
                    "SELECT b.cid, b.posted_at FROM blocks b
                       LEFT JOIN ingest_records r ON r.block_cid = b.cid
                      WHERE b.channel_id = ?1 AND r.block_cid IS NULL
                      ORDER BY (b.cid = ?2) DESC, b.hlc_wall_ms, b.hlc_logical,
                               b.hlc_origin, b.cid",
                )?;
                stmt.query_map(params![slug, channel_id], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (cid, posted_at) in unsequenced {
                let signer = RecordSigner {
                    channel_id: channel_id.clone(),
                    key,
                    ingest_wall_ms: u64::try_from(posted_at).unwrap_or(0).saturating_mul(1000),
                    ingest_logical: 0,
                };
                sequence_on(&tx, &slug, &cid, &signer)?;
                written += 1;
            }
        }
        tx.commit()?;
        Ok(written)
    }

    /// Whether `slug`'s history is sequenced, and so ordered by `seq`.
    fn is_sequenced(conn: &Connection, slug: &str) -> Result<bool> {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ingest_records WHERE slug = ?)",
            [slug],
            |r| r.get(0),
        )?)
    }

    pub fn get_block(&self, cid: &str) -> Result<Option<StoredBlock>> {
        let conn = self.conn.lock().expect("poisoned");
        let row = conn
            .query_row(
                &format!("SELECT {BLOCK_COLUMNS} FROM blocks WHERE cid = ?"),
                [cid],
                row_to_stored_block,
            )
            .optional()?;
        Ok(row)
    }

    /// Read one channel's timeline, **oldest-first** — the order a chat client
    /// renders top-to-bottom, so no caller has to reverse it.
    ///
    /// `slug` is the channel slug exactly as blocks carry it (`#hello`):
    /// `blocks.channel_id` holds the slug lifted from manifest metadata, not
    /// the channel-create CID. A slug with no blocks — including one that was
    /// never created — yields an empty vec, never an error; to a reader
    /// "nothing said yet" and "no such channel" are the same answer.
    ///
    /// `limit` is clamped to [`MAX_HISTORY_LIMIT`].
    ///
    /// `since_hlc` selects *which* window of at most `limit` blocks:
    /// - `None` → the **newest** `limit` blocks (initial pane fill: a client
    ///   opening a busy channel wants the tail, not the first 200 ever sent).
    /// - `Some(cursor)` → the **oldest** `limit` blocks strictly after
    ///   `cursor` (forward catch-up paging).
    ///
    /// Both windows come back oldest-first.
    pub fn list_blocks_by_channel(
        &self,
        slug: &str,
        limit: usize,
        since_hlc: Option<HlcPoint>,
    ) -> Result<Vec<StoredBlock>> {
        let limit = limit.min(MAX_HISTORY_LIMIT) as i64;
        let conn = self.conn.lock().expect("SqliteStore mutex poisoned");
        // A sequenced channel's newest window is by `seq`. The HLC cursor
        // keeps its old meaning (forward paging in author-clock order) until
        // its callers move to `seq`.
        if since_hlc.is_none() && Self::is_sequenced(&conn, slug)? {
            let mut stmt = conn.prepare(&sequenced_history_sql(false))?;
            let mut newest_first = stmt
                .query_map(params![slug, limit], row_to_stored_block)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            newest_first.reverse();
            return Ok(newest_first);
        }
        let mut stmt = conn.prepare(&history_sql(since_hlc.is_some()))?;

        let blocks = match since_hlc {
            Some(cursor) => stmt
                .query_map(
                    params![slug, cursor.wall_ms as i64, cursor.logical as i64, limit],
                    row_to_stored_block,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?,
            None => {
                // The no-cursor query walks the index backwards to take the
                // newest rows; flip it so callers always see oldest-first.
                let mut newest_first = stmt
                    .query_map(params![slug, limit], row_to_stored_block)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                newest_first.reverse();
                newest_first
            }
        };
        Ok(blocks)
    }

    /// The newest `limit` blocks of `slug` strictly older than the block
    /// `before`, oldest first: one page further back than a window that starts
    /// at `before`. `None` when `before` is not a block of `slug` — whether it
    /// is unknown or belongs to another channel, so a caller cannot use the
    /// cursor to learn where a CID lives.
    ///
    /// Older and newer are history order — `seq` on a sequenced channel, else
    /// (HLC wall, logical, origin, CID) — the same total order
    /// [`Self::list_blocks_by_channel`] returns, so pages join up with no gap
    /// and no overlap.
    pub fn list_blocks_before(
        &self,
        slug: &str,
        limit: usize,
        before: &str,
    ) -> Result<Option<Vec<StoredBlock>>> {
        let Some(cursor) = self.get_block(before)? else {
            return Ok(None);
        };
        if cursor.channel_id.as_deref() != Some(slug) {
            return Ok(None);
        }
        let limit = limit.min(MAX_HISTORY_LIMIT) as i64;
        let cursor_seq = self.get_ingest_record(&cursor.cid)?.map(|r| r.seq);
        let conn = self.conn.lock().expect("SqliteStore mutex poisoned");
        if let Some(cursor_seq) = cursor_seq {
            let mut stmt = conn.prepare(&sequenced_history_sql(true))?;
            let mut newest_first = stmt
                .query_map(params![slug, limit, cursor_seq as i64], row_to_stored_block)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            newest_first.reverse();
            return Ok(Some(newest_first));
        }
        let mut stmt = conn.prepare(&history_before_sql())?;
        let mut newest_first = stmt
            .query_map(
                params![
                    slug,
                    cursor.hlc_wall_ms as i64,
                    cursor.hlc_logical as i64,
                    cursor.hlc_origin,
                    cursor.cid,
                    limit
                ],
                row_to_stored_block,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        newest_first.reverse();
        Ok(Some(newest_first))
    }

    // --- receipts ---

    pub fn insert_receipt(&self, r: &StoredReceipt) -> Result<()> {
        insert_receipt_on(&self.conn.lock().expect("poisoned"), r)
    }

    pub fn get_receipts_for_block(&self, block_cid: &str) -> Result<Vec<StoredReceipt>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT cid, block_cid, server_id, receipt_bytes, render_hash, produced_at
             FROM receipts WHERE block_cid = ? ORDER BY produced_at ASC",
        )?;
        let rows = stmt
            .query_map([block_cid], |r| {
                Ok(StoredReceipt {
                    cid: r.get(0)?,
                    block_cid: r.get(1)?,
                    server_id: r.get(2)?,
                    receipt_bytes: r.get(3)?,
                    render_hash: r.get(4)?,
                    produced_at: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Count distinct render_hash values for a block. Used by the read-time
    /// parity check: a value > 1 means federated servers disagreed about
    /// the rendered output.
    pub fn count_distinct_render_hashes(&self, block_cid: &str) -> Result<i64> {
        let conn = self.conn.lock().expect("poisoned");
        let count: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT render_hash) FROM receipts
             WHERE block_cid = ? AND render_hash IS NOT NULL",
            [block_cid],
            |r| r.get(0),
        )?;
        Ok(count)
    }

    // --- channels ---

    /// Insert or update a channel row. Deliberately does NOT touch
    /// `archived_at`: re-applying a channel-create block (federation replay,
    /// restart catch-up) must never resurrect a channel an owner archived.
    pub fn upsert_channel(&self, c: &StoredChannel) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT INTO channels (id, slug, visibility, created_at, owner_did, suite)
             VALUES (?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET
                slug = excluded.slug,
                visibility = excluded.visibility,
                owner_did = excluded.owner_did",
            params![
                c.id,
                c.slug,
                c.visibility,
                c.created_at,
                c.owner_did,
                c.suite
            ],
        )?;
        Ok(())
    }

    /// Look up a live channel. Archived channels read as absent so ops that
    /// mutate an active channel (member-add, channel-promote) fail loudly
    /// instead of silently editing a retired one.
    pub fn get_channel_by_slug(&self, slug: &str) -> Result<Option<StoredChannel>> {
        let conn = self.conn.lock().expect("poisoned");
        conn.query_row(
            &format!(
                "SELECT {CHANNEL_COLUMNS} FROM channels WHERE slug = ? AND archived_at IS NULL"
            ),
            [slug],
            row_to_stored_channel,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Look up a channel whether or not it is archived. Used by the archive
    /// path itself (which must distinguish "no such channel" from "already
    /// archived") and by diagnostics.
    pub fn get_channel_by_slug_including_archived(
        &self,
        slug: &str,
    ) -> Result<Option<StoredChannel>> {
        let conn = self.conn.lock().expect("poisoned");
        conn.query_row(
            &format!("SELECT {CHANNEL_COLUMNS} FROM channels WHERE slug = ?"),
            [slug],
            row_to_stored_channel,
        )
        .optional()
        .map_err(Into::into)
    }

    /// List live channels — what `jig channel list` shows.
    pub fn list_channels(&self) -> Result<Vec<StoredChannel>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(&format!(
            "SELECT {CHANNEL_COLUMNS} FROM channels WHERE archived_at IS NULL ORDER BY slug"
        ))?;
        let rows = stmt
            .query_map([], row_to_stored_channel)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// List every channel row, archived ones included. For operator
    /// diagnostics — an archived channel is retired, not erased.
    pub fn list_channels_including_archived(&self) -> Result<Vec<StoredChannel>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(&format!(
            "SELECT {CHANNEL_COLUMNS} FROM channels ORDER BY slug"
        ))?;
        let rows = stmt
            .query_map([], row_to_stored_channel)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Soft-delete a channel: mark it archived so it drops out of
    /// [`list_channels`] and [`get_channel_by_slug`].
    ///
    /// Returns `false` when nothing changed — the slug is unknown, or the
    /// channel was already archived — so callers can report that instead of
    /// claiming a delete that did not happen. Already-archived rows keep their
    /// original timestamp (`archived_at IS NULL` guard), which makes this the
    /// audit record of when the channel was actually retired.
    ///
    /// [`list_channels`]: SqliteStore::list_channels
    /// [`get_channel_by_slug`]: SqliteStore::get_channel_by_slug
    pub fn archive_channel(&self, slug: &str, archived_at: i64) -> Result<bool> {
        let changed = self.conn.lock().expect("poisoned").execute(
            "UPDATE channels SET archived_at = ?2 WHERE slug = ?1 AND archived_at IS NULL",
            params![slug, archived_at],
        )?;
        Ok(changed > 0)
    }

    /// When a channel was archived, or `None` if it is live or unknown.
    pub fn channel_archived_at(&self, slug: &str) -> Result<Option<i64>> {
        let conn = self.conn.lock().expect("poisoned");
        conn.query_row(
            "SELECT archived_at FROM channels WHERE slug = ?",
            [slug],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()
        .map(Option::flatten)
        .map_err(Into::into)
    }

    // --- memberships ---

    pub fn upsert_membership(&self, m: &StoredMembership) -> Result<()> {
        upsert_membership_on(&self.conn.lock().expect("poisoned"), m)
    }

    /// Whether `member_did` is a member of the channel with this slug.
    ///
    /// Resolves the slug to the channel's **id (its CID)** first, because
    /// memberships are keyed by CID and not by slug. Passing a slug straight to
    /// the memberships table compiles, matches nothing, and silently denies
    /// every real member — see the CID-keying regression at `ingest.rs:1076`.
    ///
    /// An archived or unknown channel yields `false`: `get_channel_by_slug`
    /// excludes archived rows, so nobody is a member of a channel that is no
    /// longer live. Failing closed is the right direction for an authorization
    /// input.
    pub fn is_member(&self, slug: &str, member_did: &str) -> Result<bool> {
        // `get_channel_by_slug` takes and releases the lock before returning, so
        // acquiring it below is safe. Do NOT inline its body here while holding
        // the guard: `Mutex` is not reentrant and it would deadlock.
        let Some(channel) = self.get_channel_by_slug(slug)? else {
            return Ok(false);
        };
        let conn = self.conn.lock().expect("poisoned");
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM memberships WHERE channel_id = ? AND member_did = ? LIMIT 1",
                [channel.id.as_str(), member_did],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    pub fn list_members(&self, channel_id: &str) -> Result<Vec<StoredMembership>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT channel_id, member_did, role, joined_at, source_block_cid
             FROM memberships WHERE channel_id = ? ORDER BY joined_at ASC",
        )?;
        let rows = stmt
            .query_map([channel_id], |r| {
                Ok(StoredMembership {
                    channel_id: r.get(0)?,
                    member_did: r.get(1)?,
                    role: r.get(2)?,
                    joined_at: r.get(3)?,
                    source_block_cid: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Remove `member_did` from the channel at `slug`. Returns whether a row
    /// was removed.
    ///
    /// The primitive a `member-remove` block will need. There is no such
    /// block kind yet, so today this is reached only by operators and tests —
    /// but the delivery-time authorization check exists precisely so that
    /// when a membership goes away, delivery stops with it.
    pub fn remove_membership(&self, slug: &str, member_did: &str) -> Result<bool> {
        // Same lock discipline as `is_member`: resolve the slug first, then
        // take the connection.
        let Some(channel) = self.get_channel_by_slug(slug)? else {
            return Ok(false);
        };
        let removed = self.conn.lock().expect("poisoned").execute(
            "DELETE FROM memberships WHERE channel_id = ? AND member_did = ?",
            [channel.id.as_str(), member_did],
        )?;
        Ok(removed > 0)
    }

    // --- MLS delivery service ---

    /// Record an encrypted channel's epoch-0 public state. Replaces any row
    /// for the slug: a channel-create that failed after this write leaves a
    /// row the retry must be able to overwrite, and the `channels` slug check
    /// has already refused a second live channel.
    pub fn put_mls_group(&self, g: &StoredMlsGroup) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT OR REPLACE INTO mls_groups (slug, group_id, state, epoch, group_info)
             VALUES (?,?,?,?,?)",
            params![g.slug, g.group_id, g.state, g.epoch as i64, g.group_info],
        )?;
        Ok(())
    }

    pub fn get_mls_group(&self, slug: &str) -> Result<Option<StoredMlsGroup>> {
        let conn = self.conn.lock().expect("poisoned");
        conn.query_row(
            "SELECT slug, group_id, state, epoch, group_info FROM mls_groups WHERE slug = ?",
            [slug],
            row_to_stored_mls_group,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Land a commit-carrying block on an encrypted channel: advance the
    /// group from `from_epoch`, apply the membership change, and store the
    /// block and its receipt — all in one transaction, or none of it.
    ///
    /// One transaction because clients learn of a commit only from the stored
    /// block. A group advanced without its block (a write failing in between)
    /// is at an epoch no member can reach, and every later commit is refused
    /// as stale; a block stored without the advance is a commit members apply
    /// and the server never did. Either wedges the channel for good.
    ///
    /// With `signer`, the block also gets the next record of the channel's
    /// chain in the same transaction.
    ///
    /// Returns `None` — with nothing written — when another commit moved the
    /// group off `from_epoch` first, else the record written, if any.
    #[allow(clippy::too_many_arguments)]
    pub fn land_mls_commit(
        &self,
        slug: &str,
        from_epoch: u64,
        state: &[u8],
        to_epoch: u64,
        group_info: Option<&[u8]>,
        membership: &MembershipChange,
        block: &StoredBlock,
        receipt: &StoredReceipt,
        signer: Option<&RecordSigner<'_>>,
    ) -> Result<Option<Option<IngestRecord>>> {
        let mut conn = self.conn.lock().expect("poisoned");
        let tx = conn.transaction()?;
        // `group_info` replaces the stored one even when `None`: a group info
        // describes one epoch, and serving the previous epoch's under the new
        // one would send every external joiner into a stale commit.
        let advanced = tx.execute(
            "UPDATE mls_groups SET state = ?3, epoch = ?4, group_info = ?5
              WHERE slug = ?1 AND epoch = ?2",
            params![slug, from_epoch as i64, state, to_epoch as i64, group_info],
        )?;
        if advanced == 0 {
            return Ok(None);
        }
        match membership {
            MembershipChange::None => {}
            MembershipChange::Upsert(m) => upsert_membership_on(&tx, m)?,
            MembershipChange::Remove {
                channel_id,
                member_did,
            } => {
                tx.execute(
                    "DELETE FROM memberships WHERE channel_id = ? AND member_did = ?",
                    [channel_id.as_str(), member_did.as_str()],
                )?;
            }
        }
        insert_block_on(&tx, block)?;
        insert_receipt_on(&tx, receipt)?;
        let record = signer
            .map(|signer| sequence_on(&tx, slug, &block.cid, signer))
            .transpose()?;
        tx.commit()?;
        Ok(Some(record))
    }

    /// Store a validated key package. Returns `false` if this package (by
    /// reference) was ever stored before, consumed or not.
    pub fn insert_key_package(
        &self,
        reference: &[u8],
        did: &str,
        package: &[u8],
        last_resort: bool,
        published_at: i64,
    ) -> Result<bool> {
        let inserted = self.conn.lock().expect("poisoned").execute(
            "INSERT OR IGNORE INTO mls_key_packages
                (reference, did, package, last_resort, published_at)
             VALUES (?,?,?,?,?)",
            params![reference, did, package, last_resort, published_at],
        )?;
        Ok(inserted > 0)
    }

    /// Hand out one of `did`'s key packages: the oldest ordinary one, which is
    /// consumed, or failing that the newest last-resort one, which is not.
    pub fn take_key_package(&self, did: &str, now: i64) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().expect("poisoned");
        let ordinary: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT reference, package FROM mls_key_packages
                  WHERE did = ? AND consumed_at IS NULL AND last_resort = 0
                  ORDER BY published_at ASC, reference ASC LIMIT 1",
                [did],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((reference, package)) = ordinary {
            conn.execute(
                "UPDATE mls_key_packages SET consumed_at = ? WHERE reference = ?",
                params![now, reference],
            )?;
            return Ok(Some(package));
        }
        conn.query_row(
            "SELECT package FROM mls_key_packages
              WHERE did = ? AND last_resort = 1
              ORDER BY published_at DESC, reference DESC LIMIT 1",
            [did],
            |r| r.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    /// Whether `did` has done this server's admission proof of work.
    pub fn admission_proven(&self, did: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("poisoned");
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_proofs WHERE did = ?)",
            [did],
            |r| r.get(0),
        )?)
    }

    /// Record that `did` did `bits` of admission proof of work. A later,
    /// larger proof replaces a smaller one.
    pub fn record_admission_proof(&self, did: &str, bits: u8) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT INTO admission_proofs (did, bits, proven_at) VALUES (?, ?, ?)
             ON CONFLICT(did) DO UPDATE SET bits = MAX(bits, excluded.bits)",
            params![did, bits, chrono::Utc::now().timestamp()],
        )?;
        Ok(())
    }

    /// How many ordinary (consumable) key packages `did` has left, and whether
    /// it has a last-resort one.
    pub fn key_package_stock(&self, did: &str) -> Result<(u64, bool)> {
        let conn = self.conn.lock().expect("poisoned");
        let ordinary: i64 = conn.query_row(
            "SELECT COUNT(*) FROM mls_key_packages
              WHERE did = ? AND consumed_at IS NULL AND last_resort = 0",
            [did],
            |r| r.get(0),
        )?;
        let last_resort: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM mls_key_packages WHERE did = ? AND last_resort = 1)",
            [did],
            |r| r.get(0),
        )?;
        Ok((ordinary as u64, last_resort))
    }

    // --- peers ---

    pub fn upsert_peer(&self, p: &StoredPeer) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT INTO peers (server_url, server_did, last_handshake_cid, status, alias)
             VALUES (?,?,?,?,?)
             ON CONFLICT(server_url) DO UPDATE SET
                server_did = excluded.server_did,
                last_handshake_cid = excluded.last_handshake_cid,
                status = excluded.status,
                alias = excluded.alias",
            params![
                p.server_url,
                p.server_did,
                p.last_handshake_cid,
                p.status,
                p.alias
            ],
        )?;
        Ok(())
    }

    pub fn list_peers(&self) -> Result<Vec<StoredPeer>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT server_url, server_did, last_handshake_cid, status, alias FROM peers",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(StoredPeer {
                    server_url: r.get(0)?,
                    server_did: r.get(1)?,
                    last_handshake_cid: r.get(2)?,
                    status: r.get(3)?,
                    alias: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // --- alias attestations ---

    /// Insert or replace `a.did`'s binding under `a.alias`'s suffix at
    /// `a.ns_did`. One DID holds at most one name per suffix per nameserver.
    pub fn upsert_alias_attestation(&self, a: &StoredAliasAttestation) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT INTO alias_attestations
                 (did, alias, ns_did, valid_from, valid_until, attestation_bytes, suffix)
             VALUES (?,?,?,?,?,?,?)
             ON CONFLICT(did, ns_did, suffix) DO UPDATE SET
                alias = excluded.alias,
                valid_from = excluded.valid_from,
                valid_until = excluded.valid_until,
                attestation_bytes = excluded.attestation_bytes",
            params![
                a.did,
                a.alias,
                a.ns_did,
                a.valid_from,
                a.valid_until,
                a.attestation_bytes,
                alias_suffix_of(&a.alias)
            ],
        )?;
        Ok(())
    }

    pub fn find_alias_attestation(
        &self,
        alias: &str,
        as_of: i64,
    ) -> Result<Option<StoredAliasAttestation>> {
        let conn = self.conn.lock().expect("poisoned");
        conn.query_row(
            "SELECT did, alias, ns_did, valid_from, valid_until, attestation_bytes
             FROM alias_attestations
             WHERE alias = ? AND valid_from <= ? AND valid_until > ?
             ORDER BY valid_from DESC LIMIT 1",
            params![alias, as_of, as_of],
            row_to_stored_alias_attestation,
        )
        .optional()
        .map_err(Into::into)
    }

    /// The alias `did` holds under `suffix` at `ns_did` with a binding valid at
    /// `as_of`, if any. `suffix` is matched case-insensitively, like the key.
    pub fn alias_held_by(
        &self,
        did: &str,
        ns_did: &str,
        suffix: &str,
        as_of: i64,
    ) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("poisoned");
        conn.query_row(
            "SELECT alias FROM alias_attestations
             WHERE did = ? AND ns_did = ? AND suffix = ? AND valid_from <= ? AND valid_until > ?",
            params![did, ns_did, suffix.to_ascii_lowercase(), as_of, as_of],
            |r| r.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    /// Immediately expire `did`'s binding under `alias`'s suffix at `ns_did`
    /// by setting valid_until = as_of. Called during key rotation so the
    /// old-DID row no longer appears as a current binding for its alias; the
    /// same DID's names under other suffixes are untouched.
    pub fn expire_alias_attestation(
        &self,
        did: &str,
        ns_did: &str,
        alias: &str,
        as_of: i64,
    ) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "UPDATE alias_attestations SET valid_until = ?
             WHERE did = ? AND ns_did = ? AND suffix = ?",
            rusqlite::params![as_of, did, ns_did, alias_suffix_of(alias)],
        )?;
        Ok(())
    }

    /// Lowercase `alias` on the rows `is_legacy` selects by their
    /// `attestation_bytes`, in one transaction. Returns how many rows changed.
    ///
    /// This store does not know any nameserver's formats: the caller decides
    /// which rows are safe to rewrite, namely those it re-signs from their
    /// columns on read. A row's key cannot change, since `suffix` is already
    /// stored lowercase. Fails, changing nothing, when a lowercased alias
    /// would then be held by two different DIDs at the same `ns_did` with
    /// bindings valid at `as_of`. Only the aliases this call rewrote are
    /// checked, so an unrelated existing conflict does not block it.
    pub fn normalize_alias_case(
        &self,
        is_legacy: impl Fn(&[u8]) -> bool,
        as_of: i64,
    ) -> Result<usize> {
        let conn = self.conn.lock().expect("poisoned");
        let tx = conn.unchecked_transaction()?;
        let rows = tx
            .prepare(
                "SELECT did, alias, ns_did, valid_from, valid_until, attestation_bytes
                 FROM alias_attestations",
            )?
            .query_map([], row_to_stored_alias_attestation)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut rewritten = Vec::new();
        for a in rows {
            let lower = a.alias.to_ascii_lowercase();
            if lower == a.alias || !is_legacy(&a.attestation_bytes) {
                continue;
            }
            tx.execute(
                "UPDATE alias_attestations SET alias = ?
                 WHERE did = ? AND ns_did = ? AND suffix = ?",
                params![lower, a.did, a.ns_did, alias_suffix_of(&a.alias)],
            )?;
            rewritten.push((a.ns_did, lower));
        }
        for (ns_did, alias) in &rewritten {
            let holders: i64 = tx.query_row(
                "SELECT COUNT(DISTINCT did) FROM alias_attestations
                 WHERE ns_did = ?1 AND alias = ?2 AND valid_from <= ?3 AND valid_until > ?3",
                params![ns_did, alias, as_of],
                |r| r.get(0),
            )?;
            if holders > 1 {
                return Err(PersistError::AliasCaseClash(alias.clone()));
            }
        }
        tx.commit()?;
        Ok(rewritten.len())
    }

    /// List all currently-valid attestations (valid_from <= as_of < valid_until).
    /// Used by the debug-gated /v1/handles enumeration.
    pub fn list_alias_attestations(&self, as_of: i64) -> Result<Vec<StoredAliasAttestation>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT did, alias, ns_did, valid_from, valid_until, attestation_bytes
             FROM alias_attestations
             WHERE valid_from <= ? AND valid_until > ?
             ORDER BY alias ASC",
        )?;
        let rows = stmt
            .query_map(
                rusqlite::params![as_of, as_of],
                row_to_stored_alias_attestation,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // --- TOFU keys ---

    /// Returns the existing locked DID if present, else None.
    pub fn get_tofu_key(&self, nickname: &str) -> Result<Option<StoredTofuKey>> {
        let conn = self.conn.lock().expect("poisoned");
        conn.query_row(
            "SELECT local_nickname, did, first_seen_at, locked FROM tofu_keys WHERE local_nickname = ?",
            [nickname],
            |r| {
                Ok(StoredTofuKey {
                    local_nickname: r.get(0)?,
                    did: r.get(1)?,
                    first_seen_at: r.get(2)?,
                    locked: r.get::<_, i64>(3)? != 0,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn insert_tofu_key(&self, t: &StoredTofuKey) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT INTO tofu_keys (local_nickname, did, first_seen_at, locked) VALUES (?,?,?,?)",
            params![t.local_nickname, t.did, t.first_seen_at, t.locked as i64],
        )?;
        Ok(())
    }

    // --- subscription cursors ---

    pub fn upsert_cursor(&self, c: &StoredCursor) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT INTO subscription_cursors (peer_server_url, origin_did, last_hlc_wall_ms, last_hlc_logical)
             VALUES (?,?,?,?)
             ON CONFLICT(peer_server_url, origin_did) DO UPDATE SET
                last_hlc_wall_ms = excluded.last_hlc_wall_ms,
                last_hlc_logical = excluded.last_hlc_logical",
            params![
                c.peer_server_url,
                c.origin_did,
                c.last_hlc_wall_ms,
                c.last_hlc_logical
            ],
        )?;
        Ok(())
    }

    pub fn get_cursor(
        &self,
        peer_server_url: &str,
        origin_did: &str,
    ) -> Result<Option<StoredCursor>> {
        let conn = self.conn.lock().expect("poisoned");
        conn.query_row(
            "SELECT peer_server_url, origin_did, last_hlc_wall_ms, last_hlc_logical
             FROM subscription_cursors
             WHERE peer_server_url = ? AND origin_did = ?",
            [peer_server_url, origin_did],
            |r| {
                Ok(StoredCursor {
                    peer_server_url: r.get(0)?,
                    origin_did: r.get(1)?,
                    last_hlc_wall_ms: r.get(2)?,
                    last_hlc_logical: r.get(3)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    // --- bridge KV (namespaced, per-bridge-scoped, optional TTL) ---

    pub fn bridge_kv_put(
        &self,
        bridge: &str,
        ns: &str,
        key: &str,
        value: &[u8],
        expires_at: Option<i64>,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("SqliteStore mutex poisoned");
        conn.execute(
            "INSERT INTO bridge_kv (bridge_name, ns, key, value, expires_at) VALUES (?,?,?,?,?)
             ON CONFLICT(bridge_name, ns, key) DO UPDATE SET value=excluded.value, expires_at=excluded.expires_at",
            rusqlite::params![bridge, ns, key, value, expires_at],
        )?;
        Ok(())
    }

    pub fn bridge_kv_get(
        &self,
        bridge: &str,
        ns: &str,
        key: &str,
        now: i64,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().expect("SqliteStore mutex poisoned");
        let row = conn
            .query_row(
                "SELECT value, expires_at FROM bridge_kv WHERE bridge_name=? AND ns=? AND key=?",
                rusqlite::params![bridge, ns, key],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<i64>>(1)?)),
            )
            .optional()?;
        Ok(match row {
            Some((_, Some(exp))) if exp <= now => None, // expired
            Some((v, _)) => Some(v),
            None => None,
        })
    }

    pub fn bridge_kv_delete(&self, bridge: &str, ns: &str, key: &str) -> Result<()> {
        let conn = self.conn.lock().expect("SqliteStore mutex poisoned");
        conn.execute(
            "DELETE FROM bridge_kv WHERE bridge_name=? AND ns=? AND key=?",
            rusqlite::params![bridge, ns, key],
        )?;
        Ok(())
    }

    pub fn bridge_kv_sweep(&self, bridge: &str, ns: &str, now: i64) -> Result<u64> {
        let conn = self.conn.lock().expect("SqliteStore mutex poisoned");
        let n = conn.execute(
            "DELETE FROM bridge_kv WHERE bridge_name=? AND ns=? AND expires_at IS NOT NULL AND expires_at <= ?",
            rusqlite::params![bridge, ns, now],
        )?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_block(cid: &str, channel: Option<&str>) -> StoredBlock {
        StoredBlock {
            cid: cid.to_string(),
            channel_id: channel.map(String::from),
            block_kind: "text-render".to_string(),
            sender_did: "did:jig:zSender".to_string(),
            sender_sig: vec![0u8; 64],
            bundle_bytes: b"{\"test\":true}".to_vec(),
            is_synthetic: false,
            hlc_wall_ms: 1747680000000,
            hlc_logical: 0,
            hlc_origin: "did:jig:zOrigin".to_string(),
            posted_at: 1747680001,
            origin_server: "ws://127.0.0.1:7117".to_string(),
            federated_from: None,
        }
    }

    fn test_signer(key: &ed25519_dalek::SigningKey, wall: u64) -> RecordSigner<'_> {
        RecordSigner {
            channel_id: "bafy_create".to_string(),
            key,
            ingest_wall_ms: wall,
            ingest_logical: 0,
        }
    }

    fn at_hlc(cid: &str, wall: u64) -> StoredBlock {
        StoredBlock {
            hlc_wall_ms: wall,
            ..sample_block(cid, Some("#seq"))
        }
    }

    /// A sequenced channel's chain starts at 0, links each record to the
    /// last, and orders history by `seq` whatever the authors' clocks say.
    #[test]
    fn a_sequenced_channel_is_ordered_by_its_chain() {
        let store = SqliteStore::open_in_memory().unwrap();
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let did =
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string();
        // Each author claims an earlier time than the last.
        let order = ["bafy_create", "bafy_b", "bafy_c", "bafy_d"];
        let mut records = Vec::new();
        for (i, cid) in order.iter().enumerate() {
            let block = at_hlc(cid, 1_000 - i as u64 * 10);
            records.push(
                store
                    .insert_block_sequenced(&block, &test_signer(&key, 5_000 + i as u64))
                    .unwrap(),
            );
        }
        assert!(records[0].is_genesis());
        for pair in records.windows(2) {
            assert!(pair[1].follows(&pair[0]));
        }
        for record in &records {
            record.verify(&did).unwrap();
        }
        assert_eq!(
            store.get_ingest_record("bafy_c").unwrap().as_ref(),
            Some(&records[2])
        );

        let history = block_cids(store.list_blocks_by_channel("#seq", 50, None).unwrap());
        assert_eq!(history, cids_of(&order), "history follows seq, not hlc_ts");
        let newest_two = block_cids(store.list_blocks_by_channel("#seq", 2, None).unwrap());
        assert_eq!(newest_two, cids_of(&order[2..]));
        let older = block_cids(
            store
                .list_blocks_before("#seq", 2, "bafy_c")
                .unwrap()
                .unwrap(),
        );
        assert_eq!(older, cids_of(&order[..2]), "paging back follows seq too");

        let from_one = store.list_ingest_records("#seq", 1, 2).unwrap();
        assert_eq!(from_one, records[1..3].to_vec());
    }

    fn cids_of(cids: &[&str]) -> Vec<String> {
        cids.iter().map(|c| c.to_string()).collect()
    }

    fn block_cids(blocks: Vec<StoredBlock>) -> Vec<String> {
        blocks.into_iter().map(|b| b.cid).collect()
    }

    /// Blocks stored before records existed get them once, continuing any
    /// chain already there, with the channel-create first.
    #[test]
    fn backfill_sequences_a_store_once() {
        let store = SqliteStore::open_in_memory().unwrap();
        let key = jig_core::crypto::ed25519::generate_signing_key();
        store
            .upsert_channel(&StoredChannel {
                id: "bafy_create".to_string(),
                slug: "#seq".to_string(),
                visibility: "open".to_string(),
                created_at: 0,
                owner_did: "did:jig:zOwner".to_string(),
                suite: "none".to_string(),
            })
            .unwrap();
        // A post whose author's clock runs before the channel's creation.
        store.insert_block(&at_hlc("bafy_early_post", 10)).unwrap();
        store.insert_block(&at_hlc("bafy_create", 500)).unwrap();
        store.insert_block(&at_hlc("bafy_late_post", 900)).unwrap();

        assert_eq!(store.backfill_ingest_records(&key).unwrap(), 3);
        assert_eq!(store.backfill_ingest_records(&key).unwrap(), 0, "only once");
        let chain = store.list_ingest_records("#seq", 0, 50).unwrap();
        let order: Vec<&str> = chain.iter().map(|r| r.block_cid.as_str()).collect();
        assert_eq!(order, ["bafy_create", "bafy_early_post", "bafy_late_post"]);
        assert!(chain[0].is_genesis());
        assert!(chain[1].follows(&chain[0]) && chain[2].follows(&chain[1]));

        // A later block continues the same chain.
        let next = store
            .insert_block_sequenced(&at_hlc("bafy_next", 1_000), &test_signer(&key, 9_000))
            .unwrap();
        assert!(next.follows(&chain[2]));
    }

    fn sample_receipt(
        cid: &str,
        block_cid: &str,
        server: &str,
        render_hash: Option<&str>,
    ) -> StoredReceipt {
        StoredReceipt {
            cid: cid.to_string(),
            block_cid: block_cid.to_string(),
            server_id: server.to_string(),
            receipt_bytes: b"{\"v\":\"0.2\"}".to_vec(),
            render_hash: render_hash.map(String::from),
            produced_at: 1747680001,
        }
    }

    #[test]
    fn schema_creates_all_v002_tables() {
        let store = SqliteStore::open_in_memory().unwrap();
        let tables = store.list_tables().unwrap();
        for required in [
            "alias_attestations",
            "blocks",
            "channels",
            "memberships",
            "peers",
            "receipts",
            "subscription_cursors",
            "tofu_keys",
        ] {
            assert!(
                tables.contains(&required.to_string()),
                "missing table: {required}"
            );
        }
    }

    /// `CREATE TABLE IF NOT EXISTS` never adds columns to a table that already
    /// exists, so a live server's `jig.db` would keep the pre-archive
    /// `channels` shape. Migration must backfill the column.
    #[test]
    fn migrate_adds_archived_at_to_a_pre_existing_channels_table() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE channels (
                 id          TEXT PRIMARY KEY,
                 slug        TEXT UNIQUE NOT NULL,
                 visibility  TEXT NOT NULL,
                 created_at  INTEGER NOT NULL,
                 owner_did   TEXT NOT NULL
             );
             INSERT INTO channels VALUES ('ch_1', '#legacy', 'open', 0, 'did:jig:zOwner');",
        )
        .unwrap();

        SqliteStore::migrate(&conn).unwrap();
        // Idempotent: running it twice must not error on a duplicate column.
        SqliteStore::migrate(&conn).unwrap();

        let cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('channels')")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            cols.contains(&"archived_at".to_string()),
            "channels must gain archived_at; got {cols:?}"
        );

        let store = SqliteStore {
            conn: Mutex::new(conn),
        };
        assert_eq!(
            store.list_channels().unwrap().len(),
            1,
            "pre-existing rows must read as un-archived"
        );
        assert_eq!(
            store.list_channels().unwrap()[0].suite,
            "none",
            "channels created before v0.2 were unencrypted"
        );
    }

    /// A commit that cannot be stored must not advance the group either —
    /// otherwise the server sits at an epoch no member can reach.
    #[test]
    fn a_commit_lands_whole_or_not_at_all() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .put_mls_group(&StoredMlsGroup {
                slug: "#sealed".to_string(),
                group_id: b"g".to_vec(),
                state: b"s0".to_vec(),
                epoch: 0,
                group_info: Some(b"i0".to_vec()),
            })
            .unwrap();
        let block = sample_block("bafy_commit", Some("#sealed"));
        let receipt = StoredReceipt {
            cid: "r_commit".to_string(),
            block_cid: block.cid.clone(),
            server_id: "did:jig:zServer".to_string(),
            receipt_bytes: b"{}".to_vec(),
            render_hash: None,
            produced_at: 0,
        };
        let add = MembershipChange::Upsert(StoredMembership {
            channel_id: "ch".to_string(),
            member_did: "did:jig:zBob".to_string(),
            role: "member".to_string(),
            joined_at: 0,
            source_block_cid: block.cid.clone(),
        });
        // The block is already stored, so the insert fails part-way through.
        store.insert_block(&block).unwrap();
        assert!(
            store
                .land_mls_commit("#sealed", 0, b"s1", 1, None, &add, &block, &receipt, None)
                .is_err()
        );
        let g = store.get_mls_group("#sealed").unwrap().unwrap();
        assert_eq!(
            (g.epoch, g.state.as_slice()),
            (0, &b"s0"[..]),
            "rolled back"
        );
        assert!(store.list_members("ch").unwrap().is_empty(), "rolled back");

        let fresh = sample_block("bafy_commit2", Some("#sealed"));
        let receipt = StoredReceipt {
            cid: "r_commit2".to_string(),
            block_cid: fresh.cid.clone(),
            ..receipt
        };
        assert!(
            store
                .land_mls_commit("#sealed", 0, b"s1", 1, None, &add, &fresh, &receipt, None)
                .unwrap()
                .is_some()
        );
        let g = store.get_mls_group("#sealed").unwrap().unwrap();
        assert_eq!(g.epoch, 1);
        assert_eq!(
            g.group_info, None,
            "an epoch-0 group info is not served as epoch 1's"
        );
        assert_eq!(store.list_members("ch").unwrap().len(), 1);
        assert!(
            store
                .land_mls_commit("#sealed", 0, b"sX", 1, None, &add, &fresh, &receipt, None)
                .unwrap()
                .is_none(),
            "a commit from a passed epoch writes nothing"
        );
    }

    #[test]
    fn key_packages_are_consumed_once_and_last_resort_never() {
        let store = SqliteStore::open_in_memory().unwrap();
        let did = "did:jig:zBob";
        assert!(
            store
                .insert_key_package(b"r1", did, b"kp1", false, 1)
                .unwrap()
        );
        assert!(
            store
                .insert_key_package(b"r2", did, b"kp2", false, 2)
                .unwrap()
        );
        assert!(
            store
                .insert_key_package(b"lr", did, b"kpL", true, 3)
                .unwrap()
        );
        assert!(
            !store
                .insert_key_package(b"r1", did, b"kp1", false, 9)
                .unwrap(),
            "a package is stored once"
        );
        assert_eq!(store.key_package_stock(did).unwrap(), (2, true));
        assert_eq!(store.take_key_package(did, 10).unwrap().unwrap(), b"kp1");
        assert_eq!(store.take_key_package(did, 11).unwrap().unwrap(), b"kp2");
        assert_eq!(store.take_key_package(did, 12).unwrap().unwrap(), b"kpL");
        assert_eq!(store.take_key_package(did, 13).unwrap().unwrap(), b"kpL");
        assert_eq!(store.key_package_stock(did).unwrap(), (0, true));
        assert!(
            !store
                .insert_key_package(b"r1", did, b"kp1", false, 14)
                .unwrap(),
            "a consumed package cannot be uploaded again"
        );
        assert!(
            store
                .take_key_package("did:jig:zNobody", 15)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn insert_and_get_block_round_trip() {
        let store = SqliteStore::open_in_memory().unwrap();
        let b = sample_block("bafy_test", Some("ch_hello"));
        store.insert_block(&b).unwrap();
        let fetched = store.get_block(&b.cid).unwrap().unwrap();
        assert_eq!(fetched, b);
    }

    #[test]
    fn get_block_returns_none_for_unknown_cid() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert!(store.get_block("bafy_missing").unwrap().is_none());
    }

    #[test]
    fn count_distinct_render_hashes_supports_parity_query() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .insert_block(&sample_block("bafy_x", Some("#h")))
            .unwrap();
        store
            .insert_receipt(&sample_receipt(
                "r1",
                "bafy_x",
                "did:jig:zA",
                Some("hash-1"),
            ))
            .unwrap();
        store
            .insert_receipt(&sample_receipt(
                "r2",
                "bafy_x",
                "did:jig:zB",
                Some("hash-1"),
            ))
            .unwrap();
        store
            .insert_receipt(&sample_receipt(
                "r3",
                "bafy_x",
                "did:jig:zC",
                Some("hash-2"),
            ))
            .unwrap();
        // 2 distinct hashes — divergent!
        assert_eq!(store.count_distinct_render_hashes("bafy_x").unwrap(), 2);
    }

    #[test]
    fn count_distinct_render_hashes_ignores_synthetic_null_receipts() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.insert_block(&sample_block("bafy_y", None)).unwrap();
        // 3 receipts, but all have render_hash = NULL (synthetic)
        store
            .insert_receipt(&sample_receipt("r1", "bafy_y", "did:jig:zA", None))
            .unwrap();
        store
            .insert_receipt(&sample_receipt("r2", "bafy_y", "did:jig:zB", None))
            .unwrap();
        store
            .insert_receipt(&sample_receipt("r3", "bafy_y", "did:jig:zC", None))
            .unwrap();
        assert_eq!(store.count_distinct_render_hashes("bafy_y").unwrap(), 0);
    }

    #[test]
    fn receipts_unique_per_block_and_server() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.insert_block(&sample_block("bafy_z", None)).unwrap();
        store
            .insert_receipt(&sample_receipt("r1", "bafy_z", "did:jig:zA", Some("h")))
            .unwrap();
        // Same (block_cid, server_id) — must fail uniqueness
        let dup = sample_receipt("r2", "bafy_z", "did:jig:zA", Some("h"));
        assert!(store.insert_receipt(&dup).is_err());
    }

    #[test]
    fn upsert_and_get_channel_by_slug() {
        let store = SqliteStore::open_in_memory().unwrap();
        let ch = StoredChannel {
            id: "ch_id_1".to_string(),
            slug: "#hello".to_string(),
            visibility: "open".to_string(),
            created_at: 0,
            owner_did: "did:jig:zOwner".to_string(),
            suite: "none".to_string(),
        };
        store.upsert_channel(&ch).unwrap();
        let fetched = store.get_channel_by_slug("#hello").unwrap().unwrap();
        assert_eq!(fetched, ch);
    }

    fn sample_membership(channel_id: &str, member_did: &str) -> StoredMembership {
        StoredMembership {
            channel_id: channel_id.to_string(),
            member_did: member_did.to_string(),
            role: "member".to_string(),
            joined_at: 0,
            source_block_cid: "bafyseed".to_string(),
        }
    }

    #[test]
    fn is_member_finds_a_member_and_refuses_a_stranger() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_channel(&sample_channel("bafychannelcid", "#private"))
            .unwrap();
        store
            .upsert_membership(&sample_membership("bafychannelcid", "did:jig:zMember"))
            .unwrap();

        assert!(store.is_member("#private", "did:jig:zMember").unwrap());
        assert!(!store.is_member("#private", "did:jig:zStranger").unwrap());
    }

    /// The regression this method exists to prevent: memberships are keyed by
    /// the channel's CID, not its slug. A lookup that forwards the slug straight
    /// to the memberships table compiles, matches nothing, and denies every
    /// legitimate member — a silent wrong answer, the worst kind.
    #[test]
    fn remove_membership_deletes_the_row_and_reports_it() {
        let s = SqliteStore::open_in_memory().unwrap();
        s.upsert_channel(&StoredChannel {
            id: "bafy-c".into(),
            slug: "#c".into(),
            visibility: "restricted".into(),
            created_at: 0,
            owner_did: "did:jig:zOwner".into(),
            suite: "none".to_string(),
        })
        .unwrap();
        s.upsert_membership(&StoredMembership {
            channel_id: "bafy-c".into(),
            member_did: "did:jig:zM".into(),
            role: "member".into(),
            joined_at: 0,
            source_block_cid: "bafy-add".into(),
        })
        .unwrap();
        assert!(s.is_member("#c", "did:jig:zM").unwrap());

        assert!(s.remove_membership("#c", "did:jig:zM").unwrap());
        assert!(!s.is_member("#c", "did:jig:zM").unwrap());
        assert!(
            !s.remove_membership("#c", "did:jig:zM").unwrap(),
            "removing twice reports that nothing was there"
        );
        assert!(!s.remove_membership("#nope", "did:jig:zM").unwrap());
    }

    #[test]
    fn is_member_resolves_slug_to_channel_id_first() {
        let store = SqliteStore::open_in_memory().unwrap();
        // The id and the slug are deliberately unequal, so a lookup that used
        // the slug would find nothing.
        store
            .upsert_channel(&sample_channel("bafyrealcid", "#private"))
            .unwrap();
        store
            .upsert_membership(&sample_membership("bafyrealcid", "did:jig:zMember"))
            .unwrap();

        assert!(
            store.is_member("#private", "did:jig:zMember").unwrap(),
            "is_member must resolve the slug to the channel id before querying \
             memberships — see the CID-keying regression at ingest.rs:1076"
        );
    }

    #[test]
    fn is_member_is_false_for_an_unknown_channel() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert!(!store.is_member("#nope", "did:jig:zAnyone").unwrap());
    }

    /// An archived channel has no members. `get_channel_by_slug` excludes
    /// archived rows, and failing closed is right for an authorization input.
    #[test]
    fn is_member_is_false_once_the_channel_is_archived() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_channel(&sample_channel("bafycid", "#doomed"))
            .unwrap();
        store
            .upsert_membership(&sample_membership("bafycid", "did:jig:zMember"))
            .unwrap();
        assert!(
            store.is_member("#doomed", "did:jig:zMember").unwrap(),
            "precondition: membership holds while the channel is live"
        );

        store.archive_channel("#doomed", 1).unwrap();
        assert!(
            !store.is_member("#doomed", "did:jig:zMember").unwrap(),
            "an archived channel must have no members"
        );
    }

    fn sample_channel(id: &str, slug: &str) -> StoredChannel {
        StoredChannel {
            id: id.to_string(),
            slug: slug.to_string(),
            visibility: "open".to_string(),
            created_at: 0,
            owner_did: "did:jig:zOwner".to_string(),
            suite: "none".to_string(),
        }
    }

    #[test]
    fn archive_channel_hides_it_from_list_channels() {
        // The user-visible symptom of "there is no way to delete a channel" is
        // that the row stays in `jig channel list` forever. Archiving must fix
        // exactly that.
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_channel(&sample_channel("ch_1", "#keep"))
            .unwrap();
        store
            .upsert_channel(&sample_channel("ch_2", "#scratch"))
            .unwrap();

        assert!(store.archive_channel("#scratch", 1_747_680_000).unwrap());

        let slugs: Vec<String> = store
            .list_channels()
            .unwrap()
            .into_iter()
            .map(|c| c.slug)
            .collect();
        assert_eq!(slugs, vec!["#keep".to_string()]);
    }

    #[test]
    fn archive_channel_keeps_the_row_and_records_when() {
        // Soft delete: the row survives so receipts/blocks referencing the
        // channel CID stay resolvable, and the decision is auditable.
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_channel(&sample_channel("ch_1", "#scratch"))
            .unwrap();

        store.archive_channel("#scratch", 4_242).unwrap();

        assert_eq!(store.channel_archived_at("#scratch").unwrap(), Some(4_242));
        let row = store
            .get_channel_by_slug_including_archived("#scratch")
            .unwrap()
            .expect("archived channel row must still exist");
        assert_eq!(row.id, "ch_1");
        assert_eq!(
            store.list_channels_including_archived().unwrap().len(),
            1,
            "archived channels must remain visible to diagnostics"
        );
    }

    #[test]
    fn archived_channel_is_not_resolvable_as_an_active_channel() {
        // member-add / channel-promote resolve via get_channel_by_slug; an
        // archived channel must read as absent so those ops fail loudly.
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_channel(&sample_channel("ch_1", "#scratch"))
            .unwrap();
        store.archive_channel("#scratch", 1).unwrap();
        assert!(store.get_channel_by_slug("#scratch").unwrap().is_none());
    }

    #[test]
    fn archive_channel_reports_false_for_an_unknown_slug() {
        // A silent Ok on a nonexistent channel would let the CLI print
        // "deleted" for a typo'd slug.
        let store = SqliteStore::open_in_memory().unwrap();
        assert!(!store.archive_channel("#never-existed", 1).unwrap());
        assert_eq!(store.channel_archived_at("#never-existed").unwrap(), None);
    }

    #[test]
    fn archive_channel_reports_false_when_already_archived() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_channel(&sample_channel("ch_1", "#scratch"))
            .unwrap();
        assert!(store.archive_channel("#scratch", 10).unwrap());
        assert!(!store.archive_channel("#scratch", 20).unwrap());
        assert_eq!(
            store.channel_archived_at("#scratch").unwrap(),
            Some(10),
            "re-archiving must not rewrite the original timestamp"
        );
    }

    /// Pins the history decision: archiving a channel destroys NO blocks.
    /// If a future change makes delete cascade to `blocks`, this fails.
    #[test]
    fn archiving_a_channel_destroys_no_message_history() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_channel(&sample_channel("ch_1", "#scratch"))
            .unwrap();
        store
            .insert_block(&sample_block("bafy_msg_1", Some("#scratch")))
            .unwrap();
        store
            .insert_receipt(&sample_receipt("r_1", "bafy_msg_1", "srv", None))
            .unwrap();

        store.archive_channel("#scratch", 1).unwrap();

        assert!(store.get_block("bafy_msg_1").unwrap().is_some());
        assert_eq!(
            store
                .list_blocks_by_channel("#scratch", 100, None)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.get_receipts_for_block("bafy_msg_1").unwrap().len(), 1);
    }

    #[test]
    fn upsert_channel_does_not_resurrect_an_archived_channel() {
        // upsert_channel is the channel-create effect path; it must not be an
        // accidental un-archive, or replaying an old create block would undo
        // a deliberate delete.
        let store = SqliteStore::open_in_memory().unwrap();
        let ch = sample_channel("ch_1", "#scratch");
        store.upsert_channel(&ch).unwrap();
        store.archive_channel("#scratch", 7).unwrap();
        store.upsert_channel(&ch).unwrap();
        assert_eq!(store.channel_archived_at("#scratch").unwrap(), Some(7));
    }

    #[test]
    fn upsert_membership_idempotent() {
        let store = SqliteStore::open_in_memory().unwrap();
        let m = StoredMembership {
            channel_id: "ch_id_1".to_string(),
            member_did: "did:jig:zDj".to_string(),
            role: "owner".to_string(),
            joined_at: 100,
            source_block_cid: "bafy_create".to_string(),
        };
        store.upsert_membership(&m).unwrap();
        store.upsert_membership(&m).unwrap(); // idempotent
        let members = store.list_members("ch_id_1").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0], m);
    }

    #[test]
    fn upsert_peer_updates_status_on_conflict() {
        let store = SqliteStore::open_in_memory().unwrap();
        let p1 = StoredPeer {
            server_url: "wss://peer-a".to_string(),
            server_did: "did:jig:zA".to_string(),
            last_handshake_cid: Some("bafy_hello1".to_string()),
            status: "active".to_string(),
            alias: Some("a.jig".to_string()),
        };
        store.upsert_peer(&p1).unwrap();
        let p2 = StoredPeer {
            status: "disconnected".to_string(),
            ..p1.clone()
        };
        store.upsert_peer(&p2).unwrap();
        let peers = store.list_peers().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].status, "disconnected");
    }

    #[test]
    fn find_alias_attestation_respects_validity_window() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = StoredAliasAttestation {
            did: "did:jig:zDj".to_string(),
            alias: "dj@dj.jig".to_string(),
            ns_did: "did:jig:zNs".to_string(),
            valid_from: 1000,
            valid_until: 2000,
            attestation_bytes: b"{}".to_vec(),
        };
        store.upsert_alias_attestation(&a).unwrap();
        assert!(
            store
                .find_alias_attestation("dj@dj.jig", 1500)
                .unwrap()
                .is_some()
        );
        // Before the window
        assert!(
            store
                .find_alias_attestation("dj@dj.jig", 500)
                .unwrap()
                .is_none()
        );
        // After the window (valid_until is exclusive)
        assert!(
            store
                .find_alias_attestation("dj@dj.jig", 2000)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn list_alias_attestations_returns_only_valid_window_rows() {
        let store = SqliteStore::open_in_memory().unwrap();
        let now = 1000_i64;

        // Valid (now is between valid_from and valid_until)
        store
            .upsert_alias_attestation(&StoredAliasAttestation {
                did: "did:jig:zA".into(),
                alias: "a@dj.jig".into(),
                ns_did: "did:jig:zNs".into(),
                valid_from: 500,
                valid_until: 2000,
                attestation_bytes: b"{}".to_vec(),
            })
            .unwrap();

        // Expired (valid_until <= now)
        store
            .upsert_alias_attestation(&StoredAliasAttestation {
                did: "did:jig:zB".into(),
                alias: "b@dj.jig".into(),
                ns_did: "did:jig:zNs".into(),
                valid_from: 100,
                valid_until: 500,
                attestation_bytes: b"{}".to_vec(),
            })
            .unwrap();

        // Future (valid_from > now)
        store
            .upsert_alias_attestation(&StoredAliasAttestation {
                did: "did:jig:zC".into(),
                alias: "c@dj.jig".into(),
                ns_did: "did:jig:zNs".into(),
                valid_from: 2000,
                valid_until: 3000,
                attestation_bytes: b"{}".to_vec(),
            })
            .unwrap();

        let valid = store.list_alias_attestations(now).unwrap();
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].alias, "a@dj.jig");
    }

    #[test]
    fn tofu_keys_lock_on_first_insert() {
        let store = SqliteStore::open_in_memory().unwrap();
        let key = StoredTofuKey {
            local_nickname: "dj".to_string(),
            did: "did:jig:zDj".to_string(),
            first_seen_at: 100,
            locked: true,
        };
        store.insert_tofu_key(&key).unwrap();
        let fetched = store.get_tofu_key("dj").unwrap().unwrap();
        assert_eq!(fetched, key);
        // Inserting a different DID for same nickname — must fail (PRIMARY KEY)
        let conflict = StoredTofuKey {
            local_nickname: "dj".to_string(),
            did: "did:jig:zOther".to_string(),
            first_seen_at: 200,
            locked: true,
        };
        assert!(store.insert_tofu_key(&conflict).is_err());
    }

    #[test]
    fn cursor_upsert_and_get_round_trip() {
        let store = SqliteStore::open_in_memory().unwrap();
        let c = StoredCursor {
            peer_server_url: "wss://peer-a".to_string(),
            origin_did: "did:jig:zOrigin".to_string(),
            last_hlc_wall_ms: 1747680000000,
            last_hlc_logical: 7,
        };
        store.upsert_cursor(&c).unwrap();
        // Update
        let c2 = StoredCursor {
            last_hlc_logical: 9,
            ..c.clone()
        };
        store.upsert_cursor(&c2).unwrap();
        let fetched = store
            .get_cursor("wss://peer-a", "did:jig:zOrigin")
            .unwrap()
            .unwrap();
        assert_eq!(fetched.last_hlc_logical, 9);
    }

    #[test]
    fn bridge_kv_put_get_expiry_delete_sweep() {
        let s = SqliteStore::open_in_memory().unwrap();
        // put + get (no expiry)
        s.bridge_kv_put(
            "email",
            "addrbook",
            "alice@example.com",
            b"did:jig:zS",
            None,
        )
        .unwrap();
        assert_eq!(
            s.bridge_kv_get("email", "addrbook", "alice@example.com", 0)
                .unwrap()
                .as_deref(),
            Some(&b"did:jig:zS"[..])
        );
        // expiry: now past expires_at -> None
        s.bridge_kv_put("email", "addrbook", "bob@example.com", b"x", Some(50))
            .unwrap();
        assert!(
            s.bridge_kv_get("email", "addrbook", "bob@example.com", 100)
                .unwrap()
                .is_none()
        );
        // but readable before expiry
        assert!(
            s.bridge_kv_get("email", "addrbook", "bob@example.com", 10)
                .unwrap()
                .is_some()
        );
        // sweep removes expired
        let removed = s.bridge_kv_sweep("email", "addrbook", 100).unwrap();
        assert_eq!(removed, 1);
        // delete
        s.bridge_kv_delete("email", "addrbook", "alice@example.com")
            .unwrap();
        assert!(
            s.bridge_kv_get("email", "addrbook", "alice@example.com", 0)
                .unwrap()
                .is_none()
        );
    }

    // ---- connection pragmas ---------------------------------------------

    #[test]
    fn file_backed_store_opens_in_wal_mode_with_busy_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(&dir.path().join("jig.sqlite")).unwrap();
        let conn = store.conn.lock().unwrap();

        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");

        let busy_ms: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert!(busy_ms >= 1000, "busy_timeout too small: {busy_ms}ms");
    }

    #[test]
    fn writer_is_not_blocked_by_a_concurrent_open_reader() {
        // Under the default rollback journal an open read transaction holds a
        // SHARED lock, so a second connection's commit fails with SQLITE_BUSY.
        // WAL lets the two coexist — this is the regression this test pins.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jig.sqlite");
        let reader = SqliteStore::open(&path).unwrap();
        let writer = SqliteStore::open(&path).unwrap();

        let rconn = reader.conn.lock().unwrap();
        rconn.execute_batch("BEGIN").unwrap();
        let _: i64 = rconn
            .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))
            .unwrap();

        writer
            .insert_block(&sample_block("bafy_concurrent", Some("#h")))
            .expect("write must succeed while a reader transaction is open");

        rconn.execute_batch("COMMIT").unwrap();
        drop(rconn);

        assert!(reader.get_block("bafy_concurrent").unwrap().is_some());
    }

    // ---- list_blocks_by_channel ------------------------------------------

    /// Blocks share a wall clock so ordering is decided by `hlc_logical` —
    /// exactly the tie-break the `blocks_channel_hlc_cid` index encodes.
    fn timeline_block(cid: &str, channel: &str, logical: u32) -> StoredBlock {
        StoredBlock {
            hlc_logical: logical,
            ..sample_block(cid, Some(channel))
        }
    }

    fn seed_two_channel_timeline(store: &SqliteStore) {
        for (cid, channel, logical) in [
            ("bafy_h1", "#hello", 0),
            ("bafy_o1", "#other", 0),
            ("bafy_h2", "#hello", 1),
            ("bafy_o2", "#other", 1),
            ("bafy_h3", "#hello", 2),
        ] {
            store
                .insert_block(&timeline_block(cid, channel, logical))
                .unwrap();
        }
    }

    #[test]
    fn list_blocks_by_channel_returns_only_that_channel_oldest_first() {
        let store = SqliteStore::open_in_memory().unwrap();
        seed_two_channel_timeline(&store);

        let cids: Vec<String> = store
            .list_blocks_by_channel("#hello", 50, None)
            .unwrap()
            .into_iter()
            .map(|b| b.cid)
            .collect();
        assert_eq!(cids, vec!["bafy_h1", "bafy_h2", "bafy_h3"]);
    }

    #[test]
    fn list_blocks_by_channel_keeps_the_newest_blocks_when_limit_truncates() {
        // A chat pane wants the tail of the timeline, rendered oldest-at-top.
        let store = SqliteStore::open_in_memory().unwrap();
        seed_two_channel_timeline(&store);

        let cids: Vec<String> = store
            .list_blocks_by_channel("#hello", 2, None)
            .unwrap()
            .into_iter()
            .map(|b| b.cid)
            .collect();
        assert_eq!(cids, vec!["bafy_h2", "bafy_h3"]);
    }

    #[test]
    fn list_blocks_by_channel_clamps_limit_to_max_history_limit() {
        let store = SqliteStore::open_in_memory().unwrap();
        for i in 0..(MAX_HISTORY_LIMIT + 25) {
            store
                .insert_block(&timeline_block(&format!("bafy_{i:04}"), "#hello", i as u32))
                .unwrap();
        }
        let got = store
            .list_blocks_by_channel("#hello", usize::MAX, None)
            .unwrap();
        assert_eq!(got.len(), MAX_HISTORY_LIMIT);
        // Clamping keeps the newest window, so the last block is the newest one.
        assert_eq!(got.last().unwrap().cid, format!("bafy_{:04}", 224));
    }

    #[test]
    fn list_blocks_by_channel_returns_empty_for_unknown_slug() {
        let store = SqliteStore::open_in_memory().unwrap();
        seed_two_channel_timeline(&store);
        assert!(
            store
                .list_blocks_by_channel("#nope", 50, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn list_blocks_by_channel_since_hlc_pages_forward_from_the_cursor() {
        let store = SqliteStore::open_in_memory().unwrap();
        seed_two_channel_timeline(&store);
        let first = store.list_blocks_by_channel("#hello", 50, None).unwrap();
        let cursor = HlcPoint {
            wall_ms: first[0].hlc_wall_ms,
            logical: first[0].hlc_logical,
        };

        let cids: Vec<String> = store
            .list_blocks_by_channel("#hello", 50, Some(cursor))
            .unwrap()
            .into_iter()
            .map(|b| b.cid)
            .collect();
        assert_eq!(cids, vec!["bafy_h2", "bafy_h3"], "cursor is exclusive");
    }

    #[test]
    fn list_blocks_before_pages_backwards_without_gaps_or_overlap() {
        let store = SqliteStore::open_in_memory().unwrap();
        seed_two_channel_timeline(&store);
        let page = |before: &str, limit| -> Option<Vec<String>> {
            store
                .list_blocks_before("#hello", limit, before)
                .unwrap()
                .map(|blocks| blocks.into_iter().map(|b| b.cid).collect())
        };
        assert_eq!(page("bafy_h3", 1), Some(vec!["bafy_h2".to_string()]));
        assert_eq!(
            page("bafy_h3", 50),
            Some(vec!["bafy_h1".to_string(), "bafy_h2".to_string()])
        );
        assert_eq!(page("bafy_h1", 50), Some(vec![]), "the start of history");
        assert_eq!(page("bafy_o2", 50), None, "another channel's block");
        assert_eq!(page("bafy_nope", 50), None, "an unknown block");
    }

    #[test]
    fn a_page_boundary_between_identical_hlcs_skips_nothing() {
        // One author, one millisecond: every block shares (wall, logical,
        // origin), and only the CID orders them.
        let store = SqliteStore::open_in_memory().unwrap();
        for cid in ["bafy_t1", "bafy_t2", "bafy_t3", "bafy_t4", "bafy_t5"] {
            store.insert_block(&timeline_block(cid, "#tie", 0)).unwrap();
        }
        let cids = |blocks: Vec<StoredBlock>| -> Vec<String> {
            blocks.into_iter().map(|b| b.cid).collect()
        };
        let mut seen = cids(store.list_blocks_by_channel("#tie", 2, None).unwrap());
        assert_eq!(seen, vec!["bafy_t4", "bafy_t5"]);
        loop {
            let older = cids(
                store
                    .list_blocks_before("#tie", 2, &seen[0])
                    .unwrap()
                    .unwrap(),
            );
            if older.is_empty() {
                break;
            }
            seen.splice(0..0, older);
        }
        assert_eq!(
            seen,
            vec!["bafy_t1", "bafy_t2", "bafy_t3", "bafy_t4", "bafy_t5"]
        );
    }

    #[test]
    fn list_blocks_by_channel_since_hlc_takes_the_oldest_page_after_the_cursor() {
        let store = SqliteStore::open_in_memory().unwrap();
        seed_two_channel_timeline(&store);
        let cursor = HlcPoint {
            wall_ms: 1747680000000,
            logical: 0,
        };
        let cids: Vec<String> = store
            .list_blocks_by_channel("#hello", 1, Some(cursor))
            .unwrap()
            .into_iter()
            .map(|b| b.cid)
            .collect();
        assert_eq!(cids, vec!["bafy_h2"]);
    }

    #[test]
    fn list_blocks_by_channel_queries_use_the_blocks_channel_hlc_index() {
        // The index exists precisely for this read path; a regression to a
        // full table scan or a TEMP B-TREE sort would be invisible otherwise.
        let store = SqliteStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();

        // EXPLAIN QUERY PLAN keeps the statement's bound parameters, so each
        // variant has to be given its full arity before it will step.
        let variants: [(String, Vec<i64>); 3] = [
            (history_sql(false), vec![0, 50]),
            (history_sql(true), vec![0, 0, 0, 50]),
            (history_before_sql(), vec![0, 0, 0, 0, 0, 50]),
        ];
        for (sql, args) in variants {
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let plan: String = stmt
                .query_map(rusqlite::params_from_iter(args), |r| r.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
                .join(" | ");
            assert!(
                plan.contains("blocks_channel_hlc"),
                "query does not use the channel/HLC index: {plan}\nsql: {sql}"
            );
            assert!(
                !plan.contains("TEMP B-TREE"),
                "ORDER BY is not satisfied by the index: {plan}\nsql: {sql}"
            );
        }
    }

    fn att(did: &str, alias: &str, bytes: &[u8]) -> StoredAliasAttestation {
        StoredAliasAttestation {
            did: did.into(),
            alias: alias.into(),
            ns_did: "did:jig:zNs".into(),
            valid_from: 0,
            valid_until: 2000,
            attestation_bytes: bytes.to_vec(),
        }
    }

    fn alias_rows(conn: &Connection) -> Vec<(String, String, String)> {
        conn.prepare("SELECT did, alias, suffix FROM alias_attestations ORDER BY did, suffix")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    /// A nameserver database from before suffixes keyed its aliases by
    /// `(did, ns_did)`. Migration rebuilds the table keyed by suffix and keeps
    /// every row, and running it again changes nothing.
    #[test]
    fn migrate_rekeys_a_pre_existing_alias_table_by_suffix() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE alias_attestations (
                 did TEXT NOT NULL, alias TEXT NOT NULL, ns_did TEXT NOT NULL,
                 valid_from INTEGER NOT NULL, valid_until INTEGER NOT NULL,
                 attestation_bytes BLOB NOT NULL,
                 PRIMARY KEY (did, ns_did)
             );
             INSERT INTO alias_attestations VALUES
                 ('did:jig:zA', 'Alice@dj.jig', 'did:jig:zNs', 0, 2000, x'7b7d'),
                 ('did:jig:zB', 'bare', 'did:jig:zNs', 0, 2000, x'7b7d');",
        )
        .unwrap();

        SqliteStore::migrate(&conn).unwrap();
        let once = alias_rows(&conn);
        SqliteStore::migrate(&conn).unwrap();
        assert_eq!(alias_rows(&conn), once, "a second run is a no-op");
        assert_eq!(
            once,
            [
                ("did:jig:zA".into(), "Alice@dj.jig".into(), "dj.jig".into()),
                ("did:jig:zB".into(), "bare".into(), "".into()),
            ]
        );

        let pk: Vec<String> = conn
            .prepare(
                "SELECT name FROM pragma_table_info('alias_attestations') WHERE pk > 0 ORDER BY pk",
            )
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(pk, ["did", "ns_did", "suffix"]);
    }

    #[test]
    fn one_did_holds_a_name_per_suffix() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_alias_attestation(&att("did:jig:zA", "dj@a.example", b"1"))
            .unwrap();
        store
            .upsert_alias_attestation(&att("did:jig:zA", "dj@b.example", b"2"))
            .unwrap();
        // Same suffix again replaces that suffix's row only.
        store
            .upsert_alias_attestation(&att("did:jig:zA", "deejay@a.example", b"3"))
            .unwrap();

        assert!(
            store
                .find_alias_attestation("dj@a.example", 1000)
                .unwrap()
                .is_none()
        );
        let a = store
            .find_alias_attestation("deejay@a.example", 1000)
            .unwrap()
            .unwrap();
        assert_eq!(a.attestation_bytes, b"3");
        let b = store
            .find_alias_attestation("dj@b.example", 1000)
            .unwrap()
            .unwrap();
        assert_eq!(b.attestation_bytes, b"2");

        let held = |suffix| {
            store
                .alias_held_by("did:jig:zA", "did:jig:zNs", suffix, 1000)
                .unwrap()
        };
        assert_eq!(held("a.example").as_deref(), Some("deejay@a.example"));
        assert_eq!(held("b.example").as_deref(), Some("dj@b.example"));
        assert_eq!(held("c.example"), None);
        assert_eq!(held("B.Example").as_deref(), Some("dj@b.example"));
    }

    #[test]
    fn expiring_a_name_leaves_the_same_did_s_other_suffixes() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_alias_attestation(&att("did:jig:zA", "dj@a.example", b"1"))
            .unwrap();
        store
            .upsert_alias_attestation(&att("did:jig:zA", "dj@b.example", b"2"))
            .unwrap();
        store
            .expire_alias_attestation("did:jig:zA", "did:jig:zNs", "dj@a.example", 500)
            .unwrap();
        assert!(
            store
                .find_alias_attestation("dj@a.example", 1000)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .find_alias_attestation("dj@b.example", 1000)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn normalize_alias_case_rewrites_only_the_rows_the_caller_selects() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_alias_attestation(&att("did:jig:zA", "Alice@A.example", b"legacy"))
            .unwrap();
        // Signed rows are never rewritten, even if their alias had capitals.
        store
            .upsert_alias_attestation(&att("did:jig:zB", "Bob@b.example", b"signed"))
            .unwrap();
        let before = store.find_alias_attestation("Bob@b.example", 1000).unwrap();

        let changed = store
            .normalize_alias_case(|bytes| bytes == b"legacy", 1000)
            .unwrap();
        assert_eq!(changed, 1);
        let alice = store
            .find_alias_attestation("alice@a.example", 1000)
            .unwrap()
            .unwrap();
        assert_eq!(alice.attestation_bytes, b"legacy");
        assert_eq!(
            store.find_alias_attestation("Bob@b.example", 1000).unwrap(),
            before,
            "a signed row comes out byte-identical"
        );
        let conn = store.conn.lock().unwrap();
        assert!(alias_rows(&conn).contains(&(
            "did:jig:zA".into(),
            "alice@a.example".into(),
            "a.example".into()
        )));
        assert!(
            alias_rows(&conn).contains(&(
                "did:jig:zB".into(),
                "Bob@b.example".into(),
                "b.example".into()
            )),
            "the signed row's key is lowercase, its alias untouched"
        );
        drop(conn);
        assert_eq!(
            store.normalize_alias_case(|_| true, 1000).unwrap(),
            1,
            "Bob, once allowed"
        );
        assert_eq!(
            store.normalize_alias_case(|_| true, 1000).unwrap(),
            0,
            "idempotent"
        );
    }

    #[test]
    fn normalize_alias_case_refuses_to_merge_two_holders() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_alias_attestation(&att("did:jig:zA", "Alice@a.example", b"x"))
            .unwrap();
        store
            .upsert_alias_attestation(&att("did:jig:zB", "alice@a.example", b"x"))
            .unwrap();
        let conn = store.conn.lock().unwrap();
        let before = alias_rows(&conn);
        drop(conn);

        let err = store.normalize_alias_case(|_| true, 1000).unwrap_err();
        assert!(
            matches!(&err, PersistError::AliasCaseClash(a) if a == "alice@a.example"),
            "{err}"
        );
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            alias_rows(&conn),
            before,
            "nothing changed, zB's row included"
        );
    }

    #[test]
    fn normalize_alias_case_ignores_conflicts_it_did_not_create() {
        let store = SqliteStore::open_in_memory().unwrap();
        // The same alias at two different nameservers is not a clash.
        let mut other_ns = att("did:jig:zB", "alice@a.example", b"x");
        other_ns.ns_did = "did:jig:zOtherNs".into();
        store
            .upsert_alias_attestation(&att("did:jig:zA", "Alice@a.example", b"x"))
            .unwrap();
        store.upsert_alias_attestation(&other_ns).unwrap();
        // An existing conflict between two rows it does not rewrite.
        store
            .upsert_alias_attestation(&att("did:jig:zC", "carol@a.example", b"x"))
            .unwrap();
        store
            .upsert_alias_attestation(&att("did:jig:zD", "carol@a.example", b"x"))
            .unwrap();

        assert_eq!(store.normalize_alias_case(|_| true, 1000).unwrap(), 1);
    }

    /// The suffix key is lowercase, so a DID's `Bob@B.example` and
    /// `bob@b.example` are one name, not two.
    #[test]
    fn one_name_per_suffix_holds_whatever_the_case() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert_alias_attestation(&att("did:jig:zA", "Bob@B.example", b"1"))
            .unwrap();
        store
            .upsert_alias_attestation(&att("did:jig:zA", "bob@b.example", b"2"))
            .unwrap();
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            alias_rows(&conn),
            [(
                "did:jig:zA".into(),
                "bob@b.example".into(),
                "b.example".into()
            )]
        );
    }
}
