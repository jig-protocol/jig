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

#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
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
/// Both variants are shaped to ride the `blocks_channel_hlc` index end to end:
/// equality on the leading `channel_id`, then an ordered walk of the trailing
/// HLC columns (backwards for the no-cursor case) so SQLite never materialises
/// a sort.
fn history_sql(with_cursor: bool) -> String {
    if with_cursor {
        format!(
            "SELECT {BLOCK_COLUMNS} FROM blocks \
             WHERE channel_id = ?1 AND (hlc_wall_ms, hlc_logical) > (?2, ?3) \
             ORDER BY hlc_wall_ms ASC, hlc_logical ASC, hlc_origin ASC \
             LIMIT ?4"
        )
    } else {
        format!(
            "SELECT {BLOCK_COLUMNS} FROM blocks \
             WHERE channel_id = ?1 \
             ORDER BY hlc_wall_ms DESC, hlc_logical DESC, hlc_origin DESC \
             LIMIT ?2"
        )
    }
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

fn row_to_stored_channel(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredChannel> {
    Ok(StoredChannel {
        id: r.get(0)?,
        slug: r.get(1)?,
        visibility: r.get(2)?,
        created_at: r.get(3)?,
        owner_did: r.get(4)?,
    })
}

const CHANNEL_COLUMNS: &str = "id, slug, visibility, created_at, owner_did";

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
            CREATE INDEX IF NOT EXISTS blocks_channel_hlc
                ON blocks(channel_id, hlc_wall_ms, hlc_logical, hlc_origin);

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
                archived_at INTEGER
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
                PRIMARY KEY (did, ns_did)
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

        // `CREATE TABLE IF NOT EXISTS` is a no-op on a table that already
        // exists, so columns added after a database was first created must be
        // ALTERed in. Every already-deployed server has a `channels` table
        // without `archived_at`.
        add_column_if_missing(conn, "channels", "archived_at", "INTEGER")?;
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
        self.conn.lock().expect("poisoned").execute(
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

    // --- receipts ---

    pub fn insert_receipt(&self, r: &StoredReceipt) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
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
            "INSERT INTO channels (id, slug, visibility, created_at, owner_did) VALUES (?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET
                slug = excluded.slug,
                visibility = excluded.visibility,
                owner_did = excluded.owner_did",
            params![c.id, c.slug, c.visibility, c.created_at, c.owner_did],
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
        self.conn.lock().expect("poisoned").execute(
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

    pub fn upsert_alias_attestation(&self, a: &StoredAliasAttestation) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT INTO alias_attestations (did, alias, ns_did, valid_from, valid_until, attestation_bytes)
             VALUES (?,?,?,?,?,?)
             ON CONFLICT(did, ns_did) DO UPDATE SET
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
                a.attestation_bytes
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
            |r| {
                Ok(StoredAliasAttestation {
                    did: r.get(0)?,
                    alias: r.get(1)?,
                    ns_did: r.get(2)?,
                    valid_from: r.get(3)?,
                    valid_until: r.get(4)?,
                    attestation_bytes: r.get(5)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    /// Immediately expire an attestation for a specific (did, ns_did) pair by
    /// setting valid_until = as_of. Called during key rotation to ensure the
    /// old-DID row no longer appears as a current binding for its alias.
    pub fn expire_alias_attestation(&self, did: &str, ns_did: &str, as_of: i64) -> Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "UPDATE alias_attestations SET valid_until = ?
             WHERE did = ? AND ns_did = ?",
            rusqlite::params![as_of, did, ns_did],
        )?;
        Ok(())
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
            .query_map(rusqlite::params![as_of, as_of], |r| {
                Ok(StoredAliasAttestation {
                    did: r.get(0)?,
                    alias: r.get(1)?,
                    ns_did: r.get(2)?,
                    valid_from: r.get(3)?,
                    valid_until: r.get(4)?,
                    attestation_bytes: r.get(5)?,
                })
            })?
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
        };
        store.upsert_channel(&ch).unwrap();
        let fetched = store.get_channel_by_slug("#hello").unwrap().unwrap();
        assert_eq!(fetched, ch);
    }

    fn sample_channel(id: &str, slug: &str) -> StoredChannel {
        StoredChannel {
            id: id.to_string(),
            slug: slug.to_string(),
            visibility: "open".to_string(),
            created_at: 0,
            owner_did: "did:jig:zOwner".to_string(),
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
    /// exactly the tie-break the `blocks_channel_hlc` index encodes.
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
        let variants: [(String, Vec<i64>); 2] = [
            (history_sql(false), vec![0, 50]),
            (history_sql(true), vec![0, 0, 0, 50]),
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
}
