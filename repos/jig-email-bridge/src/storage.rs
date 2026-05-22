//! Email bridge storage

use anyhow::Result;
use rusqlite::{Connection, params};
use std::path::Path;

#[derive(Clone)]
pub struct EmailStorage {
    db_path: std::path::PathBuf,
}

impl EmailStorage {
    pub fn new(path: &Path) -> Result<Self> {
        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;

        // Initialize schema
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS email_mappings (
                email TEXT PRIMARY KEY,
                jig_user TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS email_threads (
                message_id TEXT PRIMARY KEY,
                jig_thread TEXT NOT NULL,
                email_thread TEXT NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS outbound_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                jig_message_id TEXT NOT NULL,
                to_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                sent_at TEXT
            );

            CREATE TABLE IF NOT EXISTS thread_map (
                jig_thread TEXT PRIMARY KEY,
                email_message_id TEXT,
                email_references TEXT
            );",
        )?;

        Ok(Self {
            db_path: path.to_path_buf(),
        })
    }

    /// Map email address to Jig user
    pub fn map_email_to_user(&self, email: &str, user: &str) -> Result<()> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute(
            "INSERT OR REPLACE INTO email_mappings (email, jig_user, created_at) 
             VALUES (?1, ?2, datetime('now'))",
            params![email, user],
        )?;
        Ok(())
    }

    /// Get Jig user for email address
    pub fn get_user_for_email(&self, email: &str) -> Result<Option<String>> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare("SELECT jig_user FROM email_mappings WHERE email = ?1")?;
        let user = stmt.query_row(params![email], |row| row.get(0)).ok();
        Ok(user)
    }

    /// Queue an outbound email to be sent
    pub fn queue_outbound(
        &self,
        jig_message_id: &str,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<()> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute(
            "INSERT INTO outbound_queue (jig_message_id, to_email, subject, body, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, 'pending', datetime('now'))",
            params![jig_message_id, to, subject, body],
        )?;
        Ok(())
    }

    /// Fetch the next pending outbound email if available
    pub fn next_outbound(&self) -> Result<Option<OutboundEmail>> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT id, jig_message_id, to_email, subject, body FROM outbound_queue \
             WHERE status = 'pending' ORDER BY id LIMIT 1",
        )?;
        let email = stmt
            .query_row([], |row| {
                Ok(OutboundEmail {
                    id: row.get(0)?,
                    jig_message_id: row.get(1)?,
                    to: row.get(2)?,
                    subject: row.get(3)?,
                    body: row.get(4)?,
                })
            })
            .ok();
        Ok(email)
    }

    /// Mark an outbound email as sent
    pub fn mark_outbound_sent(&self, id: i64) -> Result<()> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute(
            "UPDATE outbound_queue SET status = 'sent', sent_at = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }
}

/// Simple representation of an outbound email queued for sending
pub struct OutboundEmail {
    pub id: i64,
    pub jig_message_id: String,
    pub to: String,
    pub subject: String,
    pub body: String,
}

impl OutboundEmail {
    /// Convert this queued item into an EmailMessage for SMTP sending
    pub fn to_email_message(&self) -> crate::types::EmailMessage {
        crate::types::EmailMessage::new(
            "bridge@jig.local".to_string(), // This will be overridden by from_address config
            self.to.clone(),
            self.subject.clone(),
            self.body.clone(),
        )
    }
}

impl EmailStorage {
    /// Get thread headers (In-Reply-To, References) for a Jig thread
    pub fn get_thread_headers(&self, jig_thread: &str) -> Result<(Option<String>, Option<String>)> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT email_message_id, email_references FROM thread_map WHERE jig_thread = ?1",
        )?;
        let row = stmt
            .query_row(params![jig_thread], |r| Ok((r.get(0).ok(), r.get(1).ok())))
            .ok();
        Ok(row.unwrap_or((None, None)))
    }

    /// Upsert a mapping from jig_thread -> email headers
    pub fn upsert_thread_headers(
        &self,
        jig_thread: &str,
        message_id: Option<&str>,
        references: Option<&str>,
    ) -> Result<()> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute(
            "INSERT INTO thread_map (jig_thread, email_message_id, email_references) VALUES (?1, ?2, ?3)
             ON CONFLICT(jig_thread) DO UPDATE SET email_message_id=excluded.email_message_id, email_references=excluded.email_references",
            params![jig_thread, message_id, references],
        )?;
        Ok(())
    }
}
