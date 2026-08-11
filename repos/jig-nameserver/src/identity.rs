//! Nameserver identity management (persistent ed25519 keypair)

use crate::error::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{Connection, params};
use std::path::PathBuf;

pub struct NsIdentity {
    pub secret_key: SigningKey,
    pub public_key: VerifyingKey,
}

pub fn get_or_create(db_path: &PathBuf) -> Result<NsIdentity> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS ns_identity (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            secret BLOB NOT NULL,
            public BLOB NOT NULL
        );
        "#,
    )?;

    // Try fetch existing
    if let Ok(mut stmt) = conn.prepare("SELECT secret, public FROM ns_identity WHERE id=1") {
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let secret: Vec<u8> = row.get(0)?;
            let _public: Vec<u8> = row.get(1)?;
            if secret.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&secret);
                let sk = SigningKey::from_bytes(&arr);
                let pk = VerifyingKey::from(&sk);
                return Ok(NsIdentity {
                    secret_key: sk,
                    public_key: pk,
                });
            }
        }
    }

    // Create new. Keygen lives in jig-core so the nameserver's long-lived
    // signing identity and client identities cannot drift apart; see
    // `jig_core::crypto::ed25519::generate_signing_key` for the entropy choice.
    let sk = jig_core::crypto::ed25519::generate_signing_key();
    let pk = sk.verifying_key();
    conn.execute(
        "INSERT OR REPLACE INTO ns_identity(id, secret, public) VALUES (1, ?1, ?2)",
        params![sk.to_bytes().to_vec(), pk.as_bytes().to_vec()],
    )?;
    Ok(NsIdentity {
        secret_key: sk,
        public_key: pk,
    })
}

pub fn ns_id_from_pubkey(pk: &VerifyingKey) -> String {
    let digest = blake3::hash(pk.as_bytes());
    hex::encode(digest.as_bytes())
}
