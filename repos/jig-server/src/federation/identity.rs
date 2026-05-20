//! Server identity management

use crate::{error::Result, storage::SqliteBackend};
use ed25519_dalek::Keypair;

/// Retrieve or generate the server's identity keypair
pub fn get_or_create(storage: &SqliteBackend) -> Result<Keypair> {
    storage.get_or_create_identity()
}
