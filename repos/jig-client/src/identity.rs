//! Identity loading from `~/.jig/keys/<did>.key`.
//!
//! Files are raw 32-byte ed25519 secret keys. Permission enforcement on
//! Unix: keyfile must be mode 0600 (owner-only read/write). Reads via
//! `Identity::load_from_dir`; fresh keys via `Identity::generate_and_save`
//! (the `jig init` command's backing call).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use jig_core::Did;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("keyfile not found for DID `{did}` in {dir:?}")]
    KeyfileNotFound { did: String, dir: PathBuf },
    #[error("keyfile {path:?} has insecure permissions {mode:o} (must be 0600)")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("keyfile {path:?} is malformed: expected 32 bytes, got {len}")]
    Malformed { path: PathBuf, len: usize },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A loaded ed25519 identity. Wraps the signing key + derived DID.
///
/// Construct with `load_from_dir` (existing identity) or
/// `generate_and_save` (fresh identity that's written to disk before
/// the constructor returns).
pub struct Identity {
    did: Did,
    signing: SigningKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the secret key into logs.
        f.debug_struct("Identity")
            .field("did", &self.did)
            .field("signing", &"<redacted>")
            .finish()
    }
}

impl Identity {
    /// Load an identity from `<keys_dir>/<did_str>.key`. Enforces 0600
    /// permissions on Unix; permission check is a no-op on other platforms.
    pub fn load_from_dir(keys_dir: &Path, did_str: &str) -> Result<Self, IdentityError> {
        let path = keys_dir.join(format!("{did_str}.key"));
        if !path.exists() {
            return Err(IdentityError::KeyfileNotFound {
                did: did_str.to_string(),
                dir: keys_dir.to_path_buf(),
            });
        }
        Self::enforce_secure_permissions(&path)?;
        let bytes = std::fs::read(&path)?;
        if bytes.len() != 32 {
            return Err(IdentityError::Malformed {
                path,
                len: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let signing = SigningKey::from_bytes(&arr);
        let did = Did::from_ed25519_pubkey(signing.verifying_key().as_bytes());
        Ok(Self { did, signing })
    }

    /// Generate a fresh keypair and write it to `<keys_dir>/<did>.key` with
    /// 0600 permissions on Unix. The directory is created with
    /// `create_dir_all` if missing.
    pub fn generate_and_save(keys_dir: &Path) -> Result<Self, IdentityError> {
        std::fs::create_dir_all(keys_dir)?;
        let mut secret = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut secret);
        let signing = SigningKey::from_bytes(&secret);
        let did = Did::from_ed25519_pubkey(signing.verifying_key().as_bytes());
        let path = keys_dir.join(format!("{}.key", did.to_did_jig_string()));
        std::fs::write(&path, signing.to_bytes())?;
        Self::set_secure_permissions(&path)?;
        Ok(Self { did, signing })
    }

    pub fn did(&self) -> &Did {
        &self.did
    }

    pub fn did_string(&self) -> String {
        self.did.to_did_jig_string()
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    #[cfg(unix)]
    fn enforce_secure_permissions(path: &Path) -> Result<(), IdentityError> {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(IdentityError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
        Ok(())
    }
    #[cfg(not(unix))]
    fn enforce_secure_permissions(_path: &Path) -> Result<(), IdentityError> {
        Ok(())
    }

    #[cfg(unix)]
    fn set_secure_permissions(path: &Path) -> Result<(), IdentityError> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    fn set_secure_permissions(_path: &Path) -> Result<(), IdentityError> {
        Ok(())
    }
}

/// Default keys directory: `~/.jig/keys/`.
pub fn default_keys_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".jig/keys")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_and_save_round_trips_through_load_from_dir() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        let did_str = id.did_string();
        let pubkey_bytes = *id.public_key().as_bytes();

        // Reload from same dir
        let reloaded = Identity::load_from_dir(dir.path(), &did_str).unwrap();
        assert_eq!(reloaded.did_string(), did_str);
        assert_eq!(reloaded.public_key().as_bytes(), &pubkey_bytes);
    }

    #[test]
    fn signs_and_verifies() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        let msg = b"hello world";
        let sig = id.sign(msg);
        use ed25519_dalek::Verifier;
        assert!(id.public_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn load_missing_keyfile_returns_keyfile_not_found() {
        let dir = tempdir().unwrap();
        let err = Identity::load_from_dir(dir.path(), "did:jig:znope").unwrap_err();
        assert!(matches!(err, IdentityError::KeyfileNotFound { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_keyfile() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        let did_str = id.did_string();
        let path = dir.path().join(format!("{did_str}.key"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = Identity::load_from_dir(dir.path(), &did_str).unwrap_err();
        assert!(matches!(err, IdentityError::InsecurePermissions { .. }));
    }

    #[test]
    fn debug_does_not_leak_signing_key() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        let debug_str = format!("{id:?}");
        assert!(debug_str.contains("redacted"));
        // Should NOT contain raw key bytes
        assert!(!debug_str.contains("SigningKey"));
    }

    #[test]
    fn default_keys_dir_points_to_dot_jig_keys() {
        let path = default_keys_dir();
        let s = path.to_string_lossy();
        assert!(s.ends_with(".jig/keys") || s.ends_with(".jig\\keys"));
    }

    #[test]
    fn generate_creates_canonical_did_jig_string() {
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(dir.path()).unwrap();
        let did_str = id.did_string();
        assert!(
            did_str.starts_with("did:jig:z"),
            "generated DID must use canonical form, got `{did_str}`"
        );
    }

    #[test]
    fn malformed_keyfile_returns_malformed_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("did:jig:zbad.key");
        std::fs::write(&path, b"too short").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = Identity::load_from_dir(dir.path(), "did:jig:zbad").unwrap_err();
        assert!(matches!(err, IdentityError::Malformed { len: 9, .. }));
    }
}
