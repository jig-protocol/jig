//! The OS keychain, as the default way to unlock an identity's `.jigkey`.
//!
//! The keychain holds one random 32-byte secret per DID (service `jig`,
//! account the DID). That secret opens the key file's `keychain` slot; the
//! identity key itself never enters the keychain.
//!
//! - **macOS:** the login keychain, through the Security framework.
//! - **Windows:** none yet. Windows is not a release target, so it uses the
//!   passphrase.
//! - **Linux and other Unix:** the Secret Service (GNOME Keyring, KWallet),
//!   through the `secret-tool` command from libsecret, when it is installed and
//!   a session bus is running. Otherwise there is no keychain, and the identity
//!   falls back to a passphrase. Talking to the Secret Service in-process would
//!   add an async D-Bus stack to every client build (DJ, 2026-10-18).

use zeroize::Zeroizing;

/// The keychain service name every entry is filed under.
pub const SERVICE: &str = "jig";

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain: {0}")]
    Backend(String),
}

/// A place to keep one secret per DID.
pub trait Keychain: Send + Sync {
    /// The secret filed for `did`, or `None` if there is none.
    fn get(&self, did: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError>;
    /// File `secret` for `did`, replacing any earlier one.
    fn set(&self, did: &str, secret: &[u8]) -> Result<(), KeychainError>;
    /// Remove the secret filed for `did`. Removing a missing one is not an error.
    fn delete(&self, did: &str) -> Result<(), KeychainError>;
    /// A short name for messages: "macOS keychain", "Secret Service".
    fn name(&self) -> &'static str;
}

/// The keychain this platform offers, if any is usable right now.
pub fn system() -> Option<Box<dyn Keychain>> {
    platform::system()
}

/// An in-memory keychain, for tests and for embedding callers that bring their
/// own storage.
#[derive(Default)]
pub struct MemoryKeychain(std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>);

impl Keychain for MemoryKeychain {
    fn get(&self, did: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        Ok(self
            .0
            .lock()
            .expect("keychain poisoned")
            .get(did)
            .cloned()
            .map(Zeroizing::new))
    }

    fn set(&self, did: &str, secret: &[u8]) -> Result<(), KeychainError> {
        self.0
            .lock()
            .expect("keychain poisoned")
            .insert(did.to_string(), secret.to_vec());
        Ok(())
    }

    fn delete(&self, did: &str) -> Result<(), KeychainError> {
        self.0.lock().expect("keychain poisoned").remove(did);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "in-memory keychain"
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{Keychain, KeychainError, SERVICE};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    pub fn system() -> Option<Box<dyn Keychain>> {
        match apple_native_keyring_store::keychain::Store::new() {
            Ok(store) => Some(Box::new(Native(
                store as Arc<keyring_core::CredentialStore>,
            ))),
            Err(e) => {
                tracing::debug!("no OS keychain: {e}");
                None
            }
        }
    }

    struct Native(Arc<keyring_core::CredentialStore>);

    impl Native {
        fn entry(&self, did: &str) -> Result<keyring_core::Entry, KeychainError> {
            self.0
                .build(SERVICE, did, None)
                .map_err(|e| KeychainError::Backend(e.to_string()))
        }
    }

    impl Keychain for Native {
        fn get(&self, did: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            match self.entry(did)?.get_secret() {
                Ok(secret) => Ok(Some(Zeroizing::new(secret))),
                Err(keyring_core::Error::NoEntry) => Ok(None),
                Err(e) => Err(KeychainError::Backend(e.to_string())),
            }
        }

        fn set(&self, did: &str, secret: &[u8]) -> Result<(), KeychainError> {
            self.entry(did)?
                .set_secret(secret)
                .map_err(|e| KeychainError::Backend(e.to_string()))
        }

        fn delete(&self, did: &str) -> Result<(), KeychainError> {
            match self.entry(did)?.delete_credential() {
                Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
                Err(e) => Err(KeychainError::Backend(e.to_string())),
            }
        }

        fn name(&self) -> &'static str {
            "macOS keychain"
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::Keychain;

    pub fn system() -> Option<Box<dyn Keychain>> {
        None
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
mod platform {
    //! The Secret Service through `secret-tool` (libsecret).
    //!
    //! `secret-tool store` reads the secret from stdin and `lookup` prints it
    //! on stdout, so the secret never appears in an argument list. Secrets are
    //! stored base64-encoded because `secret-tool` handles text.

    use super::{Keychain, KeychainError, SERVICE};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    use zeroize::Zeroizing;

    pub fn system() -> Option<Box<dyn Keychain>> {
        // No session bus means no Secret Service: an SSH login or a server.
        // Checking first avoids a `secret-tool` that hangs trying to start one.
        let bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
            || std::env::var_os("XDG_RUNTIME_DIR")
                .is_some_and(|dir| std::path::Path::new(&dir).join("bus").exists());
        if !bus {
            return None;
        }
        let found = Command::new("secret-tool")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        found.then(|| Box::new(SecretTool) as Box<dyn Keychain>)
    }

    struct SecretTool;

    fn backend(what: &str, detail: impl std::fmt::Display) -> KeychainError {
        KeychainError::Backend(format!("secret-tool {what}: {detail}"))
    }

    impl Keychain for SecretTool {
        fn get(&self, did: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            let out = Command::new("secret-tool")
                .args(["lookup", "service", SERVICE, "account", did])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .map_err(|e| backend("lookup", e))?;
            let stdout = Zeroizing::new(out.stdout);
            // `lookup` exits 1, printing nothing, when there is no such entry.
            if !out.status.success() || stdout.is_empty() {
                return Ok(None);
            }
            let text = std::str::from_utf8(&stdout).map_err(|e| backend("lookup", e))?;
            STANDARD
                .decode(text.trim())
                .map(|secret| Some(Zeroizing::new(secret)))
                .map_err(|e| backend("lookup", e))
        }

        fn set(&self, did: &str, secret: &[u8]) -> Result<(), KeychainError> {
            let label = format!("jig identity {did}");
            let mut child = Command::new("secret-tool")
                .args([
                    "store", "--label", &label, "service", SERVICE, "account", did,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| backend("store", e))?;
            let encoded = Zeroizing::new(STANDARD.encode(secret));
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(encoded.as_bytes())
                .map_err(|e| backend("store", e))?;
            let out = child.wait_with_output().map_err(|e| backend("store", e))?;
            if !out.status.success() {
                return Err(backend(
                    "store",
                    String::from_utf8_lossy(&out.stderr).trim().to_string(),
                ));
            }
            Ok(())
        }

        fn delete(&self, did: &str) -> Result<(), KeychainError> {
            // `clear` succeeds whether or not an entry existed.
            let status = Command::new("secret-tool")
                .args(["clear", "service", SERVICE, "account", did])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|e| backend("clear", e))?;
            if !status.success() {
                return Err(backend("clear", status));
            }
            Ok(())
        }

        fn name(&self) -> &'static str {
            "Secret Service"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_keychain_files_replaces_and_deletes() {
        let k = MemoryKeychain::default();
        assert!(k.get("did:jig:za").unwrap().is_none());
        k.set("did:jig:za", b"one").unwrap();
        k.set("did:jig:za", b"two").unwrap();
        assert_eq!(&*k.get("did:jig:za").unwrap().unwrap(), b"two");
        k.delete("did:jig:za").unwrap();
        k.delete("did:jig:za").unwrap();
        assert!(k.get("did:jig:za").unwrap().is_none());
    }
}
