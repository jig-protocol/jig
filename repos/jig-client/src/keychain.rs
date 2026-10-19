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

/// The keychain this platform offers, if any is usable right now. Every call
/// is bounded by [`TIMEOUT`].
pub fn system() -> Option<Box<dyn Keychain>> {
    platform::system().map(|k| Box::new(Bounded::new(k, TIMEOUT)) as Box<dyn Keychain>)
}

/// How long one keychain call may take. A keychain can stop to ask a person
/// (macOS asks again after the binary changes; a locked GNOME keyring asks for
/// its password), and with nobody there that question never ends. Past this,
/// the call counts as a keychain that is unavailable, and the key falls back
/// to its other slots, or to a passphrase, as it does where there is no
/// keychain at all.
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// A keychain whose every call gives up after a deadline. The call runs on its
/// own thread; one that never returns is abandoned there, and ends with the
/// process. The Secret Service backend also kills its `secret-tool` child just
/// before the deadline, so no child outlives the call.
pub struct Bounded {
    inner: std::sync::Arc<dyn Keychain>,
    timeout: std::time::Duration,
}

impl Bounded {
    pub fn new(inner: Box<dyn Keychain>, timeout: std::time::Duration) -> Self {
        Self {
            inner: inner.into(),
            timeout,
        }
    }

    fn call<T: Send + 'static>(
        &self,
        what: &'static str,
        f: impl FnOnce(&dyn Keychain) -> Result<T, KeychainError> + Send + 'static,
    ) -> Result<T, KeychainError> {
        let inner = self.inner.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f(inner.as_ref()));
        });
        rx.recv_timeout(self.timeout).unwrap_or_else(|_| {
            Err(KeychainError::Backend(format!(
                "{} did not answer a {what} within {}s; is it waiting for a prompt?",
                self.inner.name(),
                self.timeout.as_secs()
            )))
        })
    }
}

impl Keychain for Bounded {
    fn get(&self, did: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        let did = did.to_string();
        self.call("lookup", move |k| k.get(&did))
    }

    fn set(&self, did: &str, secret: &[u8]) -> Result<(), KeychainError> {
        let did = did.to_string();
        let secret = Zeroizing::new(secret.to_vec());
        self.call("store", move |k| k.set(&did, &secret))
    }

    fn delete(&self, did: &str) -> Result<(), KeychainError> {
        let did = did.to_string();
        self.call("delete", move |k| k.delete(&did))
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }
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
    use std::io::{Read as _, Write as _};
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    /// How long one `secret-tool` run may take before it is killed. Shorter
    /// than [`super::TIMEOUT`], so the child is gone before the caller gives up
    /// on the call: an abandoned child could still store a secret, or show a
    /// prompt, after jig has exited.
    const DEADLINE: Duration = Duration::from_secs(super::TIMEOUT.as_secs() - 2);

    /// `secret-tool` with an environment that holds none of jig's secrets:
    /// no `JIG_*` variable, and not the variable `JIG_KEY_UNLOCK=env:NAME`
    /// names. The rest stays, since it is how `secret-tool` finds the session
    /// bus.
    fn secret_tool() -> Command {
        let mut cmd = Command::new("secret-tool");
        scrub(&mut cmd, std::env::vars_os());
        cmd
    }

    fn scrub(
        cmd: &mut Command,
        vars: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    ) {
        for (name, value) in vars {
            if name.to_string_lossy().starts_with("JIG_") {
                cmd.env_remove(&name);
            }
            if name == "JIG_KEY_UNLOCK"
                && let Some(target) = value.to_str().and_then(|v| v.strip_prefix("env:"))
            {
                cmd.env_remove(target);
            }
        }
    }

    /// Run `cmd` with `input` on its stdin, killing it at [`DEADLINE`].
    /// Returns its exit status and stdout.
    fn run(
        what: &str,
        cmd: Command,
        input: Option<&[u8]>,
    ) -> Result<(ExitStatus, Zeroizing<Vec<u8>>), KeychainError> {
        run_within(what, cmd, input, DEADLINE)
    }

    fn run_within(
        what: &str,
        mut cmd: Command,
        input: Option<&[u8]>,
        deadline: Duration,
    ) -> Result<(ExitStatus, Zeroizing<Vec<u8>>), KeychainError> {
        let mut child = cmd
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| backend(what, e))?;
        if let Some(input) = input {
            let mut stdin = child.stdin.take().expect("stdin is piped");
            if let Err(e) = stdin.write_all(input) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(backend(what, e));
            }
        }
        let started = Instant::now();
        let status = loop {
            match child.try_wait().map_err(|e| backend(what, e))? {
                Some(status) => break status,
                None if started.elapsed() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(backend(
                        what,
                        format!(
                            "no answer within {}s; is it waiting for a prompt?",
                            deadline.as_secs()
                        ),
                    ));
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        // Its output is a few hundred bytes at most, well within a pipe's
        // buffer, so reading after it exits cannot deadlock.
        let mut stdout = Zeroizing::new(Vec::new());
        if let Some(mut out) = child.stdout.take() {
            out.read_to_end(&mut stdout).map_err(|e| backend(what, e))?;
        }
        if !status.success() {
            let mut stderr = String::new();
            if let Some(mut err) = child.stderr.take() {
                let _ = err.read_to_string(&mut stderr);
            }
            if !stderr.trim().is_empty() {
                tracing::debug!("secret-tool {what}: {}", stderr.trim());
            }
        }
        Ok((status, stdout))
    }

    pub fn system() -> Option<Box<dyn Keychain>> {
        // No session bus means no Secret Service: an SSH login or a server.
        // Checking first avoids a `secret-tool` that hangs trying to start one.
        let bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
            || std::env::var_os("XDG_RUNTIME_DIR")
                .is_some_and(|dir| std::path::Path::new(&dir).join("bus").exists());
        if !bus {
            return None;
        }
        let found = secret_tool()
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
            let mut cmd = secret_tool();
            cmd.args(["lookup", "service", SERVICE, "account", did]);
            let (status, stdout) = run("lookup", cmd, None)?;
            // `lookup` exits 1, printing nothing, when there is no such entry.
            if !status.success() || stdout.is_empty() {
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
            let mut cmd = secret_tool();
            cmd.args([
                "store", "--label", &label, "service", SERVICE, "account", did,
            ]);
            let encoded = Zeroizing::new(STANDARD.encode(secret));
            let (status, _) = run("store", cmd, Some(encoded.as_bytes()))?;
            if !status.success() {
                return Err(backend("store", status));
            }
            Ok(())
        }

        fn delete(&self, did: &str) -> Result<(), KeychainError> {
            // `clear` succeeds whether or not an entry existed.
            let mut cmd = secret_tool();
            cmd.args(["clear", "service", SERVICE, "account", did]);
            let (status, _) = run("clear", cmd, None)?;
            if !status.success() {
                return Err(backend("clear", status));
            }
            Ok(())
        }

        fn name(&self) -> &'static str {
            "Secret Service"
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::ffi::OsString;

        #[test]
        fn the_child_gets_none_of_jigs_secrets() {
            let mut cmd = Command::new("true");
            let var = |n: &str, v: &str| (OsString::from(n), OsString::from(v));
            scrub(
                &mut cmd,
                [
                    var("JIG_KEY_PASSPHRASE", "hunter2"),
                    var("JIG_KEY_UNLOCK", "env:VAULT_TOKEN"),
                    var("VAULT_TOKEN", "s3cret"),
                    var("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/bus"),
                ],
            );
            let removed: Vec<_> = cmd
                .get_envs()
                .filter(|(_, v)| v.is_none())
                .map(|(k, _)| k.to_string_lossy().into_owned())
                .collect();
            for gone in ["JIG_KEY_PASSPHRASE", "JIG_KEY_UNLOCK", "VAULT_TOKEN"] {
                assert!(removed.iter().any(|r| r == gone), "{gone} still passed on");
            }
            assert!(!removed.iter().any(|r| r == "DBUS_SESSION_BUS_ADDRESS"));
        }

        #[test]
        fn a_child_that_does_not_answer_is_killed_not_abandoned() {
            let dir = tempfile::tempdir().unwrap();
            let marker = dir.path().join("finished");
            let mut cmd = Command::new("sh");
            cmd.arg("-c")
                .arg(format!("sleep 2; touch '{}'", marker.display()));
            let started = Instant::now();
            let err = run_within("store", cmd, None, Duration::from_millis(200)).unwrap_err();
            assert!(err.to_string().contains("no answer"), "{err}");
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(2500));
            assert!(!marker.exists(), "the child ran on after the deadline");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stuck;
    impl Keychain for Stuck {
        fn get(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            std::thread::sleep(std::time::Duration::from_secs(60));
            Ok(None)
        }
        fn set(&self, _: &str, _: &[u8]) -> Result<(), KeychainError> {
            std::thread::sleep(std::time::Duration::from_secs(60));
            Ok(())
        }
        fn delete(&self, _: &str) -> Result<(), KeychainError> {
            Ok(())
        }
        fn name(&self) -> &'static str {
            "stuck keychain"
        }
    }

    #[test]
    fn a_keychain_waiting_on_a_prompt_times_out_instead_of_hanging() {
        let k = Bounded::new(Box::new(Stuck), std::time::Duration::from_millis(50));
        let started = std::time::Instant::now();
        assert!(k.get("did:jig:za").is_err());
        assert!(k.set("did:jig:za", b"s").is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_bounded_keychain_passes_answers_through() {
        let k = Bounded::new(
            Box::new(MemoryKeychain::default()),
            std::time::Duration::from_secs(5),
        );
        k.set("did:jig:za", b"one").unwrap();
        assert_eq!(&*k.get("did:jig:za").unwrap().unwrap(), b"one");
    }

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
