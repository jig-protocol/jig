//! What this device has asked of each server it used, per JEP-0017: whether
//! it withdrew custody there (R1), whether it ended local adds there (R2), and
//! which of its key packages it stocked there.
//!
//! One file per identity and per device, `~/.jig/servers/<identity-did>.json`,
//! keyed by the server's DID. It is never synced between devices: the package
//! references name this device's own MLS state, whose private init keys live
//! only here ([`crate::secure`]). It holds no secrets, so it is plain JSON,
//! like the pins ([`crate::pins`]).
//!
//! A server is keyed by its DID, not its URL: every request JEP-0017 defines
//! names the server by DID, and a URL can move while the DID stays. `url` is
//! the last URL this device used for it.
//!
//! Fields this version does not know, at the top level and in each server's
//! entry, are kept through a load and a save, so an older client does not
//! erase what a newer one wrote. The small `reach` and `local_adds` objects
//! are replaced whole whenever they change; a newer field belongs in the
//! entry beside them, not inside them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ServersError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not a server-state file: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

/// R1 at one server: the last reachability record this device published
/// there (JEP-0017 rules 12–15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reach {
    pub seq: u64,
    /// The record leaves this server out: custody is withdrawn there.
    pub withdrawn: bool,
}

/// R2 at one server: the last `jig-local-adds-v1` this device sent there and
/// the server accepted (JEP-0017 rules 16–20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAdds {
    pub seq: u64,
    pub allow: bool,
}

/// This device's state at one server.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerState {
    /// The last URL this device used for the server.
    #[serde(default)]
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach: Option<Reach>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_adds: Option<LocalAdds>,
    /// The ordinary key packages this device stocked there, each as lowercase
    /// hex of its reference (`jig_mls::delivery::validate_key_package(..).reference`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
    /// The last-resort package stocked there, the same way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort: Option<String>,
    /// Packages whose keys are being deleted: moved here before a
    /// replacement is published, cleared once the keys are gone, so a run
    /// cut short finishes the deletion next time (JEP-0017 rule 32).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retiring: Vec<String>,
    /// Fields from a newer version, kept as they are.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl ServerState {
    /// Whether custody is withdrawn here (R1). With no record published yet,
    /// custody is in force.
    pub fn custody_withdrawn(&self) -> bool {
        self.reach.is_some_and(|r| r.withdrawn)
    }

    /// Whether local adds are ended here (R2). With no marker sent yet,
    /// local adds are allowed.
    pub fn local_adds_ended(&self) -> bool {
        self.local_adds.is_some_and(|l| !l.allow)
    }

    /// R1 and R2 both in force: the server keeps no stock for this DID and
    /// refuses uploads, so this device stops stocking it (JEP-0017 rule 19).
    pub fn stock_ended(&self) -> bool {
        self.custody_withdrawn() && self.local_adds_ended()
    }
}

/// Every server this device has state for, under one identity.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerStates {
    /// By server DID.
    #[serde(default)]
    pub servers: BTreeMap<String, ServerState>,
    /// Fields from a newer version, kept as they are.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl ServerStates {
    /// `~/.jig/servers/<identity-did>.json`, with each `:` in the DID written
    /// as `_` so the name is valid on every file system.
    pub fn default_path(identity_did: &str) -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".jig")
            .join("servers")
            .join(format!("{}.json", identity_did.replace(':', "_")))
    }

    /// Read the file at `path`; a missing file is an empty state. A file that
    /// does not parse is an error, never a silent reset: forgetting which
    /// packages were stocked where would leave their keys alive.
    pub fn load(path: &Path) -> Result<Self, ServersError> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| ServersError::Parse {
                path: path.display().to_string(),
                source,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ServersError::Io {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Write through a temporary file and a rename, so a crash leaves the old
    /// file or the new one, never half of either.
    pub fn save(&self, path: &Path) -> Result<(), ServersError> {
        let io = |source| ServersError::Io {
            path: path.display().to_string(),
            source,
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self).expect("the server-state file serializes");
        std::fs::write(&tmp, bytes).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
        }
        std::fs::rename(&tmp, path).map_err(io)
    }

    /// Read the file at `path`, apply `change`, and save it, holding an
    /// exclusive lock from the read to the write. Two `jig` processes for one
    /// identity would otherwise each write back their own copy, and the later
    /// one would erase the other's change.
    pub fn update<T>(path: &Path, change: impl FnOnce(&mut Self) -> T) -> Result<T, ServersError> {
        let _lock = lock(path)?;
        let mut states = Self::load(path)?;
        let out = change(&mut states);
        states.save(path)?;
        Ok(out)
    }

    /// The state for `server_did`, created if new, with its `url` set to the
    /// one this device uses now.
    pub fn entry(&mut self, server_did: &str, url: &str) -> &mut ServerState {
        let state = self.servers.entry(server_did.to_string()).or_default();
        state.url = url.to_string();
        state
    }

    pub fn get(&self, server_did: &str) -> Option<&ServerState> {
        self.servers.get(server_did)
    }
}

/// The file's lock, held exclusively until the returned handle drops.
fn lock(path: &Path) -> Result<std::fs::File, ServersError> {
    let lock_path = path.with_extension("json.lock");
    let io = |source| ServersError::Io {
        path: lock_path.display().to_string(),
        source,
    };
    if let Some(dir) = lock_path.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(io)?;
    file.lock().map_err(io)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "did:jig:zServer";

    #[test]
    fn the_default_path_names_the_identity_without_colons() {
        let path = ServerStates::default_path("did:jig:zMe");
        assert!(path.ends_with(".jig/servers/did_jig_zMe.json"));
    }

    #[test]
    fn a_missing_file_is_an_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        let states = ServerStates::load(&dir.path().join("none.json")).unwrap();
        assert!(states.servers.is_empty());
    }

    #[test]
    fn a_file_that_does_not_parse_is_an_error_not_a_reset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(matches!(
            ServerStates::load(&path),
            Err(ServersError::Parse { .. })
        ));
    }

    #[test]
    fn state_round_trips_and_entry_keeps_the_latest_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers").join("did:jig:zMe.json");
        ServerStates::update(&path, |s| {
            let e = s.entry(S, "https://old.example");
            e.reach = Some(Reach {
                seq: 7,
                withdrawn: true,
            });
            e.local_adds = Some(LocalAdds {
                seq: 2,
                allow: true,
            });
            e.packages = vec!["aa".into(), "bb".into()];
            e.last_resort = Some("cc".into());
        })
        .unwrap();
        ServerStates::update(&path, |s| {
            s.entry(S, "https://new.example");
        })
        .unwrap();
        let back = ServerStates::load(&path).unwrap();
        let e = back.get(S).unwrap();
        assert_eq!(e.url, "https://new.example");
        assert_eq!(
            e.reach,
            Some(Reach {
                seq: 7,
                withdrawn: true
            })
        );
        assert_eq!(
            e.local_adds,
            Some(LocalAdds {
                seq: 2,
                allow: true
            })
        );
        assert_eq!(e.packages, ["aa", "bb"]);
        assert_eq!(e.last_resort.as_deref(), Some("cc"));
    }

    #[test]
    fn unknown_fields_survive_a_load_and_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "servers": {S: {"url": "u", "erase": {"acts_at": 9}}},
                "future": [1, 2]
            })
            .to_string(),
        )
        .unwrap();
        ServerStates::update(&path, |s| {
            s.entry(S, "u2");
        })
        .unwrap();
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["future"], serde_json::json!([1, 2]));
        assert_eq!(raw["servers"][S]["erase"]["acts_at"], 9);
        assert_eq!(raw["servers"][S]["url"], "u2");
    }

    #[test]
    fn stock_ends_only_with_custody_withdrawn_and_local_adds_ended() {
        let state = |withdrawn: Option<bool>, allow: Option<bool>| ServerState {
            reach: withdrawn.map(|withdrawn| Reach { seq: 1, withdrawn }),
            local_adds: allow.map(|allow| LocalAdds { seq: 1, allow }),
            ..ServerState::default()
        };
        // Nothing sent yet: custody in force, local adds allowed.
        assert!(!state(None, None).stock_ended());
        assert!(!state(Some(true), None).stock_ended());
        assert!(!state(None, Some(false)).stock_ended());
        assert!(!state(Some(false), Some(false)).stock_ended());
        assert!(!state(Some(true), Some(true)).stock_ended());
        assert!(state(Some(true), Some(false)).stock_ended());
    }
}
