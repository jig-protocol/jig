//! The channels this device stopped reading at a critical block of a kind
//! this build does not implement (JEP-0005 rule 14c), kept between sessions.
//!
//! A reader stops at such a block rather than read past it: on an encrypted
//! channel it may change the group. The chain head this device keeps moves
//! past the block all the same (its record is the owner's, and checks out),
//! so without this file a restart would carry on from there and the block
//! would be skipped after all. A build that implements the kind drops the
//! stop ([`UpgradeStops::release_known`]), and reads the channel again from
//! its history.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::secure::server_key;

/// The error code a server answers a subscribe or history read with for a
/// channel it stopped at a block kind it does not implement.
pub use jig_pipeline::fanout::CHANNEL_NEEDS_UPGRADE;

/// Where one channel stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeStop {
    /// The kind name, as the author signed it.
    pub kind: String,
    /// The block's CID.
    pub cid: String,
    /// Its `seq` in the channel, when it came with its record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum UpgradeStopsError {
    #[error("reading {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    /// A file that does not parse is an error, never an empty store: an empty
    /// one would let a reader past the block it stopped at.
    #[error("{path} does not parse: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    #[error("writing {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
}

/// The stops, by server and then by the channel reference the reader used.
#[derive(Debug, Default)]
pub struct UpgradeStops {
    path: PathBuf,
    stops: Stops,
}

impl UpgradeStops {
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".jig")
            .join("upgrade-stops.json")
    }

    /// Load the store at `path`; a missing file is an empty store.
    pub fn load(path: &Path) -> Result<Self, UpgradeStopsError> {
        Ok(Self {
            path: path.to_path_buf(),
            stops: read(path)?,
        })
    }

    /// Where `channel` on `server` stopped, if it did.
    pub fn get(&self, server: &str, channel: &str) -> Option<&UpgradeStop> {
        self.stops.get(&server_key(server))?.get(channel)
    }

    /// Keep that `channel` on `server` stopped at `stop`. The first stop
    /// stays: a reader never gets past it, so a later one is not reached.
    pub fn record(
        &mut self,
        server: &str,
        channel: &str,
        stop: UpgradeStop,
    ) -> Result<(), UpgradeStopsError> {
        let key = server_key(server);
        self.update(|stops| {
            let server = stops.entry(key).or_default();
            if server.contains_key(channel) {
                return ((), false);
            }
            server.insert(channel.to_string(), stop);
            ((), true)
        })
    }

    /// Drop the stop of `channel` on `server` when `implemented` says this
    /// build implements its kind now. Returns the stop still in force, if any.
    pub fn release_known(
        &mut self,
        server: &str,
        channel: &str,
        implemented: impl Fn(&str) -> bool,
    ) -> Result<Option<UpgradeStop>, UpgradeStopsError> {
        let key = server_key(server);
        self.update(|stops| {
            let Some(stop) = stops.get(&key).and_then(|s| s.get(channel)).cloned() else {
                return (None, false);
            };
            if !implemented(&stop.kind) {
                return (Some(stop), false);
            }
            if let Some(server) = stops.get_mut(&key) {
                server.remove(channel);
                if server.is_empty() {
                    stops.remove(&key);
                }
            }
            (None, true)
        })
    }

    /// Apply `change` to the store as it is on disk now, holding an exclusive
    /// lock from the read to the write, and save when it reports a change.
    /// Two processes for one device (a `jig chat` beside a `jig tail`) would
    /// otherwise each write back their own copy, and the later one would
    /// erase the other's stop.
    fn update<T>(
        &mut self,
        change: impl FnOnce(&mut Stops) -> (T, bool),
    ) -> Result<T, UpgradeStopsError> {
        let _lock = self.lock()?;
        self.stops = read(&self.path)?;
        let (out, changed) = change(&mut self.stops);
        if changed {
            self.save()?;
        }
        Ok(out)
    }

    /// The store's lock file, locked exclusively until the returned handle
    /// drops. Blocks while another process holds it.
    fn lock(&self) -> Result<std::fs::File, UpgradeStopsError> {
        let path = self.path.with_extension("json.lock");
        let fail = |source| UpgradeStopsError::Write {
            path: path.display().to_string(),
            source,
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(fail)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(fail)?;
        file.lock().map_err(fail)?;
        Ok(file)
    }

    /// Write the store through a temporary file and a rename, so a crash
    /// leaves the old store or the new one, never half of either. Called only
    /// under [`Self::lock`], so no two writers share the temporary file.
    fn save(&self) -> Result<(), UpgradeStopsError> {
        let fail = |source| UpgradeStopsError::Write {
            path: self.path.display().to_string(),
            source,
        };
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(fail)?;
        }
        let bytes = serde_json::to_vec_pretty(&self.stops).expect("a map of strings serializes");
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).map_err(fail)?;
        std::fs::rename(&tmp, &self.path).map_err(fail)
    }
}

type Stops = BTreeMap<String, BTreeMap<String, UpgradeStop>>;

/// The store at `path`; a missing file is an empty one.
fn read(path: &Path) -> Result<Stops, UpgradeStopsError> {
    let shown = || path.display().to_string();
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| UpgradeStopsError::Parse {
            path: shown(),
            source,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(source) => Err(UpgradeStopsError::Read {
            path: shown(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stop(kind: &str) -> UpgradeStop {
        UpgradeStop {
            kind: kind.to_string(),
            cid: "bafy".to_string(),
            seq: Some(4),
        }
    }

    #[test]
    fn a_stop_survives_a_reload_and_keeps_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stops.json");
        let mut stops = UpgradeStops::load(&path).unwrap();
        assert!(stops.get("wss://a.example", "#x").is_none());
        stops
            .record("wss://a.example", "#x", stop("future-kind"))
            .unwrap();
        stops
            .record("wss://a.example", "#x", stop("later"))
            .unwrap();

        let again = UpgradeStops::load(&path).unwrap();
        // The scheme is not part of which server it is.
        assert_eq!(
            again.get("https://a.example/", "#x"),
            Some(&stop("future-kind"))
        );
        assert!(again.get("wss://a.example", "#y").is_none());
    }

    #[test]
    fn a_stop_is_released_only_by_a_build_that_implements_its_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stops.json");
        let mut stops = UpgradeStops::load(&path).unwrap();
        stops.record("wss://a", "#x", stop("future-kind")).unwrap();
        assert_eq!(
            stops.release_known("wss://a", "#x", |_| false).unwrap(),
            Some(stop("future-kind"))
        );
        assert_eq!(
            stops.release_known("wss://a", "#x", |_| true).unwrap(),
            None
        );
        assert!(
            UpgradeStops::load(&path)
                .unwrap()
                .get("wss://a", "#x")
                .is_none()
        );
    }

    /// Two stores loaded from one file each record a stop: neither erases
    /// the other's, as a stale snapshot written back would.
    #[test]
    fn two_stores_on_one_file_keep_each_others_stops() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stops.json");
        let mut a = UpgradeStops::load(&path).unwrap();
        let mut b = UpgradeStops::load(&path).unwrap();
        a.record("wss://a", "#x", stop("future-kind")).unwrap();
        b.record("wss://a", "#y", stop("key-link")).unwrap();
        let both = UpgradeStops::load(&path).unwrap();
        assert!(both.get("wss://a", "#x").is_some());
        assert!(both.get("wss://a", "#y").is_some());
    }

    #[test]
    fn a_file_that_does_not_parse_is_an_error_not_an_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stops.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(
            UpgradeStops::load(&path),
            Err(UpgradeStopsError::Parse { .. })
        ));
    }
}
