//! A channel this reader cannot read past without an upgrade (JEP-0005 rule
//! 14c): its owner sequenced a critical block of a kind this build, or the
//! server it reads through, does not implement.
//!
//! The reader stops that channel there, says so once, and `jig` exits with
//! [`EXIT_NEEDS_UPGRADE`]. A stop this device found is kept
//! ([`jig_client::upgrade_stops`]) so a restart does not read past the block;
//! a build that implements the kind drops it. A non-critical block of an
//! unknown kind is skipped without a word: it is in the chain, and nothing in
//! it is for this reader.

use std::path::Path;

use jig_client::open::OpenError;
use jig_client::upgrade_stops::{UpgradeStop, UpgradeStops};
use jig_core::BlockKind;

/// Exit status when a channel needs an upgrade to read further: this build,
/// or the server's. The next code after 78, the no-key-slot status.
pub const EXIT_NEEDS_UPGRADE: u8 = 79;

/// Why a channel stopped.
#[derive(Debug, thiserror::Error)]
pub enum NeedsUpgrade {
    /// This build does not implement a critical block's kind.
    #[error(
        "{channel} needs an upgrade: it uses block kind `{kind}`{}, which jig {} does not \
         understand. Upgrade jig to keep reading this channel.",
        seq.map(|s| format!(" (seq {s})")).unwrap_or_default(),
        env!("CARGO_PKG_VERSION")
    )]
    Client {
        channel: String,
        kind: String,
        seq: Option<u64>,
    },
    /// The server this reader reads through stopped the channel there
    /// (`CHANNEL_NEEDS_UPGRADE`). Its message names what must upgrade: this
    /// server, or the client, at a kind the client does not declare (JEP-0005
    /// rule 11a).
    #[error("{channel}: this channel needs an upgrade. The server says: {message}")]
    Server { channel: String, message: String },
}

/// Whether `e`, anywhere in its chain, is a channel needing an upgrade.
pub fn is_needs_upgrade(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| cause.is::<NeedsUpgrade>())
}

/// The block `e` failed to open on, when it is of an unknown kind.
pub fn unknown_kind(e: &anyhow::Error) -> Option<&OpenError> {
    e.chain()
        .filter_map(|cause| cause.downcast_ref::<OpenError>())
        .find(|open| matches!(open, OpenError::UnknownKind { .. }))
}

/// Keep `channel` on `server` stopped at the critical block `e` names, and
/// say so. `e` must be [`OpenError::UnknownKind`].
pub fn stop_at(stops: &Path, server: &str, channel: &str, e: &OpenError) -> anyhow::Error {
    let OpenError::UnknownKind { cid, kind, seq, .. } = e else {
        return anyhow::anyhow!("{e}");
    };
    let stop = UpgradeStop {
        kind: kind.clone(),
        cid: cid.clone(),
        seq: *seq,
    };
    // A stop that cannot be kept still stops this session; the warning says
    // a restart may not.
    if let Err(save) =
        UpgradeStops::load(stops).and_then(|mut all| all.record(server, channel, stop.clone()))
    {
        eprintln!("warning: could not keep {channel}'s stop for the next session: {save}");
    }
    NeedsUpgrade::Client {
        channel: channel.to_string(),
        kind: stop.kind,
        seq: stop.seq,
    }
    .into()
}

/// Refuse to open `channel` on `server` while it is stopped at a kind this
/// build does not implement; drop the stop when it does.
pub fn check_open(stops: &Path, server: &str, channel: &str) -> anyhow::Result<()> {
    let mut all = UpgradeStops::load(stops)?;
    match all.release_known(server, channel, |kind| kind.parse::<BlockKind>().is_ok())? {
        None => Ok(()),
        Some(stop) => Err(NeedsUpgrade::Client {
            channel: channel.to_string(),
            kind: stop.kind,
            seq: stop.seq,
        }
        .into()),
    }
}

/// `e`, as the server's `CHANNEL_NEEDS_UPGRADE` stop of `channel` when it is
/// one: a history read refused with that code. Anything else is `e`.
pub fn server_stop(channel: &str, e: anyhow::Error) -> anyhow::Error {
    let refused = e
        .chain()
        .filter_map(|cause| cause.downcast_ref::<crate::cmd::secure::Refused>())
        .find(|r| r.code == jig_client::upgrade_stops::CHANNEL_NEEDS_UPGRADE);
    match refused {
        Some(r) => NeedsUpgrade::Server {
            channel: channel.to_string(),
            message: r.message.clone(),
        }
        .into(),
        None => e,
    }
}

/// A server's `CHANNEL_NEEDS_UPGRADE` answer to a history read, from its
/// JSON error body, as the error to stop with.
pub fn from_error_body(channel: &str, body: &str) -> Option<anyhow::Error> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    if value.get("code")?.as_str()? != jig_client::upgrade_stops::CHANNEL_NEEDS_UPGRADE {
        return None;
    }
    let message = value
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or_default();
    Some(
        NeedsUpgrade::Server {
            channel: channel.to_string(),
            message: message.to_string(),
        }
        .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn critical() -> OpenError {
        OpenError::UnknownKind {
            cid: "bafy".to_string(),
            kind: "future-kind".to_string(),
            critical: true,
            channel_id: Some("chan".to_string()),
            seq: Some(7),
        }
    }

    #[test]
    fn a_stop_says_so_and_holds_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let stops = dir.path().join("stops.json");
        check_open(&stops, "wss://a", "#x").unwrap();

        let e = stop_at(&stops, "wss://a", "#x", &critical());
        assert!(is_needs_upgrade(&e));
        let shown = format!("{e}");
        assert!(shown.contains("#x needs an upgrade"), "{shown}");
        assert!(shown.contains("`future-kind` (seq 7)"), "{shown}");

        // The next session refuses the channel; other channels open.
        let again = check_open(&stops, "wss://a", "#x").unwrap_err();
        assert!(is_needs_upgrade(&again));
        check_open(&stops, "wss://a", "#y").unwrap();
    }

    #[test]
    fn a_build_that_implements_the_kind_drops_the_stop() {
        let dir = tempfile::tempdir().unwrap();
        let stops = dir.path().join("stops.json");
        let known = OpenError::UnknownKind {
            cid: "bafy".to_string(),
            kind: "text-render".to_string(),
            critical: true,
            channel_id: None,
            seq: Some(7),
        };
        let _ = stop_at(&stops, "wss://a", "#x", &known);
        check_open(&stops, "wss://a", "#x").unwrap();
        check_open(&stops, "wss://a", "#x").unwrap();
    }

    #[test]
    fn a_servers_needs_upgrade_answer_is_read_from_its_body() {
        let body = r#"{"code":"CHANNEL_NEEDS_UPGRADE","message":"block kind `k` at seq 3"}"#;
        let e = from_error_body("#x", body).unwrap();
        assert!(is_needs_upgrade(&e));
        assert!(format!("{e}").contains("needs an upgrade. The server says"));
        assert!(from_error_body("#x", r#"{"code":"NOT_FOUND","message":""}"#).is_none());
        assert!(from_error_body("#x", "not json").is_none());
    }
}
