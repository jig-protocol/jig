//! The text-render input a chat message's manifest gives. Pure, so it is built with or without
//! the `executor` feature; `executor::text_input` re-exports it.

/// The text-render input a block's manifest gives: its body, author, channel name, clock and
/// version. `None` when the manifest has no `body`, since rendering the empty string would hash a
/// message nobody sent.
///
/// The server and every re-executing client build the input with this one function, so they
/// cannot disagree on what was rendered.
pub fn text_input(manifest: &jig_core::BlockManifest) -> Option<text_block::Input> {
    let body = manifest.metadata.get("body")?.as_str()?;
    let channel = manifest
        .metadata
        .get("channel")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let hlc = manifest.hlc_ts.as_ref();
    Some(text_block::Input {
        sender_did: manifest
            .authors
            .first()
            .map(|a| a.did.to_string())
            .unwrap_or_default(),
        channel_id: channel.to_string(),
        body_raw: body.to_string(),
        hlc_wall_ms: hlc.map(|h| h.wall_ms).unwrap_or(0),
        hlc_logical: hlc.map(|h| h.logical).unwrap_or(0),
        hlc_origin: hlc.map(|h| h.server_did.to_string()).unwrap_or_default(),
        client_version: manifest.version.to_string(),
    })
}
