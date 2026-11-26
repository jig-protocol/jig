//! A channel as the user names it on the command line (F2 Task 0c, design
//! section 6): `#slug`, a channel id, or a `jig:` link.
//!
//! - `#slug` is a name, unique only on the server that orders the channel.
//! - A channel id is the canonical text of the CID of the channel's
//!   `channel-create` block, and names one channel everywhere.
//! - `jig:<channel-id>[?sequencer=<did>&slug=<slug>]` is the link form of a
//!   channel id. The query carries hints, never identity: the channel is the
//!   id, whichever server orders it now or whatever it is called there. The
//!   hints are checked and then left out, since every command addresses the
//!   channel on the server it is configured for. Unknown keys are ignored, so
//!   a later release can add one. Values are percent-decoded (a DID holds
//!   `:`).
//!
//! Anything else is refused at parse time. Before this, an argument that was
//! neither a slug nor an id reached the server and was answered "no such
//! channel", so this changes only where and how such an argument is refused.

/// The longest `jig:` link taken.
pub const MAX_LINK_BYTES: usize = 512;

const SCHEME: &str = "jig:";

const FORMS: &str = "a channel is `#slug`, a channel id, or `jig:<channel-id>`";

/// The channel `raw` names, as a command sends it to the server: a `#slug`
/// or a channel id. A `jig:` link gives its id.
pub fn parse(raw: &str) -> Result<String, String> {
    if raw.trim().is_empty() {
        return Err("channel must not be blank (try `#hello`)".to_string());
    }
    if raw.starts_with('#') {
        return Ok(raw.to_string());
    }
    if jig_core::canonical_cid::is_canonical_text(raw) {
        return Ok(raw.to_string());
    }
    if let Some(link) = raw.strip_prefix(SCHEME) {
        return parse_link(raw, link).map(|link| link.channel_id);
    }
    Err(format!("`{raw}` is not a channel: {FORMS}"))
}

/// A `jig:` link, its hints checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub channel_id: String,
    pub sequencer: Option<String>,
    pub slug: Option<String>,
}

fn parse_link(raw: &str, link: &str) -> Result<Link, String> {
    if raw.len() > MAX_LINK_BYTES {
        return Err(format!(
            "a `jig:` link is at most {MAX_LINK_BYTES} bytes; this one is {}",
            raw.len()
        ));
    }
    let (id, query) = match link.split_once('?') {
        Some((id, query)) => (id, Some(query)),
        None => (link, None),
    };
    if !jig_core::canonical_cid::is_canonical_text(id) {
        return Err(format!(
            "`{id}` in `{raw}` is not a channel id: the id is the canonical text of a \
             channel-create block's CID"
        ));
    }
    let mut out = Link {
        channel_id: id.to_string(),
        sequencer: None,
        slug: None,
    };
    for pair in query.into_iter().flat_map(|q| q.split('&')) {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value).map_err(|why| format!("`{raw}`: {key}: {why}"))?;
        let (field, value) = match key {
            "sequencer" => {
                let did = jig_core::Did::canonicalize(&value)
                    .map_err(|_| format!("`{raw}`: sequencer `{value}` is not a did:jig"))?;
                (&mut out.sequencer, did.to_did_jig_string())
            }
            "slug" => {
                if !value.starts_with('#') || value.len() < 2 {
                    return Err(format!("`{raw}`: slug `{value}` is not a `#slug`"));
                }
                (&mut out.slug, value)
            }
            // A hint this build does not read.
            _ => continue,
        };
        if field.replace(value).is_some() {
            return Err(format!("`{raw}`: `{key}` is given twice"));
        }
    }
    Ok(out)
}

/// `s` with each `%XX` decoded, as UTF-8.
fn percent_decode(s: &str) -> Result<String, &'static str> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .ok_or("a `%` without two hex digits")?;
            let hex = std::str::from_utf8(hex).map_err(|_| "a `%` without two hex digits")?;
            let byte = u8::from_str_radix(hex, 16).map_err(|_| "a `%` without two hex digits")?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "not UTF-8 once decoded")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> String {
        jig_core::canonical_cid::of(b"channel-create").to_string()
    }

    fn did() -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    #[test]
    fn a_slug_and_an_id_are_taken_as_given() {
        assert_eq!(parse("#ops").unwrap(), "#ops");
        assert_eq!(parse(&id()).unwrap(), id());
    }

    #[test]
    fn a_link_gives_its_channel_id() {
        assert_eq!(parse(&format!("jig:{}", id())).unwrap(), id());
        let encoded = did().replace(':', "%3A");
        let link = format!("jig:{}?sequencer={encoded}&slug=%23ops", id());
        assert_eq!(parse(&link).unwrap(), id());
        let parsed = parse_link(&link, link.strip_prefix(SCHEME).unwrap()).unwrap();
        assert_eq!(parsed.sequencer, Some(did()));
        assert_eq!(parsed.slug.as_deref(), Some("#ops"));
        // A DID needs no encoding where `:` is allowed in a query.
        let plain = format!("jig:{}?sequencer={}", id(), did());
        assert_eq!(parse(&plain).unwrap(), id());
    }

    #[test]
    fn hints_never_change_the_channel() {
        let other = {
            let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
        };
        for link in [
            format!("jig:{}?slug=%23ops", id()),
            format!("jig:{}?slug=%23elsewhere&sequencer={other}", id()),
            format!("jig:{}?later=1&&slug=%23ops", id()),
        ] {
            assert_eq!(parse(&link).unwrap(), id(), "{link}");
        }
    }

    #[test]
    fn anything_else_is_refused() {
        let long = format!("jig:{}?pad={}", id(), "x".repeat(MAX_LINK_BYTES));
        for bad in [
            "",
            "  ",
            "ops",
            "hello",
            "jig:",
            "jig:ops",
            "jig:#ops",
            // An id in another spelling than the canonical one.
            &id().to_uppercase(),
            &format!("jig:{}", id().to_uppercase()),
            // A CID that is not a canonical channel id (CIDv0).
            "jig:QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
            &format!("jig:{}?sequencer=alice", id()),
            &format!("jig:{}?slug=ops", id()),
            &format!("jig:{}?slug=%23a&slug=%23b", id()),
            &format!("jig:{}?slug=%2", id()),
            &format!("jig:{}?slug=%23%FF", id()),
            &long,
        ] {
            assert!(parse(bad).is_err(), "{bad:?} was taken");
        }
    }
}
