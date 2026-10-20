//! `jig dm <who> [message]` — a direct message is a locked, encrypted
//! channel with two members.
//!
//! Not a separate scheme: the channel is `restricted` (only its owner adds
//! members — the spec's *locked* membership) and `mls`, owned by whoever opened
//! it. Growing it into a group DM is `jig channel add`; opening it up is
//! `jig channel promote`. Neither re-encrypts anything.
//!
//! The slug is derived from the two DIDs, so either side running `jig dm`
//! lands in the same channel. Because anyone can derive it, `jig dm` checks
//! who is actually in the channel's MLS tree before sending, and refuses a
//! channel with anyone but the two of them in it — one somebody else opened
//! for the pair, or one since grown into a group DM (`jig send --channel` and
//! `jig chat` still reach that). The server also lets only one of the pair
//! create the slug.

use anyhow::{Context, Result};
use serde_json::json;

use crate::cmd::channel::{create_with, resolve_who};
use crate::cmd::common::CliContext;
use crate::cmd::secure::Secure;

pub use jig_core::dm::dm_slug;

/// Whether this device's copy of the DM's MLS tree (`roster`) is fit to send
/// to as a DM between `me` and `peer`: `me` is in it and nobody but the two
/// of them is. The tree is what decides who can read, and nobody gets into it
/// without a member's commit — unlike the server's member list or owner,
/// which a server can make up. `Err` names who else is in it.
fn check_roster<'a>(roster: &'a [String], me: &str, peer: &str) -> Result<(), Option<&'a str>> {
    if !roster.iter().any(|d| d == me) {
        return Err(None);
    }
    match roster.iter().find(|d| *d != me && *d != peer) {
        Some(other) => Err(Some(other)),
        None => Ok(()),
    }
}

pub async fn run(ctx: &CliContext, who: String, message: String) -> Result<()> {
    let peer = resolve_who(ctx, &who).await?;
    let me = ctx.identity()?.did_string();
    if peer == me {
        anyhow::bail!("that is you");
    }
    let slug = dm_slug(&me, &peer);
    let secure = Secure::open(ctx)?;

    match secure.channel(&slug).await? {
        Some(info) if info.encrypted() => {}
        Some(_) => anyhow::bail!("{slug} exists but is not encrypted; not using it as a DM"),
        None => {
            let meta = json!({"dm": true, "dm_peer": peer});
            create_with(ctx, &slug, "restricted", true, true, meta).await?;
        }
    }
    // A DM the other side opened reaches this device as a welcome in its
    // history, so catch up before asking who is in it.
    secure.sync(&slug).await?;
    let roster = if secure.session.has_group(secure.server(), &slug)? {
        secure.session.group_members(secure.server(), &slug)?
    } else {
        Vec::new()
    };
    match check_roster(&roster, &me, &peer) {
        Ok(()) => {}
        Err(None) => anyhow::bail!(
            "{slug} exists but this device is not in it yet; ask {peer} to run `jig dm {me}`"
        ),
        Err(Some(other)) => anyhow::bail!(
            "{slug} includes {other}, not only you and {peer}; refusing to use it as a DM"
        ),
    }
    // Add the other side if they are not in yet — on first use, or when an
    // earlier add failed (they had published no key packages, say).
    if !roster.contains(&peer) {
        crate::cmd::channel::add(ctx, slug.clone(), peer.clone())
            .await
            .with_context(|| format!("adding {peer} to {slug}"))?;
    }

    if message.trim().is_empty() {
        return crate::cmd::chat::run(ctx, crate::cmd::chat::ChatArgs { channel: slug }).await;
    }
    secure.sync(&slug).await?;
    let cid = secure.send(&slug, message.trim()).await?;
    println!("{cid}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dm_is_only_ever_the_two_of_them() {
        let (me, peer) = ("did:jig:zAlice", "did:jig:zBob");
        let r = |ds: &[&str]| ds.iter().map(|d| d.to_string()).collect::<Vec<_>>();
        assert_eq!(check_roster(&r(&[me, peer]), me, peer), Ok(()));
        // Just opened; the peer is added next.
        assert_eq!(check_roster(&r(&[me]), me, peer), Ok(()));
        // Someone else took the slug and added both of us, or grew it.
        let squatted = r(&["did:jig:zMallory", me, peer]);
        assert_eq!(
            check_roster(&squatted, me, peer),
            Err(Some("did:jig:zMallory"))
        );
        // Not in it at all.
        assert_eq!(check_roster(&r(&[peer]), me, peer), Err(None));
        assert_eq!(check_roster(&[], me, peer), Err(None));
    }
}
