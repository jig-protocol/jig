//! `jig dm <who> [message]` — a direct message is a locked, encrypted
//! channel with two members.
//!
//! Not a separate scheme: the channel is `restricted` (only its owner adds
//! members — the spec's *locked* membership) and `mls`, owned by whoever opened
//! it. Growing it into a group DM is `jig channel add`; opening it up is
//! `jig channel promote`. Neither re-encrypts anything.
//!
//! The slug is derived from the two DIDs, so either side running `jig dm`
//! lands in the same channel.

use anyhow::{Context, Result};
use serde_json::json;

use crate::cmd::channel::{create_with, resolve_who};
use crate::cmd::common::CliContext;
use crate::cmd::secure::Secure;

/// `#dm/` plus 16 hex digits of a domain-separated hash of the sorted pair.
pub fn dm_slug(a: &str, b: &str) -> String {
    let mut pair = [a, b];
    pair.sort_unstable();
    let digest = jig_core::hash_labeled_parts(&[
        ("domain", b"jig-dm-v1".as_slice()),
        ("a", pair[0].as_bytes()),
        ("b", pair[1].as_bytes()),
    ]);
    format!("#dm/{}", &digest.to_hex()[..16])
}

pub async fn run(ctx: &CliContext, who: String, message: String) -> Result<()> {
    let peer = resolve_who(ctx, &who)?;
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
            create_with(ctx, &slug, "restricted", true, true, json!({"dm": true})).await?;
        }
    }
    // Add the other side if they are not in yet — on first use, or when an
    // earlier add failed (they had published no key packages, say).
    #[derive(serde::Deserialize)]
    struct Members {
        members: Vec<Member>,
    }
    #[derive(serde::Deserialize)]
    struct Member {
        did: String,
    }
    let members: Members = secure
        .get_json(&format!(
            "/api/v1/channels/{}/members",
            crate::cmd::channel::escape_slug_for_url(&slug)
        ))
        .await?;
    if !members.members.iter().any(|m| m.did == peer) {
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
    fn either_side_derives_the_same_slug() {
        let a = "did:jig:zAlice";
        let b = "did:jig:zBob";
        assert_eq!(dm_slug(a, b), dm_slug(b, a));
        assert_ne!(dm_slug(a, b), dm_slug(a, "did:jig:zCarol"));
        assert!(dm_slug(a, b).starts_with("#dm/"));
        assert_eq!(dm_slug(a, b).len(), "#dm/".len() + 16);
    }
}
