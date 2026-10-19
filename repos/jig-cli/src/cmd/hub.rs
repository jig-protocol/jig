//! The hub offer in `jig init`: a first server for someone with none.
//!
//! When `jig init` runs at a terminal and no `--server` was given, it offers
//! the project's hub server, says what the hub can see, and defaults to no.
//! On yes it points `[server] base_url` at the hub and pins the hub's DID
//! before the first connection, so that connection is checked against a
//! DID this build ships rather than trusted on first use.
//!
//! Dormant until DJ fills in both [`HUB_SERVER_URL`] and [`HUB_SERVER_DID`]:
//! while either is a placeholder the offer is never shown, in any build.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{Context, Result};

/// The hub server `jig init` offers.
///
/// TODO(DJ): set to the hub's URL. Until then this is under the reserved
/// `.invalid` TLD (RFC 2606), which can never resolve to anyone's host.
pub const HUB_SERVER_URL: &str = "https://hub.placeholder.invalid";

/// The hub server's DID, pinned before the first connection.
///
/// TODO(DJ): set to the hub's DID from the key ceremony.
pub const HUB_SERVER_DID: &str = PLACEHOLDER_HUB_DID;

/// Not a did:jig at all, so it can never match a server's DID.
const PLACEHOLDER_HUB_DID: &str = "did:jig:placeholder";

/// What the offer says the hub can see. Open channels are plaintext.
pub const DISCLOSURE: &str = "The hub sees who you talk to and when, and the content of open \
                              channels. It cannot read encrypted channels or DMs.";

/// A hub to offer: a real URL and the DID to pin for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hub {
    pub url: String,
    pub did: String,
}

/// The hub this build can offer, or `None` while either constant is a
/// placeholder.
pub fn shipped_hub() -> Option<Hub> {
    hub_from(HUB_SERVER_URL, HUB_SERVER_DID)
}

fn hub_from(url: &str, did: &str) -> Option<Hub> {
    let host = reqwest::Url::parse(url).ok()?.host_str()?.to_string();
    if host == "invalid" || host.ends_with(".invalid") || did == PLACEHOLDER_HUB_DID {
        return None;
    }
    jig_core::Did::from_did_jig_string(did).ok()?;
    Some(Hub {
        url: url.trim_end_matches('/').to_string(),
        did: did.to_string(),
    })
}

/// Whether `jig init` may ask at all: never with `--server`, never with
/// `JIG_NONINTERACTIVE` set, and never without a terminal on both ends (which
/// covers `curl | bash`, whose stdin is the pipe).
pub fn may_ask(
    server_flag_given: bool,
    noninteractive_env: bool,
    stdin_tty: bool,
    stdout_tty: bool,
) -> bool {
    !server_flag_given && !noninteractive_env && stdin_tty && stdout_tty
}

/// Ask whether to use `hub`. Anything but an explicit yes is no, including
/// an empty line and end of input.
pub fn ask(hub: &Hub, input: &mut impl BufRead, output: &mut impl Write) -> Result<bool> {
    writeln!(
        output,
        "No server configured. Use the jig hub at {} as your first server?",
        hub.url
    )?;
    writeln!(output, "  {DISCLOSURE}")?;
    write!(output, "Use the hub? [y/N] ")?;
    output.flush()?;
    let mut line = String::new();
    input.read_line(&mut line).context("reading the answer")?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Offer the shipped hub when this run may ask. Returns the hub chosen, if
/// any. The caller writes it to `cli.toml` and pins its DID.
pub fn offer(server_flag_given: bool) -> Result<Option<Hub>> {
    let Some(hub) = shipped_hub() else {
        return Ok(None);
    };
    let noninteractive = std::env::var_os("JIG_NONINTERACTIVE").is_some_and(|v| !v.is_empty());
    if !may_ask(
        server_flag_given,
        noninteractive,
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    ) {
        return Ok(None);
    }
    let yes = ask(&hub, &mut std::io::stdin().lock(), &mut std::io::stdout())?;
    Ok(yes.then_some(hub))
}

/// Pin `hub`'s DID in the pin store at `pins_path` before anything connects.
pub fn pin(hub: &Hub, pins_path: &std::path::Path) -> Result<()> {
    let mut pins = jig_client::pins::Pins::load(pins_path)
        .with_context(|| format!("loading {}", pins_path.display()))?;
    pins.check_server_did(&hub.url, &hub.did)
        .with_context(|| format!("pinning {} for {}", hub.did, hub.url))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_DID: &str = "did:jig:zgu6iu77ozi4lfrctnyf5ewdp3mmna4hfbycz6hkd7c767ol2ptqq";

    #[test]
    fn this_build_offers_no_hub_while_its_constants_are_placeholders() {
        assert_eq!(shipped_hub(), None);
    }

    #[test]
    fn a_hub_needs_a_real_url_and_a_real_did() {
        assert_eq!(hub_from("https://hub.placeholder.invalid", REAL_DID), None);
        assert_eq!(hub_from("https://invalid", REAL_DID), None);
        assert_eq!(hub_from("https://hub.example", PLACEHOLDER_HUB_DID), None);
        assert_eq!(hub_from("https://hub.example", "not-a-did"), None);
        assert_eq!(
            hub_from("https://hub.example/", REAL_DID),
            Some(Hub {
                url: "https://hub.example".into(),
                did: REAL_DID.into()
            })
        );
    }

    #[test]
    fn the_offer_is_only_ever_made_at_a_terminal_without_a_server() {
        assert!(may_ask(false, false, true, true));
        assert!(!may_ask(true, false, true, true), "--server given");
        assert!(!may_ask(false, true, true, true), "JIG_NONINTERACTIVE");
        assert!(
            !may_ask(false, false, false, true),
            "curl | bash: stdin is a pipe"
        );
        assert!(!may_ask(false, false, true, false), "output redirected");
    }

    #[test]
    fn only_an_explicit_yes_takes_the_hub() {
        let hub = hub_from("https://hub.example", REAL_DID).unwrap();
        for (answer, want) in [
            ("y\n", true),
            ("YES\n", true),
            ("\n", false),
            ("", false),
            ("n\n", false),
            ("sure\n", false),
        ] {
            let mut out = Vec::new();
            let got = ask(&hub, &mut answer.as_bytes(), &mut out).unwrap();
            assert_eq!(got, want, "answer {answer:?}");
            let shown = String::from_utf8(out).unwrap();
            assert!(shown.contains(DISCLOSURE), "{shown}");
            assert!(shown.contains("[y/N]"), "defaults to no: {shown}");
        }
    }

    #[test]
    fn the_hub_did_is_pinned_before_the_first_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let hub = hub_from("https://hub.example", REAL_DID).unwrap();
        pin(&hub, &path).unwrap();
        let mut pins = jig_client::pins::Pins::load(&path).unwrap();
        assert_eq!(pins.server(&hub.url).unwrap().server_did, REAL_DID);
        assert!(
            pins.check_server_did(&hub.url, "did:jig:zImpostor")
                .is_err(),
            "a server presenting another DID is refused"
        );
    }
}
