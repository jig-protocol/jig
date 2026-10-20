//! The channel slug grammar, checked when a channel is created.
//!
//! A slug is a display name (JEP-0005 rule 1): channels are keyed by id, and
//! a slug is unique only per sequencer. It still has to be unambiguous to the
//! people reading it, so new slugs have one canonical spelling:
//!
//! - A **user slug** is `#` and 1 to 64 characters from `[a-z0-9_-]`, the
//!   first one `[a-z0-9]`. No uppercase, no `/`, no whitespace, nothing
//!   outside ASCII: `#General`, `#café`, a fullwidth `＃x` or a zero-width
//!   joiner inside a slug would otherwise each be a distinct channel that
//!   looks like another. A slug is never lowercased for its author; a
//!   non-conforming one is refused.
//! - **Reserved namespaces** are the only slugs with a `/`:
//!   - `#dm/` and 16 lowercase hex digits ([`crate::dm::dm_slug`]), which
//!     the server's DM rule further limits to the pair that derives it;
//!   - `#jig/` and 1 to 59 characters from `[a-z0-9_-]`, created only by the
//!     server itself (its manifest log is `#jig/manifest`);
//!   - `#email/` and 16 lowercase hex digits, the email bridge's mail
//!     threads, created only through the bridge.
//!
//!   Which namespace a slug claims is decided on its ASCII-lowercased form,
//!   so `#JIG/x` and `#Dm/x` are refused as reserved, not let through as
//!   some other channel.
//!
//! This module only classifies a slug; it knows nothing of who is asking.
//! Who may create each [`SlugClass`] is the server's rule, at
//! `channel-create` (`jig-pipeline`'s ingest).
//!
//! Channels created before this grammar keep their slugs: it applies to
//! creates only, and lookups stay exact-match.

use crate::dm::DM_PREFIX;

/// The server's own namespace.
pub const JIG_PREFIX: &str = "#jig/";
/// The email bridge's mail-thread namespace.
pub const EMAIL_PREFIX: &str = "#email/";
/// The longest user slug, after the `#`.
pub const MAX_USER_SLUG_LEN: usize = 64;
/// The longest name in `#jig/`, after the prefix.
pub const MAX_JIG_NAME_LEN: usize = 59;
/// The hex digits after `#dm/` and `#email/`.
pub const HASH_SLUG_HEX_LEN: usize = 16;

/// The class of a well-formed slug: an ordinary channel or one of the
/// reserved namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlugClass {
    /// An ordinary channel: anyone may create it.
    User,
    /// `#dm/`: a direct message, created only by one of the pair that
    /// derives the slug ([`crate::dm::dm_slug`]).
    Dm,
    /// `#email/`: an email-bridge mail thread, created only by the bridge.
    Email,
    /// `#jig/`: the server's own channels, created only by the server.
    Server,
}

/// Why a slug is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlugError {
    #[error("a channel slug starts with `#`")]
    NoHash,
    #[error("a channel slug has 1 to {max} characters after `#`")]
    Length { max: usize },
    #[error("a channel slug starts with a lowercase letter or digit after `#`")]
    BadFirst,
    #[error(
        "a channel slug uses only lowercase ASCII letters, digits, `-` and `_` \
         (found {found:?})"
    )]
    BadChar { found: char },
    #[error("a `{prefix}` slug is `{prefix}` followed by {shape}")]
    BadReserved {
        prefix: &'static str,
        shape: &'static str,
    },
}

fn user_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'
}

/// Check `name` (the part after a prefix) against `[a-z0-9_-]{1,max}` with a
/// first character `[a-z0-9]`.
fn check_name(name: &str, max: usize) -> Result<(), SlugError> {
    if let Some(found) = name.chars().find(|c| !user_char(*c)) {
        return Err(SlugError::BadChar { found });
    }
    // All ASCII from here, so bytes are characters.
    if name.is_empty() || name.len() > max {
        return Err(SlugError::Length { max });
    }
    if !name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return Err(SlugError::BadFirst);
    }
    Ok(())
}

/// Check a user slug: `#` and `[a-z0-9_-]{1,64}`, first character
/// `[a-z0-9]`. Reserved namespaces are refused here (they contain `/`); use
/// [`classify_slug`] to admit them.
pub fn check_user_slug(slug: &str) -> Result<(), SlugError> {
    let name = slug.strip_prefix('#').ok_or(SlugError::NoHash)?;
    check_name(name, MAX_USER_SLUG_LEN)
}

/// The reserved class `slug` claims, judged on its ASCII-lowercased form,
/// whether or not it is well formed. `None` for a user slug.
pub fn reserved_class(slug: &str) -> Option<SlugClass> {
    let lower = slug.to_ascii_lowercase();
    if lower.starts_with(DM_PREFIX) {
        Some(SlugClass::Dm)
    } else if lower.starts_with(EMAIL_PREFIX) {
        Some(SlugClass::Email)
    } else if lower.starts_with(JIG_PREFIX) {
        Some(SlugClass::Server)
    } else {
        None
    }
}

/// Whether `slug` claims a reserved namespace (on its lowercased form).
pub fn is_reserved(slug: &str) -> bool {
    reserved_class(slug).is_some()
}

fn check_hex_tail(slug: &str, prefix: &'static str) -> Result<(), SlugError> {
    let bad = SlugError::BadReserved {
        prefix,
        shape: "16 lowercase hex digits",
    };
    let tail = slug.strip_prefix(prefix).ok_or(bad.clone())?;
    if tail.len() == HASH_SLUG_HEX_LEN
        && tail
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        Ok(())
    } else {
        Err(bad)
    }
}

/// Classify the slug of a new channel, refusing one outside the grammar.
///
/// A slug whose lowercased form starts with a reserved prefix is in that
/// namespace and must have its exact shape, prefix included in lowercase:
/// `#JIG/x` or `#Dm/x` is refused, never read as a user slug.
pub fn classify_slug(slug: &str) -> Result<SlugClass, SlugError> {
    match reserved_class(slug) {
        Some(SlugClass::Server) => {
            let bad = SlugError::BadReserved {
                prefix: JIG_PREFIX,
                shape: "1 to 59 characters from [a-z0-9_-]",
            };
            let name = slug.strip_prefix(JIG_PREFIX).ok_or(bad.clone())?;
            check_name(name, MAX_JIG_NAME_LEN).map_err(|_| bad)?;
            Ok(SlugClass::Server)
        }
        Some(SlugClass::Dm) => check_hex_tail(slug, DM_PREFIX).map(|()| SlugClass::Dm),
        Some(SlugClass::Email) => check_hex_tail(slug, EMAIL_PREFIX).map(|()| SlugClass::Email),
        Some(SlugClass::User) | None => check_user_slug(slug).map(|()| SlugClass::User),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_slugs_in_the_grammar_are_accepted() {
        let max = format!("#{}", "a".repeat(MAX_USER_SLUG_LEN));
        for slug in ["#general", "#dev-ops", "#a", "#0", "#with_underscore", &max] {
            assert_eq!(classify_slug(slug), Ok(SlugClass::User), "{slug}");
            assert_eq!(check_user_slug(slug), Ok(()), "{slug}");
        }
    }

    #[test]
    fn user_slugs_outside_the_grammar_are_refused() {
        let too_long = format!("#{}", "a".repeat(MAX_USER_SLUG_LEN + 1));
        let cases: &[(&str, SlugError)] = &[
            ("#General", SlugError::BadChar { found: 'G' }),
            ("#café", SlugError::BadChar { found: 'é' }),
            ("＃x", SlugError::NoHash),
            ("#ｘ", SlugError::BadChar { found: 'ｘ' }),
            ("#a\u{200d}b", SlugError::BadChar { found: '\u{200d}' }),
            ("#a b", SlugError::BadChar { found: ' ' }),
            ("#tab\t", SlugError::BadChar { found: '\t' }),
            (&too_long, SlugError::Length { max: 64 }),
            ("#", SlugError::Length { max: 64 }),
            ("#-lead", SlugError::BadFirst),
            ("#_lead", SlugError::BadFirst),
            ("#team/ops", SlugError::BadChar { found: '/' }),
            ("general", SlugError::NoHash),
        ];
        for (slug, want) in cases {
            assert_eq!(classify_slug(slug).as_ref(), Err(want), "{slug:?}");
        }
    }

    #[test]
    fn dm_slugs_have_one_shape() {
        let dm = crate::dm::dm_slug("did:jig:za", "did:jig:zb");
        assert_eq!(classify_slug(&dm), Ok(SlugClass::Dm));
        for bad in [
            "#dm/xyz",
            "#dm/0011223344556677aa",
            "#dm/0011223344AABBCC",
            "#Dm/0011223344556677",
            "#DM/x",
        ] {
            assert!(
                matches!(
                    classify_slug(bad),
                    Err(SlugError::BadReserved { prefix: "#dm/", .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn server_slugs_have_one_shape() {
        assert_eq!(classify_slug("#jig/manifest"), Ok(SlugClass::Server));
        assert_eq!(
            classify_slug(&format!("#jig/{}", "a".repeat(59))),
            Ok(SlugClass::Server)
        );
        for slug in [
            "#JIG/manifest",
            "#Jig/x",
            "#jig/",
            "#jig/Bad",
            "#jig/a/b",
            &format!("#jig/{}", "a".repeat(60)),
        ] {
            assert!(
                matches!(
                    classify_slug(slug),
                    Err(SlugError::BadReserved {
                        prefix: "#jig/",
                        ..
                    })
                ),
                "{slug}"
            );
        }
    }

    #[test]
    fn email_threads_have_one_shape() {
        assert_eq!(
            classify_slug("#email/0011223344556677"),
            Ok(SlugClass::Email)
        );
        for slug in [
            "#email/x",
            "#EMAIL/0011223344556677",
            "#Email/0011223344556677",
        ] {
            assert!(
                matches!(
                    classify_slug(slug),
                    Err(SlugError::BadReserved {
                        prefix: "#email/",
                        ..
                    })
                ),
                "{slug}"
            );
        }
    }

    #[test]
    fn reserved_is_judged_on_the_lowercased_form() {
        for (slug, class) in [
            ("#dm/x", SlugClass::Dm),
            ("#DM/x", SlugClass::Dm),
            ("#jig/x", SlugClass::Server),
            ("#JIG/x", SlugClass::Server),
            ("#Email/x", SlugClass::Email),
        ] {
            assert_eq!(reserved_class(slug), Some(class), "{slug}");
            assert!(is_reserved(slug));
        }
        for slug in ["#general", "#dmx", "#jig", "#jigsaw", "#emailx"] {
            assert!(!is_reserved(slug), "{slug}");
        }
    }
}
