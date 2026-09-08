//! Gate 3: may this caller do this, here?
//!
//! Deliberately a pure function of already-fetched facts rather than something
//! that queries the store itself. Two reasons: it is trivially testable without
//! a database, and the fanout path calls it per delivery, where doing I/O inside
//! the decision would be a performance problem.

use crate::auth::GateOutcome;

/// A channel's read policy.
///
/// The stored column is free-form `TEXT`, so parsing must be total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Readable by any admitted caller.
    Open,
    /// Readable only by members and the owner.
    Restricted,
}

impl Visibility {
    /// Parse a stored visibility string, **failing closed**.
    ///
    /// Anything unrecognised is treated as `Restricted`. A typo, or a value
    /// written by a newer version of the server, must deny rather than grant:
    /// guessing wrong in this direction refuses a legitimate reader, who can be
    /// told why. Guessing wrong in the other direction silently publishes a
    /// private channel, and nobody finds out.
    pub fn parse(raw: &str) -> Self {
        match raw {
            "open" => Visibility::Open,
            _ => Visibility::Restricted,
        }
    }
}

/// Decide whether a caller may read a channel.
///
/// `is_member` and `is_owner` are supplied by the caller so this stays pure.
///
/// The owner check is not a convenience. An owner who never added themselves to
/// the memberships table would otherwise be locked out of the channel they
/// created, which presents to them as data loss rather than as a permissions
/// error.
pub fn authorize_read(
    visibility: Visibility,
    is_member: bool,
    is_owner: bool,
) -> Result<(), GateOutcome> {
    match visibility {
        Visibility::Open => Ok(()),
        Visibility::Restricted if is_member || is_owner => Ok(()),
        Visibility::Restricted => Err(GateOutcome::AuthzNotMember),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_channel_is_readable_by_any_admitted_caller() {
        assert_eq!(authorize_read(Visibility::Open, false, false), Ok(()));
    }

    #[test]
    fn a_restricted_channel_is_readable_by_a_member() {
        assert_eq!(authorize_read(Visibility::Restricted, true, false), Ok(()));
    }

    #[test]
    fn a_restricted_channel_refuses_a_non_member() {
        assert_eq!(
            authorize_read(Visibility::Restricted, false, false),
            Err(GateOutcome::AuthzNotMember)
        );
    }

    /// An owner who never added themselves as a member must still read their own
    /// channel. Otherwise creating a restricted channel locks out its creator,
    /// which looks like data loss.
    #[test]
    fn a_restricted_channel_is_readable_by_its_owner() {
        assert_eq!(authorize_read(Visibility::Restricted, false, true), Ok(()));
    }

    #[test]
    fn visibility_parses_the_two_known_values() {
        assert_eq!(Visibility::parse("open"), Visibility::Open);
        assert_eq!(Visibility::parse("restricted"), Visibility::Restricted);
    }

    /// The stored column is free-form TEXT. A typo, a value from a newer
    /// server, or an empty string must all DENY — the failure that matters is
    /// silently publishing a private channel, not refusing a legitimate reader.
    #[test]
    fn an_unknown_visibility_string_fails_closed() {
        for raw in ["banana", "", "OPEN", "public", "Open"] {
            assert_eq!(
                Visibility::parse(raw),
                Visibility::Restricted,
                "unrecognised visibility {raw:?} must be treated as the closed case"
            );
            assert_eq!(
                authorize_read(Visibility::parse(raw), false, false),
                Err(GateOutcome::AuthzNotMember)
            );
        }
    }
}
