//! The one place the stored `channels.visibility` string is interpreted.
//!
//! The column is free-form `TEXT`, so interpretation must be total, and it
//! must **fail closed**: anything that is not exactly `open` is restricted. A
//! typo, or a value written by a newer server, must deny rather than grant —
//! refusing a legitimate reader is visible and explicable, while guessing the
//! other way silently publishes a private channel and nobody finds out.
//!
//! `jig-server`'s read gate has its own `Visibility::parse` with the same
//! rule; a test there holds the two to identical answers.

/// Whether a stored visibility string means "anyone admitted may read".
pub fn is_open(visibility: &str) -> bool {
    visibility == "open"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_word_open_is_open() {
        assert!(is_open("open"));
        for not_open in ["restricted", "", "Open", "OPEN", " open", "open ", "public"] {
            assert!(!is_open(not_open), "{not_open:?} must fail closed");
        }
    }
}
