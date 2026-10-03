//! Revocation: the list of keys that must never be trusted again.
//!
//! ## Why a list and not a shorter allow list
//!
//! Revocation is usually implemented by removing a key from the trust anchor. For
//! a signature whose trust anchor is a fingerprint pinned somewhere the host
//! cannot rewrite, that does not work: editing the file is exactly the
//! substitution the pin defends against, so a compromised operator could quietly
//! un-revoke a burned key and a verifier reading only the file would see nothing
//! wrong.
//!
//! So revocation travels on its own channel and is checked **before** the pin. A
//! revoked key fails even when it is the pinned one, and un-revoking is a
//! deliberate act on a list rather than an edit to a file that has other purposes.
//!
//! ## The format
//!
//! One `SHA256:…` fingerprint per line, `#` starts a comment, blank lines are
//! ignored. Anything else is an error naming the line, because a typo in a
//! revocation list is a key that stays trusted — the quietest possible failure,
//! and the one worth shouting about.
//!
//! This lives in the core crate rather than beside the CLI so that Python and
//! WebAssembly callers can honour a revocation list too. A binding that could
//! verify a signature but not a revocation would report a burned key as good,
//! which is worse than not verifying at all because it looks like an answer.

use std::collections::BTreeSet;
use std::path::Path;

use crate::{Error, Result};

/// A set of revoked fingerprints, checked before any pin.
#[derive(Clone, Debug, Default)]
pub struct Revocations {
    fingerprints: BTreeSet<String>,
}

impl Revocations {
    /// Parse a revocation list. See the module docs for the format.
    ///
    /// `origin` appears in errors so a caller reading one knows which file to fix.
    pub fn parse(text: &str, origin: &str) -> Result<Self> {
        let mut fingerprints = BTreeSet::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if !crate::sshsig::is_fingerprint(line) {
                return Err(Error::Invalid(format!(
                    "{origin}:{}: expected a SHA256:… fingerprint, got {line:?}",
                    number + 1
                )));
            }
            fingerprints.insert(line.to_string());
        }
        Ok(Self { fingerprints })
    }

    /// Read a revocation list from a file.
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| Error::Invalid(format!("cannot read {}: {error}", path.display())))?;
        Self::parse(&text, &path.display().to_string())
    }

    /// Revoke these fingerprints in memory.
    pub fn from_fingerprints(fingerprints: impl IntoIterator<Item = String>) -> Self {
        Self {
            fingerprints: fingerprints.into_iter().collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Whether this key is on the list.
    pub fn is_revoked(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
    }

    /// Refuse a revoked key, before anything is checked against it.
    pub fn refuse(&self, fingerprint: &str) -> Result<()> {
        if self.is_revoked(fingerprint) {
            return Err(Error::Invalid(format!(
                "{fingerprint} is revoked: a burned key is refused even when it is the pinned one"
            )));
        }
        Ok(())
    }

    /// The fingerprints, in order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.fingerprints.iter().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "SHA256:TXqo/u13biOBWNJi/NM+MweBh6qhWr2Ur/pEdnNUG44";

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let list = Revocations::parse(&format!("# burned keys\n\n{PIN}\n"), "list").unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.is_revoked(PIN));
        assert!(!list.is_revoked("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn a_typo_is_an_error_naming_the_line_not_a_skipped_line() {
        // The quietest failure there is: a key that stays trusted because the line
        // was misspelled.
        for (text, line) in [("# c\n\nSHA256:abc\nnope\n", 3), ("SHA256:abc\n", 1)] {
            let error = Revocations::parse(text, "revoked.txt").unwrap_err();
            let said = error.to_string();
            assert!(said.contains(&format!("revoked.txt:{line}")), "{said}");
            assert!(said.contains("SHA256:"), "{said}");
        }
        // The prefix is right but the body is too short to be a fingerprint, which
        // is the near miss worth catching rather than skipping.
        assert!(Revocations::parse(&format!("SHA256:{}\n", "a".repeat(43)), "l").is_ok());
        assert!(Revocations::parse(&format!("SHA256:{}\n", "a".repeat(42)), "l").is_err());
    }

    #[test]
    fn a_revoked_key_is_refused_even_when_it_is_the_pinned_one() {
        let list = Revocations::from_fingerprints([PIN.to_string()]);
        assert!(list.refuse(PIN).is_err());
        assert!(list
            .refuse("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .is_ok());
    }

    #[test]
    fn an_empty_list_revokes_nothing() {
        let list = Revocations::parse("\n# nothing yet\n", "l").unwrap();
        assert!(list.is_empty());
        assert!(list.refuse(PIN).is_ok());
        assert_eq!(list.iter().count(), 0);
    }

    #[test]
    fn duplicates_collapse() {
        let list = Revocations::parse(&format!("{PIN}\n{PIN}\n"), "l").unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn a_missing_file_is_reported_as_such() {
        let error = Revocations::read(Path::new("/nonexistent/revoked.txt")).unwrap_err();
        assert!(error.to_string().contains("cannot read"), "{error}");
    }
}
