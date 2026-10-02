//! Signed attestations: a named person standing behind a chain head.
//!
//! A chain proves that nothing inside it changed after the fact, and a remote
//! anchor proves that a trusted copy exists elsewhere. Neither says *who* looked
//! at it or *when*. An attestation is that missing statement: a small document
//! naming a chain head, signed by one key, verifiable by anyone holding that
//! key's public half.
//!
//! ## What it is for
//!
//! Detecting a rewrite is a technical property. Being able to say "this was
//! reviewed and released by a named person at a stated time, and here is their
//! signature" is an accountability property, and the two fail differently. A
//! stolen key can produce a perfectly valid attestation for a chain that never
//! existed; what it cannot do is produce one that a verifier holding a *pinned*
//! fingerprint rejects, or that predates a compromise when the signature reached
//! a third party at the time.
//!
//! ## Why the document is small and separate
//!
//! The document names a head (`seq` plus `digest`) and nothing else, so signing
//! is instant and a single signature covers a whole chain however long it grows.
//! It is a *sidecar*: `<chain>.attestation.json` and `<chain>.attestation.sig`,
//! beside the chain and never inside it. `nostoi-v1` records are immutable and
//! append-only, so putting signatures in them would mean a new record format
//! and a new revision for something that does not belong to the chain's
//! integrity.
//!
//! ## Canonical bytes
//!
//! [`Attestation::canonical_bytes`] is the same canonical JSON that a record's
//! digest is computed over — `json.dumps(record, sort_keys=True,
//! separators=(",", ":"))` — so any language can recompute
//! [`Attestation::digest`] and know exactly which bytes were signed. That is the
//! point of doing it this way rather than signing a pretty-printed file.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::chain::{Head, StreamingVerification};
use crate::{Error, Result};

/// The only attestation version this code produces or accepts.
pub const ATTESTATION_V1: &str = "nostoi-attestation-v1";

/// Default signing namespace. `ssh-keygen -Y sign` requires one, and it scopes
/// the signature so a signature made here cannot be replayed as a signature for
/// some other use of the same key.
pub const DEFAULT_NAMESPACE: &str = "nostoi-attestation";

/// A signed statement about one chain head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Always [`ATTESTATION_V1`].
    pub v: String,
    /// The chain identity, matching what an anchor for this chain would record.
    pub chain: String,
    /// The record format of the chain (`nostoi-v1`).
    pub format: String,
    /// The attested head's sequence number.
    pub seq: u64,
    /// The attested head's digest.
    pub digest: String,
    /// When the attestation was made, RFC 3339 UTC.
    pub anchored_at: String,
    /// The signing identity, matching an `allowed_signers` entry.
    pub principal: String,
    /// The signing key's fingerprint, `SHA256:...`. Carried in the document so
    /// a reader can see *which* key signed it, and pinned at verification time
    /// so a substituted key is rejected rather than believed.
    pub fingerprint: String,
    /// The remote checkpoint this head was also anchored at, when there is one.
    /// Optional, and omitted rather than null when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_key: Option<String>,
}

/// The sidecar paths for a chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sidecars {
    pub document: PathBuf,
    pub signature: PathBuf,
}

impl Sidecars {
    /// `<chain>.attestation.json` and `<chain>.attestation.sig`.
    pub fn for_chain(chain: &Path) -> Sidecars {
        let name = chain
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        let suffix = match &name {
            Some(name) => format!("{name}.attestation"),
            None => "chain.attestation".to_string(),
        };
        Sidecars {
            document: chain.with_file_name(format!("{suffix}.json")),
            signature: chain.with_file_name(format!("{suffix}.sig")),
        }
    }

    /// True when both sidecars are present.
    pub fn present(&self) -> bool {
        self.document.is_file() && self.signature.is_file()
    }

    /// What is missing, phrased for a person deciding what to do about it.
    pub fn missing_description(&self) -> Option<String> {
        if self.present() {
            return None;
        }
        let absent = [
            (!self.document.is_file()).then_some(self.document.display().to_string()),
            (!self.signature.is_file()).then_some(self.signature.display().to_string()),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        Some(format!("missing {}", absent.join(" and ")))
    }
}

/// How an attestation relates to a chain's current head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// The attestation names the chain's current head.
    Current,
    /// The chain has advanced past the attested head; the attestation still
    /// covers the intact prefix it names.
    Stale { ahead_by: u64 },
    /// The chain's head does not match what was attested, and the chain is
    /// shorter than the attestation claims. Truncation, or the wrong chain.
    Truncated,
    /// The chain does not verify at the attested position: rewritten history.
    Rewritten,
}

impl Coverage {
    pub fn is_current(self) -> bool {
        matches!(self, Coverage::Current)
    }
}

impl Attestation {
    /// Build an attestation for `head`.
    pub fn new(
        chain: &str,
        format: &str,
        head: &Head,
        anchored_at: OffsetDateTime,
        principal: &str,
        fingerprint: &str,
        anchor_key: Option<String>,
    ) -> Result<Self> {
        let attestation = Attestation {
            v: ATTESTATION_V1.to_string(),
            chain: chain.to_string(),
            format: format.to_string(),
            seq: head.seq,
            digest: head.digest.clone(),
            anchored_at: anchored_at
                .to_offset(time::UtcOffset::UTC)
                .format(&Rfc3339)
                .map_err(|error| Error::Invalid(format!("anchored_at: {error}")))?,
            principal: principal.to_string(),
            fingerprint: fingerprint.to_string(),
            anchor_key,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    /// The exact bytes a signature covers.
    ///
    /// One line of canonical JSON, the same rule records use, so the digest below
    /// can be recomputed in any language without reimplementing anything.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let value: Value =
            serde_json::to_value(self).map_err(|error| Error::Invalid(error.to_string()))?;
        Ok(crate::canonical::to_string(&value).into_bytes())
    }

    /// The SHA-256 of [`Attestation::canonical_bytes`], in lowercase hex.
    ///
    /// This identifies which document was signed. It is not a substitute for the
    /// signature: anyone can recompute it.
    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }

    /// Reject a document that this code could not have produced.
    ///
    /// Deliberately independent of any signature: a valid signature over a
    /// malformed document still proves nothing, and checking the shape first
    /// keeps the failure legible.
    pub fn validate(&self) -> Result<()> {
        if self.v != ATTESTATION_V1 {
            return Err(Error::Invalid(format!(
                "unsupported attestation version {:?}",
                self.v
            )));
        }
        if self.chain.trim().is_empty() || self.principal.trim().is_empty() {
            return Err(Error::Invalid(
                "an attestation must name a chain and a signing principal".into(),
            ));
        }
        if self.seq == 0 {
            return Err(Error::Invalid(
                "an attestation cannot name sequence 0: there is no such record".into(),
            ));
        }
        if self.digest.len() != 64
            || !self
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid(
                "an attested digest must be 64 lowercase hex characters".into(),
            ));
        }
        if !self.fingerprint.starts_with("SHA256:") {
            return Err(Error::Invalid(
                "an attested fingerprint must look like SHA256:<base64>".into(),
            ));
        }
        OffsetDateTime::parse(&self.anchored_at, &Rfc3339).map_err(|error| {
            Error::Invalid(format!(
                "anchored_at must be RFC 3339 UTC, got {:?}: {error}",
                self.anchored_at
            ))
        })?;
        Ok(())
    }

    /// Read a document from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(crate::error::io(path))?;
        let attestation: Attestation = serde_json::from_str(&text)
            .map_err(|error| Error::Invalid(format!("invalid attestation: {error}")))?;
        attestation.validate()?;
        Ok(attestation)
    }

    /// Whether this attestation covers a chain verified as `verification`.
    ///
    /// Uses the verified checkpoint at the attested sequence, so an attestation
    /// over an intact prefix is honoured even when the chain has grown since.
    pub fn coverage(&self, verification: &StreamingVerification) -> Coverage {
        let Some(head) = &verification.report.head else {
            return Coverage::Rewritten;
        };
        let Some(checkpoint) = &verification.checkpoint else {
            return Coverage::Rewritten;
        };
        if checkpoint.seq != self.seq || checkpoint.digest != self.digest {
            return Coverage::Rewritten;
        }
        if head.seq == self.seq && head.digest == self.digest {
            return Coverage::Current;
        }
        if head.seq > self.seq {
            return Coverage::Stale {
                ahead_by: head.seq - self.seq,
            };
        }
        Coverage::Truncated
    }

    /// Whether this attestation's chain identity matches.
    pub fn matches_chain(&self, chain: &str) -> bool {
        self.chain == chain
    }
}

/// A verified attestation and how it relates to the chain.
#[derive(Clone, Debug)]
pub struct Attested {
    pub attestation: Attestation,
    pub coverage: Coverage,
    /// The chain head this was checked against.
    pub head: Head,
}

impl Attested {
    /// True only when the attestation names the chain's current head.
    ///
    /// A stale attestation is not a failure: it still proves the prefix it names
    /// was intact and was attested by this key. Callers that need "this exact
    /// head was signed" must ask for it explicitly.
    pub fn covers_head(&self) -> bool {
        self.coverage.is_current()
    }
}

/// Verify a chain against a document, without looking at any signature.
///
/// The caller is expected to have established that the signature is good; this
/// establishes that the document means something true about *this* chain. Split
/// in two so a portable verifier can do the second part without `ssh-keygen`.
pub fn check(
    chain: &Path,
    attestation: &Attestation,
    format: Option<crate::Format>,
) -> Result<Attested> {
    attestation.validate()?;
    let verification = crate::verify_streaming(chain, format, Some(attestation.seq))?;
    let coverage = attestation.coverage(&verification);
    if coverage == Coverage::Rewritten {
        // Prefer the verifier's own diagnosis of where the chain stops fitting.
        return Err(Error::Broken(
            verification
                .report
                .problem
                .clone()
                .unwrap_or(crate::Problem::Digest {
                    seq: attestation.seq,
                }),
        ));
    }
    let head =
        verification.report.head.clone().ok_or_else(|| {
            Error::Invalid("the chain is empty, so nothing can be attested".into())
        })?;
    Ok(Attested {
        attestation: attestation.clone(),
        coverage,
        head,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(seq: u64, digest: &str) -> Head {
        Head {
            seq,
            digest: digest.to_string(),
        }
    }

    fn sample(seq: u64) -> Attestation {
        Attestation::new(
            "production/kernel",
            "nostoi-v1",
            &head(seq, &"a".repeat(64)),
            OffsetDateTime::parse("2026-02-01T12:00:00Z", &Rfc3339).unwrap(),
            "alice@workstation",
            "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            None,
        )
        .unwrap()
    }

    #[test]
    fn canonical_bytes_are_one_sorted_line() {
        let attestation = sample(7);
        let bytes = attestation.canonical_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            !text.contains('\n'),
            "canonical bytes must be a single line"
        );
        assert!(
            text.starts_with(r#"{"anchored_at":"#),
            "keys are sorted: {text}"
        );
        assert_eq!(
            bytes,
            attestation.canonical_bytes().unwrap(),
            "deterministic"
        );
        // The digest is over exactly these bytes, so it is recomputable.
        assert_eq!(attestation.digest().unwrap().len(), 64);
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            attestation.digest().unwrap()
        );
    }

    #[test]
    fn the_document_says_only_what_it_must() {
        let text = String::from_utf8(sample(3).canonical_bytes().unwrap()).unwrap();
        for expected in [
            r#""v":"nostoi-attestation-v1""#,
            r#""chain":"production/kernel""#,
            r#""format":"nostoi-v1""#,
            r#""seq":3"#,
            r#""digest":"#,
            r#""principal":"alice@workstation""#,
            r#""fingerprint":"SHA256:"#,
        ] {
            assert!(text.contains(expected), "{expected} missing from {text}");
        }
        assert!(!text.contains("anchor_key"), "omitted, not null: {text}");
    }

    #[test]
    fn a_malformed_document_is_refused() {
        let base = sample(1);
        type Mutation = (&'static str, fn(&mut Attestation));
        let cases: &[Mutation] = &[
            ("version", |a| a.v = "nostoi-attestation-v2".into()),
            ("chain", |a| a.chain = "  ".into()),
            ("principal", |a| a.principal = String::new()),
            ("seq", |a| a.seq = 0),
            ("digest length", |a| a.digest = "abc".into()),
            ("digest case", |a| a.digest = "A".repeat(64)),
            ("fingerprint", |a| a.fingerprint = "md5:x".into()),
            ("timestamp", |a| a.anchored_at = "yesterday".into()),
        ];
        for (label, mutate) in cases {
            let mut attestation = base.clone();
            mutate(&mut attestation);
            let mut attestation = base.clone();
            mutate(&mut attestation);
            assert!(
                attestation.validate().is_err(),
                "{label} should have been refused"
            );
        }
    }

    #[test]
    fn tampering_changes_the_digest() {
        let attestation = sample(9);
        let before = attestation.digest().unwrap();
        let mut altered = attestation.clone();
        altered.seq = 10;
        assert_ne!(before, altered.digest().unwrap());
        let mut altered = attestation.clone();
        altered.principal = "mallory@elsewhere".into();
        assert_ne!(before, altered.digest().unwrap());
        // The shape check does not notice a well-formed edit; only the signature
        // and the chain binding do, which is why both are required.
        assert!(altered.validate().is_ok());
    }

    #[test]
    fn sidecars_sit_beside_the_chain_and_are_not_inside_it() {
        let sidecars = Sidecars::for_chain(Path::new("/var/lib/nostoi/kernel.sqlite"));
        assert_eq!(
            sidecars.document,
            Path::new("/var/lib/nostoi/kernel.sqlite.attestation.json")
        );
        assert_eq!(
            sidecars.signature,
            Path::new("/var/lib/nostoi/kernel.sqlite.attestation.sig")
        );
        assert!(sidecars.missing_description().is_some());
    }
}
