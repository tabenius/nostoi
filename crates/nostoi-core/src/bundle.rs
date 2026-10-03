//! Attestation bundles: a portable, self-describing envelope.
//!
//! ## Why a bundle at all
//!
//! An attestation lives as two sidecar files beside a chain. That is the right
//! shape for a machine checking its own evidence, and the wrong shape for
//! *handing the evidence to somebody else*: three files, no manifest, no stated
//! fingerprint, and nothing that says which of them matters.
//!
//! A bundle is one file carrying the document, the signature, and the
//! fingerprint to pin. It is what you publish where it cannot be retracted, what
//! you hand to an auditor, and what a service like a museum ingests.
//!
//! ## What a bundle is self-sufficient about, and what it is not
//!
//! The public key is **not** in the bundle, because `ssh-keygen` already embeds
//! it in the signature. A receiver can extract it, show it, and pin it without
//! being handed a key out of band — which also means the bundle cannot be used to
//! smuggle in a different key.
//!
//! What a bundle cannot do by itself is tell you whether to *trust* the key. A
//! fingerprint proves who signed; it does not say who that is, whether the key is
//! revoked, or whether anyone has vouched for it. That is what a pin and a
//! revocation list are for, and why [`verify_bundle`] takes both as arguments
//! rather than reading them from the bundle.
//!
//! ## The document is stored as a value, not as bytes
//!
//! The signed bytes are the canonical serialization of the document, and the
//! receiver recomputes them. So whitespace in the bundle file is irrelevant, as it
//! is everywhere else, and there is no way for the two to disagree.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::attestation::{
    read_capped, write_guarded, Attestation, Canonicality, Document, ReadDocument,
};
use crate::revocation::Revocations;
use crate::{sshsig, Error, Result};

/// The only bundle version this code produces or accepts.
pub const BUNDLE_V1: &str = "nostoi-attestation-bundle-v1";

/// One file carrying everything needed to check an attestation later.
///
/// Deliberately small and flat: a receiver should be able to store it, index it
/// and display it without understanding anything else in this crate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    /// Always [`BUNDLE_V1`].
    pub v: String,
    /// The signing namespace the signature was made in.
    pub namespace: String,
    /// The key fingerprint to pin, `SHA256:...`.
    ///
    /// Repeated outside the document on purpose. A receiver should be able to
    /// compare what it was given against what it already trusts *before* it
    /// decides to spend any effort on the rest.
    pub fingerprint: String,
    /// The attestation, as a value. Canonical bytes are derived, never stored.
    pub document: Attestation,
    /// The armored SSHSIG signature over the document's canonical bytes.
    pub signature: String,
    /// Optional free text for whoever reads it: what this is, where it came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The most a bundle file may weigh.
///
/// The signature and the document are both small; the note is free text. The cap
/// keeps a bundle to something that can be attached to an issue or committed.
pub const MAX_BUNDLE_BYTES: u64 = 1024 * 1024;

impl Bundle {
    /// Check everything that does not need the signature or a chain.
    ///
    /// This catches the cheap failures first — a malformed bundle, a fingerprint
    /// that disagrees with the document — so a receiver can reject before it
    /// parses a signature.
    pub fn validate(&self) -> Result<()> {
        if self.v != BUNDLE_V1 {
            return Err(Error::Invalid(format!(
                "unsupported bundle version {:?}",
                self.v
            )));
        }
        if self.namespace.trim().is_empty() {
            return Err(Error::Invalid("a bundle must state its namespace".into()));
        }
        self.document.validate()?;
        if self.document.fingerprint != self.fingerprint {
            return Err(Error::Invalid(format!(
                "the bundle pins {} but the document names {}",
                self.fingerprint, self.document.fingerprint
            )));
        }
        if self.signature.trim().is_empty() {
            return Err(Error::Invalid(
                "a bundle with no signature proves nothing".into(),
            ));
        }
        Ok(())
    }

    /// The canonical bytes the signature covers.
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        self.document.canonical_bytes()
    }
}

/// What a caller expects of a bundle beyond "the signature is good".
///
/// The defaults are the strict ones, and that is deliberate: a caller that has
/// thought about trust can relax them, and a caller that has not gets a refusal
/// rather than a shrug.
#[derive(Clone, Debug, Default)]
pub struct Expectations {
    /// The key that must have signed, `SHA256:…`.
    ///
    /// `None` means the caller has no pin. That is allowed and it is not a
    /// recommendation: the bundle's own fingerprint then names a key nobody has
    /// vouched for, and the honest description of the result is "signed by
    /// someone unknown".
    pub fingerprint: Option<String>,
    /// The namespace the signature must have been made in.
    ///
    /// `None` accepts the namespace the signature says it used, which is the one
    /// place a bundle gets to speak for itself. Set it when you know.
    pub namespace: Option<String>,
    /// Keys that must be refused whatever else is true.
    pub revoked: Option<Revocations>,
}

/// A bundle whose signature, pin and revocation standing have been checked.
///
/// `how` says how the signature was checked, because a reader deciding whether to
/// trust this should know whether a program or the built-in verifier did it.
#[derive(Clone, Debug)]
pub struct CheckedBundle {
    pub bundle: Bundle,
    /// The key that signed, equal to the bundle's own pin.
    pub fingerprint: String,
    /// The public key the signature carried, `ssh-ed25519 <base64>`.
    pub public_key: String,
    /// The namespace the signature was made in.
    pub namespace: String,
    /// The bytes the signature covers, for storage and display.
    pub canonical_bytes: Vec<u8>,
    /// `built-in` or `ssh-keygen`.
    pub how: &'static str,
    /// Whether the signing key is revoked. Always false here: a revoked key is
    /// refused rather than reported, so that no caller can mistake a bundle it
    /// stored for one it accepted.
    pub revoked: bool,
}

/// Check a bundle without `ssh-keygen`.
///
/// The portable half of `nostoi verify-bundle`: shape, signature, the pin it
/// carries, the pin the caller expects, and the revocation list. Everything
/// needed is in the bundle and the arguments, so this works in a WebAssembly
/// component, a browser, or anywhere else without a subprocess.
///
/// A caller that has both should use both. `ssh-keygen` is the reference
/// implementation and this is a reading of a document that describes itself
/// wrongly in two places; a disagreement between them is worth more than either
/// answer, and the CLI treats it as a failure.
pub fn verify_bundle(bundle: &Bundle, expected: &Expectations) -> Result<CheckedBundle> {
    bundle.validate()?;
    if let Some(namespace) = &expected.namespace {
        if &bundle.namespace != namespace {
            return Err(Error::Invalid(format!(
                "the bundle signs namespace {:?}, not {namespace:?}",
                bundle.namespace
            )));
        }
    }
    if let Some(revoked) = &expected.revoked {
        // Before the signature, and before the pin: a burned key is not going to
        // become unburned by being verified.
        revoked.refuse(&bundle.fingerprint)?;
    }
    let canonical_bytes = bundle.signed_bytes()?;
    let verified = sshsig::verify(&bundle.signature, &canonical_bytes, &bundle.namespace)?;
    if verified.fingerprint != bundle.fingerprint {
        return Err(Error::Invalid(format!(
            "the bundle pins {} but the signature is from {}",
            bundle.fingerprint, verified.fingerprint
        )));
    }
    if let Some(pinned) = &expected.fingerprint {
        if &verified.fingerprint != pinned {
            return Err(Error::Invalid(format!(
                "signed by {}, which is not the pinned key {pinned}",
                verified.fingerprint
            )));
        }
    }
    Ok(CheckedBundle {
        bundle: bundle.clone(),
        fingerprint: verified.fingerprint,
        public_key: sshsig::public_key_line(&verified.public_key)?,
        namespace: verified.namespace,
        canonical_bytes,
        how: "built-in",
        revoked: false,
    })
}

/// Serialize a bundle to the exact bytes to publish.
pub fn to_json(bundle: &Bundle) -> Result<String> {
    serde_json::to_string_pretty(bundle)
        .map_err(|error| Error::Invalid(format!("serialize bundle: {error}")))
}

/// Read a bundle from a path.
pub fn read_bundle(path: &Path) -> Result<Bundle> {
    let bytes = read_capped(path, MAX_BUNDLE_BYTES)?;
    let text = String::from_utf8(bytes)
        .map_err(|error| Error::Invalid(format!("{} is not UTF-8: {error}", path.display())))?;
    parse(&text)
}

/// Read a bundle from text, tolerating formatting.
pub fn parse(text: &str) -> Result<Bundle> {
    // A byte-order mark is not JSON, and serde's complaint about it does not say
    // so. Refused rather than stripped, as everywhere else: a file that needs
    // fixing before it can be read is worth telling someone about.
    if text.starts_with('\u{feff}') {
        return Err(Error::Invalid(
            "a bundle must not start with a byte-order mark; remove it".into(),
        ));
    }
    let bundle: Bundle = serde_json::from_str(text)
        .map_err(|error| Error::Invalid(format!("invalid bundle: {error}")))?;
    bundle.validate()?;
    Ok(bundle)
}

/// Write a bundle, refusing to write through a symlink.
pub fn write_bundle(path: &Path, bundle: &Bundle) -> Result<()> {
    bundle.validate()?;
    write_guarded(path, to_json(bundle)?.as_bytes())
}

/// Read the document a bundle wraps, in the shape the rest of this crate uses.
pub fn as_document(bundle: &Bundle) -> Result<ReadDocument> {
    bundle.validate()?;
    let canonical = crate::attestation::canonical_bytes(&bundle.document)?;
    Ok(ReadDocument {
        attestation: bundle.document.clone(),
        document: Document {
            // The bundle stores a value, so there is no "as written" to record:
            // the canonical form is the only byte sequence it can produce.
            on_disk: canonical.clone().into_bytes(),
            canonical,
            canonicality: Canonicality::Canonical,
        },
    })
}
