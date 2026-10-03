//! Signing and verifying attestations with `ssh-keygen -Y sign`.
//!
//! The signature itself is `ssh-keygen`'s. This module builds the document,
//! invokes the tool with an explicit argv (never a shell string), parses what it
//! reports back, and refuses to accept anything it cannot pin.
//!
//! ## The pin is the trust anchor, not the allowed-signers file
//!
//! `ssh-keygen -Y verify` trusts whatever key the `allowed_signers` file lists
//! for the principal, and it says so: a file naming a different principal but
//! containing the same public key verifies successfully. So an attacker who can
//! edit that file can substitute a key and produce attestations that verify.
//!
//! What cannot be substituted silently is the fingerprint. Verification parses
//! the key fingerprint out of `ssh-keygen`'s own success line and requires it to
//! equal both the fingerprint recorded in the document and the one pinned by the
//! operator. Pin it somewhere the host cannot rewrite; see
//! `docs/ATTESTATIONS.md`.
//!
//! ## Signing needs a human
//!
//! A passphrase-protected key must be unlocked interactively. Nothing here runs
//! unattended: `nostoi attest` needs a terminal, an agent, or a key that needs
//! no passphrase. When `ssh-keygen` cannot reach a terminal it says the
//! passphrase was incorrect, which is misleading, so that case is recognised and
//! explained here instead.

use std::path::{Path, PathBuf};
use std::process::Command;

use nostoi_core::attestation::{self, Attestation, Attested, Sidecars, DEFAULT_NAMESPACE};
use nostoi_core::bundle::{Bundle, BUNDLE_V1};

pub use nostoi_core::attestation::{Canonicality, ReadDocument};
use nostoi_core::time::now as now_rfc3339;
use nostoi_core::Format;

use crate::{Error, Result};

/// Where `ssh-keygen` lives. Overridable so tests need no key of their own.
pub const DEFAULT_PROGRAM: &str = "ssh-keygen";

/// How to sign.
#[derive(Clone, Debug)]
pub struct Signer {
    /// The private key to sign with. Never passed to a shell.
    pub key: PathBuf,
    /// The identity to record, matching an `allowed_signers` entry.
    pub principal: String,
    /// Signing namespace, which scopes the signature to this use of the key.
    pub namespace: String,
    pub program: PathBuf,
}

impl Signer {
    pub fn new(key: impl Into<PathBuf>, principal: impl Into<String>) -> Self {
        Signer {
            key: key.into(),
            principal: principal.into(),
            namespace: DEFAULT_NAMESPACE.to_string(),
            program: PathBuf::from(DEFAULT_PROGRAM),
        }
    }
}

/// A signature, ready to be written beside the chain.
#[derive(Clone, Debug)]
pub struct Signed {
    pub attestation: Attestation,
    /// The exact bytes that were signed.
    pub document: Vec<u8>,
    /// The signature file `ssh-keygen` produced.
    pub signature: Vec<u8>,
    /// The `allowed_signers` line this key needs, for the operator to install.
    pub allowed_signers_line: String,
    /// What the previous attestation covered, when one was replaced.
    pub replaced: Option<Attestation>,
    /// Kept so `with_description` can re-sign without being handed the key again.
    key: PathBuf,
    principal: String,
    namespace: String,
    program: PathBuf,
}

/// Key fingerprints that must not be trusted, however they are presented.
///
/// Why this is a separate list rather than "edit your `allowed_signers` file":
/// editing that file is exactly the substitution the fingerprint pin defends
/// against. If revoking a key meant editing the file, then a compromised
/// operator could quietly un-revoke it, and a verifier reading only the file
/// would see nothing wrong. Revocation therefore travels on its own channel and
/// is checked *before* the pin, so a burned key fails even when it is pinned.
#[derive(Clone, Debug, Default)]
pub struct Revocations {
    fingerprints: Vec<String>,
}

impl Revocations {
    /// Read a revocation list: one `SHA256:…` fingerprint per line, `#` comments
    /// and blank lines ignored.
    ///
    /// Anything else on a line is a mistake worth reporting rather than skipping,
    /// because a typo in a revocation list is a key that stays trusted.
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| Error::Invalid(format!("cannot read {}: {error}", path.display())))?;
        let mut fingerprints = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if !line.starts_with("SHA256:") {
                return Err(Error::Invalid(format!(
                    "{}:{}: expected a SHA256:… fingerprint, got {line:?}",
                    path.display(),
                    number + 1
                )));
            }
            fingerprints.push(line.to_string());
        }
        Ok(Self { fingerprints })
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
        self.fingerprints.iter().any(|entry| entry == fingerprint)
    }
}

/// How to verify.
#[derive(Clone, Debug)]
pub struct Verifier {
    /// An `allowed_signers` file naming `principal`.
    pub allowed_signers: PathBuf,
    pub principal: String,
    pub namespace: String,
    pub program: PathBuf,
    /// The fingerprint to pin, `SHA256:...`.
    ///
    /// Checked against the fingerprint `ssh-keygen` reports *and* against the one
    /// in the document, so neither the allowed-signers file nor the document can
    /// introduce a key the operator did not pin.
    pub fingerprint: Option<String>,
    /// Keys refused outright, checked before the pin.
    pub revoked: Option<Revocations>,
}

impl Verifier {
    pub fn new(allowed_signers: impl Into<PathBuf>, principal: impl Into<String>) -> Self {
        Verifier {
            allowed_signers: allowed_signers.into(),
            principal: principal.into(),
            namespace: DEFAULT_NAMESPACE.to_string(),
            program: PathBuf::from(DEFAULT_PROGRAM),
            fingerprint: None,
            revoked: None,
        }
    }

    /// Refuse these revoked keys, whatever else says otherwise.
    pub fn revoking(mut self, revoked: Revocations) -> Self {
        self.revoked = Some(revoked);
        self
    }

    /// Pin the expected key fingerprint.
    pub fn pin(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }
}

/// Expand a leading `~/`, which a shell would normally do and an argv will not.
///
/// `~user` is deliberately refused rather than resolved: looking up another
/// account's home means reading the password database, and silently signing with
/// someone else's key is worse than an error. `HOME` unset is also an error, since
/// the literal path would otherwise reach `ssh-keygen` and produce a complaint
/// about a file that cannot exist.
pub fn expand_home(path: &Path) -> Result<PathBuf> {
    let text = path.to_string_lossy();
    if text.starts_with('~') && !text.starts_with("~/") {
        return Err(Error::Invalid(format!(
            "{text} cannot be expanded: only ~/ is understood here. Pass the path to the \
             key directly if you meant another account."
        )));
    }
    match text.strip_prefix("~/") {
        Some(rest) => match std::env::var("HOME") {
            Ok(home) if !home.is_empty() => Ok(Path::new(&home).join(rest)),
            _ => Err(Error::Invalid(format!(
                "cannot expand {text}: HOME is not set, so pass an absolute path to the key"
            ))),
        },
        None => Ok(path.to_path_buf()),
    }
}

/// Whether a private key file is encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEncryption {
    /// The key can be used without a passphrase.
    None,
    /// The key needs a passphrase, an agent, or a hardware token.
    Encrypted,
    /// The file was not in a format we recognise, so this says nothing.
    Unknown,
}

/// Inspect a private key file rather than discovering its state from ssh-keygen's
/// stderr.
///
/// Two reasons. The specific one: with no terminal, `ssh-keygen -Y sign` reports
/// "incorrect passphrase supplied to decrypt private key", which sends people
/// hunting for a typo in a passphrase that was never wrong. The structural one:
/// the file says what it is, so there is no reason to run a command to find out
/// and then interpret its prose.
pub fn key_encryption(key: &Path) -> KeyEncryption {
    let Ok(text) = std::fs::read_to_string(key) else {
        return KeyEncryption::Unknown;
    };
    if text.contains("Proc-Type: 4,ENCRYPTED") || text.contains("DEK-Info:") {
        return KeyEncryption::Encrypted;
    }
    // The OpenSSH format base64-encodes "openssh-key-v1\0" then a cipher name.
    if !text.contains("OPENSSH PRIVATE KEY") {
        return KeyEncryption::Unknown;
    }
    let encoded: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .filter(|line| !line.trim().is_empty())
        .collect();
    let Some(blob) = base64_decode(&encoded) else {
        return KeyEncryption::Unknown;
    };
    let magic = b"openssh-key-v1\0";
    if !blob.starts_with(magic) {
        return KeyEncryption::Unknown;
    }
    // A length-prefixed string follows the magic: 4 bytes of length, then the name.
    let start = magic.len();
    if blob.len() < start + 4 {
        return KeyEncryption::Unknown;
    }
    let length = u32::from_be_bytes([
        blob[start],
        blob[start + 1],
        blob[start + 2],
        blob[start + 3],
    ]) as usize;
    let name_start = start + 4;
    let name_end = name_start + length;
    if blob.len() < name_end {
        return KeyEncryption::Unknown;
    }
    match &blob[name_start..name_end] {
        b"none" => KeyEncryption::None,
        _ => KeyEncryption::Encrypted,
    }
}

/// Refuse early, and say what is actually needed.
///
/// `is_terminal` on stdin is the honest test: `ssh-keygen` prompts on the
/// terminal, so without one an encrypted key cannot be used and there is no point
/// spawning it just to read the complaint.
fn require_unlocked(key: &Path) -> Result<()> {
    if key_encryption(key) != KeyEncryption::Encrypted {
        return Ok(());
    }
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Ok(());
    }
    Err(Error::Invalid(format!(
        "{} is passphrase-protected and there is no terminal to type it into, so \
         ssh-keygen cannot use it. Attesting is a human step by design: run this from a \
         terminal, load the key into ssh-agent first, or use a key without a passphrase.",
        key.display()
    )))
}

/// Decode standard base64, for reading the OpenSSH key header.
///
/// Hand-rolled because the facade deliberately has no base64 dependency: the one
/// thing it decodes is a key file the operator already has on disk.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in text.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        buffer = (buffer << 6) | value(byte)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// The signing key's fingerprint, as `ssh-keygen` reports it.
pub fn fingerprint(program: &Path, key: &Path) -> Result<String> {
    let output = run(program, &["-lf", &key.to_string_lossy()])?;
    parse_fingerprint(&output)
        .ok_or_else(|| Error::Invalid(format!("could not read a fingerprint from {key:?}")))
}

/// The `allowed_signers` line this key needs.
///
/// Prefers the `.pub` file ssh-keygen writes next to the private key, because
/// `ssh-keygen -y -f` on an encrypted key asks for the passphrase a second time.
/// One prompt for one signature.
pub fn allowed_signers_line(program: &Path, key: &Path, principal: &str) -> Result<String> {
    let public = public_key(program, key)?;
    Ok(format!("{principal} {public}"))
}

/// The public half of a key, from `<key>.pub` when it exists.
fn public_key(program: &Path, key: &Path) -> Result<String> {
    let mut sidecar = key.as_os_str().to_os_string();
    sidecar.push(".pub");
    let sidecar = std::path::PathBuf::from(sidecar);
    let text = match std::fs::read_to_string(&sidecar) {
        Ok(text) => text,
        Err(_) => run(program, &["-y", "-f", &key.to_string_lossy()])?,
    };
    let public = text.trim();
    if !(public.starts_with("ssh-")
        || public.starts_with("ecdsa-")
        || public.starts_with("sk-")
        || public.starts_with("cert-v01@openssh.com"))
    {
        return Err(Error::Invalid(format!(
            "{key:?} did not yield a public key"
        )));
    }
    Ok(public.to_string())
}

/// Build an attestation for the chain's current head and sign it.
///
/// Nothing is written: the caller decides where the signature goes, so a
/// signature can be reviewed before it becomes evidence.
pub fn sign(
    chain: &Path,
    chain_id: &str,
    format: Option<Format>,
    signer: &Signer,
    anchor_key: Option<String>,
) -> Result<Signed> {
    let (head, detected_format) = head_of(chain, format)?;
    require_unlocked(&signer.key)?;
    let fingerprint = fingerprint(&signer.program, &signer.key)?;
    let now = now_rfc3339();
    let identity = if chain_id.is_empty() {
        chain.display().to_string()
    } else {
        chain_id.to_string()
    };
    let attestation = Attestation::new(
        &identity,
        &detected_format,
        &head,
        now,
        &signer.principal,
        &fingerprint,
        anchor_key,
    )?;
    let document = attestation.canonical_bytes()?;
    let signature = sign_bytes(&signer.program, &signer.key, &signer.namespace, &document)?;
    let allowed_signers_line =
        allowed_signers_line(&signer.program, &signer.key, &signer.principal)?;
    let sidecars = Sidecars::for_chain(chain);
    let replaced = load_if_present(&sidecars.document);
    Ok(Signed {
        attestation,
        document,
        signature,
        allowed_signers_line,
        replaced,
        key: signer.key.clone(),
        principal: signer.principal.clone(),
        namespace: signer.namespace.clone(),
        program: signer.program.clone(),
    })
}

/// Add the optional human-facing fields and re-sign.
///
/// The fields live inside the signed bytes, so adding them afterwards would break
/// the signature. Re-signing is the honest way to do it, and the timestamp moves
/// with it — correctly, because this is a new attestation made now rather than a
/// relabelling of an old one.
///
/// Named for the re-sign rather than the fields: [`describe`] already means "one
/// line about an attestation".
pub fn with_description(
    signed: Signed,
    described: nostoi_core::attestation::Described,
) -> Result<Signed> {
    let attestation = signed
        .attestation
        .describe(described)
        .map_err(Error::from)?;
    let document = attestation.canonical_bytes()?;
    let signature = sign_bytes(&signed.program, &signed.key, &signed.namespace, &document)?;
    Ok(Signed {
        attestation,
        document,
        signature,
        allowed_signers_line: signed.allowed_signers_line,
        replaced: signed.replaced,
        key: signed.key,
        principal: signed.principal,
        namespace: signed.namespace,
        program: signed.program,
    })
}

/// Write a signed attestation beside its chain.
pub fn write(chain: &Path, signed: &Signed) -> Result<Sidecars> {
    let sidecars = Sidecars::for_chain(chain);
    write_sidecar(&sidecars.document, &signed.document)?;
    write_sidecar(&sidecars.signature, &signed.signature)?;
    Ok(sidecars)
}

/// Write one sidecar, refusing to write through a symlink.
///
/// `fs::write` follows symlinks, so a planted `audit.jsonl.attestation.sig`
/// pointing somewhere else would be overwritten by us rather than created. That
/// is worth refusing: these files sit next to an audit chain, which is exactly
/// where something might try to redirect a write.
///
/// This is best effort and says so. A symlink created between the check and the
/// write still wins, and protecting the directory components too would need
/// `openat` with `O_NOFOLLOW` on each one. Catching the planted-in-advance case
/// and the accidental one is what this buys.
fn write_sidecar(path: &Path, bytes: &[u8]) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(Error::Invalid(format!(
                "{} is a symlink, so it was not written; move it aside if that is \
                 intended, and check what it points at",
                path.display()
            )))
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(crate::error::io(path)(error)),
    }
    std::fs::write(path, bytes).map_err(crate::error::io(path))
}

/// The chain's head and the format name the verifier detected.
fn head_of(chain: &Path, format: Option<Format>) -> Result<(nostoi_core::Head, String)> {
    let loaded = nostoi_core::open(chain, format).map_err(Error::from)?;
    let report = loaded.verify();
    if let Some(problem) = report.problem {
        return Err(Error::Broken(problem));
    }
    let head = report.head.ok_or_else(|| {
        Error::Invalid("the chain is empty, so there is nothing to attest".into())
    })?;
    Ok((head, report.format))
}

/// Read the attestation sidecars for a chain, without checking any signature.
///
/// The document comes back with its canonical form and whether the file already
/// matched it, so no caller has to recompute canonicalization just to describe it.
pub fn read(chain: &Path) -> Result<Option<ReadDocument>> {
    let sidecars = Sidecars::for_chain(chain);
    if let Some(missing) = sidecars.missing_description() {
        return Err(Error::Invalid(format!(
            "this chain has no attestation ({missing})"
        )));
    }
    attestation::read_document(&sidecars.document)
        .map(Some)
        .map_err(Error::from)
}

/// A short description of a chain's attestation, for the read-only commands.
///
/// `head_seq` is the chain's current head, or 0 when it is empty. Nothing here
/// checks the signature, and the wording says so: the read-only commands are not
/// given an allowed-signers file, so they can report what a document claims and
/// whether it still covers the head, but not that it is genuine. See
/// [`verify`] for that.
pub fn summary(chain: &Path, head_seq: u64) -> String {
    match present(chain) {
        Some(read) => describe(&read.attestation, head_seq, chain),
        None => {
            let sidecars = Sidecars::for_chain(chain);
            match sidecars.missing_description() {
                Some(missing) => format!(
                    "no attestation ({missing}); sign one with: \
                     nostoi attest {} --principal you@host",
                    chain.display()
                ),
                None => format!("no readable attestation beside {}", chain.display()),
            }
        }
    }
}

/// One line about an attestation that has already been read.
///
/// Split from [`summary`] so a caller that has the document in hand does not read
/// it again, which is what the browser does on every reload and must not do on
/// every frame.
pub fn describe(attestation: &Attestation, head_seq: u64, chain: &Path) -> String {
    let short = attestation
        .fingerprint
        .split_once(':')
        .map(|(_, rest)| rest.to_string())
        .unwrap_or_else(|| attestation.fingerprint.clone());
    let mut line = format!(
        "attested by {} with key SHA256:{short} at seq {} ({})",
        attestation.principal, attestation.seq, attestation.anchored_at
    );
    if attestation.seq == head_seq {
        line.push_str(" [covers the current head; signature not checked here]");
    } else if attestation.seq < head_seq {
        line.push_str(&format!(
            " [stale: the chain is at {head_seq}; nostoi attest {} --principal {} to cover it, \
             nostoi verify-attestation to check the signature]",
            chain.display(),
            attestation.principal
        ));
    } else {
        line.push_str(&format!(
            " [the chain ends at {head_seq}, before the attested {}: nostoi verify-attestation {} \
             --allowed-signers FILE --principal {}]",
            attestation.seq,
            chain.display(),
            attestation.principal
        ));
    }
    line
}

/// The attestation sidecars for a chain, if both are there.
///
/// Deliberately total: the read-only commands use this to *mention* an
/// attestation, and it must never fail because one is missing or malformed.
/// Nothing here checks the signature, so nothing here may claim an attestation is
/// good; `nostoi verify-attestation` is the command that does that.
pub fn present(chain: &Path) -> Option<ReadDocument> {
    read(chain).ok().flatten()
}

/// The document already at this path, if there is a readable one.
fn load_if_present(path: &Path) -> Option<Attestation> {
    if !path.is_file() {
        return None;
    }
    attestation::read_document(path)
        .ok()
        .map(|read| read.attestation)
}

/// Verify the chain's attestation, failing closed at every step.
///
/// The signature is checked against the canonical bytes of the *parsed content*,
/// never against the bytes that happened to be on disk. That is the whole reason
/// formatting cannot matter: an indented file says the same thing, canonicalizes
/// to the same bytes and carries the same signature, while any change to a value
/// changes those bytes and fails. Formatting is reported, never fatal.
pub fn verify(chain: &Path, verifier: &Verifier) -> Result<Attested> {
    let sidecars = Sidecars::for_chain(chain);
    let read = read(chain)?.expect("read checked for the sidecars");
    let attestation = read.attestation;
    let canonical = read.document.canonical.clone();
    let signature =
        read_bounded(&sidecars.signature, MAX_SIGNATURE_BYTES).map_err(Error::Invalid)?;
    if signature.is_empty() {
        return Err(Error::Invalid(format!(
            "{} is empty: an attestation with no signature proves nothing",
            sidecars.signature.display()
        )));
    }

    let reported = verify_signature(&SignatureCheck {
        program: &verifier.program,
        allowed_signers: &verifier.allowed_signers,
        principal: &verifier.principal,
        namespace: &verifier.namespace,
        signature: &signature,
        document: canonical.as_bytes(),
        fingerprint: Some(&attestation.fingerprint),
        revoked: verifier.revoked.as_ref(),
    })?;

    if reported != attestation.fingerprint {
        return Err(Error::Invalid(format!(
            "the document claims key {} but it was signed by {reported}",
            attestation.fingerprint
        )));
    }
    if let Some(pinned) = &verifier.fingerprint {
        if &reported != pinned {
            return Err(Error::Invalid(format!(
                "signed by {reported}, which is not the pinned key {pinned}"
            )));
        }
    }
    let mut checked = attestation::check(chain, &attestation, None).map_err(Error::from)?;
    checked.document = read.document;
    Ok(checked)
}

/// Wrap a signature into a publishable bundle.
///
/// The fingerprint is repeated outside the document so a receiver can compare it
/// against what it already trusts before doing anything else, and the public key
/// is deliberately *not* included: `ssh-keygen` embeds it in the signature, so a
/// bundle cannot be used to smuggle in a different one.
pub fn bundle(signed: &Signed, namespace: &str, note: Option<String>) -> Result<Bundle> {
    let bundle = Bundle {
        v: BUNDLE_V1.to_string(),
        namespace: namespace.to_string(),
        fingerprint: signed.attestation.fingerprint.clone(),
        document: signed.attestation.clone(),
        signature: String::from_utf8(signed.signature.clone()).map_err(|_| {
            Error::Invalid("the signature is not UTF-8, so it cannot be bundled".into())
        })?,
        note,
    };
    bundle.validate()?;
    Ok(bundle)
}

/// Check a bundle's signature, its pin and its namespace, with no chain.
///
/// This is what a receiver does when a bundle arrives: there is no local chain to
/// compare against yet, so it answers "is this a genuine attestation by the key I
/// already trust, and what does it claim" rather than "does it match these
/// records". The document is validated and its canonical bytes recomputed, so a
/// bundle whose document was edited fails here rather than at some later point.
pub fn verify_bundle(bundle: &Bundle, verifier: &Verifier) -> Result<CheckedBundle> {
    bundle.validate()?;
    let reported = verify_signature(&SignatureCheck {
        program: &verifier.program,
        allowed_signers: &verifier.allowed_signers,
        principal: &verifier.principal,
        namespace: &bundle.namespace,
        signature: bundle.signature.as_bytes(),
        document: &bundle.signed_bytes()?,
        fingerprint: Some(&bundle.fingerprint),
        revoked: verifier.revoked.as_ref(),
    })?;
    if reported != bundle.fingerprint {
        return Err(Error::Invalid(format!(
            "the bundle pins {} but the signature is from {reported}",
            bundle.fingerprint
        )));
    }
    if let Some(pinned) = &verifier.fingerprint {
        if &reported != pinned {
            return Err(Error::Invalid(format!(
                "signed by {reported}, which is not the pinned key {pinned}"
            )));
        }
    }
    Ok(CheckedBundle {
        bundle: bundle.clone(),
        fingerprint: reported,
        canonical_bytes: bundle.signed_bytes()?,
    })
}

/// A bundle whose signature and pin have been checked.
#[derive(Clone, Debug)]
pub struct CheckedBundle {
    pub bundle: Bundle,
    /// The fingerprint `ssh-keygen` reported, equal to the bundle's own.
    pub fingerprint: String,
    /// The bytes the signature covers, for storage and display.
    pub canonical_bytes: Vec<u8>,
}

/// Serialize a bundle to the exact bytes to publish.
pub fn to_json(bundle: &Bundle) -> Result<String> {
    nostoi_core::bundle::to_json(bundle).map_err(Error::from)
}

/// Read a bundle from disk.
pub fn read_bundle(path: &Path) -> Result<Bundle> {
    nostoi_core::bundle::read_bundle(path).map_err(Error::from)
}

/// Write a bundle, refusing to write through a symlink.
pub fn write_bundle(path: &Path, bundle: &Bundle) -> Result<()> {
    nostoi_core::bundle::write_bundle(path, bundle).map_err(Error::from)
}

/// Rewrite the document in canonical form, if it is not already.
///
/// Takes the document that was verified rather than reading its own, which does
/// two things. It makes the coupling explicit instead of conventional: the bytes
/// being replaced are provably the bytes the signature already covers. And it
/// closes a lost-update window — between verifying and repairing, the file could
/// have changed, and writing the older canonical form would silently discard
/// whatever replaced it. So the file is re-read and compared first, and a change
/// is an error rather than an overwrite.
pub fn canonicalize(chain: &Path, verified: &nostoi_core::attestation::Document) -> Result<bool> {
    let sidecars = Sidecars::for_chain(chain);
    if verified.canonicality.is_canonical() {
        return Ok(false);
    }
    let current =
        std::fs::read(&sidecars.document).map_err(crate::error::io(&sidecars.document))?;
    if current != verified.on_disk {
        return Err(Error::Invalid(format!(
            "{} changed since it was verified, so it was not rewritten; run \
             verify-attestation again",
            sidecars.document.display()
        )));
    }
    write_sidecar(&sidecars.document, verified.canonical.as_bytes())?;
    Ok(true)
}

/// Sign bytes with `ssh-keygen -Y sign`.
fn sign_bytes(program: &Path, key: &Path, namespace: &str, document: &[u8]) -> Result<Vec<u8>> {
    // ssh-keygen signs a file and writes `<file>.sig` beside it, so the bytes go
    // to a private temporary directory that removes itself.
    let dir = temp_dir("nostoi-attest")?;
    let path = dir.join("attestation.json");
    std::fs::write(&path, document).map_err(crate::error::io(&path))?;
    run(
        program,
        &[
            "-Y",
            "sign",
            "-f",
            &key.to_string_lossy(),
            "-n",
            namespace,
            &path.to_string_lossy(),
        ],
    )
    .map_err(|error| explain_signing_failure(error, key))?;
    let signature_path = dir.join("attestation.json.sig");
    let signature = read_bounded(&signature_path, MAX_SIGNATURE_BYTES).map_err(|error| {
        Error::Invalid(format!(
            "ssh-keygen reported success but wrote no readable signature ({error})"
        ))
    })?;
    Ok(signature)
}

/// Verify bytes with `ssh-keygen -Y verify`, returning the key it trusted.
/// Verify a signature over `document`, returning the fingerprint it trusted.
///
/// The signature goes to a private temporary file because `ssh-keygen -Y verify`
/// takes a path rather than reading standard input for the signature itself.
#[allow(clippy::too_many_arguments)]
/// Refuse a principal the trust anchor does not mention.
///
/// An `allowed_signers` entry is `principal[,principal…] <key> [options]`, and a
/// principal is only usable if one of its lines lists it. Checking here gives a
/// specific answer instead of ssh-keygen's single generic refusal, which is the
/// difference between "your file does not mention this identity" and "this
/// document was altered".
fn require_known_principal(allowed_signers: &Path, principal: &str) -> Result<()> {
    let text = std::fs::read_to_string(allowed_signers).map_err(|error| {
        Error::Invalid(format!(
            "cannot read {}: {error}",
            allowed_signers.display()
        ))
    })?;
    let known = text.lines().any(|line| {
        let line = line.split('#').next().unwrap_or("").trim();
        line.split_whitespace()
            .next()
            .is_some_and(|names| names.split(',').any(|name| name == principal))
    });
    if known {
        return Ok(());
    }
    let listed: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    Err(Error::Invalid(format!(
        "{} has no entry for {principal:?}{}",
        allowed_signers.display(),
        if listed.is_empty() {
            ", and lists no principals at all".to_string()
        } else {
            format!("; it lists {}", listed.join(", "))
        }
    )))
}

/// Everything needed to ask `ssh-keygen` about one signature.
///
/// A struct rather than eight positional arguments, because the two trust-policy
/// fields have to travel with the invocation: revocation is checked before the
/// signature runs, which means the expected fingerprint has to arrive alongside
/// the list it is checked against.
struct SignatureCheck<'a> {
    program: &'a Path,
    allowed_signers: &'a Path,
    principal: &'a str,
    namespace: &'a str,
    signature: &'a [u8],
    document: &'a [u8],
    fingerprint: Option<&'a str>,
    revoked: Option<&'a Revocations>,
}

/// Check one signature, returning the fingerprint `ssh-keygen` trusted.
///
/// The signature goes to a private temporary file because `ssh-keygen -Y verify`
/// takes a path rather than reading standard input for the signature itself.
fn verify_signature(check: &SignatureCheck<'_>) -> Result<String> {
    let SignatureCheck {
        program,
        allowed_signers,
        principal,
        namespace,
        signature,
        document,
        fingerprint,
        revoked,
    } = *check;
    // Before anything else: a revoked key is refused even when it is the pinned
    // one, because un-revoking it must not be a matter of editing a file.
    if let (Some(revoked), Some(fingerprint)) = (revoked, fingerprint) {
        if revoked.is_revoked(fingerprint) {
            return Err(Error::Invalid(format!(
                "{fingerprint} is revoked; a revoked key is refused even when it is \
                 the pinned one"
            )));
        }
    }
    // ssh-keygen answers "Could not verify signature." for a bad signature *and"
    // for a principal it has never heard of, so the two are told apart here rather
    // than both being reported as a failed signature.
    require_known_principal(allowed_signers, principal)?;
    let dir = temp_dir("nostoi-attest")?;
    let path = dir.join("attestation.sig");
    std::fs::write(&path, signature).map_err(crate::error::io(&path))?;
    let mut child = Command::new(program)
        .args([
            "-Y",
            "verify",
            "-f",
            &allowed_signers.to_string_lossy(),
            "-I",
            principal,
            "-n",
            namespace,
            "-s",
            &path.to_string_lossy(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| Error::Invalid(format!("cannot run {}: {error}", program.display())))?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("piped");
        // A closed pipe here means ssh-keygen already decided, which is fine.
        let _ = stdin.write_all(document);
    }
    let output = child.wait_with_output().map_err(|error| {
        Error::Invalid(format!("{} did not finish: {error}", program.display()))
    })?;
    if !output.status.success() {
        return Err(Error::Invalid(verification_failure(
            &allowed_signers.to_string_lossy(),
            principal,
            namespace,
            &output.stdout,
            &output.stderr,
        )));
    }
    parse_fingerprint(&String::from_utf8_lossy(&output.stdout)).ok_or_else(|| {
        Error::Invalid(
            "ssh-keygen reported a good signature without naming the key it trusted".into(),
        )
    })
}

/// Turn `ssh-keygen`'s terse failure into something actionable.
fn verification_failure(
    allowed_signers: &str,
    principal: &str,
    namespace: &str,
    stdout: &[u8],
    stderr: &[u8],
) -> String {
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    if said.contains("namespace does not match") {
        return format!(
            "the signature was made for a different namespace; this attestation expects {namespace:?}"
        );
    }
    if said.contains("Unable to open allowed keys file") {
        return format!(
            "no usable allowed_signers file at {allowed_signers}; it must contain a line for {principal:?}"
        );
    }
    if said.contains("incorrect signature") || said.contains("Could not verify signature") {
        // The most common cause by far: the document or signature was edited,
        // or the pinned key is not the one that signed.
        return "the signature does not verify against this document and key".to_string();
    }
    format!(
        "ssh-keygen could not verify the signature: {}",
        first_line(&said)
    )
}

/// A passphrase-protected key with no terminal is reported as a wrong passphrase.
fn explain_signing_failure(error: Error, key: &Path) -> Error {
    let detail = error.to_string();
    // require_unlocked catches the predictable case. This catches the rest: an
    // agent or a hardware token that still needs confirmation, or a key file we
    // could not classify.
    let needs_terminal = detail.contains("incorrect passphrase")
        || detail.contains("ssh_askpass")
        || detail.contains("/dev/tty");
    if !needs_terminal {
        return error;
    }
    Error::Invalid(format!(
        "could not unlock {}: ssh-keygen needs an interactive terminal, a loaded ssh-agent, \
         or a key without a passphrase. Attesting is a human step by design; a service must not \
         sign on its own.",
        key.display()
    ))
}

/// The largest signature we will read. An armored SSHSIG block is around a
/// kilobyte.
///
/// The document limit lives next to the document reader, in `nostoi-core`, since
/// that is where the read happens and every caller benefits.
const MAX_SIGNATURE_BYTES: u64 = 1024 * 1024;

/// Read a file, refusing one larger than `limit`.
fn read_bounded(path: &Path, limit: u64) -> std::result::Result<Vec<u8>, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)
        .map_err(|error| format!("cannot open {} ({error})", path.display()))?;
    let size = file
        .metadata()
        .map_err(|error| format!("cannot stat {} ({error})", path.display()))?
        .len();
    if size > limit {
        return Err(format!(
            "{} is {size} bytes, over the {limit} byte limit for this kind of file",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {} ({error})", path.display()))?;
    if bytes.len() as u64 > limit {
        // The file grew between the stat and the read.
        return Err(format!(
            "{} is larger than the {limit} byte limit",
            path.display()
        ));
    }
    Ok(bytes)
}

/// Run a program and return its standard output.
///
/// Both streams are read because some of ssh-keygen's refusals are split across
/// them, but only standard output is returned: the interesting part of a failure is
/// folded into the error here, and a captured stderr that nothing reads is worse
/// than no field at all.
fn run(program: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| Error::Invalid(format!("cannot run {}: {error}", program.display())))?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "{} {} failed: {}",
            program.display(),
            args.first().copied().unwrap_or_default(),
            first_line(&both(&output.stdout, &output.stderr))
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Two captured streams as one string, since some tools split a message across
/// them and reporting half of it sends people looking in the wrong place.
fn both(a: &[u8], b: &[u8]) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(a),
        String::from_utf8_lossy(b)
    )
}

/// The `SHA256:...` token from an `ssh-keygen` line.
fn parse_fingerprint(text: &str) -> Option<String> {
    text.split_whitespace()
        .find(|token| token.starts_with("SHA256:"))
        .map(str::to_string)
}

/// The first line of a tool's output that says something.
///
/// ssh-keygen frames some refusals in a box of `@` characters, and the banner is
/// the first line while the actual complaint is four lines down. Reporting the
/// banner would be reporting nothing.
fn first_line(text: &str) -> String {
    const NOISE: &[char] = &['@', '!', '-', '=', '#', '*', ' '];
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.chars().all(|c| NOISE.contains(&c)))
        .unwrap_or("");
    let trimmed: String = line.chars().take(200).collect();
    if line.chars().count() > 200 {
        format!("{trimmed}…")
    } else {
        trimmed
    }
}

/// A private directory for the bytes handed to `ssh-keygen`, removed on drop.
///
/// Three properties, each of which `create_dir_all` alone does not give:
///
/// * **Private.** The mode is forced to 0700. A umask-derived directory is
///   typically 0775, which is group-writable: another account in the same group
///   could read the document or, worse, write into it.
/// * **Exclusive.** `mkdir` fails if the name exists, and the name is derived
///   from the pid and a clock, so it is guessable. Adopting a directory somebody
///   else created is how an attacker gets a path they control into our own
///   process. A collision retries under a new name instead.
/// * **Temporary.** The guard removes the directory on every path out, including
///   the error paths. Removing it by hand at the end of the happy path leaks a
///   directory per failed attempt otherwise.
///
/// The remaining risk is a symlink planted inside the directory after it is
/// created: `ssh-keygen` writes `<file>.sig` beside the file it is given, and
/// would follow a symlink there. The window is small and the directory is 0700,
/// so this is hardening rather than a guarantee.
fn temp_dir(prefix: &str) -> Result<TempDir> {
    for attempt in 0..ATTEMPTS {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default();
        let dir =
            std::env::temp_dir().join(format!("{prefix}-{}-{nanos}-{attempt}", std::process::id()));
        match create_private(&dir) {
            Ok(()) => return Ok(TempDir { path: dir }),
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists && attempt + 1 < ATTEMPTS => {}
            Err(error) => return Err(crate::error::io(&dir)(error)),
        }
    }
    Err(Error::Invalid(format!(
        "could not create a private directory under {}",
        std::env::temp_dir().display()
    )))
}

/// How many names to try before giving up on a collision.
const ATTEMPTS: usize = 8;

/// Create one directory, privately, and fail if it already exists.
///
/// `create_dir_all` is the wrong call twice over: it derives the mode from the
/// umask, and it succeeds on a directory that is already there. The second is
/// the dangerous one, because the name is derived from the pid and a clock.
fn create_private(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// A directory that deletes itself when it goes out of scope.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // A failure here would mask the error that caused the drop, so it is
        // deliberately ignored. Nothing of value is left behind either way: the
        // only files are the document being signed and the signature.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_private_directory_is_private_and_unique_and_self_removing() {
        use std::os::unix::fs::PermissionsExt;

        let first = temp_dir("nostoi-test").unwrap();
        let second = temp_dir("nostoi-test").unwrap();
        assert_ne!(first.path, second.path, "each call gets its own directory");
        assert_eq!(
            std::fs::metadata(&first.path).unwrap().permissions().mode() & 0o777,
            0o700,
            "the mode must be forced, not inherited from the umask"
        );

        let path = first.path.clone();
        drop(first);
        assert!(
            !path.exists(),
            "dropping the guard must remove the directory"
        );
        drop(second);
    }

    #[test]
    fn an_existing_directory_is_refused_rather_than_adopted() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("taken");
        create_private(&existing).unwrap();
        // Adopting somebody else's directory is how a path they control ends up in
        // our own process, so a second attempt has to fail.
        let error = create_private(&existing).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    }
}
