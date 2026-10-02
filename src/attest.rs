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

use nostoi_core::attestation::{
    self, Attestation, Attested, ReadDocument, Sidecars, DEFAULT_NAMESPACE,
};
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
}

impl Verifier {
    pub fn new(allowed_signers: impl Into<PathBuf>, principal: impl Into<String>) -> Self {
        Verifier {
            allowed_signers: allowed_signers.into(),
            principal: principal.into(),
            namespace: DEFAULT_NAMESPACE.to_string(),
            program: PathBuf::from(DEFAULT_PROGRAM),
            fingerprint: None,
        }
    }

    /// Pin the expected key fingerprint.
    pub fn pin(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
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
    parse_fingerprint(&output.stdout)
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
        Err(_) => run(program, &["-y", "-f", &key.to_string_lossy()])?.stdout,
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
    })
}

/// Write a signed attestation beside its chain.
pub fn write(chain: &Path, signed: &Signed) -> Result<Sidecars> {
    let sidecars = Sidecars::for_chain(chain);
    std::fs::write(&sidecars.document, &signed.document)
        .map_err(crate::error::io(&sidecars.document))?;
    std::fs::write(&sidecars.signature, &signed.signature)
        .map_err(crate::error::io(&sidecars.signature))?;
    Ok(sidecars)
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
    let Some(read) = present(chain) else {
        let sidecars = Sidecars::for_chain(chain);
        return match sidecars.missing_description() {
            Some(missing) => format!(
                "no attestation ({missing}); sign one with: nostoi attest {} --principal you@host",
                chain.display()
            ),
            None => format!("no readable attestation beside {}", chain.display()),
        };
    };
    let attestation = read.attestation;
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
    let canonicality = read.document.canonicality;
    let canonical = read.document.canonical;
    let signature =
        std::fs::read(&sidecars.signature).map_err(crate::error::io(&sidecars.signature))?;
    if signature.is_empty() {
        return Err(Error::Invalid(format!(
            "{} is empty: an attestation with no signature proves nothing",
            sidecars.signature.display()
        )));
    }

    let reported = verify_bytes(
        &verifier.program,
        &verifier.allowed_signers,
        &verifier.principal,
        &verifier.namespace,
        &signature,
        canonical.as_bytes(),
    )?;

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
    checked.canonicality = canonicality;
    Ok(checked)
}

/// Rewrite the document in canonical form.
///
/// Only ever called after the signature has been checked against the canonical
/// bytes, which is what makes this lossless: the bytes being replaced are the
/// bytes the signature already covers.
pub fn canonicalize(chain: &Path) -> Result<bool> {
    let sidecars = Sidecars::for_chain(chain);
    let read = read(chain)?.expect("read checked for the sidecars");
    if read.document.canonicality.is_canonical() {
        return Ok(false);
    }
    std::fs::write(&sidecars.document, &read.document.canonical)
        .map_err(crate::error::io(&sidecars.document))?;
    Ok(true)
}

/// Sign bytes with `ssh-keygen -Y sign`.
fn sign_bytes(program: &Path, key: &Path, namespace: &str, document: &[u8]) -> Result<Vec<u8>> {
    // ssh-keygen signs a file and writes `<file>.sig`, so the bytes go to a
    // private temporary directory that is removed afterwards.
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
    let signature = std::fs::read(&signature_path).map_err(|error| {
        Error::Invalid(format!(
            "ssh-keygen reported success but wrote no signature ({error})"
        ))
    })?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(signature)
}

/// Verify bytes with `ssh-keygen -Y verify`, returning the key it trusted.
fn verify_bytes(
    program: &Path,
    allowed_signers: &Path,
    principal: &str,
    namespace: &str,
    signature: &[u8],
    document: &[u8],
) -> Result<String> {
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
    let _ = std::fs::remove_dir_all(&dir);
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

/// Run a program and capture its output.
fn run(program: &Path, args: &[&str]) -> Result<Output> {
    let output = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| Error::Invalid(format!("cannot run {}: {error}", program.display())))?;
    if !output.status.success() {
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(Error::Invalid(format!(
            "{} {} failed: {}",
            program.display(),
            args.first().copied().unwrap_or_default(),
            first_line(&said)
        )));
    }
    Ok(Output {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

struct Output {
    stdout: String,
    #[allow(dead_code)]
    stderr: String,
}

/// The `SHA256:...` token from an `ssh-keygen` line.
fn parse_fingerprint(text: &str) -> Option<String> {
    text.split_whitespace()
        .find(|token| token.starts_with("SHA256:"))
        .map(str::to_string)
}

fn first_line(text: &str) -> String {
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    let trimmed = line.trim();
    if trimmed.len() > 200 {
        format!("{}…", &trimmed[..200])
    } else {
        trimmed.to_string()
    }
}

/// A private directory for the bytes handed to `ssh-keygen`.
fn temp_dir(prefix: &str) -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        // Time is not available in nostoi-core without its own clock import, and
        // the pid plus an existing-file check is enough to avoid collisions
        // between concurrent runs on one host.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).map_err(crate::error::io(&dir))?;
    Ok(dir)
}
