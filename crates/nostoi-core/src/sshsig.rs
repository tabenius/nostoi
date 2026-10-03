//! SSH signatures ([PROTOCOL.sshsig]), verified without `ssh-keygen`.
//!
//! ## Why this exists
//!
//! `ssh-keygen -Y verify` is the reference implementation and what the CLI uses
//! when it has a program to run. It is not always available: a WebAssembly
//! component has no subprocesses, a browser has no filesystem, and a service
//! verifying bundles handed to it over HTTP usually has no business shelling
//! out to the host's ssh tooling. Without something like this, "check this
//! signature" is a thing only native tools can answer, and a bundle can be
//! stored but never checked — which is how a provenance page ends up asserting
//! something nobody verified.
//!
//! So the format is read here directly. [`crate::bundle::verify_bundle`] is the
//! portable half of `nostoi verify-bundle`; the CLI checks a bundle twice, once
//! each way, and refuses a disagreement.
//!
//! ## The format
//!
//! ```text
//! byte[6] "SSHSIG"  uint32 version=1  string publickey  string namespace
//! string reserved=""  string hash_algorithm  string signature
//! ```
//!
//! Each `string` is a uint32 length followed by that many bytes, and the magic is
//! a bare six-byte field rather than a string. The signed message is not the
//! document itself but
//!
//! ```text
//! byte[6] "SSHSIG"  string namespace  string reserved  string hash_algorithm
//! string H(message)
//! ```
//!
//! Two details are easy to get wrong and both break every good signature:
//!
//!   * The magic is bare in both places. PROTOCOL.sshsig writes
//!     `string MAGIC_PREAMBLE` where `ssh-keygen` writes six raw bytes. An
//!     implementation that follows the document computes a different message and
//!     rejects everything.
//!   * A fingerprint is `SHA256:` and **plain** base64 of SHA-256 over the key
//!     *blob*, padding stripped, exactly as `ssh-keygen -lf` prints it. Hashing
//!     the raw key, or using base64url, yields a string no other OpenSSH tool
//!     will ever print.
//!
//! ## What is accepted
//!
//! Ed25519 with SHA-512, which is what `ssh-keygen` produces for an Ed25519 key
//! and the only thing WebCrypto offers. RSA, ECDSA and DSA are refused with a
//! named reason rather than skipped: "not checked" and "good" must not look the
//! same to a caller deciding whether to trust something.
//!
//! ## What this does not decide
//!
//! That the signature is *good* is not the same as the key being *trusted*, and
//! this module only ever speaks about the first. Trust comes from a fingerprint
//! pin and a revocation list, which the caller supplies; see
//! [`crate::bundle::verify_bundle`].

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

use crate::{Error, Result};

const MAGIC: &[u8; 6] = b"SSHSIG";
const VERSION: u32 = 1;
const KEY_TYPE: &str = "ssh-ed25519";
const HASH_ALGORITHM: &str = "sha512";
/// A fingerprint is base64 of 32 bytes with the padding stripped.
const FINGERPRINT_BODY: usize = 43;

/// One parsed SSHSIG container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshSig {
    pub version: u32,
    /// The public key, in SSH wire format: `string "ssh-ed25519" string key`.
    pub public_key: Vec<u8>,
    pub namespace: String,
    /// Always empty in practice; kept so a container that sets it is refused
    /// rather than quietly interpreted.
    pub reserved: Vec<u8>,
    pub hash_algorithm: String,
    /// The signature, in SSH wire format.
    pub signature: Vec<u8>,
}

/// A signature that checked out, and the key that made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// `SHA256:...`, as `ssh-keygen -lf` would print the same key.
    pub fingerprint: String,
    /// The key blob the signature carried. Public by construction.
    pub public_key: Vec<u8>,
    pub namespace: String,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, at: 0 }
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| {
                Error::Invalid(format!(
                    "the signature ends inside {what}: it is {} bytes, {n} more were needed",
                    self.bytes.len()
                ))
            })?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u32(&mut self, what: &str) -> Result<u32> {
        let raw = self.take(4, what)?;
        Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn string(&mut self, what: &str) -> Result<&'a [u8]> {
        let n = self.u32(&format!("the length of {what}"))? as usize;
        self.take(n, what)
    }

    fn text(&mut self, what: &str) -> Result<String> {
        let raw = self.string(what)?;
        String::from_utf8(raw.to_vec())
            .map_err(|_| Error::Invalid(format!("{what} is not valid UTF-8")))
    }
}

/// Decode an armored block, refusing anything that is not exactly that block.
///
/// The BEGIN and END lines are required rather than searched for: a signature
/// pasted out of a document that also contains other armor must not verify by
/// accident.
pub fn parse_armored(armored: &str) -> Result<Vec<u8>> {
    let text = armored.trim();
    let rest = text
        .strip_prefix("-----BEGIN SSH SIGNATURE-----")
        .ok_or_else(|| Error::Invalid("not an armored SSH signature: no BEGIN line".into()))?;
    let body = rest
        .strip_suffix("-----END SSH SIGNATURE-----")
        .ok_or_else(|| Error::Invalid("not an armored SSH signature: no END line".into()))?;
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Err(Error::Invalid("the armored signature is empty".into()));
    }
    // Refuse before decoding rather than letting the decoder decide: a body with
    // a stray character is a paste error, not a signature.
    if !compact
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return Err(Error::Invalid("the armored signature is not base64".into()));
    }
    BASE64
        .decode(compact.as_bytes())
        .map_err(|error| Error::Invalid(format!("the armored signature is not base64: {error}")))
}

/// Parse an SSHSIG container.
pub fn parse(bytes: &[u8]) -> Result<SshSig> {
    let mut reader = Reader::new(bytes);
    let magic = reader.take(6, "the magic")?;
    if magic != MAGIC {
        return Err(Error::Invalid("not an SSHSIG signature".into()));
    }
    let version = reader.u32("the version")?;
    if version != VERSION {
        return Err(Error::Invalid(format!(
            "unsupported SSHSIG version {version}, expected {VERSION}"
        )));
    }
    let public_key = reader.string("the public key")?.to_vec();
    let namespace = reader.text("the namespace")?;
    let reserved = reader.string("the reserved field")?.to_vec();
    let hash_algorithm = reader.text("the hash algorithm")?;
    let signature = reader.string("the signature")?.to_vec();
    if reader.at != bytes.len() {
        return Err(Error::Invalid(format!(
            "{} bytes trail the signature in an SSHSIG container",
            bytes.len() - reader.at
        )));
    }
    Ok(SshSig {
        version,
        public_key,
        namespace,
        reserved,
        hash_algorithm,
        signature,
    })
}

/// The OpenSSH fingerprint of a key blob: `SHA256:` and unpadded base64.
///
/// Over the blob rather than the raw key, which is what makes the result
/// comparable with `ssh-keygen -lf` and with every other OpenSSH tool.
pub fn fingerprint(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    format!("SHA256:{}", BASE64.encode(digest).trim_end_matches('='))
}

/// Whether a string is shaped like a fingerprint, without saying anything about
/// whether it is *the right* fingerprint.
pub fn is_fingerprint(text: &str) -> bool {
    text.strip_prefix("SHA256:")
        .is_some_and(|body| body.len() == FINGERPRINT_BODY)
}

/// The public key as `allowed_signers` and `ssh-keygen -lf` print it,
/// `ssh-ed25519 <base64>`.
pub fn public_key_line(public_key: &[u8]) -> Result<String> {
    ed25519_raw(public_key)?;
    Ok(format!("{KEY_TYPE} {}", BASE64.encode(public_key)))
}

fn ssh_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// The bytes a signature covers: the namespace and the message digest.
///
/// Public because a caller may want to reproduce them, and because a test that
/// pins them against `ssh-keygen` should not have to reimplement the assembly.
pub fn signed_payload(namespace: &str, message: &[u8]) -> Vec<u8> {
    let digest = Sha512::digest(message);
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&ssh_string(namespace.as_bytes()));
    out.extend_from_slice(&ssh_string(&[]));
    out.extend_from_slice(&ssh_string(HASH_ALGORITHM.as_bytes()));
    out.extend_from_slice(&ssh_string(&digest));
    out
}

fn ed25519_raw(blob: &[u8]) -> Result<[u8; 32]> {
    let mut reader = Reader::new(blob);
    let name = reader.text("the key algorithm")?;
    if name != KEY_TYPE {
        return Err(Error::Invalid(format!(
            "unsupported key type {name:?}: only {KEY_TYPE} is verified here"
        )));
    }
    let raw = reader.string("the key")?;
    if raw.len() != 32 {
        return Err(Error::Invalid(format!(
            "an ed25519 key is 32 bytes, this one is {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(out)
}

fn ed25519_signature(blob: &[u8]) -> Result<Signature> {
    let mut reader = Reader::new(blob);
    let name = reader.text("the signature algorithm")?;
    if name != KEY_TYPE {
        return Err(Error::Invalid(format!(
            "unsupported signature type {name:?}: only {KEY_TYPE} is verified here"
        )));
    }
    let raw = reader.string("the signature")?;
    let bytes: [u8; 64] = raw.try_into().map_err(|_| {
        Error::Invalid(format!(
            "an ed25519 signature is 64 bytes, this one is {}",
            raw.len()
        ))
    })?;
    Ok(Signature::from_bytes(&bytes))
}

/// Check an armored signature over `message`, made in `namespace`.
///
/// Refuses rather than returns a verdict when it cannot check: an unsupported
/// algorithm, a mismatched namespace and a malformed container are all answers a
/// caller must not mistake for success.
pub fn verify(armored: &str, message: &[u8], namespace: &str) -> Result<Verified> {
    let parsed = parse(&parse_armored(armored)?)?;
    if parsed.hash_algorithm != HASH_ALGORITHM {
        return Err(Error::Invalid(format!(
            "unsupported hash algorithm {:?}, expected {HASH_ALGORITHM}",
            parsed.hash_algorithm
        )));
    }
    if !parsed.reserved.is_empty() {
        return Err(Error::Invalid(
            "the SSHSIG reserved field must be empty".into(),
        ));
    }
    if parsed.namespace != namespace {
        return Err(Error::Invalid(format!(
            "the signature was made in namespace {:?}, not {namespace:?}",
            parsed.namespace
        )));
    }
    let raw = ed25519_raw(&parsed.public_key)?;
    let key = VerifyingKey::from_bytes(&raw)
        .map_err(|error| Error::Invalid(format!("unusable ed25519 key: {error}")))?;
    let signature = ed25519_signature(&parsed.signature)?;
    // `verify_strict` also rejects a small-order key and a non-canonical
    // signature. Both are things ssh-keygen never produces, so accepting them
    // would only widen what this code says yes to.
    key.verify_strict(&signed_payload(&parsed.namespace, message), &signature)
        .map_err(|_| Error::Invalid("the signature does not verify".into()))?;
    Ok(Verified {
        fingerprint: fingerprint(&parsed.public_key),
        public_key: parsed.public_key,
        namespace: parsed.namespace,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::Bundle;

    /// A real bundle: `ssh-keygen -Y sign` over the canonical bytes of its
    /// document, with the key whose fingerprint is in the bundle. Regenerate with
    /// `nostoi attest --bundle`, and check it against the CLI as
    /// tests/attestation.rs does.
    const BUNDLE: &str = include_str!("../tests/vectors/sshsig-bundle.json");

    fn bundle() -> Bundle {
        serde_json::from_str(BUNDLE).expect("the fixture is a bundle")
    }

    fn message() -> Vec<u8> {
        bundle().signed_bytes().expect("canonical bytes")
    }

    #[test]
    fn a_real_signature_verifies() {
        let b = bundle();
        let verified = verify(&b.signature, &message(), "nostoi-attestation").expect("verifies");
        assert_eq!(verified.fingerprint, b.fingerprint);
        assert_eq!(verified.namespace, b.namespace);
        assert_eq!(
            public_key_line(&verified.public_key).unwrap(),
            format!("ssh-ed25519 {}", BASE64.encode(&verified.public_key))
        );
        assert!(is_fingerprint(&verified.fingerprint));
    }

    #[test]
    fn the_message_is_bound() {
        let b = bundle();
        let mut edited = message();
        edited.push(b' ');
        assert!(verify(&b.signature, &edited, "nostoi-attestation").is_err());
        assert!(verify(&b.signature, b"", "nostoi-attestation").is_err());
        // Whitespace is not part of the signature: only the canonical bytes are.
        assert!(verify(&b.signature, &message(), "nostoi-attestation").is_ok());
    }

    #[test]
    fn the_namespace_is_bound() {
        // A signature made for one use of a key must not be replayable as a
        // signature for another, which is what the namespace is for.
        let b = bundle();
        assert!(verify(&b.signature, &message(), "some-other-use").is_err());
    }

    #[test]
    fn the_fingerprint_is_the_one_ssh_keygen_prints() {
        let verified = verify(&bundle().signature, &message(), "nostoi-attestation").unwrap();
        // Plain base64, no padding, and no base64url: `-` and `_` must not appear,
        // or no other OpenSSH tool will print the same string.
        assert!(!verified.fingerprint.contains('-'));
        assert!(!verified.fingerprint.contains('_'));
        assert!(!is_fingerprint("SHA256:short"));
        assert!(!is_fingerprint(
            &verified.fingerprint.replace("SHA256:", "")
        ));
        // The digest is over the key blob, not the raw key.
        let raw = &verified.public_key[15..];
        assert_ne!(Some(fingerprint(raw)), Some(verified.fingerprint.clone()));
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let mut bytes = parse_armored(&bundle().signature).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let armored = armor(&bytes);
        let error = verify(&armored, &message(), "nostoi-attestation").unwrap_err();
        assert!(error.to_string().contains("does not verify"), "{error}");
    }

    fn armor(bytes: &[u8]) -> String {
        format!(
            "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
            BASE64.encode(bytes)
        )
    }

    #[test]
    fn armor_must_be_a_whole_block() {
        let armored = &bundle().signature;
        assert!(parse_armored("not armored").is_err());
        assert!(parse_armored("-----BEGIN SSH SIGNATURE-----\n").is_err());
        assert!(
            parse_armored("-----BEGIN SSH SIGNATURE-----\n\n-----END SSH SIGNATURE-----").is_err()
        );
        assert!(parse_armored(
            "-----BEGIN SSH SIGNATURE-----\nnot base64!\n-----END SSH SIGNATURE-----"
        )
        .is_err());
        assert!(parse_armored(&armored.replace("SSH SIGNATURE", "PGP SIGNATURE")).is_err());
        // Surrounding whitespace from a copy-paste is fine.
        assert!(parse_armored(&format!("\n{armored}\n")).is_ok());
    }

    #[test]
    fn a_truncated_container_is_refused_rather_than_half_read() {
        let bytes = parse_armored(&bundle().signature).unwrap();
        for cut in [7usize, 12, 40, bytes.len() - 1] {
            let error = verify(&armor(&bytes[..cut]), &message(), "nostoi-attestation");
            assert!(
                error.is_err(),
                "a container cut at {cut} bytes must not verify"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = parse_armored(&bundle().signature).unwrap();
        bytes.push(0);
        let error = verify(&armor(&bytes), &message(), "nostoi-attestation").unwrap_err();
        assert!(error.to_string().contains("trail"), "{error}");
    }

    #[test]
    fn another_key_algorithm_is_refused_by_name() {
        let mut parsed = parse(&parse_armored(&bundle().signature).unwrap()).unwrap();
        // An RSA container: still a valid SSHSIG, but not one this verifies.
        let raw = b"ssh-rsa";
        let mut blob = Vec::new();
        blob.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        blob.extend_from_slice(raw);
        parsed.public_key = blob;
        let error =
            verify(&armor(&rebuild(&parsed)), &message(), "nostoi-attestation").unwrap_err();
        assert!(error.to_string().contains("ssh-rsa"), "{error}");
    }

    #[test]
    fn the_preimage_starts_with_a_bare_magic() {
        // PROTOCOL.sshsig writes `string MAGIC_PREAMBLE`. If this ever starts with
        // a length prefix, every good signature in the wild stops verifying.
        let payload = signed_payload("nostoi-attestation", b"hello\n");
        assert_eq!(&payload[..6], MAGIC);
        assert_eq!(&payload[6..10], &(18u32).to_be_bytes());
    }

    fn rebuild(sig: &SshSig) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&sig.version.to_be_bytes());
        for part in [
            &sig.public_key,
            sig.namespace.as_bytes(),
            &sig.reserved,
            sig.hash_algorithm.as_bytes(),
            &sig.signature,
        ] {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }
}
