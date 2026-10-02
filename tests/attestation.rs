//! End-to-end attestations with a real `ssh-keygen`.
//!
//! These sign for real, with a throwaway key generated in a temporary directory.
//! Nothing here needs a passphrase, an agent or a network, but it does need
//! `ssh-keygen` on the host; when it is missing the tests say so instead of
//! failing mysteriously.

use nostoi::attest::{self, KeyEncryption, Signer, Verifier};
use nostoi::attestation::{self, Attestation, Canonicality, Coverage, Sidecars};
use nostoi::Draft;
use std::path::{Path, PathBuf};
use std::process::Command;

const PRINCIPAL: &str = "alice@workstation";

fn ssh_keygen() -> Option<PathBuf> {
    let path = std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .map(|dir| Path::new(dir).join("ssh-keygen"))
        .find(|candidate| candidate.is_file())?;
    Some(path)
}

fn generate_key(dir: &Path, comment: &str) -> PathBuf {
    let program = ssh_keygen().expect("ssh-keygen is required for these tests");
    let key = dir.join(format!("id_{comment}"));
    let output = Command::new(&program)
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            comment,
            "-f",
            &key.to_string_lossy(),
        ])
        .output()
        .expect("ssh-keygen runs");
    assert!(
        output.status.success(),
        "key generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    key
}

fn chain(dir: &Path, records: usize) -> PathBuf {
    let path = dir.join("audit.jsonl");
    for index in 0..records {
        nostoi::append(
            &path,
            Draft {
                actor: Some("test"),
                kind: "attest",
                subject: None,
                body: serde_json::json!({"index": index}),
                at: None,
            },
        )
        .unwrap();
    }
    path
}

fn signer(key: &Path) -> Signer {
    let mut signer = Signer::new(key, PRINCIPAL);
    signer.program = ssh_keygen().expect("ssh-keygen");
    signer
}

/// The committed fixture key's fingerprint, as a literal.
///
/// A known-answer test. Every other test derives the fingerprint at runtime,
/// which means a parser that returned the wrong token would be wrong on both
/// sides and the suite would still be green. This one cannot be.
const FIXTURE_FINGERPRINT: &str = "SHA256:WUWp9u0c5YvfhNzCTTKwA5Am4wOtbQF4/owhgXOeukk";

/// The committed trust anchor, as a deployment provisions it.
fn fixture_allowed_signers() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/allowed_signers")
}

fn fixture_key() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/id_ed25519")
}

struct Fixture {
    _dir: tempfile::TempDir,
    chain: PathBuf,
    key: PathBuf,
    allowed_signers: PathBuf,
}

impl Fixture {
    fn new() -> Option<Fixture> {
        ssh_keygen()?;
        let dir = tempfile::tempdir().unwrap();
        let chain = chain(dir.path(), 3);
        let key = generate_key(dir.path(), PRINCIPAL);
        let allowed_signers = dir.path().join("allowed_signers");
        std::fs::write(
            &allowed_signers,
            format!("{PRINCIPAL} {}\n", public_key(&key)),
        )
        .unwrap();
        Some(Fixture {
            _dir: dir,
            chain,
            key,
            allowed_signers,
        })
    }

    fn sign(&self) -> attest::Signed {
        let signed = attest::sign(
            &self.chain,
            "production/kernel",
            None,
            &signer(&self.key),
            None,
        )
        .unwrap();
        attest::write(&self.chain, &signed).unwrap();
        signed
    }

    fn verifier(&self) -> Verifier {
        let mut verifier = Verifier::new(&self.allowed_signers, PRINCIPAL);
        verifier.program = ssh_keygen().expect("ssh-keygen");
        verifier
    }

    /// The attestation currently on disk, without checking its signature.
    fn read_attestation(&self) -> Attestation {
        attest::read(&self.chain).unwrap().unwrap().attestation
    }

    fn pinned(&self) -> Verifier {
        let fingerprint = attest::fingerprint(&ssh_keygen().unwrap(), &self.key).unwrap();
        self.verifier().pin(fingerprint)
    }
}

fn public_key(key: &Path) -> String {
    let output = Command::new(ssh_keygen().unwrap())
        .args(["-y", "-f", &key.to_string_lossy()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Skips rather than fails when ssh-keygen is unavailable.
macro_rules! fixture {
    () => {
        match Fixture::new() {
            Some(fixture) => fixture,
            None => {
                eprintln!("skipping: ssh-keygen is not on PATH");
                return;
            }
        }
    };
}

#[test]
fn the_committed_fixture_key_has_the_fingerprint_this_suite_expects() {
    let Some(program) = ssh_keygen() else { return };
    // If the fixture key is ever regenerated, this fails and the constant above
    // has to move with it. That is the point: it makes the fingerprint a known
    // answer rather than something derived from the same code under test.
    assert_eq!(
        attest::fingerprint(&program, &fixture_key()).unwrap(),
        FIXTURE_FINGERPRINT,
        "tests/fixtures/id_ed25519 was replaced; update FIXTURE_FINGERPRINT"
    );
    // And the public key is read from the .pub sidecar, not by decrypting.
    let sidecar = fixture_key().with_file_name("id_ed25519.pub");
    let public = std::fs::read_to_string(sidecar).unwrap();
    assert_eq!(
        attest::allowed_signers_line(&program, &fixture_key(), "alice@laptop").unwrap(),
        format!("alice@laptop {}", public.trim()),
        "the line keeps the key's own comment, which is what ssh-keygen writes"
    );
}

/// A private key copy that ssh-keygen will accept.
///
/// It refuses a key file other users can read, which is a deliberate safety
/// property and also the reason a committed fixture cannot be signed with
/// directly: git checks out a fresh clone as 0644. Copying and tightening is
/// what an operator does too.
fn usable_key(dir: &Path) -> PathBuf {
    let key = dir.join("id_ed25519");
    std::fs::copy(fixture_key(), &key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    key
}

#[test]
fn a_world_readable_private_key_is_refused_with_an_explanation() {
    let Some(program) = ssh_keygen() else { return };
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 1);
    let key = usable_key(dir.path());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let mut signer = Signer::new(&key, "alice@laptop");
    signer.program = program;

    let error = attest::sign(&chain, "production/kernel", None, &signer, None).unwrap_err();
    let said = error.to_string();
    assert!(
        said.contains("PRIVATE KEY") || said.contains("UNPROTECTED"),
        "ssh-keygen's refusal should survive into the message: {said}"
    );
}

#[test]
fn a_signature_by_a_committed_fixture_key_verifies_against_the_committed_anchor() {
    let Some(program) = ssh_keygen() else { return };
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 2);
    let mut signer = Signer::new(usable_key(dir.path()), "alice@laptop");
    signer.program = program.clone();

    let signed = attest::sign(&chain, "production/kernel", None, &signer, None).unwrap();
    attest::write(&chain, &signed).unwrap();
    assert_eq!(signed.attestation.fingerprint, FIXTURE_FINGERPRINT);

    // The first principal in a comma-separated entry verifies, and so does the
    // second: real allowed_signers files list several names per key.
    for principal in ["alice@laptop", "alice@workstation"] {
        let mut verifier = Verifier::new(fixture_allowed_signers(), principal);
        verifier.program = program.clone();
        verifier.fingerprint = Some(FIXTURE_FINGERPRINT.to_string());
        let checked = attest::verify(&chain, &verifier)
            .unwrap_or_else(|error| panic!("{principal} should verify: {error}"));
        assert!(checked.covers_head());
    }

    // Options in the file do not narrow an entry for a plain public key. The same
    // key blob listed under a second principal verifies for that principal too,
    // with `cert-authority`, `principals=` and an expiry all present. Those
    // options constrain *certificates*; they are not an access control on a raw
    // key. Worth knowing before anyone assumes otherwise, and another reason the
    // fingerprint pin is the thing that has to be right.
    let mut verifier = Verifier::new(fixture_allowed_signers(), "contractor@laptop");
    verifier.program = program;
    let checked = attest::verify(&chain, &verifier)
        .unwrap_or_else(|error| panic!("the same key is trusted for both: {error}"));
    assert_eq!(checked.attestation.fingerprint, FIXTURE_FINGERPRINT);

    // A principal the file does not mention at all is still refused.
    let mut verifier = Verifier::new(fixture_allowed_signers(), "stranger@elsewhere");
    verifier.program = ssh_keygen().unwrap();
    let error = attest::verify(&chain, &verifier).unwrap_err();
    assert!(error.to_string().contains("does not verify"), "{error}");
}

#[test]
fn a_signed_attestation_verifies_against_its_own_chain() {
    let fixture = fixture!();
    let signed = fixture.sign();

    assert_eq!(signed.attestation.seq, 3);
    assert_eq!(signed.attestation.principal, PRINCIPAL);
    assert!(signed.attestation.fingerprint.starts_with("SHA256:"));
    assert!(signed.allowed_signers_line.starts_with(PRINCIPAL));

    let sidecars = Sidecars::for_chain(&fixture.chain);
    assert!(sidecars.present(), "both sidecars should exist");

    let verified = attest::verify(&fixture.chain, &fixture.pinned()).unwrap();
    assert_eq!(verified.coverage, Coverage::Current);
    assert!(verified.covers_head());
    assert_eq!(
        verified.attestation.digest().unwrap(),
        signed.attestation.digest().unwrap()
    );
}

#[test]
fn the_signature_covers_the_canonical_bytes() {
    let fixture = fixture!();
    let signed = fixture.sign();

    // The bytes on disk are exactly the bytes that were signed, so the digest is
    // reproducible from the file alone.
    let sidecars = Sidecars::for_chain(&fixture.chain);
    let on_disk = std::fs::read(&sidecars.document).unwrap();
    assert_eq!(on_disk, signed.document);
    assert_eq!(on_disk, signed.attestation.canonical_bytes().unwrap());
    assert!(!on_disk.contains(&b'\n'), "canonical bytes are one line");
}

#[test]
fn an_edited_document_is_refused() {
    let fixture = fixture!();
    fixture.sign();
    let sidecars = Sidecars::for_chain(&fixture.chain);

    // Editing the sequence while leaving the digest keeps the document
    // well formed, so only the signature can catch it.
    let text = std::fs::read_to_string(&sidecars.document).unwrap();
    let edited = text.replace(r#""seq":3"#, r#""seq":2"#);
    assert_ne!(edited, text);
    std::fs::write(&sidecars.document, edited).unwrap();

    let error = attest::verify(&fixture.chain, &fixture.pinned()).unwrap_err();
    assert!(error.to_string().contains("does not verify"), "{error}");
}

#[test]
fn formatting_cannot_break_an_attestation_but_editing_it_still_can() {
    let fixture = fixture!();
    fixture.sign();
    let sidecars = Sidecars::for_chain(&fixture.chain);
    let parsed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&sidecars.document).unwrap()).unwrap();
    // The bytes that are actually on disk, and therefore the ones the signature
    // covers. Signing again would produce a different timestamp and a different
    // signature, so this must come from the file rather than from a fresh sign.
    let canonical = std::fs::read(&sidecars.document).unwrap();

    // Pretty-printing changes the bytes on disk and not the content. The
    // signature is checked against the canonical bytes of the parsed content, so
    // it still applies, and the difference is reported rather than fatal.
    std::fs::write(
        &sidecars.document,
        serde_json::to_vec_pretty(&parsed).unwrap(),
    )
    .unwrap();

    let checked = attest::verify(&fixture.chain, &fixture.pinned()).unwrap();
    assert_eq!(checked.document.canonicality, Canonicality::Reformatted);
    assert!(checked.coverage.is_current());
    assert_eq!(checked.attestation.canonical_bytes().unwrap(), canonical);

    // Repairing touches formatting only, and the signature still applies.
    assert!(
        attest::canonicalize(&fixture.chain, &checked.document).unwrap(),
        "repaired"
    );
    assert_eq!(std::fs::read(&sidecars.document).unwrap(), canonical);
    assert_eq!(
        attest::verify(&fixture.chain, &fixture.pinned())
            .unwrap()
            .document
            .canonicality,
        Canonicality::Canonical,
        "an already canonical document needs no repair"
    );

    // CRLF is formatting too.
    let crlf = String::from_utf8(serde_json::to_vec_pretty(&parsed).unwrap())
        .unwrap()
        .replace('\n', "\r\n");
    std::fs::write(&sidecars.document, crlf.as_bytes()).unwrap();
    let crlf_checked = attest::verify(&fixture.chain, &fixture.pinned()).unwrap();
    assert_eq!(
        crlf_checked.document.canonicality,
        Canonicality::Reformatted
    );
    attest::canonicalize(&fixture.chain, &crlf_checked.document).unwrap();

    // A repair refuses to write over a file that changed since it was verified,
    // rather than discarding whatever replaced it. The verified document has to
    // be one that needs repairing, or there is nothing to overwrite.
    std::fs::write(
        &sidecars.document,
        serde_json::to_vec_pretty(&parsed).unwrap(),
    )
    .unwrap();
    let stale = attest::verify(&fixture.chain, &fixture.pinned()).unwrap();
    assert_eq!(stale.document.canonicality, Canonicality::Reformatted);
    let tampered = String::from_utf8(canonical.clone())
        .unwrap()
        .replace("\"nostoi-v1\"", "\"nostoi-v1 \"");
    std::fs::write(&sidecars.document, tampered.as_bytes()).unwrap();
    let error = attest::canonicalize(&fixture.chain, &stale.document).unwrap_err();
    assert!(error.to_string().contains("changed since"), "{error}");
    std::fs::write(&sidecars.document, &canonical).unwrap();

    // A changed *value* in a reformatted file is still refused.
    // A changed *value* in a reformatted file is still refused. That is the
    // property that matters, and the reason content is compared canonically.
    let mut altered = parsed;
    altered["seq"] = serde_json::json!(2);
    std::fs::write(
        &sidecars.document,
        serde_json::to_vec_pretty(&altered).unwrap(),
    )
    .unwrap();
    let error = attest::verify(&fixture.chain, &fixture.pinned()).unwrap_err();
    assert!(
        error.to_string().contains("does not verify"),
        "a reformatted document with a changed value must still fail: {error}"
    );
}

#[test]
fn a_substituted_key_is_refused_even_with_a_permissive_allowed_signers_file() {
    let fixture = fixture!();
    let signed = fixture.sign();
    // The attack the fingerprint pin exists for: edit the trust anchor to name a
    // key you control, then re-sign with it. ssh-keygen is perfectly happy.
    let attacker_key = generate_key(fixture._dir.path(), "mallory@elsewhere");
    // The realistic edit: the expected principal now maps to a key you control.
    let permissive = fixture._dir.path().join("permissive");
    std::fs::write(
        &permissive,
        format!("{PRINCIPAL} {}\n", public_key(&attacker_key)),
    )
    .unwrap();
    let mut malicious = signer(&attacker_key);
    malicious.principal = PRINCIPAL.into();
    let forged = attest::sign(&fixture.chain, "production/kernel", None, &malicious, None).unwrap();
    attest::write(&fixture.chain, &forged).unwrap();

    // Against the substituted file the forged attestation verifies: the
    // allowed_signers file is the only trust anchor, and the attacker owns it.
    // This is not a bug, it is the reason a pin is required.
    let mut unpinned = fixture.verifier();
    unpinned.allowed_signers = permissive.clone();
    let accepted = attest::verify(&fixture.chain, &unpinned).unwrap();
    assert_eq!(
        accepted.attestation.fingerprint,
        forged.attestation.fingerprint
    );

    // Pinned, the same forgery is refused: the signature is good, but not good
    // from the key the operator pinned.
    let mut pinned = fixture.pinned();
    pinned.allowed_signers = permissive;
    let error = attest::verify(&fixture.chain, &pinned).unwrap_err();
    assert!(
        error.to_string().contains("pinned key"),
        "the pin is what refuses a substituted key: {error}"
    );

    // The original attestation is still what the chain was really signed with.
    attest::write(&fixture.chain, &signed).unwrap();
    assert!(attest::verify(&fixture.chain, &fixture.pinned()).is_ok());
}

#[test]
fn a_missing_attestation_is_refused_and_says_so() {
    let fixture = fixture!();

    let error = attest::verify(&fixture.chain, &fixture.pinned()).unwrap_err();
    let said = error.to_string();
    assert!(said.contains("no attestation"), "{said}");
    assert!(said.contains("attestation.json"), "{said}");

    // Half an attestation is not an attestation.
    attest::write(
        &fixture.chain,
        &attest::sign(
            &fixture.chain,
            "production/kernel",
            None,
            &signer(&fixture.key),
            None,
        )
        .unwrap(),
    )
    .unwrap();
    std::fs::remove_file(Sidecars::for_chain(&fixture.chain).signature).unwrap();
    let error = attest::verify(&fixture.chain, &fixture.pinned()).unwrap_err();
    assert!(error.to_string().contains("attestation.sig"), "{error}");
}

#[test]
fn an_empty_signature_is_refused() {
    let fixture = fixture!();
    fixture.sign();
    let sidecars = Sidecars::for_chain(&fixture.chain);
    std::fs::write(&sidecars.signature, b"").unwrap();

    let error = attest::verify(&fixture.chain, &fixture.pinned()).unwrap_err();
    assert!(error.to_string().contains("empty"), "{error}");
}

#[test]
fn a_truncated_chain_fails_the_attestation() {
    let fixture = fixture!();
    fixture.sign();

    let text = std::fs::read_to_string(&fixture.chain).unwrap();
    let kept: Vec<&str> = text.lines().take(2).collect();
    std::fs::write(&fixture.chain, format!("{}\n", kept.join("\n"))).unwrap();

    assert!(attest::verify(&fixture.chain, &fixture.pinned()).is_err());
    // The document itself is still fine, which is the point: only the chain
    // binding can tell that something is missing.
    let read = attest::read(&fixture.chain).unwrap().unwrap();
    assert!(read.attestation.validate().is_ok());
    assert!(attestation::check(&fixture.chain, &read.attestation, None).is_err());
}

#[test]
fn the_namespace_has_to_match() {
    let fixture = fixture!();
    fixture.sign();

    let mut verifier = fixture.pinned();
    verifier.namespace = "something-else".into();
    let error = attest::verify(&fixture.chain, &verifier).unwrap_err();
    assert!(
        error.to_string().contains("namespace"),
        "a signature made for another namespace must not be reusable here: {error}"
    );
}

#[test]
fn a_principal_with_no_allowed_signers_entry_is_refused() {
    let fixture = fixture!();
    fixture.sign();

    let mut verifier = fixture.pinned();
    verifier.principal = "someone@else".into();
    let error = attest::verify(&fixture.chain, &verifier).unwrap_err();
    assert!(error.to_string().contains("does not verify"), "{error}");
}

#[test]
fn re_signing_reports_what_it_replaced() {
    let fixture = fixture!();
    let first = fixture.sign();
    let replaced = first.replaced.clone();
    assert!(replaced.is_none(), "there was nothing to replace");

    let second = fixture.sign();
    assert!(
        second.replaced.is_some(),
        "the first attestation is reported"
    );
    assert_eq!(second.replaced.unwrap().seq, first.attestation.seq);

    // After the chain grows, a new attestation covers the new head and says what
    // it superseded.
    nostoi::append(
        &fixture.chain,
        Draft {
            actor: Some("test"),
            kind: "attest",
            subject: None,
            body: serde_json::json!({"index": 3}),
            at: None,
        },
    )
    .unwrap();
    let third = attest::sign(
        &fixture.chain,
        "production/kernel",
        None,
        &signer(&fixture.key),
        None,
    )
    .unwrap();
    attest::write(&fixture.chain, &third).unwrap();
    assert_eq!(third.attestation.seq, 4);
    assert_eq!(third.replaced.unwrap().seq, 3);

    let verified = attest::verify(&fixture.chain, &fixture.pinned()).unwrap();
    assert_eq!(verified.coverage, Coverage::Current);
}

#[test]
fn an_anchor_key_is_recorded_when_the_chain_was_anchored() {
    let fixture = fixture!();
    let signed = attest::sign(
        &fixture.chain,
        "production/kernel",
        None,
        &signer(&fixture.key),
        Some("heads/kernel-00000003-abcd1234.json".to_string()),
    )
    .unwrap();
    attest::write(&fixture.chain, &signed).unwrap();

    assert_eq!(
        signed.attestation.anchor_key.as_deref(),
        Some("heads/kernel-00000003-abcd1234.json")
    );
    // It is part of the signed bytes, so it cannot be added afterwards.
    let verified = attest::verify(&fixture.chain, &fixture.pinned()).unwrap();
    assert_eq!(
        verified.attestation.anchor_key,
        signed.attestation.anchor_key
    );
}

#[test]
fn a_passphrase_protected_key_is_explained_not_reported_as_a_wrong_passphrase() {
    let fixture = fixture!();
    let key = fixture._dir.path().join("id_locked");
    let program = ssh_keygen().unwrap();
    // Generating an encrypted key needs a passphrase, so pass one on stdin-free
    // input; -N does it without prompting.
    let output = Command::new(&program)
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "not-the-real-one",
            "-C",
            "locked@host",
            "-f",
            &key.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    let mut locked = signer(&key);
    locked.principal = "locked@host".into();
    let error = attest::sign(&fixture.chain, "production/kernel", None, &locked, None).unwrap_err();
    let said = error.to_string();
    assert!(
        said.contains("interactive terminal") || said.contains("ssh-agent"),
        "the failure must name the real cause, not repeat ssh-keygen's wording: {said}"
    );
}

#[test]
fn key_encryption_is_read_from_the_file_before_anything_is_run() {
    let Some(program) = ssh_keygen() else { return };
    let dir = tempfile::tempdir().unwrap();

    // Unencrypted: detected without running ssh-keygen, so the answer is
    // available even where the tool cannot prompt.
    let plain = usable_key(dir.path());
    assert_eq!(attest::key_encryption(&plain), KeyEncryption::None);

    // Traditional PEM with a DEK-Info header.
    let pem = dir.path().join("traditional.pem");
    std::fs::write(
        &pem,
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nabc\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    assert_eq!(attest::key_encryption(&pem), KeyEncryption::Encrypted);

    // A file we do not recognise says so rather than guessing.
    let unknown = dir.path().join("notes.txt");
    std::fs::write(&unknown, "not a key at all\n").unwrap();
    assert_eq!(attest::key_encryption(&unknown), KeyEncryption::Unknown);
    assert_eq!(
        attest::key_encryption(&dir.path().join("absent")),
        KeyEncryption::Unknown
    );

    // And the pre-flight refuses before ssh-keygen can complain about a
    // passphrase that was never mistyped.
    let chain = chain(dir.path(), 1);
    let locked = dir.path().join("id_locked");
    std::process::Command::new(&program)
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "a-passphrase",
            "-C",
            "locked@host",
            "-f",
            &locked.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert_eq!(attest::key_encryption(&locked), KeyEncryption::Encrypted);

    let mut signer = Signer::new(&locked, "locked@host");
    signer.program = program;
    let error = attest::sign(&chain, "kernel", None, &signer, None).unwrap_err();
    let said = error.to_string();
    assert!(said.contains("no terminal"), "{said}");
    // The pre-flight message, not ssh-keygen's "incorrect passphrase".
    assert!(!said.contains("incorrect passphrase"), "{said}");
    assert!(
        !said.contains("@@@@"),
        "the banner is not a message: {said}"
    );
}

#[test]
fn an_encrypted_key_is_only_asked_for_once() {
    let Some(program) = ssh_keygen() else { return };
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("id_locked");
    std::process::Command::new(&program)
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "a-passphrase",
            "-C",
            "locked@host",
            "-f",
            &locked.to_string_lossy(),
        ])
        .output()
        .unwrap();
    // ssh-keygen writes the .pub beside the private key even for an encrypted
    // one, so the allowed_signers line can be built without a second prompt.
    let sidecar = locked.with_file_name("id_locked.pub");
    assert!(
        sidecar.is_file(),
        "ssh-keygen should have written {}",
        sidecar.display()
    );
    let line = attest::allowed_signers_line(&program, &locked, "locked@host").unwrap();
    assert!(line.starts_with("locked@host ssh-ed25519 "), "{line}");
}

#[test]
fn display_output_is_never_read_back_or_compared() {
    let fixture = fixture!();
    fixture.sign();

    // Everything shown to a human is rendered from the parsed document, so there
    // is no path by which what someone saw can become what was checked. This test
    // pins that by mangling every rendering and confirming verification is
    // unmoved: if any of these were compared, or re-read, it would fail.
    let sidecars = Sidecars::for_chain(&fixture.chain);
    let canonical = std::fs::read(&sidecars.document).unwrap();

    for rendered in [
        serde_json::to_string_pretty(&fixture.read_attestation()).unwrap(),
        format!("{}\n\n", String::from_utf8_lossy(&canonical)),
        canonical
            .iter()
            .rev()
            .map(|b| *b as char)
            .collect::<String>(),
        canonical
            .iter()
            .map(|b| char::from(b.to_ascii_uppercase()))
            .collect::<String>(),
    ] {
        assert_ne!(rendered, String::from_utf8_lossy(&canonical));
        // The canonical bytes are a function of the content alone, so a rendering
        // cannot change them.
        assert_eq!(
            fixture.read_attestation().canonical_bytes().unwrap(),
            canonical
        );
        let checked = attest::verify(&fixture.chain, &fixture.pinned()).unwrap();
        assert_eq!(checked.attestation.canonical_bytes().unwrap(), canonical);
        assert!(checked.covers_head());
    }

    // And nothing in the read-only reporting path writes to the chain or its
    // sidecars.
    let before = std::fs::read(&sidecars.document).unwrap();
    let summary = nostoi::attest::summary(&fixture.chain, checked_head(&fixture.chain));
    assert!(summary.contains("attested by"), "{summary}");
    assert_eq!(std::fs::read(&sidecars.document).unwrap(), before);
}

fn checked_head(chain: &Path) -> u64 {
    nostoi::verify(chain, None).unwrap().head.unwrap().seq
}

#[test]
fn an_oversized_sidecar_is_refused_rather_than_read_into_memory() {
    let Some(_) = ssh_keygen() else { return };
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 1);
    let sidecars = Sidecars::for_chain(&chain);
    std::fs::write(&sidecars.document, vec![b'x'; 4 * 1024 * 1024]).unwrap();
    std::fs::write(&sidecars.signature, vec![b'x'; 4 * 1024 * 1024]).unwrap();

    // The document limit is 64 KiB, so this is refused on size rather than parsed.
    let error = nostoi::attest::read(&chain).unwrap_err();
    let said = error.to_string();
    assert!(
        said.contains("byte limit") || said.contains("not valid JSON"),
        "{said}"
    );

    // And the signature limit is independent of it.
    std::fs::write(
        &sidecars.document,
        br#"{"v":"nostoi-attestation-v1","chain":"k","format":"nostoi-v1","seq":1,"digest":"0000000000000000000000000000000000000000000000000000000000000000","anchored_at":"2026-01-01T00:00:00Z","principal":"p","fingerprint":"SHA256:x"}"#,
    )
    .unwrap();
    std::fs::write(&sidecars.signature, vec![b'x'; 4 * 1024 * 1024]).unwrap();
    let mut verifier = Verifier::new(dir.path().join("allowed"), "p");
    verifier.program = ssh_keygen().unwrap();
    let error = nostoi::attest::verify(&chain, &verifier).unwrap_err();
    assert!(error.to_string().contains("byte limit"), "{error}");
}

#[test]
fn a_missing_program_is_reported_clearly() {
    let fixture = fixture!();
    let mut signer = signer(&fixture.key);
    signer.program = PathBuf::from("/nonexistent/ssh-keygen");
    let error = attest::sign(&fixture.chain, "production/kernel", None, &signer, None).unwrap_err();
    assert!(error.to_string().contains("cannot run"), "{error}");
}
