//! End-to-end attestations with a real `ssh-keygen`.
//!
//! These sign for real, with a throwaway key generated in a temporary directory.
//! Nothing here needs a passphrase, an agent or a network, but it does need
//! `ssh-keygen` on the host; when it is missing the tests say so instead of
//! failing mysteriously.

use nostoi::attest::{self, Signer, Verifier};
use nostoi::attestation::{self, Coverage, Sidecars};
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
fn a_document_that_is_not_canonical_is_refused_before_the_signature() {
    let fixture = fixture!();
    fixture.sign();
    let sidecars = Sidecars::for_chain(&fixture.chain);

    // Pretty-printing does not change what the document says, but it does change
    // the bytes the signature covers, so it must not be silently accepted.
    let parsed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&sidecars.document).unwrap()).unwrap();
    std::fs::write(
        &sidecars.document,
        serde_json::to_vec_pretty(&parsed).unwrap(),
    )
    .unwrap();

    let error = attest::verify(&fixture.chain, &fixture.pinned()).unwrap_err();
    assert!(error.to_string().contains("canonical"), "{error}");
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
    let (document, _) = attest::read(&fixture.chain).unwrap().unwrap();
    assert!(document.validate().is_ok());
    assert!(attestation::check(&fixture.chain, &document, None).is_err());
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
fn a_missing_program_is_reported_clearly() {
    let fixture = fixture!();
    let mut signer = signer(&fixture.key);
    signer.program = PathBuf::from("/nonexistent/ssh-keygen");
    let error = attest::sign(&fixture.chain, "production/kernel", None, &signer, None).unwrap_err();
    assert!(error.to_string().contains("cannot run"), "{error}");
}
