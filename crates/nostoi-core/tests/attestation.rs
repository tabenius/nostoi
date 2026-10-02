//! Attestations checked against real chains.
//!
//! The signature is out of scope here: what matters is that a document which is
//! perfectly well formed can still be wrong about the chain, and that each way
//! of being wrong is reported as itself.

use nostoi_core::attestation::{
    self, read_document, Attestation, Canonicality, Coverage, Sidecars, ATTESTATION_V1,
};
use nostoi_core::{Draft, Format, Head};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const FINGERPRINT: &str = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

fn chain(dir: &std::path::Path, records: usize) -> (std::path::PathBuf, Head) {
    let path = dir.join("audit.jsonl");
    for index in 0..records {
        nostoi_core::append(
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
    let head = nostoi_core::open(&path, None)
        .unwrap()
        .verify()
        .head
        .unwrap();
    (path, head)
}

fn attest(head: &Head, chain: &str) -> Attestation {
    Attestation::at(
        chain,
        "nostoi-v1",
        head,
        OffsetDateTime::parse("2026-02-01T12:00:00Z", &Rfc3339).unwrap(),
        "alice@workstation",
        FINGERPRINT,
        None,
    )
    .unwrap()
}

#[test]
fn an_attestation_over_the_current_head_covers_it() {
    let dir = tempfile::tempdir().unwrap();
    let (path, head) = chain(dir.path(), 5);
    let attestation = attest(&head, "production/kernel");

    let checked = attestation::check(&path, &attestation, None).unwrap();

    assert_eq!(checked.coverage, Coverage::Current);
    assert!(checked.covers_head());
    assert_eq!(checked.head.seq, 5);
    assert_eq!(attestation.v, ATTESTATION_V1);
    assert!(attestation.matches_chain("production/kernel"));
    assert!(!attestation.matches_chain("production/other"));
}

#[test]
fn an_attestation_over_an_intact_prefix_stays_valid_as_the_chain_grows() {
    let dir = tempfile::tempdir().unwrap();
    let (path, early) = chain(dir.path(), 3);
    let attestation = attest(&early, "production/kernel");

    // The chain moves on. The signature still says something true.
    for index in 3..7 {
        nostoi_core::append(
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

    let checked = attestation::check(&path, &attestation, None).unwrap();

    assert_eq!(checked.coverage, Coverage::Stale { ahead_by: 4 });
    assert!(
        !checked.covers_head(),
        "stale is not the same as covering the current head"
    );
}

#[test]
fn a_truncated_chain_does_not_satisfy_an_attestation() {
    let dir = tempfile::tempdir().unwrap();
    let (path, head) = chain(dir.path(), 6);
    let attestation = attest(&head, "production/kernel");

    // Cut the tail: the remaining records still verify among themselves, so
    // only the attestation can tell that anything is missing.
    let text = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = text.lines().take(4).collect();
    std::fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

    assert!(
        attestation::check(&path, &attestation, None).is_err(),
        "a truncated chain must not pass an attestation over its former head"
    );
    assert!(nostoi_core::verify(&path, None).unwrap().ok);
}

#[test]
fn a_rewritten_chain_is_caught_even_when_its_own_hashes_agree() {
    let dir = tempfile::tempdir().unwrap();
    let (path, head) = chain(dir.path(), 4);
    let attestation = attest(&head, "production/kernel");

    // Replace record 2 and recompute every digest after it, so the chain is
    // internally consistent and still ends at a different head. This is the
    // attack the attestation exists to catch: nothing inside the chain can
    // notice, because every link agrees.
    let text = std::fs::read_to_string(&path).unwrap();
    let mut records: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    records[1]["body"] = serde_json::json!({"index": "rewritten"});
    let mut previous = nostoi_core::GENESIS.to_string();
    for record in &mut records {
        let object = record.as_object_mut().unwrap();
        object.insert("previous".to_string(), serde_json::json!(previous));
        previous = nostoi_core::format::json_record_digest(object);
        object.insert("digest".to_string(), serde_json::json!(previous));
    }
    let rebuilt: String = records
        .iter()
        .map(|record| format!("{}\n", nostoi_core::canonical::to_string(record)))
        .collect();
    std::fs::write(&path, rebuilt).unwrap();

    let checked = attestation::check(&path, &attestation, None);
    assert!(
        checked.is_err(),
        "recomputing every digest must not defeat the attestation"
    );
}

#[test]
fn an_empty_chain_is_not_reported_as_a_rewritten_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    std::fs::write(&path, "").unwrap();

    // A chain with no records cannot carry an attestation, and saying "record 3's
    // digest does not match" about a file with no records sends someone hunting
    // for a corruption that is not there.
    let head = Head {
        seq: 3,
        digest: "a".repeat(64),
    };
    let attestation = attest(&head, "kernel");
    let error = attestation::check(&path, &attestation, None).unwrap_err();
    let said = error.to_string();
    assert!(said.contains("no records"), "{said}");
    assert!(!said.contains("digest"), "{said}");

    // And the outcome is its own, not `Rewritten`.
    let verification = nostoi_core::verify_streaming(&path, None, Some(3)).unwrap();
    assert_eq!(attestation.coverage(&verification), Coverage::Empty);
}

#[test]
fn a_malformed_document_never_reaches_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (path, head) = chain(dir.path(), 2);
    let mut attestation = attest(&head, "production/kernel");
    attestation.seq = 0;

    let error = attestation::check(&path, &attestation, None).unwrap_err();
    assert!(
        error.to_string().contains("sequence 0"),
        "the shape check should speak first: {error}"
    );
}

#[test]
fn the_sidecars_are_written_next_to_the_chain_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let (path, head) = chain(dir.path(), 2);
    let sidecars = Sidecars::for_chain(&path);
    assert!(!sidecars.present());
    let description = sidecars.missing_description().unwrap();
    assert!(description.contains("attestation.json"), "{description}");
    assert!(description.contains("attestation.sig"), "{description}");

    let attestation = attest(&head, "production/kernel");
    std::fs::write(&sidecars.document, attestation.canonical_bytes().unwrap()).unwrap();
    std::fs::write(&sidecars.signature, b"signature placeholder").unwrap();
    assert!(sidecars.present());
    assert!(sidecars.missing_description().is_none());

    let loaded = Attestation::load(&sidecars.document).unwrap();
    assert_eq!(loaded, attestation);
    assert_eq!(loaded.digest().unwrap(), attestation.digest().unwrap());

    // A chain that has been renamed takes its sidecars with it.
    let moved = dir.path().join("renamed.jsonl");
    std::fs::rename(&path, &moved).unwrap();
    let moved_sidecars = Sidecars::for_chain(&moved);
    assert!(!moved_sidecars.document.exists());
}

#[test]
fn canonical_bytes_are_ascii_whatever_the_content() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, head) = chain(dir.path(), 1);
    // A chain identity with a non-ASCII character, in NFC.
    let attestation = Attestation::new(
        "produktion/kerné",
        "nostoi-v1",
        &head,
        "2026-02-01T12:00:00Z",
        "zoë@laptop",
        FINGERPRINT,
        None,
    )
    .unwrap();

    let bytes = attestation.canonical_bytes().unwrap();
    assert!(
        bytes.is_ascii(),
        "the signed bytes must be ASCII so no encoding mismatch can corrupt them"
    );
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains(r#"\u00e9"#), "é is escaped: {text}");
    assert!(text.contains(r#"\u00eb"#), "ë is escaped: {text}");

    // It round-trips: the escaped form parses back to the same content.
    let parsed: Attestation = serde_json::from_slice(&attestation.canonical_bytes().unwrap())
        .expect("canonical bytes parse back");
    assert_eq!(parsed, attestation);
    assert_eq!(
        parsed.canonical_bytes().unwrap(),
        attestation.canonical_bytes().unwrap()
    );
}

#[test]
fn the_two_unicode_normalizations_are_refused_rather_than_confused() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, head) = chain(dir.path(), 1);

    // NFC and NFD look identical, are canonically equivalent, and hash
    // differently. Silently rewriting one into the other would mean the signed
    // bytes are not the ones the operator typed, so the ambiguous one is refused.
    let nfc = Attestation::new(
        "produktion/kerné",
        "nostoi-v1",
        &head,
        "2026-02-01T12:00:00Z",
        "zoë@laptop",
        FINGERPRINT,
        None,
    )
    .unwrap();
    let mut nfd = nfc.clone();
    nfd.chain = "produktion/kerne\u{301}".into();
    nfd.principal = "zo\u{e9}@laptop".into();

    assert!(nfc.validate().is_ok());
    let error = nfd.validate().unwrap_err();
    assert!(error.to_string().contains("NFC"), "{error}");
    // The two forms really would hash differently, which is why refusing beats
    // guessing. Canonical bytes cannot be computed for the NFD document, because
    // validation refuses it first; the escaped forms show the difference.
    let nfc_bytes = String::from_utf8(nfc.canonical_bytes().unwrap()).unwrap();
    assert!(nfc_bytes.contains(r#"\u00e9"#), "{nfc_bytes}");
    assert!(
        !nfc_bytes.contains(r#"\u0301"#),
        "NFC has no combining acute to escape: {nfc_bytes}"
    );
}

#[test]
fn encoding_problems_are_named_rather_than_reported_as_invalid_json() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, head) = chain(dir.path(), 1);
    let attestation = attest(&head, "kernel");
    let document = dir.path().join("doc.json");
    let sidecars = Sidecars {
        document: document.clone(),
        signature: dir.path().join("doc.json.sig"),
    };
    // A byte-order mark is not JSON, and "expected value" does not say so.
    std::fs::write(&sidecars.document, b"\xEF\xBB\xBF{}").unwrap();
    let error = read_document(&sidecars.document).unwrap_err();
    assert!(error.to_string().contains("byte-order mark"), "{error}");

    // Bytes that are not UTF-8 at all.
    std::fs::write(&sidecars.document, b"{\"chain\":\"\xFF\xFE\"}").unwrap();
    let error = read_document(&sidecars.document).unwrap_err();
    let said = error.to_string();
    assert!(said.contains("not valid UTF-8"), "{said}");
    assert!(said.contains("byte "), "the offset helps: {said}");

    // Two byte-order marks is a different mistake from one.
    std::fs::write(&sidecars.document, b"\xEF\xBB\xBF\xEF\xBB\xBF{}").unwrap();
    let error = read_document(&sidecars.document).unwrap_err();
    assert!(error.to_string().contains("more than one"), "{error}");

    // A missing file is still an IO error, not an encoding one.
    let error = read_document(&dir.path().join("absent.json")).unwrap_err();
    assert!(matches!(error, nostoi_core::Error::Io { .. }), "{error:?}");

    // And the happy path reports canonical form accurately.
    std::fs::write(&sidecars.document, attestation.canonical_bytes().unwrap()).unwrap();
    let read = read_document(&sidecars.document).unwrap();
    assert_eq!(read.canonicality(), Canonicality::Canonical);
    std::fs::write(
        &sidecars.document,
        serde_json::to_vec_pretty(&attestation).unwrap(),
    )
    .unwrap();
    let read = read_document(&sidecars.document).unwrap();
    assert_eq!(read.canonicality(), Canonicality::Reformatted);
    assert_eq!(read.attestation, attestation);
}

#[test]
fn the_document_does_not_depend_on_the_chain_format_spelling() {
    let dir = tempfile::tempdir().unwrap();
    let (path, head) = chain(dir.path(), 2);
    let attestation = attest(&head, "production/kernel");

    // An explicit format that matches the file behaves as detection would.
    let checked = attestation::check(&path, &attestation, Some(Format::Nostoi)).unwrap();
    assert!(checked.covers_head());

    // A document claiming a different format is still checked against the chain,
    // and the mismatch is visible rather than silently accepted.
    let mut mismatched = attestation.clone();
    mismatched.format = "weftmark-ledger-v1".into();
    let error = attestation::check(&path, &mismatched, Some(Format::Nostoi)).unwrap_err();
    assert!(!error.to_string().is_empty());
}
