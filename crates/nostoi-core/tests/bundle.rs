//! Bundle verification without `ssh-keygen`.
//!
//! The signature in the fixture was made by `ssh-keygen -Y sign`, and the
//! integration test in the parent crate checks that both paths — this one and the
//! program — agree about a bundle signed during the test run. What matters here
//! is that every refusal is a refusal, because this code is what a WebAssembly
//! host, a browser or a service with no subprocess will be using.

use nostoi_core::bundle::{self, Bundle, Expectations};
use nostoi_core::revocation::Revocations;

const BUNDLE: &str = include_str!("vectors/sshsig-bundle.json");

fn bundle() -> Bundle {
    serde_json::from_str(BUNDLE).expect("the fixture is a bundle")
}

fn pinned() -> Expectations {
    Expectations {
        fingerprint: Some(bundle().fingerprint),
        ..Expectations::default()
    }
}

#[test]
fn a_bundle_signed_by_ssh_keygen_verifies_without_it() {
    let checked = bundle::verify_bundle(&bundle(), &pinned()).expect("verifies");
    assert_eq!(checked.fingerprint, bundle().fingerprint);
    assert_eq!(checked.how, "built-in");
    assert!(!checked.revoked);
    assert!(checked
        .public_key
        .starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"));
    assert_eq!(checked.canonical_bytes, bundle().signed_bytes().unwrap());
    assert_eq!(checked.namespace, "nostoi-attestation");
}

#[test]
fn a_pin_the_caller_did_not_ask_for_is_a_refusal() {
    // The bundle is entirely valid; it is simply signed by a key nobody vouched
    // for. Both readings are refusals, which is the point: this code does not get
    // to decide that a self-declared key is a trustworthy one.
    // No pin at all is allowed, and then the result says only what is true: that
    // this key signed it. Nothing here turns "signed" into "trusted".
    let unknown = bundle::verify_bundle(&bundle(), &Expectations::default()).expect("verifies");
    assert_eq!(unknown.fingerprint, bundle().fingerprint);

    let wrong = Expectations {
        fingerprint: Some(format!("SHA256:{}", "A".repeat(43))),
        ..Expectations::default()
    };
    let error = bundle::verify_bundle(&bundle(), &wrong).unwrap_err();
    assert!(error.to_string().contains("not the pinned key"), "{error}");
}

#[test]
fn a_bundle_whose_pin_was_swapped_is_refused() {
    let mut edited = bundle();
    edited.fingerprint = format!("SHA256:{}", "A".repeat(43));
    let error = bundle::verify_bundle(&edited, &Expectations::default()).unwrap_err();
    assert!(error.to_string().contains("the bundle pins"), "{error}");
}

#[test]
fn an_edited_document_does_not_verify() {
    for edit in [
        |d: &mut nostoi_core::attestation::Attestation| d.title = Some("edited".into()),
        |d: &mut nostoi_core::attestation::Attestation| d.digest = "b".repeat(64),
        |d: &mut nostoi_core::attestation::Attestation| d.seq += 1,
        |d: &mut nostoi_core::attestation::Attestation| d.principal = "mallory@laptop".into(),
    ] {
        let mut edited = bundle();
        edit(&mut edited.document);
        assert!(
            bundle::verify_bundle(&edited, &pinned()).is_err(),
            "an edited document must not verify"
        );
    }
}

#[test]
fn a_revoked_key_is_refused_before_the_signature_is_even_read() {
    let revoked = Revocations::from_fingerprints([bundle().fingerprint]);
    let expectations = Expectations {
        fingerprint: Some(bundle().fingerprint),
        revoked: Some(revoked),
        ..Expectations::default()
    };
    // Even with the correct pin. That is the whole reason revocation is a separate
    // channel: the pin is the thing an attacker with host access would edit.
    let error = bundle::verify_bundle(&bundle(), &expectations).unwrap_err();
    assert!(error.to_string().contains("revoked"), "{error}");

    // And a bundle whose signature is nonsense is still reported as revoked, so a
    // caller cannot learn anything about the signature by watching the error.
    let mut broken = bundle();
    broken.signature = "-----BEGIN SSH SIGNATURE-----\nZm9v\n-----END SSH SIGNATURE-----\n".into();
    let error = bundle::verify_bundle(&broken, &expectations).unwrap_err();
    assert!(error.to_string().contains("revoked"), "{error}");
}

#[test]
fn a_namespace_the_caller_requires_is_enforced() {
    let expectations = Expectations {
        namespace: Some("nostoi-attestation".into()),
        ..pinned()
    };
    assert!(bundle::verify_bundle(&bundle(), &expectations).is_ok());

    let wrong = Expectations {
        namespace: Some("some-other-use".into()),
        ..pinned()
    };
    let error = bundle::verify_bundle(&bundle(), &wrong).unwrap_err();
    assert!(error.to_string().contains("namespace"), "{error}");
}

#[test]
fn an_unparseable_bundle_is_refused_before_any_crypto() {
    let mut edited = bundle();
    edited.v = "nostoi-attestation-bundle-v2".into();
    let error = bundle::verify_bundle(&edited, &pinned()).unwrap_err();
    assert!(
        error.to_string().contains("unsupported bundle version"),
        "{error}"
    );
}
