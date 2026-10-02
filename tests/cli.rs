//! The `nostoi` binary end to end, and conformance with the stdlib Python
//! reference (`contrib/python/nostoi.py`) in both directions.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn nostoi(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nostoi"))
        .args(args)
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn python(script: &str, path: &Path) -> Option<Output> {
    let contrib = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contrib/python");
    Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(path)
        .env("PYTHONPATH", contrib)
        .output()
        .ok()
}

#[test]
fn exit_codes_say_intact_broken_or_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.jsonl");
    let p = path.to_str().unwrap();
    assert_eq!(
        code(&nostoi(&[
            "append",
            p,
            "--kind",
            "one",
            "--body",
            r#"{"n":1}"#
        ])),
        0
    );
    assert_eq!(code(&nostoi(&["append", p, "--kind", "two"])), 0);
    assert_eq!(code(&nostoi(&["verify", p])), 0);

    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replacen(r#""n":1"#, r#""n":2"#, 1);
    std::fs::write(&path, text).unwrap();
    let broken = nostoi(&["verify", p]);
    assert_eq!(code(&broken), 1);
    assert!(String::from_utf8_lossy(&broken.stdout).contains("record 1 was altered"));
    assert_eq!(
        code(&nostoi(&["append", p, "--kind", "three"])),
        1,
        "a broken chain is never extended"
    );
    assert_eq!(code(&nostoi(&["verify", "/nonexistent/chain.jsonl"])), 2);
    assert_eq!(
        code(&nostoi(&["append", p, "--kind", "x", "--body", "not json"])),
        2
    );
}

#[test]
fn python_and_rust_write_one_chain_together() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.jsonl");
    let Some(out) = python(
        r#"
import sys, nostoi
nostoi.append(sys.argv[1], kind="skill.run", actor="agent:py", subject="run-1",
              body={"input": "Gretel går \U0001f986 — \"q\" \\ /", "n": 7, "ok": True, "none": None})
"#,
        &path,
    ) else {
        eprintln!("python3 not available: skipping");
        return;
    };
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let p = path.to_str().unwrap();
    assert_eq!(
        code(&nostoi(&["verify", p])),
        0,
        "Rust verifies what Python wrote"
    );
    assert_eq!(
        code(&nostoi(&[
            "append",
            p,
            "--kind",
            "tool.call",
            "--body",
            r#"{"tool":"x","big":18446744073709551615}"#
        ])),
        0
    );
    let out = python(
        r#"
import sys, nostoi
report = nostoi.verify(sys.argv[1])
assert report["ok"] and report["verified"] == 2, report
nostoi.append(sys.argv[1], kind="after", body={"list": [1, {"b": 2, "a": 1}]})
"#,
        &path,
    )
    .unwrap();
    assert!(
        out.status.success(),
        "Python verifies what Rust wrote: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let head = nostoi(&["head", p]);
    assert_eq!(code(&head), 0);
    assert!(String::from_utf8_lossy(&head.stdout).starts_with("3 "));
}

#[test]
fn log_follow_streams_new_records_once_verified() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live.jsonl");
    let p = path.to_str().unwrap().to_string();
    nostoi(&["append", &p, "--kind", "first"]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_nostoi"))
        .args(["log", &p, "--follow", "--interval", "50"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let first = lines.next().unwrap().unwrap();
    assert!(first.contains(r#""kind":"first""#));
    nostoi(&["append", &p, "--kind", "second"]);
    let deadline = Instant::now() + Duration::from_secs(10);
    let second = lines.next().unwrap().unwrap();
    assert!(Instant::now() < deadline);
    assert!(second.contains(r#""kind":"second""#) && second.contains(r#""verified":true"#));
    child.kill().unwrap();
    let _ = child.wait();
}

fn ssh_keygen() -> Option<std::path::PathBuf> {
    let path = std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .map(|dir| Path::new(dir).join("ssh-keygen"))
        .find(|candidate| candidate.is_file())?;
    Some(path)
}

#[test]
fn attesting_signs_the_head_and_verifying_checks_it() {
    let Some(ssh_keygen) = ssh_keygen() else {
        eprintln!("skipping: ssh-keygen is not on PATH");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let chain = path.to_str().unwrap().to_string();
    nostoi(&["append", &chain, "--kind", "first"]);
    nostoi(&["append", &chain, "--kind", "second"]);

    // Before: the read-only commands say what is missing and how to fix it.
    let verify = nostoi(&["verify", &chain]);
    assert_eq!(code(&verify), 0);
    let said = String::from_utf8_lossy(&verify.stdout);
    assert!(said.contains("no attestation"), "{said}");
    assert!(said.contains("nostoi attest"), "{said}");

    let key = dir.path().join("id_ed25519");
    let generated = std::process::Command::new(&ssh_keygen)
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "alice@laptop",
            "-f",
            &key.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(generated.status.success());

    let attested = nostoi(&[
        "attest",
        &chain,
        "--key",
        &key.to_string_lossy(),
        "--principal",
        "alice@laptop",
    ]);
    assert_eq!(
        code(&attested),
        0,
        "{}",
        String::from_utf8_lossy(&attested.stderr)
    );
    let said = String::from_utf8_lossy(&attested.stdout);
    assert!(said.contains("attested seq=2"), "{said}");
    assert!(said.contains("alice@laptop"), "{said}");
    // The operator is told how to check it, and warned about the timestamp gap.
    assert!(said.contains("verify-attestation"), "{said}");
    assert!(said.contains("proves authorship"), "{said}");

    // After: the document is reported, still labelled unchecked.
    let verify = nostoi(&["verify", &chain]);
    let said = String::from_utf8_lossy(&verify.stdout);
    assert!(said.contains("attested by alice@laptop"), "{said}");
    assert!(said.contains("covers the current head"), "{said}");

    let json: serde_json::Value =
        serde_json::from_slice(&nostoi(&["verify", &chain, "--json"]).stdout).unwrap();
    assert_eq!(json["attestation"]["present"], true);
    assert_eq!(json["attestation"]["signature"], "unchecked");
    assert_eq!(json["attestation"]["principal"], "alice@laptop");
    assert_eq!(json["attestation"]["covers_head"], true);

    // Now the signature, with the key pinned.
    let public = std::process::Command::new(&ssh_keygen)
        .args(["-y", "-f", &key.to_string_lossy()])
        .output()
        .unwrap();
    let allowed = dir.path().join("allowed_signers");
    std::fs::write(
        &allowed,
        format!(
            "alice@laptop {}\n",
            String::from_utf8_lossy(&public.stdout).trim()
        ),
    )
    .unwrap();
    let fingerprint = String::from_utf8_lossy(
        &std::process::Command::new(&ssh_keygen)
            .args(["-lf", &key.to_string_lossy()])
            .output()
            .unwrap()
            .stdout,
    )
    .split_whitespace()
    .nth(1)
    .unwrap()
    .to_string();

    let checked = nostoi(&[
        "verify-attestation",
        &chain,
        "--allowed-signers",
        &allowed.to_string_lossy(),
        "--principal",
        "alice@laptop",
        "--fingerprint",
        &fingerprint,
    ]);
    assert_eq!(
        code(&checked),
        0,
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("signature verified"));

    // A different pin is refused.
    let wrong = nostoi(&[
        "verify-attestation",
        &chain,
        "--allowed-signers",
        &allowed.to_string_lossy(),
        "--principal",
        "alice@laptop",
        "--fingerprint",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ]);
    assert_eq!(code(&wrong), 1);
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("not the pinned key"));
}

#[test]
fn appending_makes_an_attestation_visibly_stale() {
    let Some(ssh_keygen) = ssh_keygen() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let chain = path.to_str().unwrap().to_string();
    nostoi(&["append", &chain, "--kind", "first"]);
    let key = dir.path().join("id");
    std::process::Command::new(&ssh_keygen)
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "alice@laptop",
            "-f",
            &key.to_string_lossy(),
        ])
        .output()
        .unwrap();
    nostoi(&[
        "attest",
        &chain,
        "--key",
        &key.to_string_lossy(),
        "--principal",
        "alice@laptop",
    ]);

    nostoi(&["append", &chain, "--kind", "second"]);
    let verify = nostoi(&["verify", &chain]);
    let said = String::from_utf8_lossy(&verify.stdout);
    assert!(said.contains("stale"), "{said}");
    assert!(said.contains("the chain is at 2"), "{said}");
}

#[test]
fn schema_is_read_only_and_reports_persisted_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.sqlite");
    let p = path.to_str().unwrap().to_string();
    nostoi(&["append", &p, "--kind", "first"]);
    let before = std::fs::read(&path).unwrap();

    let output = nostoi(&["schema", "--json", &p]);
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(metadata["schema_revision"], 1);
    assert_eq!(
        metadata["application_id"].as_i64().unwrap(),
        nostoi::schema::AUDIT_APPLICATION_ID
    );
    assert_eq!(metadata["record_format"], "nostoi-v1");

    // Reporting schema must never write: a read that stamped the file would be
    // indistinguishable from opening it for writing.
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
