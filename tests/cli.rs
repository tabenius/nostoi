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
