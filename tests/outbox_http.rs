#![cfg(all(feature = "s3", feature = "sqlite"))]

use nostoi::anchor::{AnchorOptions, LockMode};
use nostoi::outbox::Outbox;
use nostoi::s3::{Client, Credentials, Provider};
use nostoi::Error;
use rusqlite::Connection;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

struct Request {
    line: String,
    headers: String,
    body: Vec<u8>,
}

fn server<F>(count: usize, mut respond: F) -> (Client, thread::JoinHandle<()>)
where
    F: FnMut(usize, Request) -> (&'static str, String) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = thread::spawn(move || {
        for index in 0..count {
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "missing request {index}");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 65536);
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
            }
            let headers = String::from_utf8(header).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            assert!(length < 65536);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let (status, body) = respond(
                index,
                Request {
                    line: headers.lines().next().unwrap().into(),
                    headers,
                    body,
                },
            );
            if !status.is_empty() {
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        }
    });
    (client(&endpoint, "bucket"), handle)
}

fn client(endpoint: &str, bucket: &str) -> Client {
    Client::new(
        endpoint,
        bucket,
        "auto",
        true,
        Credentials {
            access_key: "secret-access".into(),
            secret_key: "secret-secret".into(),
            session_token: Some("secret-token".into()),
        },
    )
    .unwrap()
}
fn append(path: &Path) {
    nostoi::append(
        path,
        nostoi::Draft {
            actor: None,
            kind: "test",
            subject: None,
            body: serde_json::json!({}),
            at: None,
        },
    )
    .unwrap();
}
fn options(lock: bool) -> AnchorOptions {
    AnchorOptions {
        key: String::new(),
        format: "nostoi-v1".into(),
        chain_id: "stable-chain".into(),
        only_if_absent: true,
        lock: lock.then_some(LockMode::Compliance),
        retain_days: 30,
    }
}
fn state(path: &Path) -> String {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT state FROM anchor_outcomes ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
fn assert_durable(path: &Path, request: &Request) {
    let db = Connection::open(path).unwrap();
    let serialized: String = db
        .query_row(
            "SELECT request FROM anchor_intents ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    for secret in [
        "secret-access",
        "secret-secret",
        "secret-token",
        "Authorization",
    ] {
        assert!(!serialized.contains(secret));
    }
    let intent: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(intent["v"], nostoi::anchor::PREPARED_ANCHOR_V1);
    let bytes: Vec<u8> = serde_json::from_value(intent["body"].clone()).unwrap();
    assert_eq!(bytes, request.body);
    assert!(request
        .headers
        .to_ascii_lowercase()
        .contains("if-none-match: *"));
}

#[test]
fn crash_after_upload_replays_exact_bytes_and_deadline_then_confirms() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("audit.jsonl");
    let db = dir.path().join("outbox.db");
    append(&source);
    let observed = db.clone();
    let mut stored = String::new();
    let mut retention = String::new();
    let (client, handle) = server(5, move |i, request| match i {
        0 => {
            assert_durable(&observed, &request);
            assert_eq!(state(&observed), "pending");
            let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let expiry = value["retain_until"].as_str().unwrap();
            assert!(request.headers.contains(expiry));
            retention = format!("<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>{expiry}</RetainUntilDate></Retention>");
            stored = String::from_utf8(request.body).unwrap();
            Connection::open(&observed).unwrap().execute_batch("CREATE TRIGGER fail_outcome BEFORE UPDATE ON anchor_outcomes BEGIN SELECT RAISE(ABORT,'simulated disk failure'); END;").unwrap();
            ("200 OK", String::new())
        }
        1 | 4 => {
            assert!(request.line.contains("?retention"));
            ("200 OK", retention.clone())
        }
        2 => {
            assert_eq!(request.body, stored.as_bytes());
            assert!(request.headers.contains(
                serde_json::from_str::<serde_json::Value>(&stored).unwrap()["retain_until"]
                    .as_str()
                    .unwrap()
            ));
            ("412 Precondition Failed", String::new())
        }
        3 => ("200 OK", stored.clone()),
        _ => unreachable!(),
    });
    let mut outbox = Outbox::open(&db, &source).unwrap();
    assert!(matches!(
        outbox.anchor_head(&source, &client, options(true), Provider::S3),
        Err(Error::AnchorUnconfirmed { .. })
    ));
    assert_eq!(state(&db), "pending");
    drop(outbox);
    Connection::open(&db)
        .unwrap()
        .execute_batch("DROP TRIGGER fail_outcome")
        .unwrap();
    Outbox::open(&db, &source)
        .unwrap()
        .reconcile(&client)
        .unwrap();
    handle.join().unwrap();
    assert_eq!(state(&db), "confirmed");
}

#[test]
fn lost_response_is_reconciled_and_repeated_head_is_idempotent_new_head_is_new_intent() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("audit.jsonl");
    let db = dir.path().join("outbox.db");
    append(&source);
    let observed = db.clone();
    let mut stored = String::new();
    let (client, handle) = server(6, move |i, request| match i {
        0 => {
            assert_durable(&observed, &request);
            stored = String::from_utf8(request.body).unwrap();
            ("", String::new())
        }
        1 | 3 => {
            assert_eq!(request.body, stored.as_bytes());
            ("412 Precondition Failed", String::new())
        }
        2 | 4 => ("200 OK", stored.clone()),
        5 => {
            assert_durable(&observed, &request);
            assert_ne!(request.body, stored.as_bytes());
            ("200 OK", String::new())
        }
        _ => unreachable!(),
    });
    let mut outbox = Outbox::open(&db, &source).unwrap();
    let first = outbox
        .anchor_head(&source, &client, options(false), Provider::S3)
        .unwrap();
    drop(outbox);
    let mut outbox = Outbox::open(&db, &source).unwrap();
    let repeated = outbox
        .anchor_head(&source, &client, options(false), Provider::S3)
        .unwrap();
    assert_eq!(first.anchored_at, repeated.anchored_at);
    append(&source);
    let new = outbox
        .anchor_head(&source, &client, options(false), Provider::S3)
        .unwrap();
    assert_ne!(first.key, new.key);
    handle.join().unwrap();
    let count: i64 = Connection::open(&db)
        .unwrap()
        .query_row("SELECT count(*) FROM anchor_intents", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn missing_or_failed_retention_stays_actionable_and_wrong_target_is_blocked() {
    for status in ["200 OK", "403 Forbidden"] {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("audit.jsonl");
        let db = dir.path().join("outbox.db");
        append(&source);
        let (client, handle) = server(2, move |i, _| {
            if i == 0 {
                ("200 OK", String::new())
            } else {
                (status, String::new())
            }
        });
        let mut outbox = Outbox::open(&db, &source).unwrap();
        assert!(matches!(
            outbox.anchor_head(&source, &client, options(true), Provider::S3),
            Err(Error::AnchorUnconfirmed { .. })
        ));
        handle.join().unwrap();
        assert_eq!(state(&db), "unresolved");
        let wrong = self::client("http://127.0.0.1:1", "other");
        assert!(matches!(outbox.reconcile(&wrong), Err(Error::Invalid(_))));
        assert_eq!(state(&db), "unresolved");
    }
}

#[test]
fn rejected_upload_and_retention_configuration_conflict_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("audit.jsonl");
    let db = dir.path().join("outbox.db");
    append(&source);
    let (client, handle) = server(1, |_, _| ("403 Forbidden", String::new()));
    let mut outbox = Outbox::open(&db, &source).unwrap();
    assert!(matches!(
        outbox.anchor_head(&source, &client, options(true), Provider::S3),
        Err(Error::S3(_))
    ));
    handle.join().unwrap();
    assert_eq!(state(&db), "rejected");
    let mut changed = options(true);
    changed.retain_days = 31;
    assert!(matches!(
        outbox.anchor_head(&source, &client, changed, Provider::S3),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn source_and_foreign_databases_cannot_be_outboxes() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("audit.db");
    append(&source);
    assert!(matches!(
        Outbox::open(&source, &source),
        Err(Error::Invalid(_))
    ));
    let alias = dir.path().join("alias.db");
    std::fs::hard_link(&source, &alias).unwrap();
    assert!(matches!(
        Outbox::open(&alias, &source),
        Err(Error::Invalid(_))
    ));
    let foreign = dir.path().join("foreign.db");
    Connection::open(&foreign)
        .unwrap()
        .execute_batch("CREATE TABLE audit_events(x)")
        .unwrap();
    assert!(matches!(
        Outbox::open(&foreign, &source),
        Err(Error::Invalid(_))
    ));
    let db = dir.path().join("outbox.db");
    Outbox::open(&db, &source).unwrap();
    let other = dir.path().join("other.jsonl");
    append(&other);
    assert!(matches!(Outbox::open(&db, &other), Err(Error::Invalid(_))));
}

#[test]
fn exhausted_upload_receipts_preserve_typed_uncertainty_and_durable_intent() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("audit.jsonl");
    let db = dir.path().join("outbox.db");
    append(&source);
    let observed = db.clone();
    let (client, handle) = server(4, move |i, request| {
        if i < 3 {
            assert_durable(&observed, &request);
            ("", String::new())
        } else {
            assert!(request.line.starts_with("GET "));
            ("404 Not Found", String::new())
        }
    });
    let mut outbox = Outbox::open(&db, &source).unwrap();
    assert!(matches!(
        outbox.anchor_head(&source, &client, options(false), Provider::S3),
        Err(Error::UploadUncertain { .. })
    ));
    handle.join().unwrap();
    assert_eq!(state(&db), "unresolved");
}

#[test]
fn existing_different_bytes_are_never_confirmed_or_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("audit.jsonl");
    let db = dir.path().join("outbox.db");
    append(&source);
    let mut stored = String::new();
    let (client, handle) = server(2, move |i, request| {
        if i == 0 {
            let mut anchor: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            anchor["anchored_at"] = serde_json::json!("2020-01-01T00:00:00Z");
            stored = serde_json::to_string_pretty(&anchor).unwrap();
            ("412 Precondition Failed", String::new())
        } else {
            assert!(request.line.starts_with("GET "));
            ("200 OK", stored.clone())
        }
    });
    let mut outbox = Outbox::open(&db, &source).unwrap();
    assert!(matches!(
        outbox.anchor_head(&source, &client, options(false), Provider::S3),
        Err(Error::AnchorUnconfirmed { .. })
    ));
    handle.join().unwrap();
    assert_eq!(state(&db), "unresolved");
}

#[cfg(feature = "cli")]
#[test]
fn cli_rejects_outbox_with_verify_before_reading_credentials() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nostoi-anchor"))
        .args([
            "audit.db",
            "--endpoint",
            "http://127.0.0.1:1",
            "--bucket",
            "bucket",
            "--verify",
            "--outbox",
            "outbox.db",
        ])
        .env_remove("AWS_ACCESS_KEY_ID")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("cannot be used with"), "{error}");
}

#[test]
fn ordinary_prepared_api_preserves_nonconditional_uploads_and_old_unlocked_timestamps() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("audit.jsonl");
    append(&source);
    let mut config = options(false);
    config.only_if_absent = false;
    let prepared = nostoi::anchor::prepare_anchor(&source, config, Provider::S3).unwrap();
    let mut value = serde_json::to_value(prepared).unwrap();
    value["anchor"]["anchored_at"] = serde_json::json!("2000-01-01T00:00:00Z");
    let anchor: nostoi::anchor::Anchor = serde_json::from_value(value["anchor"].clone()).unwrap();
    value["body"] = serde_json::to_value(serde_json::to_vec_pretty(&anchor).unwrap()).unwrap();
    let prepared = serde_json::from_value(value).unwrap();
    let (client, handle) = server(1, |_, request| {
        assert!(request.line.starts_with("PUT "));
        assert!(!request
            .headers
            .to_ascii_lowercase()
            .contains("if-none-match"));
        assert!(!request
            .headers
            .to_ascii_lowercase()
            .contains("x-amz-object-lock-mode"));
        assert!(String::from_utf8(request.body)
            .unwrap()
            .contains("2000-01-01T00:00:00Z"));
        ("200 OK", String::new())
    });
    nostoi::anchor::publish_prepared(&client, &prepared, false).unwrap();
    handle.join().unwrap();
}

#[test]
fn fresh_ordinary_request_cannot_confirm_existing_object_with_expired_actual_retention() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("audit.jsonl");
    append(&source);
    let mut existing = String::new();
    let (client, handle) = server(3, move |i, request| match i {
        0 => {
            let mut old: nostoi::anchor::Anchor = serde_json::from_slice(&request.body).unwrap();
            old.anchored_at = "2000-01-01T00:00:00Z".into();
            old.retain_until = Some("2000-01-31T00:00:00Z".into());
            existing = serde_json::to_string_pretty(&old).unwrap();
            ("412 Precondition Failed", String::new())
        }
        1 => ("200 OK", existing.clone()),
        2 => {
            assert!(request.line.contains("?retention"));
            ("200 OK", "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2000-01-31T00:00:00Z</RetainUntilDate></Retention>".into())
        }
        _ => unreachable!(),
    });
    assert!(matches!(
        nostoi::anchor::anchor_head(&source, &client, options(true), Provider::S3),
        Err(Error::AnchorUnconfirmed { .. })
    ));
    handle.join().unwrap();
}
