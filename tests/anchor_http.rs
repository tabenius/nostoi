#![cfg(feature = "s3")]

use nostoi::anchor::{anchor_head, Anchor, AnchorOptions, LockMode};
use nostoi::s3::{Client, Credentials, Provider};
use nostoi::{Draft, Error};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const OBJECT: &str = "/bucket/heads/test.json";
const TIMEOUT: Duration = Duration::from_secs(5);

struct Request {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn read_request(stream: &mut TcpStream) -> Request {
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(TIMEOUT)).unwrap();
    let deadline = Instant::now() + TIMEOUT;
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(Instant::now() < deadline, "HTTP header deadline exceeded");
        assert!(bytes.len() < 64 * 1024, "HTTP headers too large");
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    let text = String::from_utf8(bytes).unwrap();
    let mut lines = text.lines();
    let line = lines.next().unwrap().to_string();
    let headers: Vec<_> = lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_string(), value.trim().to_string())
        })
        .collect();
    let mut request = Request {
        line,
        headers,
        body: Vec::new(),
    };
    let length = request
        .header("content-length")
        .unwrap_or("0")
        .parse::<usize>()
        .unwrap();
    assert!(length < 1024 * 1024, "HTTP body too large");
    request.body.resize(length, 0);
    stream.read_exact(&mut request.body).unwrap();
    assert!(request
        .header("authorization")
        .unwrap()
        .starts_with("AWS4-HMAC-SHA256 "));
    request
}

fn server<F>(count: usize, mut respond: F) -> (Client, JoinHandle<Vec<Request>>)
where
    F: FnMut(usize, &Request) -> (&'static str, String) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for index in 0..count {
            let deadline = Instant::now() + TIMEOUT;
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "missing HTTP request {index}");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            let request = read_request(&mut stream);
            let (status, body) = respond(index, &request);
            // An empty status deliberately drops the connection after reading
            // the upload, simulating storage succeeding but its receipt being lost.
            if status.is_empty() {
                requests.push(request);
                continue;
            }
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            requests.push(request);
        }
        requests
    });
    let client = Client::new(
        &endpoint,
        "bucket",
        "us-east-1",
        true,
        Credentials {
            access_key: "test".into(),
            secret_key: "test-secret".into(),
            session_token: None,
        },
    )
    .unwrap();
    (client, handle)
}

fn call_anchor(client: &Client, lock: Option<LockMode>) -> nostoi::Result<Anchor> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    nostoi::append(
        &path,
        Draft {
            actor: Some("test"),
            kind: "anchor.http",
            subject: None,
            body: serde_json::json!({"event": 1}),
            at: Some("2026-01-01T00:00:00Z".into()),
        },
    )
    .unwrap();
    anchor_head(
        &path,
        client,
        AnchorOptions {
            key: "heads/test.json".into(),
            format: "nostoi-v1".into(),
            chain_id: "http-regression-chain".into(),
            only_if_absent: true,
            lock,
            retain_days: 30,
        },
        Provider::S3,
    )
}

fn assert_put(request: &Request, locked: bool) -> Anchor {
    assert_eq!(request.line, format!("PUT {OBJECT} HTTP/1.1"));
    assert_eq!(request.header("if-none-match"), Some("*"));
    assert_eq!(
        request.header("content-type"),
        Some("application/json; charset=utf-8")
    );
    let anchor: Anchor = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(anchor.chain, "http-regression-chain");
    assert_eq!(anchor.format, "nostoi-v1");
    assert_eq!(anchor.key, "heads/test.json");
    if locked {
        assert_eq!(request.header("x-amz-object-lock-mode"), Some("COMPLIANCE"));
        assert_eq!(
            request.header("x-amz-object-lock-retain-until-date"),
            anchor.retain_until.as_deref()
        );
        assert_eq!(
            request.header("x-amz-sdk-checksum-algorithm"),
            Some("SHA256")
        );
        assert!(request.header("x-amz-checksum-sha256").is_some());
    } else {
        assert!(request.header("x-amz-object-lock-mode").is_none());
    }
    anchor
}

#[test]
fn conditional_412_reconciles_identical_head_and_returns_existing_anchor() {
    let mut existing = String::new();
    let (client, server) = server(2, move |index, request| {
        if index == 0 {
            let mut anchor = assert_put(request, false);
            // A retry must accept the same head even if its upload time differs.
            anchor.anchored_at = "2026-01-02T00:00:00Z".into();
            existing = serde_json::to_string(&anchor).unwrap();
            ("412 Precondition Failed", String::new())
        } else {
            assert_eq!(request.line, format!("GET {OBJECT} HTTP/1.1"));
            ("200 OK", existing.clone())
        }
    });
    let result = call_anchor(&client, None);
    let requests = server.join().unwrap();
    let anchor = result.unwrap();
    let uploaded: Anchor = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(anchor.digest, uploaded.digest);
    assert_eq!(anchor.seq, uploaded.seq);
    assert_eq!(anchor.anchored_at, "2026-01-02T00:00:00Z");
}

#[test]
fn committed_upload_with_lost_receipt_is_reconciled_without_overwrite() {
    let mut existing = String::new();
    let (client, server) = server(3, move |index, request| match index {
        0 => {
            assert_put(request, false);
            existing = String::from_utf8(request.body.clone()).unwrap();
            ("", String::new())
        }
        1 => {
            assert_put(request, false);
            assert_eq!(request.body, existing.as_bytes());
            ("412 Precondition Failed", String::new())
        }
        _ => {
            assert_eq!(request.line, format!("GET {OBJECT} HTTP/1.1"));
            ("200 OK", existing.clone())
        }
    });
    let result = call_anchor(&client, None);
    let requests = server.join().unwrap();
    let anchor = result.unwrap();
    let uploaded: Anchor = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(anchor.digest, uploaded.digest);
    assert_eq!(anchor.anchored_at, uploaded.anchored_at);
}

#[test]
fn permission_denied_upload_is_not_retried() {
    let (client, server) = server(1, |_, request| {
        assert_put(request, false);
        (
            "403 Forbidden",
            "<Error><Code>AccessDenied</Code></Error>".into(),
        )
    });
    let result = call_anchor(&client, None);
    server.join().unwrap();
    assert!(matches!(result, Err(Error::S3(message)) if message.contains("403")));
}

#[test]
fn locked_upload_with_lost_receipt_reconciles_and_verifies_retention() {
    let mut stored = String::new();
    let mut retention = String::new();
    let (client, server) = server(4, move |index, request| match index {
        0 => {
            let anchor = assert_put(request, true);
            retention = format!("<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>", anchor.retain_until.unwrap());
            stored = String::from_utf8(request.body.clone()).unwrap();
            ("", String::new())
        }
        1 => {
            assert_eq!(request.body, stored.as_bytes());
            ("412 Precondition Failed", String::new())
        }
        2 => ("200 OK", stored.clone()),
        _ => {
            assert_eq!(request.line, format!("GET {OBJECT}?retention HTTP/1.1"));
            ("200 OK", retention.clone())
        }
    });
    let result = call_anchor(&client, Some(LockMode::Compliance));
    server.join().unwrap();
    assert_eq!(result.unwrap().mode.as_deref(), Some("COMPLIANCE"));
}

#[test]
fn exhausted_upload_receipts_are_reconciled_by_reading_the_locked_object() {
    let mut stored = String::new();
    let mut retention = String::new();
    let (client, server) = server(5, move |index, request| match index {
        0..=2 => {
            let anchor = assert_put(request, true);
            if index == 0 {
                stored = String::from_utf8(request.body.clone()).unwrap();
                retention = format!("<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>", anchor.retain_until.unwrap());
            } else {
                assert_eq!(request.body, stored.as_bytes());
            }
            ("", String::new())
        }
        3 => ("200 OK", stored.clone()),
        _ => ("200 OK", retention.clone()),
    });
    let result = call_anchor(&client, Some(LockMode::Compliance));
    server.join().unwrap();
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn exhausted_uploads_with_no_readable_object_report_unknown_outcome() {
    let (client, server) = server(4, |index, request| {
        if index < 3 {
            assert_put(request, true);
            ("", String::new())
        } else {
            ("404 Not Found", String::new())
        }
    });
    let result = call_anchor(&client, Some(LockMode::Compliance));
    server.join().unwrap();
    assert!(
        matches!(result, Err(Error::UploadUncertain { ref key, .. }) if key == "heads/test.json")
    );
}

#[test]
fn exhausted_retention_requests_report_stored_but_unconfirmed() {
    let (client, server) = server(4, |index, request| {
        if index == 0 {
            assert_put(request, true);
            ("200 OK", String::new())
        } else {
            ("503 Service Unavailable", String::new())
        }
    });
    let result = call_anchor(&client, Some(LockMode::Compliance));
    server.join().unwrap();
    assert!(
        matches!(result, Err(Error::AnchorUnconfirmed { ref key, .. }) if key == "heads/test.json")
    );
}

#[test]
fn conditional_412_rejects_mismatched_existing_anchor() {
    for field in ["v", "chain", "format", "seq", "digest", "key"] {
        let mut existing = String::new();
        let (client, server) = server(2, move |index, request| {
            if index == 0 {
                let anchor = assert_put(request, false);
                let mut value = serde_json::to_value(anchor).unwrap();
                value[field] = if field == "seq" {
                    serde_json::json!(value[field].as_u64().unwrap() + 1)
                } else {
                    serde_json::json!("different")
                };
                existing = serde_json::to_string(&value).unwrap();
                ("412 Precondition Failed", String::new())
            } else {
                assert_eq!(request.line, format!("GET {OBJECT} HTTP/1.1"));
                ("200 OK", existing.clone())
            }
        });
        let result = call_anchor(&client, None);
        server.join().unwrap();
        assert!(
            matches!(result, Err(Error::AnchorUnconfirmed { ref detail, .. }) if detail.contains("different chain or head")),
            "mismatch in {field} was not rejected: {result:?}"
        );
    }
}

fn retention_case(
    status: &'static str,
    mode: &'static str,
    seconds: i64,
) -> nostoi::Result<Anchor> {
    let mut retain_until = String::new();
    let (client, server) = server(2, move |index, request| {
        if index == 0 {
            let anchor = assert_put(request, true);
            let requested =
                OffsetDateTime::parse(anchor.retain_until.as_ref().unwrap(), &Rfc3339).unwrap();
            retain_until = (requested + time::Duration::seconds(seconds))
                .format(&Rfc3339)
                .unwrap();
            ("200 OK", String::new())
        } else {
            assert_eq!(request.line, format!("GET {OBJECT}?retention HTTP/1.1"));
            let body = if mode.is_empty() {
                "<Retention/>".into()
            } else {
                format!(
                    "<Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Mode>{mode}</Mode><RetainUntilDate>{retain_until}</RetainUntilDate></Retention>"
                )
            };
            (status, body)
        }
    });
    let result = call_anchor(&client, Some(LockMode::Compliance));
    let requests = server.join().unwrap();
    if let Ok(anchor) = &result {
        let uploaded: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(serde_json::to_value(anchor).unwrap(), uploaded);
    }
    result
}

#[test]
fn absent_retention_is_rejected() {
    for status in ["404 Not Found", "200 OK"] {
        let result = retention_case(status, "", 0);
        assert!(
            matches!(result, Err(Error::AnchorUnconfirmed { ref detail, .. }) if detail.contains("retention was not returned")),
            "absent retention ({status}) was not rejected: {result:?}"
        );
    }
}

#[test]
fn incorrect_retention_mode_is_rejected() {
    let result = retention_case("200 OK", "GOVERNANCE", 86400);
    assert!(
        matches!(result, Err(Error::AnchorUnconfirmed { ref detail, .. }) if detail.contains("retention does not meet the request")),
        "incorrect retention mode was not rejected: {result:?}"
    );
}

#[test]
fn shorter_retention_is_rejected() {
    let result = retention_case("200 OK", "COMPLIANCE", -1);
    assert!(
        matches!(result, Err(Error::AnchorUnconfirmed { ref detail, .. }) if detail.contains("retention does not meet the request")),
        "shorter retention was not rejected: {result:?}"
    );
}

#[test]
fn verified_retention_at_or_beyond_requested_deadline_succeeds() {
    for seconds in [0, 86400] {
        let anchor = retention_case("200 OK", "COMPLIANCE", seconds).unwrap();
        assert_eq!(anchor.mode.as_deref(), Some("COMPLIANCE"));
        let anchored_at = OffsetDateTime::parse(&anchor.anchored_at, &Rfc3339).unwrap();
        let retain_until =
            OffsetDateTime::parse(anchor.retain_until.as_ref().unwrap(), &Rfc3339).unwrap();
        assert_eq!(retain_until - anchored_at, time::Duration::days(30));
    }
}

#[test]
fn remote_checkpoint_detects_truncation_rewrite_and_identity_mismatch() {
    for case in [
        "extended",
        "truncated",
        "empty",
        "rewritten",
        "identity",
        "format",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let append = |value| {
            nostoi::append(
                &path,
                Draft {
                    actor: None,
                    kind: "test",
                    subject: None,
                    body: serde_json::json!({"value":value}),
                    at: Some("2026-01-01T00:00:00Z".into()),
                },
            )
            .unwrap()
        };
        append(1);
        let prefix = std::fs::read(&path).unwrap();
        let head = append(2);
        let mut checkpoint = Anchor {
            v: "nostoi-anchor-v1".into(),
            chain: "trusted-chain".into(),
            format: "nostoi-v1".into(),
            seq: head.seq,
            digest: head.digest,
            anchored_at: "2026-01-01T00:00:00Z".into(),
            provider: "s3".into(),
            key: "heads/test.json".into(),
            mode: None,
            retain_until: None,
        };
        match case {
            "extended" => {
                append(3);
            }
            "truncated" => std::fs::write(&path, prefix).unwrap(),
            "empty" => std::fs::write(&path, []).unwrap(),
            "rewritten" => {
                std::fs::remove_file(&path).unwrap();
                append(10);
                append(20);
                assert!(nostoi::verify(&path, None).unwrap().ok);
            }
            "identity" => checkpoint.chain = "other-chain".into(),
            "format" => checkpoint.format = "other-format".into(),
            _ => unreachable!(),
        }
        let remote = serde_json::to_string(&checkpoint).unwrap();
        let (client, server) = server(1, move |_, request| {
            assert_eq!(request.line, format!("GET {OBJECT} HTTP/1.1"));
            ("200 OK", remote.clone())
        });
        let result =
            nostoi::anchor::verify_anchor(&path, &client, "heads/test.json", "trusted-chain");
        server.join().unwrap();
        if case == "extended" {
            let result = result.unwrap();
            assert_eq!(result.anchor.seq, 2);
            assert_eq!(result.local_head.seq, 3);
            assert_eq!(result.verified_records, 3);
        } else {
            assert!(
                matches!(result, Err(Error::AnchorMismatch(_))),
                "{case}: {result:?}"
            );
        }
    }
}

#[test]
#[cfg(feature = "cli")]
fn verify_cli_fetches_checkpoint_without_uploading() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.sqlite");
    let head = nostoi::append(
        &path,
        Draft {
            actor: None,
            kind: "test",
            subject: None,
            body: serde_json::json!({}),
            at: None,
        },
    )
    .unwrap();
    let remote =
        serde_json::json!({"v":"nostoi-anchor-v1", "chain":"cli-chain", "format":"nostoi-v1",
        "seq":head.seq, "digest":head.digest, "anchored_at":"2026-01-01T00:00:00Z", "provider":"s3",
        "key":"heads/test.json", "mode":null, "retain_until":null})
        .to_string();
    // A separately bound server exposes its endpoint through the signed client
    // request target; use a dedicated listener for the command-line boundary.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + TIMEOUT;
        let mut stream = loop {
            if let Ok((stream, _)) = listener.accept() {
                break stream;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        };
        let request = read_request(&mut stream);
        assert_eq!(request.line, format!("GET {OBJECT} HTTP/1.1"));
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{remote}",
            remote.len()
        )
        .unwrap();
    });
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nostoi-anchor"))
        .args([
            "--verify",
            "--endpoint",
            &endpoint,
            "--bucket",
            "bucket",
            "--path-style",
            "--key",
            "heads/test.json",
            "--chain-id",
            "cli-chain",
        ])
        .arg(&path)
        .env("AWS_ACCESS_KEY_ID", "test")
        .env("AWS_SECRET_ACCESS_KEY", "test-secret")
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["verified_records"], 1);
}
