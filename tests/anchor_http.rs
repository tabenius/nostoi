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
            matches!(result, Err(Error::S3(ref message)) if message.contains("different chain or head")),
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
            matches!(result, Err(Error::S3(ref message)) if message.contains("retention was not returned")),
            "absent retention ({status}) was not rejected: {result:?}"
        );
    }
}

#[test]
fn incorrect_retention_mode_is_rejected() {
    let result = retention_case("200 OK", "GOVERNANCE", 86400);
    assert!(
        matches!(result, Err(Error::S3(ref message)) if message.contains("retention does not meet the request")),
        "incorrect retention mode was not rejected: {result:?}"
    );
}

#[test]
fn shorter_retention_is_rejected() {
    let result = retention_case("200 OK", "COMPLIANCE", -1);
    assert!(
        matches!(result, Err(Error::S3(ref message)) if message.contains("retention does not meet the request")),
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
