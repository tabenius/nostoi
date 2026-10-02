#![cfg(feature = "s3")]

use nostoi::s3::{Client, Credentials, PutOptions};
use nostoi::Error;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Nonblocking accepts and bounded request reads ensure a missing retry fails,
// rather than leaving a fixture thread blocked indefinitely.
fn fixture(
    responses: Vec<(u16, String, String)>,
) -> (Client, Arc<AtomicUsize>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for (status, headers, body) in responses {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "request acceptance deadline");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 16 * 1024);
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request
                .to_ascii_lowercase()
                .contains("x-amz-date: 20260101t0000"));
            write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}", body.len()).unwrap();
        }
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let clock_calls = Arc::clone(&calls);
    let client = Client::new(
        &endpoint,
        "bucket",
        "auto",
        true,
        Credentials {
            access_key: "AKIA_REFLECTED_ACCESS".into(),
            secret_key: "REFLECTED_SECRET".into(),
            session_token: Some("REFLECTED_TOKEN".into()),
        },
    )
    .unwrap()
    .with_signing_clock(move || {
        clock_calls.fetch_add(1, Ordering::SeqCst);
        time::macros::datetime!(2026-01-01 00:00:00 UTC)
    });
    (client, calls, server)
}

fn response(status: u16, headers: &str, body: &str) -> (u16, String, String) {
    (status, headers.into(), body.into())
}

fn get_error(headers: &str, body: &str) -> String {
    let (client, calls, server) = fixture(vec![response(403, headers, body)]);
    let error = client.get_object("key").unwrap_err();
    assert!(matches!(error, Error::S3(_)));
    server.join().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    error.to_string()
}

#[test]
fn compares_actual_signed_time_in_both_directions() {
    for (server_time, expected) in [
        ("2025-12-31T23:55:00Z", "300 seconds ahead"),
        ("2026-01-01T00:05:00Z", "300 seconds behind"),
    ] {
        let xml = format!("<?xml version=\"1.0\"?><s3:Error xmlns:s3=\"urn:s3\"><s3:Code>RequestTimeTooSkewed</s3:Code><s3:RequestTime>2026-01-01T00:00:00Z</s3:RequestTime><s3:ServerTime>{server_time}</s3:ServerTime><s3:RequestId>request-123</s3:RequestId></s3:Error>");
        let error = get_error("", &xml);
        assert!(error.contains(expected), "{error}");
        assert!(error.contains("request-id=request-123"));
        assert!(error.contains("approximate, server-reported"));
        assert!(error.contains("synchronize the host clock"));
    }
    let error = get_error(
        "Date: Thu, 01 Jan 2026 00:01:00 GMT\r\n",
        "<Error><Code>RequestExpired</Code></Error>",
    );
    assert!(error.contains("60 seconds behind"), "{error}");
}

#[test]
fn skew_uses_final_retry_timestamp_without_an_extra_clock_read() {
    let (client, calls, server) = fixture(vec![
        response(503, "", ""),
        response(503, "", ""),
        response(
            403,
            "Date: Thu, 01 Jan 2026 00:00:00 GMT\r\n",
            "<Error><Code>RequestExpired</Code></Error>",
        ),
    ]);
    let clock_calls = Arc::clone(&calls);
    let client = client.with_signing_clock(move || {
        time::macros::datetime!(2026-01-01 00:00:00 UTC)
            + time::Duration::seconds(clock_calls.fetch_add(1, Ordering::SeqCst) as i64)
    });
    let error = client.get_object("key").unwrap_err().to_string();
    assert!(error.contains("2 seconds ahead"), "{error}");
    server.join().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn absent_invalid_or_mismatched_times_do_not_invent_skew() {
    for (headers, body) in [
        ("", "<Error><Code>RequestTimeTooSkewed</Code></Error>"),
        ("Date: invalid\r\n", "<Error><Code>RequestExpired</Code><ServerTime>invalid</ServerTime></Error>"),
        ("Date: Thu, 01 Jan 2026 00:01:00 GMT\r\n", "<Error><Code>RequestExpired</Code><RequestTime>2026-01-02T00:00:00Z</RequestTime></Error>"),
    ] {
        let error = get_error(headers, body);
        assert!(!error.contains("estimated clock skew"), "{error}");
        assert!(error.contains("synchronize the host clock"));
    }
}

#[test]
fn reports_codes_and_actionable_hints_without_reflective_messages() {
    for (code, hint) in [
        ("AccessDenied", "required permissions"),
        ("SignatureDoesNotMatch", "signed headers"),
        ("ExpiredToken", "refresh the session"),
        ("AuthorizationHeaderMalformed", "region and endpoint"),
    ] {
        let xml = format!("<Error><Code>{code}</Code><Message>Authorization AWS4-HMAC-SHA256 Credential=AKIA_REFLECTED_ACCESS REFLECTED_SECRET REFLECTED_TOKEN</Message><CanonicalRequest>x-amz-security-token:REFLECTED_TOKEN</CanonicalRequest><RequestId>REFLECTED_SECRET</RequestId><HostId>prefixREFLECTED_TOKENsuffix</HostId></Error>");
        let error = get_error(
            "x-amz-request-id: AKIA_REFLECTED_ACCESS\r\nx-amz-id-2: Credential=echo\r\n",
            &xml,
        );
        assert!(error.contains(&format!("code={code}")), "{error}");
        assert!(error.contains(hint));
        for secret in [
            "AKIA_REFLECTED_ACCESS",
            "REFLECTED_SECRET",
            "REFLECTED_TOKEN",
            "Credential=",
            "CanonicalRequest",
        ] {
            assert!(!error.contains(secret), "{error}");
        }
    }
    let (client, _, server) = fixture(vec![response(404, "", "<Error><Code>NoSuchKey</Code><Message>REFLECTED_SECRET</Message><RequestId>missing-1</RequestId></Error>")]);
    let error = client.get_object("key").unwrap_err().to_string();
    server.join().unwrap();
    assert!(error.contains("GetObject returned 404; code=NoSuchKey; request-id=missing-1"));
    assert!(!error.contains("REFLECTED_SECRET"));
}

#[test]
fn rejects_oversized_malformed_and_injected_metadata() {
    for xml in [
        format!("<Error><Code>{}</Code></Error>", "x".repeat(20_000)),
        "<Error><Code>AccessDenied</Code><Code>ExpiredToken</Code></Error>".into(),
        "<!DOCTYPE Error [<!ENTITY secret 'REFLECTED_SECRET'>]><Error><Code>&secret;</Code></Error>".into(),
        "<Error><Code><Nested>REFLECTED_SECRET</Nested></Code></Error>".into(),
        "<Error><Code>REFLECTED_TOKEN</Code><RequestId>bad&#10;value</RequestId></Error>".into(),
        "<Error><Code>AccessDenied</Code>".into(),
    ] {
        let error = get_error(&format!("x-amz-request-id: {}\r\n", "a".repeat(200)), &xml);
        assert!(error.len() < 400, "{error}");
        assert!(!error.contains("REFLECTED"));
        assert!(!error.contains("request-id="));
    }
}

#[test]
fn definite_forbidden_and_exhausted_ambiguous_put_remain_distinct() {
    let options = PutOptions {
        content_type: "application/json".into(),
        lock: None,
        only_if_absent: true,
    };
    for statuses in [vec![403], vec![503, 403], vec![503, 503, 503]] {
        let expected_calls = statuses.len();
        let ambiguous = statuses[0] == 503;
        let responses = statuses
            .into_iter()
            .map(|status| {
                response(
                    status,
                    "x-amz-request-id: last-attempt\r\n",
                    "<Error><Code>AccessDenied</Code><Message>REFLECTED_SECRET</Message></Error>",
                )
            })
            .collect();
        let (client, calls, server) = fixture(responses);
        let error = match client.put_object("key", &[], &options) {
            Err(error) => error,
            Ok(_) => panic!("unexpected success"),
        };
        assert_eq!(matches!(error, Error::UploadUncertain { .. }), ambiguous);
        let detail = error.to_string();
        assert!(detail.contains("request-id=last-attempt"), "{detail}");
        assert!(!detail.contains("REFLECTED_SECRET"));
        assert_eq!(detail.contains("after an ambiguous attempt"), ambiguous);
        server.join().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
    }
}

#[test]
fn exhausted_transient_get_and_retention_report_final_request_id() {
    let (client, calls, server) = fixture(vec![
        response(503, "x-amz-request-id: first\r\n", ""),
        response(503, "x-amz-request-id: second\r\n", ""),
        response(
            503,
            "",
            "<Error><Code>SlowDown</Code><RequestId>final</RequestId></Error>",
        ),
        response(
            403,
            "x-amz-request-id: retention\r\n",
            "<Error><Code>AccessDenied</Code></Error>",
        ),
        response(404, "", "<Error><Code>NoSuchKey</Code></Error>"),
    ]);
    let error = client.get_object("key").unwrap_err().to_string();
    assert!(error.contains("code=SlowDown; request-id=final"), "{error}");
    let error = client.get_object_retention("key").unwrap_err().to_string();
    assert!(
        error.contains("GetObjectRetention returned 403; code=AccessDenied; request-id=retention")
    );
    assert_eq!(client.get_object_retention("key").unwrap(), None);
    server.join().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 5);
}
