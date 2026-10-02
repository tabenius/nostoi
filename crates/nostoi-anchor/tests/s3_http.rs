use nostoi_anchor::s3::{Client, Credentials, LockMode, ObjectLock, PutOptions};
use std::io::{Read, Write};
use std::net::TcpListener;

#[test]
fn put_and_retention_use_real_http_and_reject_conflicts() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for index in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let header_end = loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                bytes.push(byte[0]);
                if bytes.ends_with(b"\r\n\r\n") {
                    break bytes.len();
                }
            };
            let headers = String::from_utf8(bytes[..header_end].to_vec())
                .unwrap()
                .to_ascii_lowercase();
            assert!(headers.contains("authorization: aws4-hmac-sha256"));
            if index != 1 {
                assert!(headers.starts_with("put /bucket/heads/test.json "));
                assert!(headers.contains("if-none-match: *"));
                assert!(headers.contains("x-amz-object-lock-mode: compliance"));
                assert!(headers.contains("x-amz-sdk-checksum-algorithm: sha256"));
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                assert_eq!(body, b"{}");
            } else {
                assert!(headers.starts_with("get /bucket/heads/test.json?retention "));
            }
            let (status, body) = match index {
                0 => ("200 OK", ""),
                1 => ("200 OK", "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2027-01-01T00:00:00Z</RetainUntilDate></Retention>"),
                _ => ("412 Precondition Failed", ""),
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
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
    let options = PutOptions {
        content_type: "application/json".into(),
        only_if_absent: true,
        lock: Some(ObjectLock {
            mode: LockMode::Compliance,
            retain_until: time::OffsetDateTime::parse(
                "2027-01-01T00:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap(),
        }),
    };
    client
        .put_object("heads/test.json", b"{}", &options)
        .unwrap();
    assert_eq!(
        client
            .get_object_retention("heads/test.json")
            .unwrap()
            .unwrap()
            .mode,
        "COMPLIANCE"
    );
    assert!(
        client
            .put_object("heads/test.json", b"{}", &options)
            .unwrap()
            .existed
    );
    server.join().unwrap();
}
