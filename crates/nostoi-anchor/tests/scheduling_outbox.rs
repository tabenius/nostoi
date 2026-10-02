#![cfg(all(feature = "sqlite", feature = "cli", target_os = "linux"))]

//! Offline integration of the scheduling helper with the real Rust binary.
//! The test-only executable adapter maps local HTTPS to HTTP and adds path-style
//! addressing so no custom CA or production TLS bypass is required.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{Duration, Instant};

/// The deployment helpers under test live in the repository, not in this crate,
/// so walk up from the manifest directory until they turn up.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|dir| dir.join("contrib/systemd/nostoi-anchor-runner").is_file())
        .expect("repository root containing contrib/systemd")
        .to_path_buf()
}

#[test]
fn the_runners_fan_out_argv_is_accepted_by_the_real_binary() {
    // The runner's own tests record argv against a fake executable, so they cannot
    // see whether the real parser accepts it. They did not: --endpoint and --bucket
    // were `required`, so every fan-out run through the runner died on argument
    // parsing, before a single destination was contacted. This runs the real
    // binary with exactly the arguments the runner builds.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("audit.jsonl");
    nostoi_core::append(
        &source,
        nostoi_core::Draft {
            actor: None,
            kind: "test",
            subject: None,
            body: serde_json::json!({"event": 1}),
            at: None,
        },
    )
    .unwrap();

    let targets = dir.path().join("anchors.json");
    std::fs::write(
        &targets,
        serde_json::to_string_pretty(&serde_json::json!({
            "targets": [
                {
                    "name": "one",
                    "endpoint": "https://s3.us-west-2.amazonaws.com",
                    "bucket": "b",
                    "region": "us-west-2",
                    "lock": "compliance",
                    "retain_days": 365,
                    "credentials": "one",
                },
                {
                    "name": "two",
                    "endpoint": "https://s3.us-west-004.backblazeb2.com",
                    "bucket": "b",
                    "region": "us-west-004",
                    "path_style": true,
                    "lock": "compliance",
                    "retain_days": 365,
                    "credentials": "two",
                },
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let credentials = dir.path().join("credentials");
    for name in ["one", "two"] {
        let sub = credentials.join(name);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            sub.join("aws-access-key-id"),
            format!(
                "{name}-key
"
            ),
        )
        .unwrap();
        std::fs::write(
            sub.join("aws-secret-access-key"),
            format!(
                "{name}-secret
"
            ),
        )
        .unwrap();
    }
    let outbox_dir = dir.path().join("outbox");
    std::fs::create_dir_all(&outbox_dir).unwrap();

    // Exactly what nostoi-anchor-runner execs in fan-out mode.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nostoi-anchor"))
        .arg(&source)
        .arg("--targets")
        .arg(&targets)
        .arg("--chain-id")
        .arg("scheduled-chain")
        .arg("--credentials-dir")
        .arg(&credentials)
        .arg("--outbox-dir")
        .arg(&outbox_dir)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("required"),
        "the runner's argv must parse: {stderr}"
    );
    // Exit 2 is the uncertain-upload code and 3 the unconfirmed one; anything else
    // is argument parsing or a usage error, which is what this is about.
    assert!(
        matches!(output.status.code(), Some(2) | Some(3)),
        "expected a per-destination failure, not a usage error: status {:?}\n{stderr}",
        output.status.code()
    );

    // And the two modes cannot be mixed: a half-migrated unit must fail loudly
    // rather than quietly publish to one destination while reporting several.
    let mixed = std::process::Command::new(env!("CARGO_BIN_EXE_nostoi-anchor"))
        .arg(&source)
        .arg("--targets")
        .arg(&targets)
        .arg("--endpoint")
        .arg("https://s3.us-west-2.amazonaws.com")
        .arg("--bucket")
        .arg("b")
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&mixed.stderr).contains("one destination"),
        "{:?}",
        String::from_utf8_lossy(&mixed.stderr)
    );
    assert_ne!(mixed.status.code(), Some(0));

    // A single destination still names what it is missing.
    let single = std::process::Command::new(env!("CARGO_BIN_EXE_nostoi-anchor"))
        .arg(&source)
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&single.stderr);
    assert!(said.contains("--endpoint is required"), "{said}");
}

#[test]
fn a_missing_outbox_directory_is_named_rather_than_left_to_the_database_driver() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("audit.jsonl");
    nostoi_core::append(
        &source,
        nostoi_core::Draft {
            actor: None,
            kind: "test",
            subject: None,
            body: serde_json::json!({"event": 1}),
            at: None,
        },
    )
    .unwrap();
    let targets = dir.path().join("anchors.json");
    std::fs::write(
        &targets,
        serde_json::json!({
            "targets": [{
                "name": "one",
                "endpoint": "https://s3.us-west-2.amazonaws.com",
                "bucket": "b",
                "region": "us-west-2",
                "credentials": "one",
            }]
        })
        .to_string(),
    )
    .unwrap();
    let credentials = dir.path().join("credentials");
    std::fs::create_dir_all(credentials.join("one")).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nostoi-anchor"))
        .arg(&source)
        .arg("--targets")
        .arg(&targets)
        .arg("--credentials-dir")
        .arg(&credentials)
        .arg("--outbox-dir")
        .arg(dir.path().join("absent"))
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("does not exist"), "{said}");
    // Not the driver's phrasing, which does not say what to do about it.
    assert!(!said.contains("unable to open database file"), "{said}");
}

#[test]
fn scheduled_publish_uses_durable_outbox_and_verifier_uses_separate_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("audit.jsonl");
    let outbox = dir.path().join("outbox.sqlite");
    nostoi_core::append(
        &source,
        nostoi_core::Draft {
            actor: None,
            kind: "test",
            subject: None,
            body: serde_json::json!({"event":1}),
            at: None,
        },
    )
    .unwrap();
    let original = std::fs::read(&source).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o400)).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let observed = outbox.clone();
    let server =
        std::thread::spawn(move || {
            let mut stored = Vec::new();
            let mut key_path = String::new();
            for index in 0..4 {
                let deadline = Instant::now() + Duration::from_secs(8);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "missing scheduled request {index}"
                            );
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("{error}"),
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
                let header = String::from_utf8(header).unwrap();
                let expected_access = if index == 3 {
                    "verifier-access"
                } else {
                    "publisher-access"
                };
                assert!(header.contains(&format!("Credential={expected_access}/")));
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(length < 65536);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                let request = header.lines().next().unwrap();
                if index == 0 {
                    assert!(request.starts_with("PUT /bucket/heads/"));
                    key_path = request.split_whitespace().nth(1).unwrap().into();
                    stored = body.clone();
                    let db = rusqlite::Connection::open(&observed).unwrap();
                    let (intent, state): (String, String) = db.query_row(
                    "SELECT request,state FROM anchor_intents JOIN anchor_outcomes USING(key)", [],
                    |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
                    let intent: serde_json::Value = serde_json::from_str(&intent).unwrap();
                    let exact: Vec<u8> = serde_json::from_value(intent["body"].clone()).unwrap();
                    assert_eq!(exact, body);
                    assert_eq!(state, "pending");
                } else if index == 1 {
                    assert_eq!(request, format!("PUT {key_path} HTTP/1.1"));
                    assert_eq!(body, stored);
                    assert!(header.to_ascii_lowercase().contains("if-none-match: *"));
                } else {
                    assert_eq!(request, format!("GET {key_path} HTTP/1.1"));
                }
                let (status, response) = match index {
                    0 => ("200 OK", &[][..]),
                    1 => ("412 Precondition Failed", &[][..]),
                    _ => ("200 OK", stored.as_slice()),
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                stream.write_all(response).unwrap();
            }
        });

    let binary = env!("CARGO_BIN_EXE_nostoi-anchor");
    let adapter = dir.path().join("local-transport-adapter");
    let literal = serde_json::to_string(binary).unwrap();
    std::fs::write(&adapter, format!("#!/usr/bin/env python3\nimport os,sys\nargs=sys.argv[1:]\ni=args.index('--endpoint')+1\nargs[i]=args[i].replace('https://','http://',1)\nos.execv({literal}, [{literal}]+args+['--path-style'])\n")).unwrap();
    std::fs::set_permissions(&adapter, std::fs::Permissions::from_mode(0o700)).unwrap();
    let credentials = |name: &str| {
        let path = dir.path().join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("aws-access-key-id"), format!("{name}-access")).unwrap();
        std::fs::write(path.join("aws-secret-access-key"), format!("{name}-secret")).unwrap();
        std::fs::write(path.join("aws-session-token"), "").unwrap();
        path
    };
    let publisher = credentials("publisher");
    let verifier = credentials("verifier");
    let runner = repo_root().join("contrib/systemd/nostoi-anchor-runner");
    let command = |mode: &str, credentials: &std::path::Path| {
        let mut command = Command::new("sh");
        command
            .arg(&runner)
            .arg(mode)
            .env("CHAIN", &source)
            .env("ENDPOINT", &endpoint)
            .env("BUCKET", "bucket")
            .env("REGION", "auto")
            .env("CHAIN_ID", "scheduled-chain")
            .env("NOSTOI_ANCHOR_BIN", &adapter)
            .env("CREDENTIALS_DIRECTORY", credentials)
            .env("NO_PROXY", "*")
            .env_remove("OUTBOX")
            .env_remove("TRUSTED_KEY")
            .env_remove("LOCK")
            .env_remove("RETAIN_DAYS");
        command
    };
    let published = command("publish", &publisher)
        .env("OUTBOX", &outbox)
        .output()
        .unwrap();
    assert!(
        published.status.success(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&published.stdout).unwrap();
    let repeated = command("publish", &publisher)
        .env("OUTBOX", &outbox)
        .output()
        .unwrap();
    assert!(
        repeated.status.success(),
        "{}",
        String::from_utf8_lossy(&repeated.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&repeated.stdout).unwrap(),
        receipt
    );
    // Simulates the operator supplying an independently checked trusted key.
    let verified = command("verify", &verifier)
        .env("TRUSTED_KEY", receipt["key"].as_str().unwrap())
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verified.stdout).unwrap()["verified_records"],
        1
    );
    server.join().unwrap();
    assert_eq!(std::fs::read(&source).unwrap(), original);
    let db = rusqlite::Connection::open(&outbox).unwrap();
    let (count, state): (i64, String) = db
        .query_row(
            "SELECT count(*), min(state) FROM anchor_outcomes",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((count, state.as_str()), (1, "confirmed"));
}
