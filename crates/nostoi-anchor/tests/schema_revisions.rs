#![cfg(feature = "sqlite")]

use nostoi_anchor::Error;
use nostoi_core::{schema, sqlite::Store, Draft};
use rusqlite::params;
use rusqlite::Connection;
use serde_json::json;
use std::path::Path;

fn audit(path: &Path) {
    Store::open(path)
        .unwrap()
        .append(Draft {
            actor: None,
            kind: "test",
            subject: None,
            body: json!({"value":1}),
            at: Some("2026-01-01T00:00:00Z".into()),
        })
        .unwrap();
}

fn legacy(path: &Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch("DROP TABLE nostoi_schema_meta; PRAGMA application_id=0; PRAGMA user_version=0; PRAGMA journal_mode=DELETE;").unwrap();
}

fn records(path: &Path) -> Vec<(i64, String, String, String)> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare("SELECT seq,previous,digest,record FROM nostoi_records ORDER BY seq")
        .unwrap();
    stmt.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })
    .unwrap()
    .collect::<std::result::Result<_, _>>()
    .unwrap()
}

#[test]
fn legacy_read_is_unmodified_and_writer_adoption_preserves_record_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.sqlite");
    audit(&path);
    legacy(&path);
    let original = records(&path);
    let file = std::fs::read(&path).unwrap();
    let info = schema::inspect(&path).unwrap();
    assert!(info.legacy_unversioned);
    assert_eq!(info.schema_revision, 0);
    assert!(nostoi_core::verify(&path, None).unwrap().ok);
    assert_eq!(std::fs::read(&path).unwrap(), file);
    drop(Store::open_verified(&path).unwrap());
    let info = schema::inspect(&path).unwrap();
    assert_eq!(info.application_id, schema::AUDIT_APPLICATION_ID);
    assert_eq!(info.schema_revision, schema::AUDIT_SCHEMA_REVISION);
    assert!(info.adopted_legacy);
    assert!(!info.legacy_unversioned);
    assert!(info.created_by_version.is_none());
    assert_eq!(
        info.last_migrated_by_version.as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(records(&path), original);
    drop(Store::open(&path).unwrap());
    assert_eq!(records(&path), original);
}

#[test]
fn new_database_is_labelled_and_readable_through_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.sqlite");
    audit(&path);
    let info = schema::inspect(&path).unwrap();
    assert_eq!(info.schema_revision, 1);
    assert_eq!(info.record_format, "nostoi-v1");
    assert!(!info.adopted_legacy);
    assert_eq!(
        info.created_by_version.as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn future_wrong_identity_and_inconsistent_metadata_fail_without_persistent_changes() {
    for mutation in [
        "PRAGMA user_version=2",
        "PRAGMA application_id=1094861636",
        "UPDATE nostoi_schema_meta SET schema_revision=99",
        "UPDATE nostoi_schema_meta SET component='other-component'",
        "UPDATE nostoi_schema_meta SET record_format='nostoi-v99'",
        "DROP TABLE nostoi_schema_meta",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future.sqlite");
        audit(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=DELETE").unwrap();
        conn.execute_batch(mutation).unwrap();
        drop(conn);
        let original = std::fs::read(&path).unwrap();
        assert!(Store::open(&path).is_err(), "{mutation}");
        assert!(nostoi_core::verify(&path, None).is_err(), "{mutation}");
        assert!(schema::inspect(&path).is_err(), "{mutation}");
        assert_eq!(std::fs::read(&path).unwrap(), original, "{mutation}");
    }
}

#[test]
fn unfamiliar_legacy_definitions_and_foreign_databases_are_not_stamped() {
    for sql in [
        "CREATE TABLE unrelated(data TEXT)",
        "CREATE VIEW unrelated AS SELECT 1 AS data",
        "CREATE TABLE nostoi_records(seq INTEGER PRIMARY KEY,previous TEXT,digest TEXT,record TEXT)",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foreign.sqlite");
        let conn = Connection::open(&path).unwrap(); conn.execute_batch(sql).unwrap(); drop(conn);
        let original = std::fs::read(&path).unwrap();
        assert!(Store::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[test]
fn external_ephor_metadata_is_never_relabelled() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ephor.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE governance_events (chain_sequence INTEGER,id TEXT,node_id TEXT,aggregate_id TEXT,agent_class TEXT,action TEXT,arguments TEXT,outcome TEXT,occurred_at_ms INTEGER,caller_stack TEXT,previous_hash TEXT,signature TEXT); PRAGMA application_id=1234; PRAGMA user_version=42;").unwrap();
    drop(conn);
    let original = std::fs::read(&path).unwrap();
    assert!(nostoi_core::verify(&path, None).unwrap().ok);
    assert!(Store::open(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

fn legacy_outbox(path: &Path, source: &Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(schema::OUTBOX_SCHEMA).unwrap();
    conn.execute(
        "INSERT INTO outbox_meta(id,source) VALUES(1,?1)",
        [std::fs::canonicalize(source).unwrap().to_str().unwrap()],
    )
    .unwrap();
}

#[test]
fn outbox_migration_is_atomic_and_wrong_source_is_not_adopted() {
    use nostoi_anchor::outbox::Outbox;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite");
    audit(&source);
    let other = dir.path().join("other.sqlite");
    audit(&other);
    let path = dir.path().join("outbox.sqlite");
    legacy_outbox(&path, &source);
    let original = std::fs::read(&path).unwrap();
    assert!(Outbox::open(&path, &other).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_bind BEFORE INSERT ON outbox_meta BEGIN SELECT RAISE(ABORT,'simulated binding failure'); END;").unwrap();
    assert!(Outbox::open(&path, &source).is_err());
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row("PRAGMA application_id", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='nostoi_schema_meta'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    conn.execute_batch("DROP TRIGGER reject_bind").unwrap();
    drop(conn);
    drop(Outbox::open(&path, &source).unwrap());
    let info = schema::inspect(&path).unwrap();
    assert_eq!(info.application_id, schema::OUTBOX_APPLICATION_ID);
    assert_eq!(info.schema_revision, schema::OUTBOX_SCHEMA_REVISION);
    assert!(info.adopted_legacy);
}

#[test]
fn future_outboxes_and_wrong_components_are_rejected_without_changes() {
    for mutation in [
        "PRAGMA user_version=2".to_owned(),
        format!("PRAGMA application_id={}", schema::AUDIT_APPLICATION_ID),
        "UPDATE nostoi_schema_meta SET component='wrong-outbox'".to_owned(),
        "UPDATE nostoi_schema_meta SET record_format='nostoi-prepared-anchor-v9'".to_owned(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.sqlite");
        audit(&source);
        let path = dir.path().join("outbox.sqlite");
        drop(nostoi_anchor::outbox::Outbox::open(&path, &source).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=DELETE").unwrap();
        conn.execute_batch(&mutation).unwrap();
        drop(conn);
        let before = std::fs::read(&path).unwrap();
        assert!(
            nostoi_anchor::outbox::Outbox::open(&path, &source).is_err(),
            "{mutation}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "{mutation}");
    }
}

#[test]
fn legacy_outbox_envelopes_and_upload_bytes_survive_migration_and_recovery() {
    use nostoi_anchor::anchor::{prepare_anchor, AnchorOptions, LockMode};
    use nostoi_anchor::s3::{Client, Credentials, Provider};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite");
    audit(&source);
    let path = dir.path().join("outbox.sqlite");
    legacy_outbox(&path, &source);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = Client::new(
        &format!("http://{}", listener.local_addr().unwrap()),
        "bucket",
        "auto",
        true,
        Credentials {
            access_key: "test".into(),
            secret_key: "test".into(),
            session_token: None,
        },
    )
    .unwrap();
    let mut intent = serde_json::to_value(
        prepare_anchor(
            &source,
            AnchorOptions {
                key: "heads/legacy.json".into(),
                format: "nostoi-v1".into(),
                chain_id: "schema-test".into(),
                only_if_absent: true,
                lock: Some(LockMode::Compliance),
                retain_days: 30,
            },
            Provider::S3,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(intent["v"], nostoi_anchor::anchor::PREPARED_ANCHOR_V1);
    intent.as_object_mut().unwrap().remove("v");
    let request = intent.to_string();
    let bytes: Vec<u8> = serde_json::from_value(intent["body"].clone()).unwrap();
    let deadline = intent["anchor"]["retain_until"]
        .as_str()
        .unwrap()
        .to_owned();
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE outbox_meta SET target=?1",
        [client.target_identity()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO anchor_intents VALUES(?1,?2)",
        params!["heads/legacy.json", request],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO anchor_outcomes VALUES('heads/legacy.json','pending')",
        [],
    )
    .unwrap();
    drop(conn);
    let mut outbox = nostoi_anchor::outbox::Outbox::open(&path, &source).unwrap();
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .query_row("SELECT request FROM anchor_intents", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        request
    );
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        for index in 0..2 {
            let timeout = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < timeout);
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
                assert!(header.len() < 65536);
            }
            let header = String::from_utf8(header).unwrap();
            let response = if index == 0 {
                assert!(header.starts_with("PUT /bucket/heads/legacy.json "));
                assert!(header.contains(&deadline));
                let len: usize = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; len];
                stream.read_exact(&mut body).unwrap();
                assert_eq!(body, bytes);
                String::new()
            } else {
                assert!(header.starts_with("GET /bucket/heads/legacy.json?retention "));
                format!("<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>{deadline}</RetainUntilDate></Retention>")
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            )
            .unwrap();
        }
    });
    outbox.reconcile(&client).unwrap();
    server.join().unwrap();
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row("SELECT request FROM anchor_intents", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        request
    );
    assert_eq!(
        conn.query_row("SELECT state FROM anchor_outcomes", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "confirmed"
    );
}

#[test]
fn prepared_request_future_versions_are_explicit_and_malformed_versions_are_not_legacy() {
    use nostoi_anchor::anchor::{prepare_anchor, publish_prepared, AnchorOptions, PreparedAnchor};
    use nostoi_anchor::s3::{Client, Credentials, Provider};
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite");
    audit(&source);
    let original = serde_json::to_value(
        prepare_anchor(
            &source,
            AnchorOptions {
                key: String::new(),
                format: "nostoi-v1".into(),
                chain_id: "test".into(),
                only_if_absent: true,
                lock: None,
                retain_days: 0,
            },
            Provider::S3,
        )
        .unwrap(),
    )
    .unwrap();
    let client = Client::new(
        "http://127.0.0.1:1",
        "bucket",
        "auto",
        true,
        Credentials {
            access_key: "test".into(),
            secret_key: "test".into(),
            session_token: None,
        },
    )
    .unwrap();
    let mut future = original.clone();
    future["v"] = json!("nostoi-prepared-anchor-v2");
    let prepared: PreparedAnchor = serde_json::from_value(future).unwrap();
    assert!(matches!(
        publish_prepared(&client, &prepared, true),
        Err(Error::UnsupportedSchema { .. })
    ));
    for version in [serde_json::Value::Null, json!(2)] {
        let mut malformed = original.clone();
        malformed["v"] = version;
        assert!(serde_json::from_value::<PreparedAnchor>(malformed).is_err());
    }
    let mut historical = original;
    historical.as_object_mut().unwrap().remove("v");
    let prepared: PreparedAnchor = serde_json::from_value(historical.clone()).unwrap();
    assert_eq!(serde_json::to_value(prepared).unwrap(), historical);
}
