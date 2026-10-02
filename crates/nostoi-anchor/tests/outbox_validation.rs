#![cfg(feature = "sqlite")]

use nostoi_anchor::anchor::{
    prepare_anchor, publish_prepared, AnchorOptions, LockMode, PreparedAnchor,
};
use nostoi_anchor::outbox::Outbox;
use nostoi_anchor::s3::{Client, Credentials, Provider};
use nostoi_anchor::Error;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Respond immediately to unexpected I/O so a broken validation guard fails
// with an observable request count rather than hanging on a network timeout.
struct NetworkGuard {
    client: Client,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    thread: Option<thread::JoinHandle<()>>,
}

impl NetworkGuard {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let stopped = stop.clone();
        let counted = requests.clone();
        let thread = thread::spawn(move || loop {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    counted.fetch_add(1, Ordering::SeqCst);
                    socket
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let _ = socket.read(&mut [0; 16384]);
                    let _ = socket.write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if stopped.load(Ordering::SeqCst) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("accept: {e}"),
            }
        });
        let client = Client::new(
            &endpoint,
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
        Self {
            client,
            stop,
            requests,
            thread: Some(thread),
        }
    }
}

impl Drop for NetworkGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
        assert_eq!(
            self.requests.load(Ordering::SeqCst),
            0,
            "validation must precede all network I/O"
        );
    }
}

fn options() -> AnchorOptions {
    AnchorOptions {
        key: "heads/validation.json".into(),
        format: "nostoi-v1".into(),
        chain_id: "validation-chain".into(),
        only_if_absent: true,
        lock: Some(LockMode::Compliance),
        retain_days: 30,
    }
}

fn source(path: &Path) {
    nostoi_core::append(
        path,
        nostoi_core::Draft {
            actor: None,
            kind: "test",
            subject: None,
            body: json!({}),
            at: None,
        },
    )
    .unwrap();
}

fn sync_body(request: &mut Value) {
    let anchor: nostoi_anchor::anchor::Anchor =
        serde_json::from_value(request["anchor"].clone()).unwrap();
    request["body"] = serde_json::to_value(serde_json::to_vec_pretty(&anchor).unwrap()).unwrap();
}

fn corrupt(db: &Path, original: &Value, changed: &Value, state: &str) {
    let conn = Connection::open(db).unwrap();
    let key = original["anchor"]["key"].as_str().unwrap();
    conn.execute(
        "INSERT INTO anchor_intents(key,request) VALUES(?1,?2)",
        params![key, original.to_string()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO anchor_outcomes(key,state) VALUES(?1,?2)",
        params![key, state],
    )
    .unwrap();
    // Simulate on-disk inconsistency; ordinary writes cannot change an intent.
    conn.execute_batch("DROP TRIGGER immutable_intents_update")
        .unwrap();
    conn.execute(
        "UPDATE anchor_intents SET request=?1 WHERE key=?2",
        params![changed.to_string(), key],
    )
    .unwrap();
}

#[test]
fn inconsistent_deserialized_and_stored_intents_fail_without_network_io() {
    let guard = NetworkGuard::new();
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("audit.jsonl");
    source(&source_path);
    let original =
        serde_json::to_value(prepare_anchor(&source_path, options(), Provider::S3).unwrap())
            .unwrap();
    let cases = [
        ("seq", json!(0)),
        ("digest", json!("A".repeat(64))),
        ("digest", json!("abc")),
        ("v", json!("nostoi-anchor-v2")),
        ("format", json!("unknown-v1")),
        ("chain", json!(" ")),
        ("chain", json!("chain\nidentity")),
        ("key", json!("")),
        ("key", json!("/absolute")),
        ("key", json!("heads/../other")),
        ("key", json!("heads/./other")),
        ("key", json!("heads/\nother")),
        ("provider", json!("unknown")),
        ("provider", json!("r2")),
        ("mode", json!("GOVERNANCE")),
        ("mode", Value::Null),
        ("retain_until", Value::Null),
        ("retain_until", json!("invalid-date")),
        ("retain_until", json!("2100-01-01T00:00:00Z")),
        ("anchored_at", json!("invalid-date")),
    ];
    let mut mutations = Vec::new();
    for (field, value) in cases {
        let mut changed = original.clone();
        changed["anchor"][field] = value;
        sync_body(&mut changed);
        mutations.push((format!("anchor.{field}"), changed, true));
    }
    for (field, value) in [
        ("only_if_absent", json!(false)),
        ("lock", Value::Null),
        ("lock", json!("Governance")),
        ("retain_days", json!(0)),
        ("retain_days", json!(31)),
        ("retain_days", json!(36501)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        // Non-conditional publication remains supported by the ordinary API.
        mutations.push((field.to_string(), changed, field != "only_if_absent"));
    }
    let mut changed = original.clone();
    changed["anchor"]["digest"] = json!("0".repeat(64));
    mutations.push(("metadata/body mismatch".into(), changed, true));
    let mut changed = original.clone();
    changed["body"] = serde_json::to_value(b"not json".to_vec()).unwrap();
    mutations.push(("invalid body JSON".into(), changed, true));
    let mut changed = original.clone();
    let mut extra = changed["anchor"].clone();
    extra["extra"] = json!(true);
    changed["body"] = serde_json::to_value(serde_json::to_vec_pretty(&extra).unwrap()).unwrap();
    mutations.push(("extra body field".into(), changed, true));
    let mut changed = original.clone();
    changed["lock"] = Value::Null;
    changed["anchor"]["mode"] = Value::Null;
    changed["anchor"]["retain_until"] = Value::Null;
    sync_body(&mut changed);
    mutations.push(("duration without lock".into(), changed, true));
    for (index, (name, changed, check_public)) in mutations.into_iter().enumerate() {
        let db = dir.path().join(format!("outbox-{index}.db"));
        let mut outbox = Outbox::open(&db, &source_path).unwrap();
        outbox.reconcile(&guard.client).unwrap();
        corrupt(&db, &original, &changed, "pending");
        assert!(
            matches!(outbox.reconcile(&guard.client), Err(Error::Invalid(_))),
            "{name}"
        );
        if check_public {
            let prepared: PreparedAnchor = serde_json::from_value(changed).unwrap();
            assert!(
                matches!(
                    publish_prepared(&guard.client, &prepared, false),
                    Err(Error::Invalid(_))
                ),
                "{name}"
            );
        }
        let state: String = Connection::open(&db)
            .unwrap()
            .query_row("SELECT state FROM anchor_outcomes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "pending", "{name}");
    }
}

#[test]
fn database_key_mismatch_fails_closed_even_with_consistent_payload() {
    let guard = NetworkGuard::new();
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("audit.jsonl");
    source(&source_path);
    let db = dir.path().join("outbox.db");
    let mut outbox = Outbox::open(&db, &source_path).unwrap();
    outbox.reconcile(&guard.client).unwrap();
    let original =
        serde_json::to_value(prepare_anchor(&source_path, options(), Provider::S3).unwrap())
            .unwrap();
    let mut changed = original.clone();
    changed["anchor"]["key"] = json!("heads/other.json");
    sync_body(&mut changed);
    corrupt(&db, &original, &changed, "pending");
    assert!(matches!(
        outbox.reconcile(&guard.client),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn expired_original_deadline_is_rejected_for_pending_and_previously_confirmed_intents() {
    let guard = NetworkGuard::new();
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("audit.jsonl");
    source(&source_path);
    let original =
        serde_json::to_value(prepare_anchor(&source_path, options(), Provider::S3).unwrap())
            .unwrap();
    let mut expired = original.clone();
    expired["anchor"]["anchored_at"] = json!("2000-01-01T00:00:00Z");
    expired["anchor"]["retain_until"] = json!("2000-01-31T00:00:00Z");
    sync_body(&mut expired);
    for initial in ["pending", "confirmed"] {
        let db = dir.path().join(format!("outbox-{initial}.db"));
        let mut outbox = Outbox::open(&db, &source_path).unwrap();
        outbox.reconcile(&guard.client).unwrap();
        corrupt(&db, &original, &expired, initial);
        let result = if initial == "pending" {
            outbox.reconcile(&guard.client).map(|_| ())
        } else {
            outbox
                .anchor_head(&source_path, &guard.client, options(), Provider::S3)
                .map(|_| ())
        };
        assert!(
            matches!(result, Err(Error::AnchorExpired { retain_until, .. }) if retain_until == "2000-01-31T00:00:00Z")
        );
        let conn = Connection::open(&db).unwrap();
        let state: String = conn
            .query_row("SELECT state FROM anchor_outcomes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "rejected");
        let persisted: String = conn
            .query_row("SELECT request FROM anchor_intents", [], |r| r.get(0))
            .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&persisted).unwrap(), expired);
        // Explicitly putting the same intent back in the retry queue never renews it.
        conn.execute("UPDATE anchor_outcomes SET state='pending'", [])
            .unwrap();
        assert!(matches!(
            outbox.reconcile(&guard.client),
            Err(Error::AnchorExpired { .. })
        ));
    }
    let prepared: PreparedAnchor = serde_json::from_value(expired).unwrap();
    assert!(matches!(
        publish_prepared(&guard.client, &prepared, false),
        Err(Error::AnchorExpired { .. })
    ));
}
