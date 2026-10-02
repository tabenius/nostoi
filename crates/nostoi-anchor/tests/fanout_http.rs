#![cfg(feature = "sqlite")]

//! Offline fan-out tests.
//!
//! Each destination gets its own in-process object store, so "independent
//! destination" means independent storage in the test rather than a shared
//! bucket that would hide a bug where one store stood in for two.

use nostoi_anchor::fanout::{self, Fanout, PublishState, ReadState, Target, TargetPublish};
use nostoi_anchor::s3::Provider;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(5);
const BUCKET: &str = "bucket";

/// How a fake destination should answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    /// Store objects and honour `If-None-Match: *`.
    Store,
    /// Refuse every write with 403, as a credential without PutObject would.
    RefuseWrites,
}

/// One destination's storage, on its own port.
struct Store {
    endpoint: String,
    objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    retention: Arc<Mutex<HashMap<String, (String, String)>>>,
    stopped: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Store {
    fn start(behaviour: Behaviour) -> Store {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let objects = Arc::new(Mutex::new(HashMap::new()));
        let retention = Arc::new(Mutex::new(HashMap::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let handle = {
            let objects = Arc::clone(&objects);
            let retention = Arc::clone(&retention);
            let stopped = Arc::clone(&stopped);
            thread::spawn(move || {
                while !stopped.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => serve(stream, behaviour, &objects, &retention),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Store {
            endpoint,
            objects,
            retention,
            stopped,
            handle: Some(handle),
        }
    }

    /// An endpoint that nothing is listening on.
    fn dead() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        endpoint
    }

    /// The retention a destination recorded, as `(mode, deadline)`.
    fn retention(&self, key: &str) -> Option<(String, String)> {
        self.retention.lock().unwrap().get(key).cloned()
    }

    fn object(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.lock().unwrap().get(key).cloned()
    }

    /// Replace what a destination holds, standing in for a compromised one.
    fn tamper(&self, key: &str, body: &str) {
        self.objects
            .lock()
            .unwrap()
            .insert(key.to_string(), body.as_bytes().to_vec());
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve(
    mut stream: TcpStream,
    behaviour: Behaviour,
    objects: &Arc<Mutex<HashMap<String, Vec<u8>>>>,
    retention: &Arc<Mutex<HashMap<String, (String, String)>>>,
) {
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(TIMEOUT)).unwrap();
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(
            std::time::Instant::now() < deadline,
            "header deadline exceeded"
        );
        let mut byte = [0];
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        bytes.push(byte[0]);
    }
    let text = String::from_utf8(bytes).unwrap();
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        })
        .collect();
    let header = |name: &str| -> Option<String> {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    let length: usize = header("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    if length > 0 && stream.read_exact(&mut body).is_err() {
        return;
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let (path, query) = path.split_once('?').unwrap_or((path.as_str(), ""));
    // Path-style addressing puts the bucket in the path; the key is what follows.
    let key = path
        .trim_start_matches('/')
        .strip_prefix(&format!("{BUCKET}/"))
        .unwrap_or_else(|| path.trim_start_matches('/'))
        .to_string();

    let response = match (method.as_str(), query) {
        ("PUT", _) if behaviour == Behaviour::RefuseWrites => (403, String::new()),
        ("PUT", _) => {
            if header("if-none-match").as_deref() == Some("*")
                && objects.lock().unwrap().contains_key(&key)
            {
                (412, String::new())
            } else {
                if let (Some(mode), Some(until)) = (
                    header("x-amz-object-lock-mode"),
                    header("x-amz-object-lock-retain-until-date"),
                ) {
                    retention.lock().unwrap().insert(key.clone(), (mode, until));
                }
                objects.lock().unwrap().insert(key, body);
                (200, String::new())
            }
        }
        // The client asks for `?retention` (no `=`).
        ("GET", query) if query.starts_with("retention") => {
            match retention.lock().unwrap().get(&key) {
                Some((mode, until)) => (
                    200,
                    format!(
                        "<Retention><Mode>{mode}</Mode><RetainUntilDate>{until}</RetainUntilDate></Retention>"
                    ),
                ),
                None => (404, String::new()),
            }
        }
        ("GET", _) => match objects.lock().unwrap().get(&key) {
            Some(value) => (200, String::from_utf8_lossy(value).into_owned()),
            None => (404, String::new()),
        },
        _ => (405, String::new()),
    };
    let (status, body) = response;
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .ok();
}

fn target(name: &str, store: &Store) -> Target {
    Target {
        name: name.to_string(),
        endpoint: store.endpoint.clone(),
        bucket: BUCKET.to_string(),
        region: "us-east-1".to_string(),
        path_style: true,
        provider: None,
        lock: Some(nostoi_anchor::anchor::LockMode::Compliance),
        retain_days: 365,
        credentials: Some(name.to_string()),
    }
}

/// A credentials directory with one subdirectory per destination, so the
/// per-destination credential path is exercised rather than the environment.
fn credentials_dir(root: &Path, names: &[&str]) {
    for name in names {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("aws-access-key-id"), format!("{name}-key")).unwrap();
        std::fs::write(dir.join("aws-secret-access-key"), format!("{name}-secret")).unwrap();
    }
}

fn chain(dir: &Path, records: usize) -> std::path::PathBuf {
    let path = dir.join("audit.jsonl");
    for index in 0..records {
        nostoi_core::append(
            &path,
            nostoi_core::Draft {
                actor: Some("test"),
                kind: "fanout",
                subject: None,
                body: serde_json::json!({"index": index}),
                at: None,
            },
        )
        .unwrap();
    }
    path
}

fn fanout_of(targets: Vec<Target>) -> Fanout {
    Fanout {
        chain_id: "production/kernel".to_string(),
        key: String::new(),
        format: "nostoi-v1".to_string(),
        targets,
    }
}

fn state_of<'a>(results: &'a [TargetPublish], name: &str) -> &'a TargetPublish {
    results
        .iter()
        .find(|result| result.name == name)
        .unwrap_or_else(|| panic!("no result for {name}"))
}

#[test]
fn every_destination_confirms_one_shared_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 3);
    let aws = Store::start(Behaviour::Store);
    let b2 = Store::start(Behaviour::Store);
    credentials_dir(dir.path(), &["aws", "b2"]);
    let config = fanout_of(vec![target("aws", &aws), target("b2", &b2)]);

    let results = fanout::publish(&chain, &config, Some(dir.path()), None).unwrap();
    let (aws_store, b2_store) = (&aws, &b2);

    assert_eq!(results.len(), 2);
    for result in &results {
        assert_eq!(result.state, PublishState::Confirmed, "{result:?}");
        assert_eq!(result.seq, 3);
    }
    assert!(fanout::is_ok(&results));

    // One timestamp for the batch: the two checkpoints describe the same
    // instant, so a later disagreement is about the chain and nothing else.
    let key = state_of(&results, "aws").key.clone();
    assert!(!key.is_empty());
    let aws: serde_json::Value =
        serde_json::from_slice(&aws.object(&key).expect("aws stored the checkpoint")).unwrap();
    let b2: serde_json::Value =
        serde_json::from_slice(&b2.object(&key).expect("b2 stored the checkpoint")).unwrap();
    assert_eq!(aws["anchored_at"], b2["anchored_at"]);
    assert_eq!(aws["chain"], b2["chain"]);
    assert_eq!(aws["format"], b2["format"]);
    assert_eq!(aws["seq"], b2["seq"]);
    assert_eq!(aws["digest"], b2["digest"]);
    assert_eq!(aws["mode"], "COMPLIANCE");
    assert_eq!(aws["retain_until"], b2["retain_until"]);
    // Both destinations recorded the same deadline, which is what made the
    // read-back in publish_prepared succeed rather than report "unconfirmed".
    let (mode, until) = aws_store.retention(&key).expect("aws recorded retention");
    assert_eq!(mode, "COMPLIANCE");
    assert_eq!(
        Some(until.clone()),
        b2_store.retention(&key).map(|(_, until)| until)
    );
    assert_eq!(
        Some(until),
        aws["retain_until"].as_str().map(str::to_string)
    );

    // Each destination has its own durable recovery state.
    let outbox_dir = dir.path().join("outbox");
    std::fs::create_dir_all(&outbox_dir).unwrap();
    let results = fanout::publish(&chain, &config, Some(dir.path()), Some(&outbox_dir)).unwrap();
    assert!(results.iter().all(|result| result.durable));
    assert!(outbox_dir.join("aws.sqlite").is_file());
    assert!(outbox_dir.join("b2.sqlite").is_file());
}

#[test]
fn one_refused_destination_does_not_stop_the_others() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 2);
    let good = Store::start(Behaviour::Store);
    let refusing = Store::start(Behaviour::RefuseWrites);
    credentials_dir(dir.path(), &["good", "refusing"]);
    let config = fanout_of(vec![target("good", &good), target("refusing", &refusing)]);

    let results = fanout::publish(&chain, &config, Some(dir.path()), None).unwrap();

    assert_eq!(state_of(&results, "good").state, PublishState::Confirmed);
    let refused = state_of(&results, "refusing");
    assert_eq!(refused.state, PublishState::Rejected);
    assert!(
        !fanout::is_ok(&results),
        "a refused destination is not a pass"
    );
    let key = state_of(&results, "good").key.clone();
    assert!(
        refusing.object(&key).is_none(),
        "a refused destination must not have stored anything"
    );
    assert!(
        refused
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("403"),
        "the reason should be reported: {:?}",
        refused.detail
    );
}

#[test]
fn an_unreachable_destination_is_reported_not_hidden() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 1);
    let live = Store::start(Behaviour::Store);
    credentials_dir(dir.path(), &["live", "gone"]);
    let mut dead = target("gone", &live);
    dead.endpoint = Store::dead();
    let config = fanout_of(vec![target("live", &live), dead]);

    let results = fanout::publish(&chain, &config, Some(dir.path()), None).unwrap();

    assert_eq!(state_of(&results, "live").state, PublishState::Confirmed);
    let unreachable = state_of(&results, "gone");
    assert!(
        !matches!(
            unreachable.state,
            PublishState::Confirmed | PublishState::AlreadyAnchored
        ),
        "an unreachable destination must never count as confirmed: {unreachable:?}"
    );
    assert!(unreachable.detail.is_some());
    assert!(!fanout::is_ok(&results));
}

#[test]
fn a_destination_without_its_own_credentials_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 1);
    let store = Store::start(Behaviour::Store);
    // Only one of the two destinations has credentials on disk.
    credentials_dir(dir.path(), &["aws"]);
    let mut second = target("b2", &store);
    second.credentials = Some("b2".to_string());
    let config = fanout_of(vec![target("aws", &store), second]);

    let results = fanout::publish(&chain, &config, Some(dir.path()), None).unwrap();

    assert_eq!(state_of(&results, "aws").state, PublishState::Confirmed);
    let missing = state_of(&results, "b2");
    assert_eq!(missing.state, PublishState::Rejected);
    let detail = missing.detail.as_deref().unwrap_or_default();
    assert!(detail.contains("aws-access-key-id"), "{detail}");
    assert!(
        detail.contains("b2"),
        "the message must name the destination: {detail}"
    );
}

#[test]
fn verification_requires_destinations_to_agree() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 3);
    let honest = Store::start(Behaviour::Store);
    let compromised = Store::start(Behaviour::Store);
    credentials_dir(dir.path(), &["honest", "compromised"]);
    let config = fanout_of(vec![
        target("honest", &honest),
        target("compromised", &compromised),
    ]);
    let results = fanout::publish(&chain, &config, Some(dir.path()), None).unwrap();
    let key = state_of(&results, "honest").key.clone();
    let mut verifying = config.clone();
    verifying.key = key.clone();

    // Nothing wrong yet: both destinations answer with the same checkpoint.
    let verified = fanout::verify(&chain, &verifying, Some(dir.path())).unwrap();
    assert!(verified.is_ok(), "{verified:#?}");
    assert!(verified.conflicts.is_empty());
    assert!(verified.unusable.is_empty());
    assert_eq!(verified.verified.unwrap().verified_records, 3);
    assert!(verified
        .per_target
        .iter()
        .all(|read| matches!(read.result, ReadState::Agreed { .. })));

    // A destination that was rewritten to claim a different chain is a
    // conflict to surface, not a vote to lose.
    let mut other = serde_json::from_slice::<serde_json::Value>(
        &honest.object(&key).expect("honest stored the checkpoint"),
    )
    .unwrap();
    other["digest"] = serde_json::json!("0".repeat(64));
    compromised.tamper(&key, &other.to_string());

    let verified = fanout::verify(&chain, &verifying, Some(dir.path())).unwrap();
    assert!(!verified.is_ok());
    assert_eq!(verified.conflicts.len(), 1, "{verified:#?}");
    assert!(
        verified.conflicts[0].contains("compromised"),
        "{verified:#?}"
    );
    // The local chain still matched the destination that told the truth, and
    // both facts are reported.
    assert!(verified.verified.is_some());
}

#[test]
fn verification_fails_closed_when_no_destination_answers() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 2);
    let dead = Store::dead();
    let mut first = target("a", &Store::start(Behaviour::Store));
    first.endpoint = dead.clone();
    let mut second = target("b", &Store::start(Behaviour::Store));
    second.endpoint = dead;
    credentials_dir(dir.path(), &["a", "b"]);
    let mut config = fanout_of(vec![first, second]);
    config.key = "heads/trusted.json".to_string();

    let verified = fanout::verify(&chain, &config, Some(dir.path())).unwrap();

    assert!(!verified.is_ok(), "no answer is not a pass");
    assert!(verified.agreed.is_none());
    assert!(verified.verified.is_none());
    assert_eq!(verified.unusable.len(), 2);
}

#[test]
fn a_missing_destination_reduces_assurance_without_failing_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 2);
    let live = Store::start(Behaviour::Store);
    credentials_dir(dir.path(), &["live", "gone"]);
    let mut gone = target("gone", &live);
    gone.endpoint = Store::dead();
    let config = fanout_of(vec![target("live", &live), gone]);
    let results = fanout::publish(&chain, &config, Some(dir.path()), None).unwrap();
    let mut verifying = config;
    verifying.key = state_of(&results, "live").key.clone();

    let verified = fanout::verify(&chain, &verifying, Some(dir.path())).unwrap();

    assert!(
        verified.is_ok(),
        "one honest destination still anchors the chain"
    );
    assert_eq!(verified.unusable.len(), 1);
    assert!(verified.verified.is_some());
}

#[test]
fn a_truncated_or_rewritten_local_chain_is_caught_by_the_agreed_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 4);
    let store = Store::start(Behaviour::Store);
    credentials_dir(dir.path(), &["only"]);
    let config = fanout_of(vec![target("only", &store)]);
    let results = fanout::publish(&chain, &config, Some(dir.path()), None).unwrap();
    let mut verifying = config;
    verifying.key = state_of(&results, "only").key.clone();

    // Drop the tail, which no local hash can detect on its own.
    let text = std::fs::read_to_string(&chain).unwrap();
    let kept: Vec<&str> = text.lines().take(2).collect();
    std::fs::write(&chain, format!("{}\n", kept.join("\n"))).unwrap();

    let verified = fanout::verify(&chain, &verifying, Some(dir.path())).unwrap();
    assert!(!verified.is_ok());
    assert!(verified.verified.is_none(), "{verified:#?}");
}

#[test]
fn unsafe_or_ambiguous_target_names_are_refused_before_any_network_use() {
    let store = Store::start(Behaviour::Store);
    let good = target("aws", &store);

    for (label, targets) in [
        ("empty", vec![]),
        ("duplicate", vec![good.clone(), good.clone()]),
        (
            "traversal",
            vec![Target {
                name: "../escape".to_string(),
                ..good.clone()
            }],
        ),
        (
            "separator",
            vec![Target {
                name: "sub/dir".to_string(),
                ..good.clone()
            }],
        ),
        (
            "leading dot",
            vec![Target {
                name: ".hidden".to_string(),
                ..good.clone()
            }],
        ),
        (
            "no bucket",
            vec![Target {
                bucket: String::new(),
                ..good.clone()
            }],
        ),
        (
            "bad endpoint",
            vec![Target {
                endpoint: "not-a-url".to_string(),
                ..good.clone()
            }],
        ),
        (
            "retain days",
            vec![Target {
                retain_days: 0,
                ..good.clone()
            }],
        ),
    ] {
        let config = fanout_of(targets);
        let error = config
            .validate()
            .err()
            .unwrap_or_else(|| panic!("{label} should have been refused"));
        assert!(!error.to_string().is_empty(), "{label}");
    }

    assert!(fanout_of(vec![good]).validate().is_ok());
}

#[test]
fn the_provider_is_detected_per_destination_or_stated_explicitly() {
    let store = Store::start(Behaviour::Store);

    // Detection is by host, so a real endpoint is recognised...
    let mut detected = target("aws", &store);
    detected.endpoint = "https://s3.us-west-2.amazonaws.com".to_string();
    assert_eq!(detected.provider(), Provider::S3);
    let mut detected_r2 = target("r2", &store);
    detected_r2.endpoint = "https://example.r2.cloudflarestorage.com".to_string();
    assert_eq!(detected_r2.provider(), Provider::R2);

    // ...and a custom domain or private endpoint, which detection cannot classify,
    // is stated instead.
    let mut stated = target("r2", &store);
    stated.provider = Some(Provider::R2);
    assert_eq!(stated.provider(), Provider::R2);

    // R2 has no object lock, so asking for one is refused for that destination
    // alone instead of failing the batch.
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 1);
    credentials_dir(dir.path(), &["aws", "r2"]);
    let plain = target("aws", &store);
    let results = fanout::publish(
        &chain,
        &fanout_of(vec![plain, stated]),
        Some(dir.path()),
        None,
    )
    .unwrap();
    assert_eq!(state_of(&results, "aws").state, PublishState::Confirmed);
    let refused = state_of(&results, "r2");
    assert_eq!(refused.state, PublishState::Rejected);
    assert!(
        refused.detail.as_deref().unwrap_or_default().contains("R2"),
        "{:?}",
        refused.detail
    );
}

#[test]
fn verification_refuses_to_choose_its_own_trusted_key() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain(dir.path(), 1);
    let store = Store::start(Behaviour::Store);
    credentials_dir(dir.path(), &["only"]);
    let config = fanout_of(vec![target("only", &store)]);

    let error = fanout::verify(&chain, &config, Some(dir.path())).unwrap_err();
    assert!(
        error.to_string().contains("explicit key"),
        "verification must not pick a trusted checkpoint: {error}"
    );
}
