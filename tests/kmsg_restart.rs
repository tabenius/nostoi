#![cfg(all(
    feature = "kmsg",
    feature = "sqlite",
    feature = "cli",
    target_os = "linux"
))]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BOOT_A: &str = "11111111-1111-1111-1111-111111111111";
const BOOT_B: &str = "22222222-2222-2222-2222-222222222222";

struct Fixture {
    _dir: tempfile::TempDir,
    store: PathBuf,
    source: PathBuf,
    boot: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Self {
            store: dir.path().join("kmsg.sqlite"),
            source: dir.path().join("source"),
            boot: dir.path().join("boot_id"),
            _dir: dir,
        };
        std::fs::write(&fixture.boot, BOOT_A).unwrap();
        fixture.input(&[]);
        fixture
    }

    fn input(&self, seqs: &[u64]) {
        let records = seqs
            .iter()
            .map(|seq| format!("6,{seq},{seq},-;message {seq}\n"))
            .collect::<String>();
        std::fs::write(&self.source, records).unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kmsg-nostoi"));
        command
            .arg(&self.store)
            .arg("--source")
            .arg(&self.source)
            .arg("--boot-id-file")
            .arg(&self.boot)
            .args(["--poll-ms", "10"]);
        command
    }

    fn once(&self) {
        let output = self.command().arg("--once").output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(nostoi::verify(&self.store, None).unwrap().ok);
    }

    fn records(&self) -> Vec<Value> {
        nostoi::open(&self.store, None)
            .unwrap()
            .entries
            .into_iter()
            .map(|entry| entry.record)
            .collect()
    }

    fn lines(&self) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|record| record["kind"] == "kmsg.line")
            .collect()
    }

    fn follow(&self, wanted: usize) -> Running {
        let child = self
            .command()
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut running = Running(child);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                running.0.try_wait().unwrap().is_none(),
                "writer exited before readiness"
            );
            if self.store.exists()
                && nostoi::open(&self.store, None).is_ok_and(|loaded| {
                    loaded
                        .entries
                        .iter()
                        .filter(|entry| entry.kind == "kmsg.line")
                        .count()
                        >= wanted
                })
            {
                break;
            }
            assert!(Instant::now() < deadline, "writer did not reach readiness");
            std::thread::sleep(Duration::from_millis(10));
        }
        running
    }
}

struct Running(Child);

impl Running {
    fn signal_and_wait(&mut self, signal: &str) -> std::process::ExitStatus {
        assert!(Command::new("kill")
            .args([signal, &self.0.id().to_string()])
            .status()
            .unwrap()
            .success());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "writer failed to stop");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn same_boot_replays_only_new_messages_even_after_empty_restart() {
    let fixture = Fixture::new();
    fixture.input(&[0, 1, 2]);
    fixture.once();
    fixture.input(&[]);
    fixture.once();
    fixture.input(&[0, 1, 2, 3]);
    fixture.once();
    let lines = fixture.lines();
    assert_eq!(
        lines
            .iter()
            .map(|line| line["body"]["kmsg_seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    assert!(lines.iter().all(|line| line["body"]["boot_id"] == BOOT_A));
}

#[test]
fn boot_change_does_not_skip_new_boot_low_sequences() {
    let fixture = Fixture::new();
    fixture.input(&[100, 101]);
    fixture.once();
    std::fs::write(&fixture.boot, BOOT_B).unwrap();
    fixture.input(&[0, 1]);
    fixture.once();
    let lines = fixture.lines();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[2]["body"]["boot_id"], BOOT_B);
    assert_eq!(lines[2]["body"]["kmsg_seq"], 0);
    assert!(fixture
        .records()
        .iter()
        .any(|record| record["body"]["reason"] == "boot_changed_or_legacy_checkpoint"));
}

#[test]
fn overwritten_restart_buffer_has_exact_gap_count() {
    let fixture = Fixture::new();
    fixture.input(&[0, 1, 2]);
    fixture.once();
    fixture.input(&[7, 8]);
    fixture.once();
    let losses: Vec<_> = fixture
        .records()
        .into_iter()
        .filter(|record| record["kind"] == "kmsg.loss")
        .collect();
    assert_eq!(losses.len(), 1);
    assert_eq!(losses[0]["body"]["lost"], 4);
    assert_eq!(losses[0]["body"]["reason"], "restart_buffer_gap");
}

#[test]
fn sigterm_commits_stop_marker_and_preserves_resume_checkpoint() {
    let fixture = Fixture::new();
    fixture.input(&[0, 1]);
    let mut running = fixture.follow(2);
    assert!(running.signal_and_wait("-TERM").success());
    let records = fixture.records();
    let stop = records.last().unwrap();
    assert_eq!(stop["kind"], "kmsg.reader.stop");
    assert_eq!(stop["body"]["reason"], "signal");
    assert_eq!(stop["body"]["last_kmsg_seq"], 1);
    fixture.input(&[0, 1, 2]);
    fixture.once();
    assert_eq!(fixture.lines().len(), 3);
}

#[test]
fn killed_writer_resumes_from_last_durable_line() {
    let fixture = Fixture::new();
    fixture.input(&[0, 1]);
    let mut running = fixture.follow(2);
    assert!(!running.signal_and_wait("-KILL").success());
    fixture.input(&[0, 1, 2]);
    fixture.once();
    assert_eq!(fixture.lines().len(), 3);
    assert!(fixture
        .records()
        .iter()
        .any(|record| record["body"]["reason"] == "unclean_restart"));
}

#[test]
fn competing_ingestor_cannot_append_duplicate_messages() {
    let fixture = Fixture::new();
    fixture.input(&[0, 1]);
    let mut running = fixture.follow(2);
    let output = fixture.command().arg("--once").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("another kmsg ingestor"));
    assert_eq!(fixture.lines().len(), 2);
    assert!(running.signal_and_wait("-INT").success());
}

#[test]
fn legacy_checkpoint_is_resumed_without_backfilling_its_payload() {
    let fixture = Fixture::new();
    let previous = nostoi::append(&fixture.store, nostoi::Draft {
        actor: Some("host:kmsg"), kind: "kmsg.line", subject: Some("kernel"),
        body: serde_json::json!({"boot_id":BOOT_A,"source":fixture.source.display().to_string(),"kmsg_seq":1,"message":"legacy"}), at: None,
    }).unwrap();
    fixture.input(&[0, 1, 2]);
    fixture.once();
    let lines = fixture.lines();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], previous.record);
    assert!(lines[0]["body"].get("schema").is_none());
    assert_eq!(lines[1]["body"]["schema"], nostoi::kmsg::KMSG_PAYLOAD_V1);
    assert_eq!(lines[1]["body"]["kmsg_seq"], 2);
    assert!(fixture
        .records()
        .iter()
        .filter(|record| record["seq"] != 1)
        .all(|record| record["body"]["schema"] == nostoi::kmsg::KMSG_PAYLOAD_V1));
}

#[test]
fn unknown_checkpoint_payload_schema_fails_before_new_records() {
    for schema in [serde_json::json!("nostoi-kmsg-v2"), serde_json::Value::Null] {
        let fixture = Fixture::new();
        nostoi::append(&fixture.store, nostoi::Draft {
            actor:Some("host:kmsg"),kind:"kmsg.line",subject:Some("kernel"),
            body:serde_json::json!({"schema":schema,"boot_id":BOOT_A,"source":fixture.source.display().to_string(),"kmsg_seq":1}),at:None,
        }).unwrap();
        fixture.input(&[0, 1, 2]);
        let before = fixture.records();
        let output = fixture.command().arg("--once").output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported schema"));
        assert_eq!(fixture.records(), before);
    }
}
