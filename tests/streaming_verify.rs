use nostoi::{chain, format, jsonl, verify_streaming, Format, Problem, GENESIS};
use serde_json::{json, Value};
use std::path::Path;

fn native_records() -> Vec<Value> {
    let mut previous = GENESIS.to_owned();
    (1..=3)
        .map(|seq| {
            let record = format::nostoi_record(
                seq,
                &previous,
                "2026-01-01T00:00:00Z",
                Some("🦆"),
                "test",
                None,
                json!({"large": u64::MAX, "nested": {"z": null, "a": [true, "é"]}}),
            )
            .unwrap();
            previous = record["digest"].as_str().unwrap().to_owned();
            record
        })
        .collect()
}

fn lines(records: &[Value]) -> String {
    records
        .iter()
        .map(|r| format!("{}\n", nostoi::canonical::to_string(r)))
        .collect()
}

fn parity(
    bytes: &[u8],
    format: Option<Format>,
    checkpoint: Option<u64>,
) -> chain::StreamingVerification {
    let loaded = jsonl::read(bytes, format).unwrap();
    let streamed = jsonl::verify_reader(bytes, format, checkpoint).unwrap();
    assert_eq!(
        serde_json::to_value(&streamed.report).unwrap(),
        serde_json::to_value(loaded.verify()).unwrap()
    );
    streamed
}

fn file_parity(path: &Path, format: Option<Format>, checkpoint: u64) {
    let loaded = nostoi::open(path, format).unwrap();
    let streamed = verify_streaming(path, format, Some(checkpoint)).unwrap();
    assert_eq!(
        serde_json::to_value(&streamed.report).unwrap(),
        serde_json::to_value(loaded.verify()).unwrap()
    );
    assert_eq!(
        streamed.checkpoint,
        (streamed.report.verified >= checkpoint)
            .then(|| loaded.entries[(checkpoint - 1) as usize].clone())
            .map(|e| nostoi::Head {
                seq: e.seq,
                digest: e.digest
            })
    );
    assert_eq!(
        serde_json::to_value(nostoi::verify(path, format).unwrap()).unwrap(),
        serde_json::to_value(streamed.report).unwrap()
    );
}

#[test]
fn native_prefix_suffix_and_read_failure_precedence() {
    let original = native_records();
    for position in 0..3 {
        for fault in ["seq", "previous", "body"] {
            let mut records = original.clone();
            match fault {
                "seq" => records[position][fault] = json!(9),
                "previous" => records[position][fault] = json!("wrong"),
                _ => records[position]["body"]["large"] = json!(0),
            }
            let text = lines(&records);
            let result = parity(text.as_bytes(), None, Some(2));
            assert!(!result.report.ok);
            assert_eq!(result.report.records, 3);
            assert_eq!(result.report.verified, position as u64);
            assert_eq!(result.checkpoint.is_some(), position == 2);
            let with_bad_tail = format!("{text}{{\"partial\":");
            let result = parity(with_bad_tail.as_bytes(), None, Some(2));
            assert_eq!(result.report.records, 3);
            assert!(!matches!(
                result.report.problem,
                Some(Problem::Unreadable { .. })
            ));
        }
    }
}

#[test]
fn jsonl_empty_truncated_utf8_blank_lines_and_partial_eof() {
    let records = native_records();
    let text = lines(&records);
    let result = parity(text.trim_end().as_bytes(), None, Some(2));
    assert!(result.report.ok);
    assert_eq!(result.checkpoint.unwrap().digest, records[1]["digest"]);
    for checkpoint in [0, 4, u64::MAX] {
        assert!(parity(text.as_bytes(), None, Some(checkpoint))
            .checkpoint
            .is_none());
    }
    assert!(parity(b"\n \n", None, Some(1)).report.ok);
    assert!(parity(b"", None, Some(1)).checkpoint.is_none());
    assert!(parity(lines(&records[..1]).as_bytes(), None, Some(2))
        .checkpoint
        .is_none());
    for suffix in [
        b"{\"partial\":".as_slice(),
        b"\xff\n".as_slice(),
        b"{}\n".as_slice(),
    ] {
        let mut bytes = format!("\n{text}\n").into_bytes();
        bytes.extend_from_slice(suffix);
        let result = parity(&bytes, None, Some(2));
        assert_eq!(result.report.records, 3);
        assert_eq!(result.report.verified, 3);
        assert!(matches!(
            result.report.problem,
            Some(Problem::Unreadable { at: 6, .. })
        ));
    }
}

#[test]
fn reader_io_errors_preserve_counts_and_earlier_chain_failure() {
    struct FailsAfter(std::io::Cursor<Vec<u8>>);
    impl std::io::Read for FailsAfter {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let n = std::io::Read::read(&mut self.0, buffer)?;
            if n == 0 {
                Err(std::io::Error::other("injected read failure"))
            } else {
                Ok(n)
            }
        }
    }
    for broken in [false, true] {
        let mut records = native_records();
        if broken {
            records[0]["kind"] = json!("tampered");
        }
        let bytes = lines(&records).into_bytes();
        let loaded = jsonl::read(FailsAfter(std::io::Cursor::new(bytes.clone())), None).unwrap();
        let result =
            jsonl::verify_reader(FailsAfter(std::io::Cursor::new(bytes)), None, Some(2)).unwrap();
        assert_eq!(
            serde_json::to_value(&result.report).unwrap(),
            serde_json::to_value(loaded.verify()).unwrap()
        );
        assert_eq!(result.report.records, 3);
        if broken {
            assert_eq!(result.report.problem, Some(Problem::Digest { seq: 1 }));
        } else {
            assert!(matches!(
                result.report.problem,
                Some(Problem::Unreadable { at: 4, .. })
            ));
        }
    }
}

#[test]
fn weftmark_vector_and_lexical_numbers_use_existing_digest_logic() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/weftmark-ledger.jsonl");
    file_parity(&path, None, 2);
    let mut record: Value = serde_json::from_str(r#"{"sequence":1,"previous_digest":"","digest":"","recorded_at":"now","kind":"test","entity_id":"x","numbers":[1.00,1e+20,18446744073709551616,-0.0]}"#).unwrap();
    record["previous_digest"] = json!(GENESIS);
    record["digest"] = json!(format::json_record_digest(record.as_object().unwrap()));
    let text = lines(&[record]);
    assert!(text.contains("1.00"));
    assert!(parity(text.as_bytes(), None, Some(1)).report.ok);
}

fn ephor_events() -> Vec<format::EphorEvent> {
    let mut previous = GENESIS.to_owned();
    (1..=3)
        .map(|seq| {
            let mut event = format::EphorEvent {
                chain_sequence: seq,
                id: "6a80fb52-2979-42cb-97bb-666552245920".into(),
                node_id: "node-a".into(),
                aggregate_id: "session-1".into(),
                agent_class: "planner".into(),
                action: "plan.create".into(),
                arguments: vec!["currency=EUR".into(), "amount=1250".into()],
                outcome: "success".into(),
                occurred_at_ms: 1_700_000_000_000,
                caller_stack: vec!["planner.plan".into()],
                previous_hash: previous.clone(),
                signature: String::new(),
            };
            event.signature = event.hash();
            previous = event.signature.clone();
            event
        })
        .collect()
}

#[test]
fn ephor_jsonl_vector_and_failures() {
    let events = ephor_events();
    assert_eq!(
        events[0].signature,
        "2a7501b1a8d0b1e390d4bfd5f407cceaeac8e09da34c783cb4c6027f127f0d55"
    );
    let mut records: Vec<_> = events.iter().map(|e| e.entry().record).collect();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ephor.jsonl");
    std::fs::write(&path, lines(&records)).unwrap();
    for format in [None, Some(Format::EphorAudit)] {
        file_parity(&path, format, 2);
    }
    records[2]["action"] = json!("altered");
    let result = parity(lines(&records).as_bytes(), None, Some(2));
    assert_eq!(result.report.problem, Some(Problem::Digest { seq: 3 }));
    assert!(result.checkpoint.is_some());
    records[2]["arguments"] = json!("not an array");
    let result = parity(lines(&records).as_bytes(), None, Some(2));
    assert!(matches!(
        result.report.problem,
        Some(Problem::Unreadable { at: 3, .. })
    ));
    assert_eq!(result.report.records, 2);
}

#[test]
fn a_rehashed_history_verifies_but_changes_the_checkpoint() {
    let original = native_records();
    let mut previous = GENESIS.to_owned();
    let rewritten: Vec<_> = original
        .iter()
        .map(|record| {
            let mut record = record.clone();
            record["body"]["large"] = json!(0);
            record["previous"] = json!(previous);
            record["digest"] = json!(format::json_record_digest(record.as_object().unwrap()));
            previous = record["digest"].as_str().unwrap().to_owned();
            record
        })
        .collect();
    let result = parity(lines(&rewritten).as_bytes(), None, Some(2));
    assert!(result.report.ok);
    assert_ne!(result.checkpoint.unwrap().digest, original[1]["digest"]);
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use nostoi::sqlite::Store;
    use rusqlite::{params, Connection};

    fn draft() -> nostoi::Draft<'static> {
        nostoi::Draft {
            actor: None,
            kind: "test",
            subject: None,
            body: json!({}),
            at: None,
        }
    }

    #[test]
    fn native_sqlite_parity_tail_failure_and_column_consistency() {
        for column in ["record", "seq", "previous", "digest"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("native.sqlite");
            let mut store = Store::open_verified(&path).unwrap();
            for _ in 0..3 {
                store.append(draft()).unwrap();
            }
            file_parity(&path, None, 2);
            let assignment = match column {
                "record" => "record = replace(record, '\"test\"', '\"altered\"')",
                "seq" => "seq = 4",
                "previous" => "previous = printf('%064d', 1)",
                _ => "digest = printf('%064d', 1)",
            };
            store.connection().execute_batch(&format!("DROP TRIGGER nostoi_records_no_update; UPDATE nostoi_records SET {assignment} WHERE seq = 3;")).unwrap();
            let result = verify_streaming(&path, None, Some(2)).unwrap();
            assert_eq!(result.report.records, 3);
            assert_eq!(result.report.verified, 2);
            assert!(result.checkpoint.is_some());
            let expected = match column {
                "seq" => Problem::Sequence {
                    seq: 3,
                    expected: 3,
                },
                "previous" => Problem::Link { seq: 3 },
                _ => Problem::Digest { seq: 3 },
            };
            assert_eq!(result.report.problem, Some(expected));
            assert!(Store::open_verified(&path).is_err());
            if column == "record" {
                file_parity(&path, None, 1);
            }
        }
    }

    #[test]
    fn ephor_sqlite_parity_and_unreadable_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ephor.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE governance_events (chain_sequence INTEGER, id TEXT, node_id TEXT, aggregate_id TEXT, agent_class TEXT, action TEXT, arguments TEXT, outcome TEXT, occurred_at_ms INTEGER, caller_stack TEXT, previous_hash TEXT, signature TEXT);").unwrap();
        for e in ephor_events() {
            conn.execute(
                "INSERT INTO governance_events VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    e.chain_sequence as i64,
                    e.id,
                    e.node_id,
                    e.aggregate_id,
                    e.agent_class,
                    e.action,
                    serde_json::to_string(&e.arguments).unwrap(),
                    e.outcome,
                    e.occurred_at_ms as i64,
                    serde_json::to_string(&e.caller_stack).unwrap(),
                    e.previous_hash,
                    e.signature
                ],
            )
            .unwrap();
        }
        file_parity(&path, None, 2);
        conn.execute(
            "UPDATE governance_events SET arguments = 'invalid' WHERE chain_sequence = 3",
            [],
        )
        .unwrap();
        let loaded = nostoi::open(&path, None).unwrap().verify();
        let result = verify_streaming(&path, None, Some(2)).unwrap();
        assert_eq!(
            serde_json::to_value(&result.report).unwrap(),
            serde_json::to_value(loaded).unwrap()
        );
        assert_eq!(result.report.records, 2);
        assert!(matches!(
            result.report.problem,
            Some(Problem::Unreadable { at: 3, .. })
        ));
        assert!(result.checkpoint.is_some());
    }
}
