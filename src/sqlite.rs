//! SQLite: Nostoi's own append-only store, and Ephor's `governance_events`.
//!
//! The Nostoi store keeps each `nostoi-v1` record whole (`record`, canonical
//! JSON) beside its chain fields. Triggers refuse any UPDATE or DELETE, and an
//! INSERT must extend the head: the next `seq`, the head's digest as
//! `previous`, and a `digest` equal to `nostoi_digest(record)`, a function the
//! writer registers (core SQLite has no SHA-256). Any SQLite reader can open
//! and verify the file; only a writer that registers the function can append.
//! The database runs in WAL mode, so Litestream can stream it off the host.

use crate::chain::{Entry, Problem, GENESIS};
use crate::error::{Error, Result};
use crate::format::{self, Format, KagpEvent};
use crate::jsonl::{Draft, Loaded};
use rusqlite::functions::FunctionFlags;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::Value;
use std::path::Path;

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS nostoi_records (
    seq       INTEGER PRIMARY KEY CHECK (seq >= 1),
    previous  TEXT    NOT NULL CHECK (length(previous) = 64),
    digest    TEXT    NOT NULL UNIQUE CHECK (length(digest) = 64),
    record    TEXT    NOT NULL CHECK (json_valid(record))
) STRICT;

CREATE TRIGGER IF NOT EXISTS nostoi_records_extend_chain
BEFORE INSERT ON nostoi_records
BEGIN
    SELECT RAISE(ABORT, 'nostoi: seq does not follow the chain head')
     WHERE NEW.seq <> COALESCE((SELECT MAX(seq) FROM nostoi_records), 0) + 1;
    SELECT RAISE(ABORT, 'nostoi: previous does not match the chain head')
     WHERE NEW.previous <> COALESCE(
           (SELECT digest FROM nostoi_records ORDER BY seq DESC LIMIT 1),
           '0000000000000000000000000000000000000000000000000000000000000000');
    SELECT RAISE(ABORT, 'nostoi: the record does not carry its chain fields')
     WHERE json_extract(NEW.record, '$.seq') IS NOT NEW.seq
        OR json_extract(NEW.record, '$.previous') IS NOT NEW.previous
        OR json_extract(NEW.record, '$.digest') IS NOT NEW.digest;
    SELECT RAISE(ABORT, 'nostoi: digest does not match the record')
     WHERE NEW.digest <> nostoi_digest(NEW.record);
END;

CREATE TRIGGER IF NOT EXISTS nostoi_records_no_update
BEFORE UPDATE ON nostoi_records
BEGIN
    SELECT RAISE(ABORT, 'nostoi: records are append-only');
END;

CREATE TRIGGER IF NOT EXISTS nostoi_records_no_delete
BEFORE DELETE ON nostoi_records
BEGIN
    SELECT RAISE(ABORT, 'nostoi: records are append-only');
END;
"#;

/// Whether `path` is an SQLite database (by its header).
pub fn is_sqlite(path: &Path) -> bool {
    let mut header = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut header))
        .is_ok()
        && &header == b"SQLite format 3\0"
}

fn register(conn: &Connection) -> rusqlite::Result<()> {
    conn.create_scalar_function(
        "nostoi_digest",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let text = ctx.get::<String>(0)?;
            let value: Value = serde_json::from_str(&text)
                .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;
            match value {
                Value::Object(map) => Ok(format::json_record_digest(&map)),
                _ => Err(rusqlite::Error::UserFunctionError(
                    "record is not an object".into(),
                )),
            }
        },
    )
}

fn has_table(conn: &Connection, name: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Read a chain from an SQLite file: the Nostoi store or Ephor's events.
pub fn load(path: &Path, format: Option<Format>) -> Result<Loaded> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let format = match format {
        Some(format) => format,
        None if has_table(&conn, "nostoi_records")? => Format::Nostoi,
        None if has_table(&conn, "governance_events")? => Format::KagpAudit,
        None => {
            return Err(Error::Invalid(
                "no chain here (neither nostoi_records nor governance_events)".into(),
            ))
        }
    };
    match format {
        Format::Nostoi => load_nostoi(&conn),
        Format::KagpAudit => load_kagp(&conn),
        Format::WeftmarkLedger => Err(Error::Invalid(
            "weftmark-ledger-v1 chains are JSONL files".into(),
        )),
    }
}

fn load_nostoi(conn: &Connection) -> Result<Loaded> {
    let mut stmt = conn.prepare("SELECT seq, record FROM nostoi_records ORDER BY seq")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut entries = Vec::new();
    let mut unreadable = None;
    for row in rows {
        let (seq, text) = row?;
        let parsed = serde_json::from_str::<Value>(&text)
            .map_err(|e| e.to_string())
            .and_then(format::nostoi_entry);
        match parsed {
            Ok(entry) => entries.push(entry),
            Err(detail) => {
                unreadable = Some(Problem::Unreadable {
                    at: seq as u64,
                    detail,
                });
                break;
            }
        }
    }
    Ok(Loaded {
        format: Format::Nostoi,
        entries,
        unreadable,
    })
}

fn strings(text: &str) -> std::result::Result<Vec<String>, String> {
    serde_json::from_str(text).map_err(|e| format!("not a JSON array of strings: {e}"))
}

fn load_kagp(conn: &Connection) -> Result<Loaded> {
    let mut stmt = conn.prepare(
        "SELECT chain_sequence, id, node_id, aggregate_id, agent_class, action, arguments,
                outcome, occurred_at_ms, caller_stack, previous_hash, signature
           FROM governance_events ORDER BY chain_sequence",
    )?;
    let mut rows = stmt.query([])?;
    let mut entries = Vec::new();
    let mut unreadable = None;
    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        let event = (|| -> std::result::Result<KagpEvent, String> {
            let get = |i: usize| row.get::<_, String>(i).map_err(|e| e.to_string());
            Ok(KagpEvent {
                chain_sequence: seq as u64,
                id: get(1)?,
                node_id: get(2)?,
                aggregate_id: get(3)?,
                agent_class: get(4)?,
                action: get(5)?,
                arguments: strings(&get(6)?)?,
                outcome: get(7)?,
                occurred_at_ms: row.get::<_, i64>(8).map_err(|e| e.to_string())? as u64,
                caller_stack: strings(&get(9)?)?,
                previous_hash: get(10)?,
                signature: get(11)?,
            })
        })();
        match event {
            Ok(event) => entries.push(event.entry()),
            Err(detail) => {
                unreadable = Some(Problem::Unreadable {
                    at: seq as u64,
                    detail,
                });
                break;
            }
        }
    }
    Ok(Loaded {
        format: Format::KagpAudit,
        entries,
        unreadable,
    })
}

/// Nostoi's append-only SQLite store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open or create the store at `path` (WAL mode, synchronous FULL).
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        register(&conn)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Append a `nostoi-v1` record. The store re-verifies the chain first and
    /// refuses to extend a broken one; the triggers check the new row again.
    pub fn append(&mut self, draft: Draft<'_>) -> Result<Entry> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let loaded = load_nostoi(&tx)?;
        let report = loaded.verify();
        if let Some(problem) = report.problem {
            return Err(Error::Broken(problem));
        }
        let (seq, previous) = match &report.head {
            Some(head) => (head.seq + 1, head.digest.clone()),
            None => (1, GENESIS.to_string()),
        };
        let at = draft.at.unwrap_or_else(crate::time::now);
        let record = format::nostoi_record(
            seq,
            &previous,
            &at,
            draft.actor,
            draft.kind,
            draft.subject,
            draft.body,
        )
        .map_err(Error::Invalid)?;
        let entry = format::nostoi_entry(record.clone()).map_err(Error::Invalid)?;
        tx.execute(
            "INSERT INTO nostoi_records (seq, previous, digest, record) VALUES (?1, ?2, ?3, ?4)",
            params![
                seq as i64,
                previous,
                entry.digest,
                crate::canonical::to_string(&record)
            ],
        )?;
        tx.commit()?;
        Ok(entry)
    }

    pub fn load(&self) -> Result<Loaded> {
        load_nostoi(&self.conn)
    }

    /// The raw connection (for tests and advanced use; writes still go
    /// through the triggers).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn draft(kind: &str) -> Draft<'_> {
        Draft {
            actor: Some("agent:a"),
            kind,
            subject: None,
            body: json!({"n": 1}),
            at: None,
        }
    }

    #[test]
    fn the_store_is_append_only_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.sqlite");
        let mut store = Store::open(&path).unwrap();
        store.append(draft("one")).unwrap();
        let second = store.append(draft("two")).unwrap();
        assert!(is_sqlite(&path));
        let report = load(&path, None).unwrap().verify();
        assert!(report.ok);
        assert_eq!(report.head.unwrap().digest, second.digest);

        let conn = store.connection();
        for sql in [
            "UPDATE nostoi_records SET record = record",
            "DELETE FROM nostoi_records",
        ] {
            let error = conn.execute(sql, []).unwrap_err().to_string();
            assert!(error.contains("append-only"), "{error}");
        }
        // A forged row: right position and link, content that does not hash.
        let forged = format::nostoi_record(
            3,
            &second.digest,
            "2026-09-27T21:00:00Z",
            None,
            "k",
            None,
            json!({}),
        )
        .unwrap();
        let mut text = crate::canonical::to_string(&forged);
        text = text.replace("\"kind\":\"k\"", "\"kind\":\"x\"");
        let digest = forged["digest"].as_str().unwrap();
        let error = conn
            .execute(
                "INSERT INTO nostoi_records (seq, previous, digest, record) VALUES (3, ?1, ?2, ?3)",
                params![second.digest, digest, text],
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("digest does not match"), "{error}");
    }

    #[test]
    fn a_store_edited_behind_its_triggers_back_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.sqlite");
        let mut store = Store::open(&path).unwrap();
        store.append(draft("one")).unwrap();
        store.append(draft("two")).unwrap();
        store
            .connection()
            .execute_batch(
                "DROP TRIGGER nostoi_records_no_update;
                 UPDATE nostoi_records SET record = replace(record, '\"one\"', '\"uno\"') WHERE seq = 1;",
            )
            .unwrap();
        assert_eq!(
            load(&path, None).unwrap().verify().problem,
            Some(Problem::Digest { seq: 1 })
        );
        assert!(matches!(
            store.append(draft("three")),
            Err(Error::Broken(_))
        ));
    }

    #[test]
    fn reads_ephors_governance_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ephor.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE governance_events (chain_sequence INTEGER, id TEXT, occurred_at_ms INTEGER,
               aggregate_id TEXT, agent_class TEXT, action TEXT, arguments TEXT, outcome TEXT,
               caller_stack TEXT, previous_hash TEXT, signature TEXT, node_id TEXT);",
        )
        .unwrap();
        let mut event = KagpEvent {
            chain_sequence: 1,
            id: "6a80fb52-2979-42cb-97bb-666552245920".into(),
            node_id: "node-a".into(),
            aggregate_id: "session-1".into(),
            agent_class: "planner".into(),
            action: "plan.create".into(),
            arguments: vec!["currency=EUR".into(), "amount=1250".into()],
            outcome: "success".into(),
            occurred_at_ms: 1_700_000_000_000,
            caller_stack: vec!["planner.plan".into()],
            previous_hash: GENESIS.into(),
            signature: String::new(),
        };
        event.signature = event.hash();
        conn.execute(
            "INSERT INTO governance_events VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                1,
                event.id,
                1_700_000_000_000i64,
                event.aggregate_id,
                event.agent_class,
                event.action,
                r#"["currency=EUR","amount=1250"]"#,
                event.outcome,
                r#"["planner.plan"]"#,
                event.previous_hash,
                event.signature,
                event.node_id
            ],
        )
        .unwrap();
        let loaded = load(&path, None).unwrap();
        assert_eq!(loaded.format, Format::KagpAudit);
        let report = loaded.verify();
        assert!(report.ok, "{:?}", report.problem);
        assert_eq!(
            report.head.unwrap().digest,
            "2a7501b1a8d0b1e390d4bfd5f407cceaeac8e09da34c783cb4c6027f127f0d55"
        );
    }
}
