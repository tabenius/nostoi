//! Core JSON Lines storage: one record per line, appended, never edited.
//!
//! Reading detects the format from the first record (`"v": "nostoi-v1"`, or
//! WeftMark's `sequence`/`previous_digest`, or Ephor's
//! `chain_sequence`/`previous_hash`). Appending (nostoi-v1 only) takes an
//! exclusive lock on the file, re-verifies the chain, refuses to extend a broken
//! one, writes one line and syncs it to disk before returning.

use crate::chain::{self, Entry, Problem, GENESIS};
use crate::error::{io, Error, Result};
use crate::format::{self, EphorEvent, Format};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// A chain as read: its format, its readable entries, and the read error that
/// stopped it, if one did.
pub struct Loaded {
    pub format: Format,
    pub entries: Vec<Entry>,
    pub unreadable: Option<Problem>,
}

impl Loaded {
    pub fn verify(&self) -> chain::Report {
        chain::verify(self.format.name(), &self.entries, self.unreadable.clone())
    }
}

/// Which JSONL format a first record is in.
pub fn detect(record: &Value) -> Option<Format> {
    let map = record.as_object()?;
    if map.get("v").and_then(Value::as_str) == Some(format::NOSTOI_V1) {
        Some(Format::Nostoi)
    } else if map.contains_key("previous_digest") && map.contains_key("sequence") {
        Some(Format::WeftmarkLedger)
    } else if map.contains_key("chain_sequence") && map.contains_key("previous_hash") {
        Some(Format::EphorAudit)
    } else {
        None
    }
}

/// Read a JSONL chain from any reader.
pub fn read(reader: impl Read, format: Option<Format>) -> Result<Loaded> {
    let mut entries = Vec::new();
    let (format, unreadable) = scan(reader, format, |entry| entries.push(entry))?;
    Ok(Loaded {
        format,
        entries,
        unreadable,
    })
}

/// Verify JSON Lines from a reader, retaining at most the current record.
/// Reads through chain failures to preserve counts and read-error precedence.
pub fn verify_reader(
    reader: impl Read,
    format: Option<Format>,
    checkpoint_seq: Option<u64>,
) -> Result<chain::StreamingVerification> {
    let mut verifier = chain::Verifier::new(checkpoint_seq);
    let (format, unreadable) = scan(reader, format, |entry| verifier.push(&entry))?;
    Ok(verifier.finish(format.name(), unreadable))
}

fn scan(
    reader: impl Read,
    format: Option<Format>,
    mut visit: impl FnMut(Entry),
) -> Result<(Format, Option<Problem>)> {
    let mut format = format;
    let mut unreadable = None;
    for (index, line) in BufReader::new(reader).lines().enumerate() {
        let at = index as u64 + 1;
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                unreadable = Some(Problem::Unreadable {
                    at,
                    detail: error.to_string(),
                });
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let record: Value = match serde_json::from_str(&line) {
            Ok(record) => record,
            Err(error) => {
                unreadable = Some(Problem::Unreadable {
                    at,
                    detail: error.to_string(),
                });
                break;
            }
        };
        let this = match format {
            Some(format) => format,
            None => match detect(&record) {
                Some(found) => {
                    format = Some(found);
                    found
                }
                None => return Err(Error::Invalid(
                    "not a chain Nostoi knows (nostoi-v1, weftmark-ledger-v1 or ephor-audit-v1)"
                        .into(),
                )),
            },
        };
        let parsed = match this {
            Format::Nostoi => format::nostoi_entry(record),
            Format::WeftmarkLedger => format::weftmark_entry(record),
            Format::EphorAudit => ephor_entry(record),
        };
        match parsed {
            Ok(entry) => visit(entry),
            Err(detail) => {
                unreadable = Some(Problem::Unreadable { at, detail });
                break;
            }
        }
    }
    Ok((format.unwrap_or(Format::Nostoi), unreadable))
}

// Decode Ephor's exported record shape; hashing and Entry conversion stay in
// EphorEvent, shared with the SQLite reader.
fn ephor_entry(record: Value) -> std::result::Result<Entry, String> {
    let text = |key: &str| {
        record[key]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("{key} is not a string"))
    };
    let number = |key: &str| {
        record[key]
            .as_u64()
            .ok_or_else(|| format!("{key} is not a positive integer"))
    };
    let list = |key: &str| {
        serde_json::from_value::<Vec<String>>(record[key].clone())
            .map_err(|e| format!("{key} is not an array of strings: {e}"))
    };
    Ok(EphorEvent {
        chain_sequence: number("chain_sequence")?,
        id: text("id")?,
        node_id: text("node_id")?,
        aggregate_id: text("aggregate_id")?,
        agent_class: text("agent_class")?,
        action: text("action")?,
        arguments: list("arguments")?,
        outcome: text("outcome")?,
        occurred_at_ms: number("occurred_at_ms")?,
        caller_stack: list("caller_stack")?,
        previous_hash: text("previous_hash")?,
        signature: text("signature")?,
    }
    .entry())
}

/// Read a JSONL chain file.
pub fn load(path: &Path, format: Option<Format>) -> Result<Loaded> {
    read(File::open(path).map_err(io(path))?, format)
}

/// What to append: everything but the chain fields, which Nostoi fills in.
pub struct Draft<'a> {
    pub actor: Option<&'a str>,
    pub kind: &'a str,
    pub subject: Option<&'a str>,
    pub body: Value,
    /// Defaults to now.
    pub at: Option<String>,
}

/// Append a `nostoi-v1` record to `path` (created if missing).
pub fn append(path: &Path, draft: Draft<'_>) -> Result<Entry> {
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)
        .map_err(io(path))?;
    // Exclusive for the whole read-verify-write: two writers must not both
    // extend the same head.
    file.lock().map_err(io(path))?;
    let result = append_locked(path, &mut file, draft);
    let _ = file.unlock();
    result
}

fn append_locked(path: &Path, file: &mut File, draft: Draft<'_>) -> Result<Entry> {
    file.seek(SeekFrom::Start(0)).map_err(io(path))?;
    let report = verify_reader(&mut *file, Some(Format::Nostoi), None)?.report;
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
    let mut line = crate::canonical::to_string(&record);
    // A complete last record need not have a newline. Preserve the record
    // boundary before appending, rather than joining two JSON objects.
    if file.metadata().map_err(io(path))?.len() > 0 {
        file.seek(SeekFrom::End(-1)).map_err(io(path))?;
        let mut last = [0];
        file.read_exact(&mut last).map_err(io(path))?;
        if last[0] != b'\n' {
            line.insert(0, '\n');
        }
    }
    line.push('\n');
    file.write_all(line.as_bytes()).map_err(io(path))?;
    file.sync_all().map_err(io(path))?;
    format::nostoi_entry(record).map_err(Error::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn draft(kind: &str) -> Draft<'_> {
        Draft {
            actor: Some("agent:a"),
            kind,
            subject: Some("cs-1"),
            body: json!({"n": 1}),
            at: None,
        }
    }

    #[test]
    fn append_preserves_a_complete_record_without_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        append(&path, draft("one")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.trim_end()).unwrap();
        append(&path, draft("two")).unwrap();
        let report = load(&path, None).unwrap().verify();
        assert!(report.ok);
        assert_eq!(report.verified, 2);
    }

    #[test]
    fn appends_verify_and_a_broken_chain_is_not_extended() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        append(&path, draft("one")).unwrap();
        let second = append(&path, draft("two")).unwrap();
        assert_eq!(second.seq, 2);
        let report = load(&path, None).unwrap().verify();
        assert!(report.ok, "{:?}", report.problem);
        assert_eq!(report.head.unwrap().digest, second.digest);

        // Edit history: the first record's kind.
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replacen("\"one\"", "\"uno\"", 1);
        std::fs::write(&path, text).unwrap();
        assert_eq!(
            load(&path, None).unwrap().verify().problem,
            Some(Problem::Digest { seq: 1 })
        );
        assert!(matches!(
            append(&path, draft("three")),
            Err(Error::Broken(Problem::Digest { seq: 1 }))
        ));
    }

    #[test]
    fn a_truncated_last_line_is_reported_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        append(&path, draft("one")).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"v\":\"nostoi-v1\",\"seq\":2,").unwrap();
        let report = load(&path, None).unwrap().verify();
        assert!(matches!(
            report.problem,
            Some(Problem::Unreadable { at: 2, .. })
        ));
        assert_eq!(report.verified, 1);
    }

    #[test]
    fn weftmarks_own_ledger_verifies_byte_for_byte() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/weftmark-ledger.jsonl");
        let loaded = load(&path, None).unwrap();
        assert_eq!(loaded.format, Format::WeftmarkLedger);
        let report = loaded.verify();
        assert!(report.ok, "{:?}", report.problem);
        assert_eq!(report.verified, 4);
    }
}
