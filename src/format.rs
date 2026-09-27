//! The chain formats Nostoi reads (and, for `nostoi-v1`, writes).
//!
//! | Format | Used by | Record | Digest |
//! | --- | --- | --- | --- |
//! | `nostoi-v1` | Nostoi's own logs (Sylvae, Frog, …) | one JSON object per line, or a row of the SQLite store | SHA-256 of the canonical JSON of the record without `digest` |
//! | `weftmark-ledger-v1` | WeftMark's `ledger.jsonl` | one JSON object per line | SHA-256 of the canonical JSON of the record without `digest` |
//! | `kagp-audit-v1` | Ephor (governance-http, agent-proxy, PostgreSQL/SQLite stores) | a `governance_events` row | SHA-256 of the length-prefixed fields |
//!
//! "Canonical JSON" is Python's `json.dumps(sort_keys=True, separators=(",", ":"))`
//! (see [`crate::canonical`]).

use crate::canonical;
use crate::chain::Entry;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

pub const NOSTOI_V1: &str = "nostoi-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Nostoi,
    WeftmarkLedger,
    KagpAudit,
}

impl Format {
    pub const ALL: [Format; 3] = [Format::Nostoi, Format::WeftmarkLedger, Format::KagpAudit];

    pub fn name(self) -> &'static str {
        match self {
            Format::Nostoi => NOSTOI_V1,
            Format::WeftmarkLedger => "weftmark-ledger-v1",
            Format::KagpAudit => "kagp-audit-v1",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Format::Nostoi => "Nostoi's own chain: JSONL or the Nostoi SQLite store",
            Format::WeftmarkLedger => "WeftMark's ledger.jsonl",
            Format::KagpAudit => "Ephor's audit chain (governance_events in SQLite)",
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Format {
    type Err = String;
    fn from_str(text: &str) -> Result<Self, String> {
        Format::ALL
            .into_iter()
            .find(|format| format.name() == text || format.name().trim_end_matches("-v1") == text)
            .ok_or_else(|| {
                format!("unknown format {text:?} (nostoi-v1, weftmark-ledger-v1, kagp-audit-v1)")
            })
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The digest of a JSON record: canonical JSON of everything but `digest`.
/// Shared by `nostoi-v1` and `weftmark-ledger-v1`.
pub fn json_record_digest(record: &Map<String, Value>) -> String {
    let mut content = record.clone();
    content.remove("digest");
    sha256_hex(canonical::to_string(&Value::Object(content)).as_bytes())
}

fn text(record: &Map<String, Value>, key: &str) -> Result<String, String> {
    match record.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(format!("{key} is not a string")),
        None => Err(format!("{key} is missing")),
    }
}

fn optional_text(record: &Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    match record.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("{key} is not a string")),
    }
}

fn position(record: &Map<String, Value>, key: &str) -> Result<u64, String> {
    record
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} is not a positive integer"))
}

fn object(value: Value) -> Result<Map<String, Value>, String> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err("not a JSON object".to_string()),
    }
}

// ── nostoi-v1 ───────────────────────────────────────────────────────

/// Build a `nostoi-v1` record, digest included.
///
/// `body` must be a JSON object of strings, booleans, nulls, 64-bit integers,
/// arrays and objects: no floats (see [`canonical::check_native`]).
pub fn nostoi_record(
    seq: u64,
    previous: &str,
    at: &str,
    actor: Option<&str>,
    kind: &str,
    subject: Option<&str>,
    body: Value,
) -> Result<Value, String> {
    if kind.trim().is_empty() {
        return Err("kind must not be empty".into());
    }
    if !body.is_object() {
        return Err("body must be a JSON object".into());
    }
    canonical::check_native(&body)?;
    let mut record = Map::new();
    record.insert("v".into(), json!(NOSTOI_V1));
    record.insert("seq".into(), json!(seq));
    record.insert("previous".into(), json!(previous));
    record.insert("at".into(), json!(at));
    if let Some(actor) = actor {
        record.insert("actor".into(), json!(actor));
    }
    record.insert("kind".into(), json!(kind));
    if let Some(subject) = subject {
        record.insert("subject".into(), json!(subject));
    }
    record.insert("body".into(), body);
    let digest = json_record_digest(&record);
    record.insert("digest".into(), json!(digest));
    Ok(Value::Object(record))
}

/// Read a `nostoi-v1` record.
pub fn nostoi_entry(record: Value) -> Result<Entry, String> {
    let map = object(record)?;
    if map.get("v").and_then(Value::as_str) != Some(NOSTOI_V1) {
        return Err(format!("not a {NOSTOI_V1} record (v)"));
    }
    if !map.get("body").is_some_and(Value::is_object) {
        return Err("body is not a JSON object".into());
    }
    Ok(Entry {
        seq: position(&map, "seq")?,
        previous: text(&map, "previous")?,
        digest: text(&map, "digest")?,
        computed: json_record_digest(&map),
        at: Some(text(&map, "at")?),
        actor: optional_text(&map, "actor")?,
        kind: text(&map, "kind")?,
        subject: optional_text(&map, "subject")?,
        record: Value::Object(map),
    })
}

// ── weftmark-ledger-v1 ──────────────────────────────────────────────

/// Read a WeftMark ledger record.
pub fn weftmark_entry(record: Value) -> Result<Entry, String> {
    let map = object(record)?;
    Ok(Entry {
        seq: position(&map, "sequence")?,
        previous: text(&map, "previous_digest")?,
        digest: text(&map, "digest")?,
        computed: json_record_digest(&map),
        at: Some(text(&map, "recorded_at")?),
        actor: None,
        kind: text(&map, "kind")?,
        subject: Some(text(&map, "entity_id")?),
        record: Value::Object(map),
    })
}

// ── kagp-audit-v1 ───────────────────────────────────────────────────

/// One Ephor audit event, as a `governance_events` row stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KagpEvent {
    pub chain_sequence: u64,
    pub id: String,
    pub node_id: String,
    pub aggregate_id: String,
    pub agent_class: String,
    pub action: String,
    pub arguments: Vec<String>,
    pub outcome: String,
    pub occurred_at_ms: u64,
    pub caller_stack: Vec<String>,
    pub previous_hash: String,
    pub signature: String,
}

/// The `kagp-audit-v1` hash (Ephor's governance-node, governance-http and
/// PostgreSQL `kagp_event_hash`): SHA-256 over `kagp-audit-v1|` and each field
/// as `<byte length>:<bytes>`, lists as their length then their items.
#[allow(clippy::too_many_arguments)]
pub fn kagp_hash(
    node_id: &str,
    id: &str,
    aggregate_id: &str,
    agent_class: &str,
    action: &str,
    arguments: &[String],
    outcome: &str,
    occurred_at_ms: u64,
    caller_stack: &[String],
    previous_hash: &str,
) -> String {
    fn field(hasher: &mut Sha256, value: &str) {
        hasher.update(value.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(value.as_bytes());
    }
    fn list(hasher: &mut Sha256, values: &[String]) {
        field(hasher, &values.len().to_string());
        for value in values {
            field(hasher, value);
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(b"kagp-audit-v1|");
    field(&mut hasher, node_id);
    field(&mut hasher, id);
    field(&mut hasher, aggregate_id);
    field(&mut hasher, agent_class);
    field(&mut hasher, action);
    list(&mut hasher, arguments);
    field(&mut hasher, outcome);
    field(&mut hasher, &occurred_at_ms.to_string());
    list(&mut hasher, caller_stack);
    field(&mut hasher, previous_hash);
    hex::encode(hasher.finalize())
}

impl KagpEvent {
    pub fn hash(&self) -> String {
        kagp_hash(
            &self.node_id,
            &self.id,
            &self.aggregate_id,
            &self.agent_class,
            &self.action,
            &self.arguments,
            &self.outcome,
            self.occurred_at_ms,
            &self.caller_stack,
            &self.previous_hash,
        )
    }

    pub fn entry(&self) -> Entry {
        Entry {
            seq: self.chain_sequence,
            previous: self.previous_hash.clone(),
            digest: self.signature.clone(),
            computed: self.hash(),
            at: Some(crate::time::from_unix_ms(self.occurred_at_ms)),
            actor: Some(self.agent_class.clone()),
            kind: self.action.clone(),
            subject: Some(self.aggregate_id.clone()),
            record: json!({
                "chain_sequence": self.chain_sequence,
                "id": self.id,
                "node_id": self.node_id,
                "aggregate_id": self.aggregate_id,
                "agent_class": self.agent_class,
                "action": self.action,
                "arguments": self.arguments,
                "outcome": self.outcome,
                "occurred_at_ms": self.occurred_at_ms,
                "caller_stack": self.caller_stack,
                "previous_hash": self.previous_hash,
                "signature": self.signature,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::GENESIS;

    #[test]
    fn kagp_matches_ephors_postgres_test_vector() {
        let hash = kagp_hash(
            "node-a",
            "6a80fb52-2979-42cb-97bb-666552245920",
            "session-1",
            "planner",
            "plan.create",
            &["currency=EUR".into(), "amount=1250".into()],
            "success",
            1_700_000_000_000,
            &["planner.plan".into()],
            GENESIS,
        );
        assert_eq!(
            hash,
            "2a7501b1a8d0b1e390d4bfd5f407cceaeac8e09da34c783cb4c6027f127f0d55"
        );
    }

    #[test]
    fn a_nostoi_record_carries_its_own_digest() {
        let record = nostoi_record(
            1,
            GENESIS,
            "2026-09-27T21:00:00Z",
            Some("agent:claude"),
            "tool.call",
            Some("cs-1"),
            json!({"tool": "weft_handoff_create", "n": 2}),
        )
        .unwrap();
        let entry = nostoi_entry(record.clone()).unwrap();
        assert_eq!(entry.digest, entry.computed);
        // What a Python producer computes with the standard library alone.
        let without_digest = r#"{"actor":"agent:claude","at":"2026-09-27T21:00:00Z","body":{"n":2,"tool":"weft_handoff_create"},"kind":"tool.call","previous":"0000000000000000000000000000000000000000000000000000000000000000","seq":1,"subject":"cs-1","v":"nostoi-v1"}"#;
        assert_eq!(entry.digest, sha256_hex(without_digest.as_bytes()));
    }

    #[test]
    fn nostoi_refuses_floats_and_non_objects() {
        let at = "2026-09-27T21:00:00Z";
        assert!(nostoi_record(1, GENESIS, at, None, "k", None, json!({"x": 1.5})).is_err());
        assert!(nostoi_record(1, GENESIS, at, None, "k", None, json!([1])).is_err());
        assert!(nostoi_record(1, GENESIS, at, None, " ", None, json!({})).is_err());
    }
}
