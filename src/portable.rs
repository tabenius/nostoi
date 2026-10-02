//! Host-independent operations shared by Python and WIT components.
//!
//! JSON is exchanged as text so JavaScript cannot silently round 64-bit
//! integers. Hosts own persistence, locking and clocks. Appending returns a
//! complete replacement JSONL value; it does not write a file.

use crate::{canonical, format, jsonl, Draft, Error, Format, Result, GENESIS};

pub fn canonical_json(json: &str) -> Result<String> {
    let value = serde_json::from_str(json).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(canonical::to_string(&value))
}

/// Report a broken chain as `ok: false`; reject unknown formats as errors.
pub fn verify_jsonl(text: &str, format: Option<&str>) -> Result<String> {
    let format = format
        .map(str::parse::<Format>)
        .transpose()
        .map_err(Error::Invalid)?;
    let report = jsonl::read(text.as_bytes(), format)?.verify();
    serde_json::to_string(&report).map_err(|e| Error::Invalid(e.to_string()))
}

/// Extend a verified Nostoi chain. An explicit timestamp avoids a host clock
/// dependency. Hosts must atomically persist the returned text under a lock.
pub fn append_jsonl(text: &str, draft: Draft<'_>) -> Result<String> {
    let at = draft
        .at
        .ok_or_else(|| Error::Invalid("an explicit RFC 3339 timestamp is required".into()))?;
    ::time::OffsetDateTime::parse(&at, &::time::format_description::well_known::Rfc3339)
        .map_err(|e| Error::Invalid(format!("invalid timestamp: {e}")))?;
    let report = jsonl::read(text.as_bytes(), Some(Format::Nostoi))?.verify();
    if let Some(problem) = report.problem {
        return Err(Error::Broken(problem));
    }
    let (seq, previous) = match report.head {
        Some(head) => (
            head.seq
                .checked_add(1)
                .ok_or_else(|| Error::Invalid("sequence overflow".into()))?,
            head.digest,
        ),
        None => (1, GENESIS.into()),
    };
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
    let mut result = text.to_owned();
    if !result.is_empty() && !result.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&canonical::to_string(&record));
    result.push('\n');
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn draft() -> Draft<'static> {
        Draft {
            actor: Some("agent:test"),
            kind: "test",
            subject: None,
            body: serde_json::json!({"unicode": "🦆", "large": u64::MAX}),
            at: Some("2026-09-27T12:00:00Z".into()),
        }
    }
    #[test]
    fn roundtrip_tamper_and_missing_newline() {
        let one = append_jsonl("", draft()).unwrap();
        let two = append_jsonl(one.trim_end(), draft()).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&verify_jsonl(&two, None).unwrap()).unwrap();
        assert_eq!(report["verified"], 2);
        let broken = two.replacen("agent:test", "agent:other", 1);
        assert!(matches!(
            append_jsonl(&broken, draft()),
            Err(Error::Broken(_))
        ));
        assert!(verify_jsonl(&broken, None)
            .unwrap()
            .contains("\"ok\":false"));
        assert!(verify_jsonl("", Some("unknown")).is_err());
        let mut missing = draft();
        missing.at = None;
        assert!(append_jsonl("", missing).is_err());
        let mut invalid = draft();
        invalid.at = Some("yesterday".into());
        assert!(append_jsonl("", invalid).is_err());
    }
}
