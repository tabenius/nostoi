//! Core host-independent operations shared by Python and WIT components.
//!
//! JSON is exchanged as text so JavaScript cannot silently round 64-bit
//! integers. Hosts own persistence, locking and clocks. Appending returns a
//! complete replacement JSONL value or an append-only delta; neither writes a
//! file. Verification retains only the current parsed record, not the history.

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
    let report = jsonl::verify_reader(text.as_bytes(), format, None)?.report;
    serde_json::to_string(&report).map_err(|e| Error::Invalid(e.to_string()))
}

/// Extend a verified Nostoi chain. An explicit timestamp avoids a host clock
/// dependency. Hosts must atomically persist the returned text under a lock.
pub fn append_jsonl(text: &str, draft: Draft<'_>) -> Result<String> {
    let delta = append_delta_jsonl(text, draft)?;
    let mut result = String::with_capacity(text.len() + delta.len());
    result.push_str(text);
    result.push_str(&delta);
    Ok(result)
}

/// Verify the entire supplied history and return only the bytes to append.
/// Includes a leading newline when needed to preserve the last record boundary.
/// The host must keep the history unchanged between verification and durable
/// append (lock or compare-and-swap), and must not treat this as an approval or
/// a persistence receipt. This API neither authenticates nor encrypts records.
pub fn append_delta_jsonl(text: &str, draft: Draft<'_>) -> Result<String> {
    let at = draft
        .at
        .ok_or_else(|| Error::Invalid("an explicit RFC 3339 timestamp is required".into()))?;
    ::time::OffsetDateTime::parse(&at, &::time::format_description::well_known::Rfc3339)
        .map_err(|e| Error::Invalid(format!("invalid timestamp: {e}")))?;
    let report = jsonl::verify_reader(text.as_bytes(), Some(Format::Nostoi), None)?.report;
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
    let mut result = String::new();
    if !text.is_empty() && !text.ends_with('\n') {
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

    #[test]
    fn delta_preserves_bytes_and_record_boundaries() {
        let one = append_jsonl("", draft()).unwrap();
        for prefix in ["", "\n", one.as_str(), one.trim_end()] {
            let delta = append_delta_jsonl(prefix, draft()).unwrap();
            let extended = format!("{prefix}{delta}");
            assert_eq!(extended, append_jsonl(prefix, draft()).unwrap());
            let report: serde_json::Value =
                serde_json::from_str(&verify_jsonl(&extended, None).unwrap()).unwrap();
            assert_eq!(report["ok"], true);
            assert_eq!(delta.trim().lines().count(), 1);
            assert_eq!(
                delta.starts_with('\n'),
                !prefix.is_empty() && !prefix.ends_with('\n')
            );
        }
        let two = append_jsonl(&one, draft()).unwrap();
        // Delta output depends on the new record, not on the size of the prefix.
        assert_eq!(
            append_delta_jsonl(&one, draft()).unwrap().len(),
            append_delta_jsonl(&two, draft()).unwrap().len()
        );
    }

    #[test]
    fn delta_refuses_tampering_gaps_bad_links_and_unreadable_tails() {
        let one = append_jsonl("", draft()).unwrap();
        let two = append_jsonl(&one, draft()).unwrap();
        for broken in [
            two.replacen("agent:test", "agent:other", 1),
            two.replacen("\"seq\":2", "\"seq\":3", 1),
            two.replacen("\"previous\":\"", "\"previous\":\"bad", 1),
            format!("{two}{{"),
        ] {
            assert!(matches!(
                append_delta_jsonl(&broken, draft()),
                Err(Error::Broken(_))
            ));
            // Preserve report counts, first-failure precedence and format detection.
            let loaded = jsonl::read(broken.as_bytes(), None).unwrap().verify();
            assert_eq!(
                verify_jsonl(&broken, None).unwrap(),
                serde_json::to_string(&loaded).unwrap()
            );
        }
        let mut missing = draft();
        missing.at = None;
        assert!(append_delta_jsonl(&one, missing).is_err());
        let mut invalid = draft();
        invalid.at = Some("yesterday".into());
        assert!(append_delta_jsonl(&one, invalid).is_err());
    }
}
