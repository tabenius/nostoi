wit_bindgen::generate!({ path: "wit", world: "audit" });

use exports::nostoi::audit::attestations::Guest as Attestations;
use exports::nostoi::audit::chains::{Draft, Guest};
use std::io::Cursor;

struct Component;

impl Guest for Component {
    fn canonical_json(json: String) -> Result<String, String> {
        nostoi::portable::canonical_json(&json).map_err(|e| e.to_string())
    }
    fn verify_jsonl(jsonl: String, format: Option<String>) -> Result<String, String> {
        nostoi::portable::verify_jsonl(&jsonl, format.as_deref()).map_err(|e| e.to_string())
    }
    fn append_jsonl(jsonl: String, entry: Draft) -> Result<String, String> {
        let body = serde_json::from_str(&entry.body_json).map_err(|e| e.to_string())?;
        nostoi::portable::append_jsonl(
            &jsonl,
            nostoi::Draft {
                at: Some(entry.at),
                actor: entry.actor.as_deref(),
                kind: &entry.kind,
                subject: entry.subject.as_deref(),
                body,
            },
        )
        .map_err(|e| e.to_string())
    }
}

impl Attestations for Component {
    fn canonical_bytes(document: String) -> Result<String, String> {
        let attestation = parse(&document)?;
        attestation.validate().map_err(|e| e.to_string())?;
        let bytes = attestation.canonical_bytes().map_err(|e| e.to_string())?;
        // Canonical bytes are ASCII by construction; a lossy conversion here
        // would hand back a digest that no longer matches the signature.
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    fn verify_document(
        jsonl: String,
        document: String,
        format: Option<String>,
    ) -> Result<String, String> {
        let attestation = parse(&document)?;
        attestation.validate().map_err(|e| e.to_string())?;
        let format = match format {
            None => None,
            Some(name) => Some(name.parse::<nostoi::Format>().map_err(|e: String| e)?),
        };
        // Stop the scan at the attested sequence: an attestation is about the
        // chain as it stood then, and the records after it are its own receipt.
        let verification = nostoi::jsonl::verify_reader(
            Cursor::new(jsonl.as_bytes()),
            format,
            Some(attestation.seq),
        )
        .map_err(|e| e.to_string())?;
        let checked = nostoi::attestation::check_verification(&attestation, verification)
            .map_err(|e| e.to_string())?;
        let report = serde_json::json!({
            "ok": true,
            // There is no allowed-signers file here, so no signature was checked.
            "signature": "unchecked",
            "chain": attestation.chain,
            "format": attestation.format,
            "seq": attestation.seq,
            "digest": attestation.digest,
            "anchored_at": attestation.anchored_at,
            "principal": attestation.principal,
            "fingerprint": attestation.fingerprint,
            "title": attestation.title,
            "manifest": attestation.manifest,
            "author": attestation.author,
            "document_digest": attestation.digest().ok(),
            "coverage": match checked.coverage {
                nostoi::attestation::Coverage::Current => serde_json::json!("current"),
                nostoi::attestation::Coverage::Stale { ahead_by } => {
                    serde_json::json!({"stale": true, "ahead_by": ahead_by})
                }
                nostoi::attestation::Coverage::Truncated => serde_json::json!("truncated"),
                nostoi::attestation::Coverage::Rewritten => serde_json::json!("rewritten"),
                nostoi::attestation::Coverage::Empty => serde_json::json!("empty"),
            },
            "covers_head": checked.covers_head(),
            "head": checked.head,
        });
        serde_json::to_string(&report).map_err(|e| e.to_string())
    }
}

fn parse(document: &str) -> Result<nostoi::attestation::Attestation, String> {
    serde_json::from_str(document).map_err(|e| format!("invalid attestation: {e}"))
}

export!(Component);
