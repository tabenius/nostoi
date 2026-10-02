wit_bindgen::generate!({ path: "wit", world: "audit" });

use exports::nostoi::audit::chains::{Draft, Guest};
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

export!(Component);
