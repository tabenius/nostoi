//! # Nostoi
//!
//! Tamper-evident audit chains, one library for all of them: verify them,
//! append to them, stream them and browse them.
//!
//! A chain is a sequence of records where each record carries the digest of
//! the one before it and a digest of its own content. Change, remove or
//! reorder any record and verification names the first one that no longer
//! fits; everything before it is intact.
//!
//! Nostoi reads three formats (see [`format`]):
//!
//! - `nostoi-v1`, its own, as JSON Lines or an append-only SQLite store;
//! - `weftmark-ledger-v1`, WeftMark's `ledger.jsonl`;
//! - `kagp-audit-v1`, Ephor's `governance_events`.
//!
//! and writes `nostoi-v1`, whose digest any language can compute: SHA-256 of
//! the record's canonical JSON without its `digest`, where canonical JSON is
//! Python's `json.dumps(record, sort_keys=True, separators=(",", ":"))`.
//!
//! ```no_run
//! use nostoi::{append, verify, Draft};
//! use serde_json::json;
//!
//! let path = std::path::Path::new("audit.jsonl");
//! append(path, Draft {
//!     actor: Some("agent:claude"),
//!     kind: "tool.call",
//!     subject: Some("cs-42"),
//!     body: json!({"tool": "weft_handoff_create"}),
//!     at: None,
//! })?;
//! let report = verify(path, None)?;
//! assert!(report.ok);
//! # Ok::<(), nostoi::Error>(())
//! ```
//!
//! *Nostoi* (Νόστοι, "homecomings") are the lost epic poems of the Greek heroes'
//! journeys home: records that should have survived and did not.

pub mod canonical;
pub mod chain;
mod error;
pub mod format;
pub mod jsonl;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod time;
#[cfg(feature = "tui")]
pub mod tui;

pub use chain::{Entry, Head, Problem, Report, GENESIS};
pub use error::{Error, Result};
pub use format::Format;
pub use jsonl::{Draft, Loaded};

use std::path::Path;

/// Read the chain at `path`: a JSONL file, or (with the `sqlite` feature) an
/// SQLite database. The format is detected unless given.
pub fn open(path: &Path, format: Option<Format>) -> Result<Loaded> {
    #[cfg(feature = "sqlite")]
    if sqlite::is_sqlite(path) {
        return sqlite::load(path, format);
    }
    jsonl::load(path, format)
}

/// Verify the chain at `path`.
pub fn verify(path: &Path, format: Option<Format>) -> Result<Report> {
    Ok(open(path, format)?.verify())
}

/// Append a `nostoi-v1` record to the chain at `path`, creating it if needed:
/// the SQLite store for an existing SQLite file or a new `.sqlite`/`.db`
/// path, JSON Lines otherwise. A broken chain is never extended.
pub fn append(path: &Path, draft: Draft<'_>) -> Result<Entry> {
    #[cfg(feature = "sqlite")]
    {
        let sqlite_name = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("sqlite" | "sqlite3" | "db")
        );
        if sqlite::is_sqlite(path) || (!path.exists() && sqlite_name) {
            return sqlite::Store::open(path)?.append(draft);
        }
    }
    jsonl::append(path, draft)
}
