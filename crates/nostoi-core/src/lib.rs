//! # Nostoi core
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
//! - `ephor-audit-v1`, Ephor's `governance_events`.
//!
//! and writes `nostoi-v1`, whose digest any language can compute: SHA-256 of
//! the record's canonical JSON without its `digest`, where canonical JSON is
//! Python's `json.dumps(record, sort_keys=True, separators=(",", ":"))`.
//!
//! ```no_run
//! use nostoi_core::{append, verify, Draft};
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
//! # Ok::<(), nostoi_core::Error>(())
//! ```
//!
//! *Nostoi* (Νόστοι, "homecomings") are the lost epic poems of the Greek heroes'
//! journeys home: records that should have survived and did not.

pub mod attestation;
pub mod bundle;
pub mod canonical;
pub mod chain;
mod error;
pub mod format;
pub mod jsonl;
pub mod portable;
#[cfg(feature = "sqlite")]
pub mod schema;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod time;

pub use attestation::{Attestation, Attested, Coverage, Described, Sidecars, ATTESTATION_V1};
pub use chain::{Entry, Head, Problem, Report, StreamingVerification, GENESIS};
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

/// Verify the entire chain at `path` with record memory bounded by its largest
/// record. See [`verify_streaming`] to also collect a checkpoint position.
pub fn verify(path: &Path, format: Option<Format>) -> Result<Report> {
    Ok(verify_streaming(path, format, None)?.report)
}

/// Verify the entire chain from genesis, optionally collecting the digest at
/// `checkpoint_seq`. No local watermark is trusted and the suffix is checked.
/// Memory for records is bounded by the largest record, not chain length.
/// SQLite reads use one coherent snapshot; JSONL reads use buffered lines.
/// A returned checkpoint can describe an intact prefix of a broken chain:
/// always check `report.ok` before accepting the full history.
pub fn verify_streaming(
    path: &Path,
    format: Option<Format>,
    checkpoint_seq: Option<u64>,
) -> Result<StreamingVerification> {
    #[cfg(feature = "sqlite")]
    if sqlite::is_sqlite(path) {
        return sqlite::verify_streaming(path, format, checkpoint_seq);
    }
    jsonl::verify_reader(
        std::fs::File::open(path).map_err(error::io(path))?,
        format,
        checkpoint_seq,
    )
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
