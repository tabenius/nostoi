//! # Nostoi
//!
//! Tamper-evident audit chains: verify them, append to them, stream them and
//! browse them.
//!
//! This package is the compatibility facade. The implementation now lives in
//! three crates, one per compartment:
//!
//! - [`nostoi_core`] formats, streaming verification and local audit storage.
//!   Portable, and the only one of the three with no network or platform
//!   assumptions.
//! - `nostoi-anchor` (with the `s3` feature) checkpoints to S3-compatible
//!   storage, verifies them again, and recovers interrupted publications.
//! - `nostoi-kmsg` (with the `kmsg` feature) reads the Linux kernel ring
//!   buffer into a chain.
//!
//! Every `nostoi::` path below is a re-export, so existing code keeps
//! compiling against this crate. New code should depend on the compartment it
//! actually needs, and get an order of magnitude less to compile and audit.

#[cfg(feature = "s3")]
pub mod anchor {
    pub use nostoi_anchor::anchor::*;
    pub use nostoi_anchor::{Error, Result};
    #[cfg(feature = "sqlite")]
    pub mod outbox {
        pub use nostoi_anchor::outbox::*;
    }
}

pub mod attestation {
    pub use nostoi_core::attestation::*;
}
pub mod attest;
pub mod canonical {
    pub use nostoi_core::canonical::*;
}
pub mod chain {
    pub use nostoi_core::chain::*;
}
mod error;
pub mod format {
    pub use nostoi_core::format::*;
}
pub mod jsonl {
    pub use nostoi_core::jsonl::*;
}
#[cfg(all(feature = "kmsg", target_os = "linux"))]
pub mod kmsg {
    pub use nostoi_kmsg::*;
}
#[cfg(all(feature = "s3", feature = "sqlite"))]
pub mod outbox {
    pub use nostoi_anchor::outbox::*;
}
pub mod portable {
    pub use nostoi_core::portable::*;
}
#[cfg(feature = "s3")]
pub mod s3 {
    pub use nostoi_anchor::s3::*;
}
#[cfg(feature = "sqlite")]
pub mod schema {
    pub use nostoi_core::schema::*;
}
#[cfg(feature = "sqlite")]
pub mod sqlite {
    pub use nostoi_core::sqlite::*;
}
pub mod time {
    pub use nostoi_core::time::*;
}
#[cfg(feature = "tui")]
pub mod tui;

pub use chain::{Entry, Head, Problem, Report, StreamingVerification, GENESIS};
pub use error::{Error, Result};
pub use format::Format;
pub use jsonl::{Draft, Loaded};

use std::path::Path;

/// Read the chain at `path`: a JSONL file, or (with the `sqlite` feature) an
/// SQLite database. The format is detected unless given.
pub fn open(path: &Path, format: Option<Format>) -> Result<Loaded> {
    nostoi_core::open(path, format).map_err(Error::from)
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
    nostoi_core::verify_streaming(path, format, checkpoint_seq).map_err(Error::from)
}

/// Append a `nostoi-v1` record to the chain at `path`, creating it if needed:
/// the SQLite store for an existing SQLite file or a new `.sqlite`/`.db`
/// path, JSON Lines otherwise. A broken chain is never extended.
pub fn append(path: &Path, draft: Draft<'_>) -> Result<Entry> {
    nostoi_core::append(path, draft).map_err(Error::from)
}
