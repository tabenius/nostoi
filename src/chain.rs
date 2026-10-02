//! The common shape of every chain Nostoi reads, and its verification.
//!
//! Each format maps its records onto [`Entry`]: a position (`seq`), the digest
//! it claims for its predecessor (`previous`), the digest it claims for itself
//! (`digest`), and the digest Nostoi recomputes from its content (`computed`).
//! [`verify`] then checks, in order, that the positions run 1, 2, 3…, that each
//! entry names its predecessor's digest (the first names the all-zero genesis
//! digest), and that each claimed digest is the recomputed one. The first
//! failure is the answer: everything before it is intact, nothing after it can
//! be trusted.

use serde::Serialize;
use serde_json::Value;
use std::fmt;

/// The digest the first entry of every chain names as its predecessor.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One record of a chain, in any format.
#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub seq: u64,
    pub previous: String,
    pub digest: String,
    /// The digest recomputed from the record's content.
    pub computed: String,
    /// When it was recorded (RFC 3339), if the format says.
    pub at: Option<String>,
    /// Who recorded it: an agent, person or service, if the format says.
    pub actor: Option<String>,
    /// What happened (an action or record kind).
    pub kind: String,
    /// What it is about: a Change Set, session, run…
    pub subject: Option<String>,
    /// The whole record, as stored.
    pub record: Value,
}

/// Why verification stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Problem {
    /// A record could not be read at all (line or row `at`).
    Unreadable { at: u64, detail: String },
    /// Positions do not run 1, 2, 3…: a record is missing or out of place.
    Sequence { seq: u64, expected: u64 },
    /// The record does not name its predecessor's digest.
    Link { seq: u64 },
    /// The record's content does not hash to the digest it claims.
    Digest { seq: u64 },
}

/// "records 1–7 are intact", "record 1 is intact", "no record is intact".
pub fn intact(verified: u64) -> String {
    match verified {
        0 => "no record is intact".to_string(),
        1 => "record 1 is intact".to_string(),
        n => format!("records 1–{n} are intact"),
    }
}

impl Problem {
    /// The position of the first record that cannot be trusted.
    pub fn position(&self) -> u64 {
        match self {
            Problem::Unreadable { at, .. } => *at,
            Problem::Sequence { seq, .. } | Problem::Link { seq } | Problem::Digest { seq } => *seq,
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::Unreadable { at, detail } => write!(f, "record {at} is unreadable: {detail}"),
            Problem::Sequence { seq, expected } => {
                write!(f, "record {seq} is out of sequence (expected {expected})")
            }
            Problem::Link { seq } => {
                write!(f, "record {seq} does not link to its predecessor")
            }
            Problem::Digest { seq } => {
                write!(
                    f,
                    "record {seq} was altered: its content does not match its digest"
                )
            }
        }
    }
}

/// What verifying a chain found.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub format: String,
    /// Records read.
    pub records: u64,
    /// Records verified, from the first: all of them when `ok`.
    pub verified: u64,
    /// The last verified record's position and digest: the head to anchor.
    pub head: Option<Head>,
    pub problem: Option<Problem>,
    pub ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Head {
    pub seq: u64,
    pub digest: String,
}

/// Full-chain verification plus an optional verified checkpoint position.
/// A checkpoint is only evidence of an intact prefix; callers must also check
/// `report.ok` before trusting the entire chain, including its suffix.
#[derive(Clone, Debug, Serialize)]
pub struct StreamingVerification {
    pub report: Report,
    pub checkpoint: Option<Head>,
}

/// Incremental verification state. Entries are borrowed, never retained.
pub(crate) struct Verifier {
    records: u64,
    head: Option<Head>,
    problem: Option<Problem>,
    checkpoint_seq: Option<u64>,
    checkpoint: Option<Head>,
}

impl Verifier {
    pub(crate) fn new(checkpoint_seq: Option<u64>) -> Self {
        Self {
            records: 0,
            head: None,
            problem: None,
            checkpoint_seq,
            checkpoint: None,
        }
    }

    pub(crate) fn push(&mut self, entry: &Entry) {
        self.push_columns(entry, None);
    }

    /// Native SQLite duplicates chain fields in columns. Check both views in
    /// the same sequence/link/digest order as ordinary chain verification.
    pub(crate) fn push_columns(&mut self, entry: &Entry, columns: Option<(i64, &str, &str)>) {
        self.records += 1;
        if self.problem.is_some() {
            return;
        }
        let expected = self.records;
        let previous = self.head.as_ref().map_or(GENESIS, |h| h.digest.as_str());
        self.problem = if entry.seq != expected
            || columns.is_some_and(|(seq, _, _)| seq < 1 || seq as u64 != entry.seq)
        {
            Some(Problem::Sequence {
                seq: entry.seq,
                expected,
            })
        } else if entry.previous != previous
            || columns.is_some_and(|(_, link, _)| link != entry.previous)
        {
            Some(Problem::Link { seq: entry.seq })
        } else if entry.digest != entry.computed
            || columns.is_some_and(|(_, _, digest)| digest != entry.digest)
        {
            Some(Problem::Digest { seq: entry.seq })
        } else {
            None
        };
        if self.problem.is_none() {
            let head = Head {
                seq: entry.seq,
                digest: entry.digest.clone(),
            };
            if self.checkpoint_seq == Some(entry.seq) {
                self.checkpoint = Some(head.clone());
            }
            self.head = Some(head);
        }
    }

    pub(crate) fn finish(self, format: &str, unreadable: Option<Problem>) -> StreamingVerification {
        let problem = self.problem.or(unreadable);
        StreamingVerification {
            report: Report {
                format: format.to_string(),
                records: self.records,
                verified: self.head.as_ref().map_or(0, |h| h.seq),
                ok: problem.is_none(),
                head: self.head,
                problem,
            },
            checkpoint: self.checkpoint,
        }
    }
}

/// Check that `entries` form an unbroken chain from the genesis digest.
/// `unreadable` is a read error met after the last entry, if any.
pub fn verify(format: &str, entries: &[Entry], unreadable: Option<Problem>) -> Report {
    let mut verifier = Verifier::new(None);
    for entry in entries {
        verifier.push(entry);
    }
    verifier.finish(format, unreadable).report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: u64, previous: &str, digest: &str) -> Entry {
        Entry {
            seq,
            previous: previous.into(),
            digest: digest.into(),
            computed: digest.into(),
            at: None,
            actor: None,
            kind: "k".into(),
            subject: None,
            record: Value::Null,
        }
    }

    #[test]
    fn an_intact_chain_verifies_to_its_head() {
        let chain = [entry(1, GENESIS, "a1"), entry(2, "a1", "b2")];
        let report = verify("t", &chain, None);
        assert!(report.ok);
        assert_eq!(
            report.head,
            Some(Head {
                seq: 2,
                digest: "b2".into()
            })
        );
    }

    #[test]
    fn the_first_break_is_reported_and_nothing_after_it_counts() {
        let mut altered = entry(2, "a1", "b2");
        altered.computed = "zz".into();
        let chain = [entry(1, GENESIS, "a1"), altered, entry(3, "b2", "c3")];
        let report = verify("t", &chain, None);
        assert_eq!(report.problem, Some(Problem::Digest { seq: 2 }));
        assert_eq!((report.verified, report.records), (1, 3));

        let gap = [entry(1, GENESIS, "a1"), entry(3, "a1", "c3")];
        assert_eq!(
            verify("t", &gap, None).problem,
            Some(Problem::Sequence {
                seq: 3,
                expected: 2
            })
        );

        let unlinked = [entry(1, GENESIS, "a1"), entry(2, "xx", "b2")];
        assert_eq!(
            verify("t", &unlinked, None).problem,
            Some(Problem::Link { seq: 2 })
        );

        let wrong_start = [entry(1, "a0", "a1")];
        assert_eq!(
            verify("t", &wrong_start, None).problem,
            Some(Problem::Link { seq: 1 })
        );
    }
}
