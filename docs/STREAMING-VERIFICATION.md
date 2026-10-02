# Streaming chain and remote-checkpoint verification

`nostoi::verify_streaming(path, format, checkpoint_seq)` verifies a complete
local history from genesis and returns a `StreamingVerification` containing:

- `report`: the usual `Report` (format, records read, intact prefix length,
  last verified head, first problem, and `ok`).
- `checkpoint`: the verified `Head` at the requested sequence, or `None` if
  no sequence was requested, the position is absent, or it is outside the
  intact prefix. Sequence zero has no record and returns `None`.

```rust,no_run
let checked = nostoi::verify_streaming(
    std::path::Path::new("audit.jsonl"), None, Some(100),
)?;
assert!(checked.report.ok);
let checkpoint = checked.checkpoint.expect("trusted position must exist");
// Compare checkpoint.digest with an independently trusted checkpoint digest.
# Ok::<(), nostoi::Error>(())
```

An intact checkpoint prefix does **not** imply an intact suffix. Always inspect
`report.ok` before accepting the whole local history. `anchor::verify_anchor`
fetches the explicitly selected remote object, checks its identity, scans the
entire local chain, and compares the digest collected at its position. It rejects
broken prefixes and suffixes, empty histories, tails shorter than the checkpoint,
and fully rehashed histories whose checkpoint differs. It neither skips the tail
nor persists or trusts a local verification watermark. Remote retention policy
and selection of an independently trusted endpoint/bucket/key remain the caller's
responsibility, as in the existing anchor API.

## Formats and snapshots

The API supports native Nostoi JSONL and SQLite, WeftMark JSONL, and Ephor JSONL
and SQLite. JSONL format detection examines the first nonblank parsed record.
Ephor JSONL uses the exported `EphorEvent::entry().record` shape: `chain_sequence`,
`id`, `node_id`, `aggregate_id`, `agent_class`, `action`, `arguments` (an array
of strings), `outcome`, `occurred_at_ms`, `caller_stack` (an array of strings),
`previous_hash`, and `signature`. Explicit `Format::EphorAudit` is also supported.
This adds Ephor JSONL support to the loaded reader as well.

SQLite verification opens a read-only connection and transaction. Table detection,
all rows, the collected checkpoint, and the resulting head belong to one snapshot.
A concurrent WAL append can commit without changing that snapshot; a subsequent
verification sees the appended record. No schema changes are required. Native
rows are streamed in `seq` order; Ephor rows in `chain_sequence` order. Native
verification also checks that the stored `seq`, `previous`, and `digest` columns
agree with the embedded JSON record, in sequence/link/digest failure order.

JSONL uses `BufReader` line iteration, preserving blank-line handling, physical
line numbers for unreadable records, invalid UTF-8 errors, and acceptance of a
complete final record without a newline. A partial final record is unreadable.
JSONL files are not transactional snapshots: callers requiring isolation from
concurrent edits must coordinate access. Verification does not impose a read lock.

## Report compatibility and deliberate tightening

The loaded/browse APIs continue to return their entries. Loaded and streaming
verification share the incremental sequence/link/digest verifier, and both readers
share their per-record parsing paths. Existing format entry conversion, canonical
JSON, lexical number preservation, and Ephor length-prefixed hashing are reused.

Successful parsed records count toward `report.records`, including records after
the first chain failure. Scanning continues after a chain failure until EOF or
the first read/parse failure, preserving loaded-verification counts. An unreadable
record is not counted. A prior chain failure wins over a later reported unreadable
record. File-open, SQL statement/iteration, and native SQLite column conversion
errors remain API errors, rather than being silently hidden in a report; Ephor
field conversion errors remain unreadable-row problems as in the loaded reader.

`nostoi::verify` now uses the streaming path, so `prepare_anchor` does too.
JSONL append verification also streams while retaining its existing exclusive
file lock. `Store::open_verified` and writer re-verification use the same native
streaming verifier.

The intentional tightening is native SQLite column/JSON consistency:
`verify`, remote verification, and anchor preparation now reject contradictory
columns that the old loaded verifier did not inspect. `Store::open_verified`
already checked this consistency. The loaded `Entry` view still verifies embedded
records alone, so `open(...).verify()` can differ for a database with contradictory
columns. First-failure positions and counts otherwise match loaded verification.
Store verification now scans through chain failures for the common report
semantics, and malformed native JSON uses its stored row sequence in the
unreadable problem (matching the loaded reader).

## Memory and cost

Verification is O(n) in records (and linear in the bytes parsed/hashed), with
record memory bounded by the largest individual line/row, rather than the whole
chain. The scanner retains one record at a time; the verifier retains a count,
the first problem, the last verified head, and at most one checkpoint head. Format
parsing and canonical hashing may allocate multiple representations of that one
record. A single huge record can therefore still allocate substantial memory;
there is no record-size limit and no claim of constant total process memory.
SQLite also has its own page cache and may use temporary sorting resources,
particularly for an Ephor table without a sequence index. SQLite memory is not
a retained Rust `Vec<Entry>` and is subject to SQLite's own resource policies.

`tests/streaming_verify.rs` covers loaded/streaming parity, prefixes and suffixes,
checkpoint absence and rewrite detection, JSONL EOF/UTF-8/read failures, lexical
numbers, format vectors, and SQLite column consistency. The SQLite unit tests
exercise deterministic concurrent-WAL snapshot behavior. Existing remote HTTP
tests exercise truncation, rewritten histories, identity checks, and CLI use.
