# Detailed Implementation Plan

## Implementation status — 2026-10-02

This section supersedes the speculative sketches below. The filenames retain
their original dates, but the current work is dated 2026-10-02.

### Implemented and verified

- **SQLite concurrent writers:** `BEGIN IMMEDIATE` plus an indexed head lookup.
  If the head has changed, re-verify the complete chain before adopting it.
  An ordinary competing append is not classified as a broken chain. The daemon's
  catch-all reopen/retry was removed; this behavior now belongs to `Store`.
- **Startup memory:** verification streams rows, retaining one parsed record
  and the current head. It checks both JSON chain fields and SQLite columns.
  Full verification remains O(total bytes), but memory no longer grows with the
  whole chain. No local watermark is treated as trusted evidence.
- **kmsg correctness/performance:** overrun gaps counted once, saturating
  arithmetic, immediate durable `kmsg.overrun` marker, reusable read buffer,
  and bounded growth to 1 MiB on EINVAL (the kernel's too-small-buffer error).
  Unknown loss before the first sequence remains unknown, not invented.
- **Anchoring:** broken chains rejected before network I/O; format comes from
  verification; retention days bounded; explicit unsafe key segments rejected.
  A conditional PUT conflict triggers GET and comparison of the existing anchor's
  version, chain identity, format, sequence, digest and key. A match is reconciled;
  a mismatch fails. For requested Object Lock, GET retention must confirm the
  mode and at least the requested expiry. A later request for longer retention
  can therefore fail on an existing immutable object rather than claim success.
- **S3 transport:** redirects disabled; bounded retries (three attempts, 100/200
  ms backoff) for GET and conditional PUT on transport errors or selected transient
  HTTP statuses. Ambiguous conditional PUT retries are reconciled through GET.
  Header whitespace normalized. Credentials no longer derive Debug.
- **CLI/service:** key and chain ID defaults enabled; R2 uses path-style URLs
  automatically. Service template uses DynamicUser, StateDirectory, restrictive
  umask, SyslogIdentifier and TimeoutStopSec. Nothing has been installed.
- **Regression coverage:** concurrent SQLite writers, overrun double-counting,
  broken-chain anchoring, and real local HTTP PUT/checksum/retention/conflict
  exchanges, alongside the AWS SigV4 worked-example vector.

### Follow-up verification queue

Follow-up branch `codex/anchor-failure-paths` adds an injectable thread-safe
signing clock and re-signs every retry, including across UTC midnight. Tests
cover deterministic signatures, GET/conditional-PUT transient retry timestamps,
identical and mismatched 412 anchor reconciliation, absent retention, wrong mode,
short retention, and successful verified retention. The all-feature suite now
passes 41 unit tests, 10 integration tests and one doctest; strict Clippy passes.

Recovery follow-up (`codex/ingest-recovery`) verifies a PUT whose response is
lost after the mock stores it: retry uses the same payload and conditional key,
receives 412, then GET reconciles the existing anchor. A 403 is not retried.
Kernel fault-injection tests exercise EPIPE followed by EAGAIN then a record,
EINTR retry, EINVAL buffer growth, and the 1 MiB allocation ceiling. No exact
loss count is reported until a subsequent sequence number makes it knowable.

### Updated benchmark — 2026-10-02

Command: `cargo run --release --example scale -- /home/xyzzy/.cache`.
Parent filesystem: ext4 (`findmnt -T`), not tmpfs. SQLite remains WAL with
`synchronous=FULL`; one commit per append. The benchmark now creates an isolated
temporary directory rather than deleting fixed filenames.

| Chain size at end of measured window | SQLite re-verify every append | Verified long-lived writer |
| --- | ---: | ---: |
| 500 | 1.5925 ms/append | 0.7094 ms/append |
| 1,000 | 3.1440 ms/append | 0.4447 ms/append |
| 2,000 | 5.5308 ms/append | 0.4439 ms/append |
| 4,000 | 10.5152 ms/append | 0.4380 ms/append |
| 10,000 | not measured | 0.6604 ms/append |
| 20,000 | not measured | 0.4447 ms/append |

These are window averages, not cumulative averages or latency percentiles.
Full streaming startup verification took 13.927 ms for 4,000 records and
75.127 ms for 20,000. This single local run supports removing the per-append
linear scan; it does not establish production throughput or peak memory.

Remaining queue:

1. Extend ambiguous-upload coverage to locked objects and exhausted retries.
2. Validate kernel-device behavior on additional distro/kernel configurations.
3. Add clock-skew diagnostics. Do not fabricate a
   skew offset; synchronize the host clock instead.
4. Measure startup peak memory and append latency percentiles at larger sizes.
5. Test against a real Object-Lock-enabled S3 bucket and an R2 locked prefix
   when deployment credentials are available. R2 bucket locking is configured
   out of band and cannot be verified through GetObjectRetention.

The earlier proposed backwards-only verification and local verified watermark
are not substitutes for full verification against a trusted external checkpoint.
Likewise, a stale cached head is not evidence of tampering by itself.

## 1. P0: Translate trigger failures to Broken (TOCTOU)
**File**: `src/sqlite.rs`
**Goal**: When another writer moves the head between cache read and INSERT, the trigger causes `rusqlite::Error` that must become `Error::Broken(Problem)`.

### Approach
- In `Store::append()`, after computing `(seq, previous)` (cached or from load), attempt INSERT inside the transaction.
- On `tx.execute(...)` failure:
  - Capture the error string/message/code.
  - If it indicates a chain/head constraint (contains "nostoi", "head", "previous", "chain", or is a constraint failure), re-verify within the same transaction via `load_nostoi(&tx)?.verify()`. If verification yields a `problem`, return `Error::Broken(problem)`. Otherwise return the original error wrapped.
  - Also consider detecting head change explicitly: `SELECT MAX(seq), digest FROM nostoi_records` and compare to cached head before/after; if mismatch, re-verify.
- Keep the trigger as source of truth; translation is purely for error semantics.

### Changes
- Modify `append()` to handle INSERT errors with translation.
- Add helper to classify constraint errors.

### Tests
- Simulate concurrent append: open two `Store::open_verified` on same DB, append from first (updates head), append from second with stale cached head → should return `Error::Broken` (or a precise broken-chain error) rather than a raw SQLite constraint error. Add a unit test using `tempfile`.

### Acceptance
- Test passes; API semantics preserved; no behavior change on intact chain.

## 2. P0: Anchor idempotency + robust status handling
**Files**: `src/anchor.rs`, `src/s3.rs`

### 2a S3: surface non-2xx clearly and allow idempotent 412
- In `s3::Client::put_object`, when `only_if_absent` and `response.status==412`, do not immediately error with a generic string; instead return a structured result or a specific error variant? Or have `put_object` return `Result<PutResult, PutError>` with `AlreadyExists` variant. But `Error` enum is flat.
- Option A: add `Error::S3Conflict(String)` or detect "already exists (If-None-Match: *)" in caller and branch. Simpler: in caller, inspect the error message? Or change `put_object` to return `Result<PutResult>` but on 412 with `only_if_absent`, return a new error variant `Error::Exists` or keep string but let caller match on context.
- Better: extend `Error` with `#[cfg(feature="s3")] #[error("s3: conflict: {0}")] Conflict(String)` or detect in `anchor_head` by calling a separate existence check. Alternatively, on 412+only_if_absent, do not error from `put_object`; instead return `PutResult{ etag: None, existed: true }`. Add `existed: bool` to `PutResult`.

**Changes to s3.rs**:
```rust
pub struct PutResult {
  pub etag: Option<String>,
  pub existed: bool, // 412 when If-None-Match:*
}
```
On 412 + only_if_absent: return `Ok(PutResult{etag:None, existed:true})` (do not error). On other non-2xx: still error.

### 2b Anchor: idempotent re-anchoring
- In `anchor_head`, after `put_object`, if `result.existed`, fetch the existing anchor (prefer `HEAD` not available? Or `GET` the key) and compare: `chain`, `format`, `seq`, `digest`. If match → return that existing anchor (idempotent success). If different → return `Error::Conflict` describing mismatch (object exists with different head).
- Implement a small `get_anchor(key)` using `Client::send("GET",...)` (or add method). Parse returned JSON back to `Anchor` (serde).
- Only do this when `only_if_absent` was requested (or always on conflict) to avoid extra GETs.

**Changes to anchor.rs**:
- Add `fn get_anchor(client: &Client, key: &str) -> Result<Anchor>`
- On `existed==true`, fetch and compare; return existing or error.

### Tests
- Mock returning 412 on second PUT with same key; ensure anchor_head returns success with same anchor fields (idempotent). Another case: different head at same key → error.

## 3. P0: Anchor key sanitization
**File**: `src/anchor.rs`

### Changes to `generate_key` and key handling
- For `chain_id`, compute slug from `std::path::Path::new(&chain_id).file_name()` or basename; fallback to full if no basename. Also strip any leading `.` components.
- Sanitize: allow only `[A-Za-z0-9._-]` in slug; replace others with `_`. Collapse `__`, trim leading/trailing `_`. If empty → `chain`.
- Truncate to 40 chars as is; if truncation happened, append a short 6-char hex of the original slug (or of chain_id hash) to reduce collision risk: e.g. `heads/{slug}-{short}-{seq:08x}-{prefix}.json` or simpler `...{slug}-{orig_hash6}-{seq:08x}-{p}.json`.
- For user-supplied `key` (non-empty): validate it contains no `..`, no control chars, and is a single path component under `heads/`? Or just reject `..` and leading `/`. Also normalize to not start with `/`. Return error if invalid.

### Acceptance
- Absolute paths don't produce leading `_`; keys are safe.

## 4. P0: kmsg loss accounting on overrun before next record
**File**: `src/kmsg.rs`

### Approach
- Add state: `overrun_pending: bool` (or count pending). When `read()` returns `-EPIPE`, set `overrun_pending = true` and `lost += ?` but we don't know yet. The gap is `(next.seq - last.seq - 1)` when next record arrives. So on `Event::Overrun`, set a flag: `self.overrun_pending = true`.
- In `emit()` (or when emitting next record), if `overrun_pending` is true, we know a gap exists before this record: compute `lost_since_last` and add to `self.lost`, then clear `overrun_pending`. Also set `overrun_pending=false` on first record after open?
- But also handle the case where after overrun we get EAGAIN/Empty and never get another record? Then the lost count is "pending" — we must expose it. Add `pub fn pending_lost(&self) -> u64` and/or ensure `take_lost()` returns pending if overrun happened but no record followed? Or when the reader is being torn down, write a marker. But in streaming, better: on `next_event()` returning `Empty` after `overrun_pending` was set, we can still account by noting the kernel's sequence numbers moved? Not directly visible without reading the next record. The ABI states "seek position be updated to the next available record" on -EPIPE; but we don't see sequence until we read. So pending loss is only quantifiable when the next record arrives.
- Document this behavior. Also in the daemon (`kmsg-nostoi.rs`), when we get `Event::Overrun`, log it (rate-limited) and remember `overrun_pending=true`. When we next get a `Record`, write `kmsg.loss` including the overrun context. If the stream ends (`once` mode with Empty after overrun and no record), write a `kmsg.loss.pending` marker with unknown count? Or just increment `lost` by 0 and ensure we don't lose the fact an overrun occurred: write `kmsg.overrun` marker immediately on receiving `Event::Overrun` (without a specific lost count) and also accumulate when next record arrives. This preserves evidence even if buffer drained.

**Changes to kmsg.rs**:
- Add `overrun_pending: bool` to `Reader`
- On `Event::Overrun`: `self.overrun_pending = true; return Ok(Event::Overrun)`
- In `emit()`: if `self.overrun_pending { let g = gap; self.lost += g; self.overrun_pending=false; }` then compute normal gap

**Changes to kmsg-nostoi.rs**:
- On `Event::Overrun`: write `kmsg.overrun` marker (once) and maybe set flag; don't spam stderr. Rate-limit by counting events per second.

## 5. P0: Robust trigger error translation in Store
**File**: `src/sqlite.rs`

### Implementation
```rust
tx.execute(
  "INSERT INTO nostoi_records (seq,previous,digest,record) VALUES (?1,?2,?3,?4)",
  params![seq as i64, previous, entry.digest, canonical::to_string(&record)],
).map_err(|e| translate_sqlite_error(&tx, e))?;
```

Helper:
```rust
fn translate_sqlite_error(tx: &Transaction, e: rusqlite::Error) -> Error {
  match &e {
    rusqlite::Error::SqliteFailure(info, msg) => {
      let text = format!("{} {:?}", info.code, msg);
      if text.contains("nostoi") || text.contains("chain") || text.contains("head") || text.contains("previous") {
        if let Ok(loaded)=load_nostoi(tx) {
          if let Some(p)=loaded.verify().problem { return Error::Broken(p); }
        }
      }
      e.into()
    },
    _ => e.into()
  }
}
```
Do this inside the transaction while it's still open (load_nostoi works on a Connection/Tx).

Also refresh cached head only on success.

### Tests
- Concurrent append simulation as above.

## 6. P1 items (schedule)
- Incremental verify (open_verified): add `Store::open_verified_with_opts(max_verify: Option<u64>)` or store watermark in meta table later. For now, add a note and plan.
- kmsg buffer growth on large records; track `pending_lost()` API.
- S3: inject time for signing; add retry with backoff for 5xx (idempotent ops). Add 412-matches-idempotency (done in 2b) and GET anchor on conflict.
- CLI: make --chain-id/--key optional in nostoi-anchor (defaults already in anchor_head; binary can pass empty strings).
- Systemd: add SyslogIdentifier, TimeoutStopSec; rate-limit stderr in kmsg-nostoi.
- Move retry-on-head-move from kmsg-nostoi binary into Store (e.g. `Store::append_with_retry(&mut self, draft, retries: usize) -> Result<Entry>`).
