# Nostoi audit and hardening review (2025-10-02)

## Summary
This review covers correctness, performance, robustness and operational hardening of the current codebase after the recent additions (Store::open_verified, kmsg reader, S3 anchoring, binaries). Items are ranked P0 (must fix before production use), P1 (strongly recommended), P2 (nice to have).

## P0
1. **TOCTOU between cached head and trigger enforcement (SQLite)**: `Store::open_verified` caches the head, and `append` uses that cached head to compute `seq+1`/`previous` without re-reading the current head at append time. The INSERT triggers still enforce against the actual head, but if another writer extends the chain after the first transaction starts, the insert will fail with a trigger error that bubbles as `rusqlite::Error` (not `Error::Broken`) because we never translate the "head mismatch"/"chain" trigger failures into `Broken(Problem)`. Callers expecting `Broken` to detect a forked chain will get a generic error and may retry incorrectly. *Fix*: on INSERT failure, catch the rusqlite error and, if it looks like the chain constraint failed (e.g. the error message contains "nostoi" or the head changed), re-verify the chain (`load()?.verify()`) and return `Error::Broken(problem)` or synthesize a precise `Problem`. Alternatively, detect head change by a quick SELECT MAX(seq) + digest in the same transaction or by comparing against the current max before insert and letting triggers be the source of truth, translating the error.
2. **Anchor: error handling for non-2xx from S3 is missing in anchor_head**: `client.put_object` returns an error on 4xx/5xx, but if the client ever changed to return non-error for certain cases, `anchor_head` unconditionally returns the serialized `Anchor` regardless of whether the object was actually stored (we assigned `_ = client.put_object(...)`). Also consider idempotency: when `only_if_absent` and key exists, S3 returns 412 — `put_object` now errors with "object already exists", which is correct. However, operators often want to treat "already anchored with the same head" as success (idempotent re-anchoring). *Fix*: when `only_if_absent` and the error indicates the object exists, read back the anchor (HEAD or GET) and compare `seq`/`digest`/`format`; if it matches, return the existing anchor instead of erroring. Otherwise return the original error.
3. **Path traversal and absolute/relative safety in anchor key generation**: `generate_key` collapses separators but keeps leading `_` (e.g. absolute paths produce keys starting with `heads/_...`). Also user-supplied `key` is used verbatim. Consider canonicalizing `chain_id` (basename or a sanitized slug), rejecting empty/unsafe keys (control chars, `..`), and documenting constraints. For R2/S3, keys are not filesystem paths but user-controlled; still worth sanitizing.
4. **kmsg: loss accounting and EPIPE semantics**: `take_lost()` returns lost count since last reset, but `Event::Overrun` is returned on `EPIPE` without recording the lost count at that moment. The ABI states `-EPIPE` means buffer overwrote records while fd was open; the sequence numbers on the next record reveal how many, which you do — but if the buffer is drained to empty after overrun before any new record arrives, `lost` remains pending with no record written. Also the marker `kmsg.loss` is only written when the next `Record` arrives. *Fix*: emit a synthetic `kmsg.overrun` with the next known gap when possible, or record a loss marker on the next event even if we haven't seen a record yet (track `overrun_happened` flag). At minimum, document this and ensure service doesn't miss a burst that fully overwrote the buffer.
5. **SQLite schema/trigger hardening**: Triggers prevent UPDATE/DELETE and check chain continuity, but they use `RAISE(ABORT, ...)` strings and rely on application logic. Consider a CHECK constraint alternative where feasible, and ensure the trigger error messages are stable (to translate them reliably as in P0.1). Also `journal_mode=WAL`, `synchronous=FULL` are set, but no `PRAGMA foreign_keys = ON` (not needed here) and no `secure_delete`/`mmap_size` tuning. More directly, the writer registers `nostoi_digest` in SQLite; if another process opens the DB without that function registered, INSERTs that call the function in triggers will fail unless the function exists — but in the same connection you register it. This is fine for the native store; document that external readers don't need the UDF to verify (they can recompute from `record` JSON). Also `busy_timeout` 5s is reasonable but should be configurable for daemon mode.

## P1
6. **O(n) verification on open_verified can stall for very large chains**: `load()` reads every row into memory and `verify()` walks them. For multi-GB SQLite with millions of records, this is O(total bytes + records) at startup. Since triggers enforce the head and each record's digest is stored, you could verify incrementally (stop at first break) and also support a "quick verify" that only checks the tail/head continuity by walking backwards from MAX(seq) using the index? Or cache a `verified_up_to` watermark in a side table and only verify new ranges. For now, acceptable for most cases, but worth noting and possibly adding a `--max-verify` or incremental verify. The index `sqlite_autoindex_nostoi_records_1` on (seq) exists, so a reverse scan to detect breaks is possible.
7. **kmsg reader: partial reads and very large records**: The kernel writes one record per `read()` in general, but the buffer is sized to 64KB and records can include many continuation lines. You read into a 64KB buffer and split; if a record grew larger than 64KB (rare but possible in some debug paths), `read()` could return a partial record? The kernel guarantees atomic delivery of a whole record to a single `read()` on the char device in practice, but to be robust, consider growing the buffer or handling the case where the last chunk has no trailing `\n` before EAGAIN? Also the fixture path reads the whole file at once (fine for tests). No action critical, but add a guard.
8. **S3 signing: canonical query and repeated headers**: Signing currently passes `canonical_query` separately (empty string) and doesn't handle query parameters that affect canonicalization (e.g. `?retention=` in GetObjectRetention). For the specific calls here (PUT to key, GET with `retention=` query) you hardcode `raw_query` and `canonical_query` correctly, but the API is easy to misuse. Also header values with repeated headers (not common for S3) aren't canonicalized per AWS spec (folding/whitespace). Low risk for current usage.
9. **S3 client: time skew and retry**: Signing uses `OffsetDateTime::now_utc()` at the moment of signing; large clock skew causes 403. Add a small skew margin or make `now` injectable for tests. Also no retries on transient 5xx/network errors (Idempotent requests like PUT with versioned keys could retry with backoff). For an anchor (write-once) retry strategy needs care (don't create duplicates), but with `only_if_absent` + checking existing object on 412 (P0.2) it's feasible.
10. **Binary UX and errors**: `nostoi-anchor` requires `--key` and `--chain-id` as flags but also takes `<CHAIN>` as positional; clap enforces them. Consider making `--chain-id` optional (default to chain path) and `--key` optional (you already generate one in `anchor_head` if empty). Also `nostoi-anchor` prints errors via `eprintln!` and returns non-zero; good. `kmsg-nostoi` writes loss/unparsable as chain records (good) but prints "ring buffer overrun" to stderr on every `EPIPE` — could be noisy; maybe rate-limit stderr logs.
11. **Systemd hardening**: The template sets `ProtectSystem=strict`, `ReadOnlyPaths=/dev/kmsg /proc/sys`, `ReadWritePaths` to specific dirs — good. Consider `PrivateDevices=yes` except maybe not needed (needs `/dev/kmsg` read-only; with `ReadOnlyPaths` it's fine). Also `AmbientCapabilities=` empty is correct (no caps needed). Add `SyslogIdentifier=kmsg-nostoi@%i` and `Documentation=` already present. Maybe `TimeoutStopSec` and ensure `Restart=on-failure` is appropriate for crash loops.
12. **Testing gaps**: No integration test for `Store::open_verified` retry-on-head-move behavior (the code has a retry path in the kmsg writer when append fails: it re-opens and retries once). That retry path lives in the binary, not in the library; consider moving it into `Store` (e.g. `append_with_retry` or make `append` self-healing on a detected head change by refreshing cache) so all writers benefit. Also mock S3 tests for 412, 403 (bad signature), and 404 retention cases would be valuable.

## P2
13. **Format compatibility and versioning**: Anchor records `v: "nostoi-anchor-v1"`, format name copied as-is. Consider adding `schema_version` and maybe the crate version. Also `generate_key` truncates slug to 40 chars — could collide in rare cases; include a short hash of `chain_id` if truncation happens.
14. **Performance of canonical JSON**: `canonical::to_string` builds a `String` via `serde_json::to_string` on a `Value` that was already serialized? The SQLite store stores `crate::canonical::to_string(&record)` where `record` is a `Value`; canonicalization is applied. For very high append rates this allocates; could be optimized, but not urgent.
15. **Logging/metrics**: No counters for lost records, overruns, append latency in the library. Daemons could export to a local sink, but outside scope for the crate core. Document operational signals (lost count is in chain as `kmsg.loss`).
16. **MSRV note**: `floor_char_boundary` was replaced to avoid MSRV 1.91+ (you already fixed). Keep an eye on dependencies.

## Concrete code snippets to fix (high value)

**P0.1: translate trigger errors on append (sketch)** in `Store::append`, when `tx.execute(...)` fails:
```rust
match tx.execute(..., params![...]) {
  Ok(_) => {},
  Err(rusqlite::Error::SqliteFailure(err, Some(msg))) if msg.contains("nostoi") => {
      // re-verify to get precise problem
      let loaded = load_nostoi(&tx)?;
      if let Some(p)=loaded.verify().problem { return Err(Error::Broken(p)); }
  },
  Err(e)=>return Err(e.into()),
}
```
(Exact string matching is brittle; better to detect head change by comparing cached (seq,prev) against current MAX before insert, or catch specific constraint names if you expose them.)

**P0.2: idempotent anchor on 412** in `anchor_head`:
```rust
match client.put_object(&key,&body,&put_options) {
  Ok(_) => Ok(anchor),
  Err(Error::S3(msg)) if options.only_if_absent && msg.contains("already exists") => {
      // TODO: fetch existing anchor and compare; if matches return it
      Err(Error::S3(msg)) // or handle
  },
  Err(e)=>Err(e),
}
```
