<p align="center"><img src="assets/logo.svg" width="180" alt="Nostoi: a duckling carrying Gretel across a river"></p>

# Nostoi

Tamper-evident audit chains, one tool for all of them: a Rust library, a CLI
and a TUI to **verify**, **append to**, **stream** and **browse** them.

A chain is a sequence of records where each record carries the digest of the
record before it and a digest of its own content. Change, remove, reorder or
insert anything and verification names the first record that no longer fits;
everything before it is intact.

Nostoi reads the chains the RAGBAZ projects already keep, and gives the rest a
common format:

| Format | Where | Store |
| --- | --- | --- |
| `nostoi-v1` | Nostoi's own; for Sylvae, Frog and anything new | JSON Lines, or the append-only SQLite store |
| `weftmark-ledger-v1` | WeftMark's `ledger.jsonl` | JSON Lines |
| `ephor-audit-v1` | Ephor's audit chain (`governance_events`) | SQLite (Ephor's store) |

*Nostoi* (Νόστοι, "the homecomings") are the lost epic poems of the Greek
heroes' journeys home: records that should have survived and did not. The
logo is the duckling that carries Gretel back across the river.

## CLI

```console
$ nostoi append audit.jsonl --kind tool.call --actor agent:claude --subject cs-42 \
    --body '{"tool": "weft_handoff_create"}'
1 67b6c51b545e267d0b55a5856f4152162b9a9c51ea25a6a1afc7d83c88d59601

$ nostoi verify audit.jsonl ~/.weftmark/ledger.jsonl /var/lib/rebekah/ephor/audit.sqlite
✓ audit.jsonl (nostoi-v1): 1 records intact, head 1 67b6c5…
✓ ledger.jsonl (weftmark-ledger-v1): 812 records intact, head 812 9c01e2…
✗ audit.sqlite (ephor-audit-v1): record 204 was altered: its content does not match its digest; records 1–203 are intact

$ nostoi log audit.jsonl --follow            # verified records as JSON lines, live
$ nostoi head audit.jsonl                    # position and digest: anchor it elsewhere
$ nostoi show audit.jsonl 17                 # one record in full
$ nostoi tui audit.jsonl                     # browse it
```

| Command | Does |
| --- | --- |
| `verify PATH…` | verify each chain; `--json` for one report per line |
| `append PATH --kind K [--actor A] [--subject S] [--body JSON\|@FILE\|-]` | append a `nostoi-v1` record (JSONL, or SQLite for `.sqlite`/`.db`); a broken chain is never extended |
| `head PATH` | the verified head, to anchor in another system |
| `show PATH [SEQ]` | list records (✓ verified, ✗ from the break on), or one in full |
| `log PATH [--follow]` | stream verified records as JSON lines; a break ends the stream |
| `tui PATH` | browse: filter, jump to the break (`b`), follow live (`f`) |
| `formats` | the formats Nostoi reads |

Exit status: **0** every chain intact, **1** a chain is broken (or would have
been extended while broken), **2** anything else (unreadable file, bad input).
Formats are detected; `--format` overrides.

## Library

```rust
use nostoi::{append, verify, Draft};
use serde_json::json;

let path = std::path::Path::new("audit.jsonl");
append(path, Draft { actor: Some("agent:claude"), kind: "tool.call",
                     subject: Some("cs-42"), body: json!({"tool": "x"}), at: None })?;
let report = verify(path, None)?;
assert!(report.ok);
```

Features: `sqlite` (the SQLite stores), `cli`, `tui`; all on by default.
`default-features = false` leaves the pure verifier: canonical JSON, the three
digests, JSONL.

## The `nostoi-v1` format

One JSON object per record:

```json
{"v":"nostoi-v1","seq":1,"previous":"000…000","at":"2026-09-27T21:00:00.000Z",
 "actor":"agent:claude","kind":"tool.call","subject":"cs-42",
 "body":{"tool":"weft_handoff_create"},"digest":"67b6c5…"}
```

- `seq` runs 1, 2, 3… with no gaps; `previous` is the previous record's
  `digest`, and 64 zeros for the first.
- `at` is RFC 3339 UTC; `kind` is required; `actor` and `subject` are optional.
- `body` is a JSON object. **No floats** (their spelling differs between
  languages; write decimals as strings) and integers within 64 bits.
- `digest` is the SHA-256, in lowercase hex, of the record **without**
  `digest`, encoded as **canonical JSON**: Python's
  `json.dumps(record, sort_keys=True, separators=(",", ":"))`. That is: keys in
  code point order, no whitespace, strings escaped with `\"`, `\\`, `\b`, `\f`,
  `\n`, `\r`, `\t` and `\uXXXX` (lowercase hex, surrogate pairs) for everything
  else outside printable ASCII, DEL included.

So any Python program can write and check a chain with the standard library
alone. [`contrib/python/nostoi.py`](contrib/python/nostoi.py) is the reference
(append with a file lock, verify), and the test suite checks Rust and Python
against each other in both directions.

WeftMark's `weftmark-ledger-v1` is hashed the same way (its record: `sequence`,
`previous_digest`, `kind`, `entity_id`, `payload`, `recorded_at`, `digest`).
Ephor's `ephor-audit-v1` hashes length-prefixed fields; see `src/format.rs`.

## The SQLite store

`nostoi append events.sqlite …` keeps each record whole beside its chain
fields in `nostoi_records`. Triggers refuse every `UPDATE` and `DELETE`, and an
`INSERT` must extend the head with a digest that matches its record. The check
calls `nostoi_digest()`, which the writer registers (SQLite has no SHA-256), so
any SQLite client can read and verify the file but only Nostoi can append. The
store runs in WAL mode, ready for [Litestream](https://litestream.io) to stream
it to S3/R2, SFTP, NATS or another disk as it is written.

## What tamper-evidence does and does not do

A chain proves that nothing *within* it was changed after the fact. It cannot
stop someone who controls the file from rewriting all of it, digests
included. For that, keep a copy they cannot reach:

- **anchor the head:** put `nostoi head` somewhere else, e.g. in WeftMark
  evidence, a Dash record or a signed manifest;
- **replicate:** stream the store to write-once storage (S3 Object Lock, an R2
  bucket lock, an append-only SFTP target).

Signed head anchors are on the roadmap.

## Status

`0.1`: the formats, both stores, the CLI and the TUI, with tests (canonical
JSON against Python's encoder, Ephor's published hash vector, a ledger written
by WeftMark itself). Adoption across the suite (Ephor, Sylvae, WeftMark, Frog,
Rebekah) and signed anchors are tracked as Frog tasks tagged `nostoi`.

## License

MIT OR Apache-2.0.
