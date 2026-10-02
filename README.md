<p align="center"><img src="assets/logo.svg" width="180" alt="Nostoi: a duckling carrying Gretel across a river"></p>

# Nostoi

Tamper-evident audit chains, one tool for all of them: a Rust library, a CLI
and a TUI to **verify**, **append to**, **stream** and **browse** them.

A chain is a sequence of records where each record carries the digest of the
record before it and a digest of its own content. Verification identifies the
first inconsistent record. Detecting removal of the tail or a fully recomputed
history requires a previously trusted head retained outside the chain.

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

The implementation is split into one crate per compartment, and the `nostoi`
crate above is a facade that re-exports them:

| Crate | Contains | Extra features |
| --- | --- | --- |
| `nostoi-core` | formats, canonical JSON, streaming verification, JSONL/SQLite stores | `sqlite` |
| `nostoi-anchor` | S3/R2 checkpoints, verification, durable outbox, the `nostoi-anchor` binary | `sqlite`, `cli` |
| `nostoi-kmsg` | the Linux kernel ring-buffer reader and the `kmsg-nostoi` daemon | `sqlite`, `cli` |

`nostoi-core` has no networking, CLI or Linux dependency, so portable consumers
and bindings use only that. Existing `nostoi::` paths keep working; see
[compartment boundaries](docs/COMPARTMENT-ARCHITECTURE.md).

## Python and WebAssembly

Native Python bindings (PyO3), a versioned WIT component, and generated
JavaScript/TypeScript bindings are available in this checkout. See
[build instructions and examples](docs/INTEROPERABILITY.md) and
[release preparation](docs/RELEASING.md). Registry publication is pending.

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
Ephor's `ephor-audit-v1` hashes length-prefixed fields; see `crates/nostoi-core/src/format.rs`.

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
  bucket lock, an append-only SFTP target);
- **anchor to more than one destination:** one account is one answer to "was this
  rewritten?", so publish the same checkpoint to several places under separate
  administrations with `nostoi-anchor --targets`. Verification then requires them
  to agree, which a single compromised destination cannot arrange. See
  [anchoring to more than one destination](docs/ANCHOR-FANOUT.md).

S3/R2 head publishing and remote-checkpoint verification are available through
the optional `s3` feature and `nostoi-anchor`. Restart-safe Linux kernel ingestion
is available through `kmsg-nostoi` with the `kmsg` feature. See
[remote checkpoints and kernel ingestion](docs/ANCHORING-AND-KMSG.md) for build,
locking, recovery, verification and shutdown behavior, and
[multi-destination anchoring](docs/ANCHOR-FANOUT.md) for publishing to several
destinations at once, per-destination credentials and how to choose them.
Cryptographically signed head anchors remain on the roadmap.

For recurring operation, `nostoi-anchor --outbox PATH` persists the exact request
before upload and recovers it after a crash. See
[durable anchor recovery](docs/DURABLE-ANCHOR-OUTBOX.md) and the repo-only
[publisher/verifier scheduling templates](docs/ANCHOR-SCHEDULING.md). Publishing
and verification use separate credentials and an independently selected trusted
checkpoint key.

Full-chain and remote-checkpoint verification now stream records rather than
retaining the entire history. See [streaming verification](docs/STREAMING-VERIFICATION.md),
[bounded S3 diagnostics](docs/S3-DIAGNOSTICS.md), and
[large-chain measurements](docs/LARGE-CHAIN-BENCHMARKS.md). A proposed next-step
[compartment architecture](docs/COMPARTMENT-ARCHITECTURE.md) describes process
privileges and a staged crate split while preserving the current API.

Owned databases now declare independent schema revisions and component identities;
prepared requests and kernel payloads also carry explicit format tags. Use
`nostoi schema PATH --json` to inspect database metadata without migration. See
[schema versioning and legacy adoption](docs/SCHEMA-VERSIONING.md).

## Status

`0.1`: the formats, both stores, the CLI and the TUI, with tests (canonical
JSON against Python's encoder, Ephor's published hash vector, a ledger written
by WeftMark itself). Adoption across the suite (Ephor, Sylvae, WeftMark, Frog,
Rebekah) and signed anchors are tracked as Frog tasks tagged `nostoi`.

## License

MIT OR Apache-2.0.
