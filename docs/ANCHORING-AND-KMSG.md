# Remote checkpoints and restart-safe kernel ingestion

## Build

On Linux:

```sh
cargo build --release -p nostoi-anchor --features cli,sqlite
cargo build --release -p nostoi-kmsg --features cli,sqlite
```

Each binary belongs to its own crate. `nostoi-anchor` needs `cli`; reading the
chain or an outbox from SQLite additionally needs `sqlite` (enabled by
default). `kmsg-nostoi` needs `cli` and `sqlite`. The `nostoi` CLI, TUI and
facade stay in the root package and keep their `s3`, `kmsg` and `tui`
features; see `docs/COMPARTMENT-ARCHITECTURE.md`.

## Publish and confirm a checkpoint

Credentials use `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and optional
`AWS_SESSION_TOKEN`. Do not place secrets in command-line arguments.

```sh
target/release/nostoi-anchor audit.sqlite \
  --endpoint https://s3.us-west-2.amazonaws.com \
  --bucket example-audit-checkpoints --region us-west-2 \
  --chain-id production/kernel --lock compliance --retain-days 365
```

Keep the returned key in an independently trusted place. The generated key
contains the chain identity hash, sequence and digest prefix. Conditional PUT
(`If-None-Match: *`) is enabled by default. The bucket must already support
Object Lock, and the credential must have upload and retention-read permissions.
The tool reads back retention and checks its mode and expiry before success.

If a receipt is lost, conditional retries reuse the same key and payload.
A 412 triggers GET and comparison of the existing checkpoint. If all upload
receipts are lost, the tool also tries GET before declaring uncertainty. It
does not overwrite an object to repair a failed verification.

Publishing exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Stored/reconciled; requested retention confirmed, if any |
| 1 | Rejected, invalid input, broken local chain, or other ordinary failure |
| 2 | Upload outcome unknown; an object may have been stored |
| 3 | Object stored/found, but identity or retention could not be confirmed |

Library callers receive `Error::UploadUncertain { key, detail }` or
`Error::AnchorUnconfirmed { key, detail }` for the latter cases. Preserve the
key and reconcile it; these errors do not mean that the object was deleted.
An existing object with insufficient retention fails confirmation rather than
silently claiming that a new retention period was applied.

### R2

```sh
target/release/nostoi-anchor audit.sqlite \
  --endpoint https://ACCOUNT_ID.r2.cloudflarestorage.com \
  --bucket example-audit-checkpoints --region auto \
  --chain-id production/kernel
```

R2 uses path-style URLs automatically. It does not implement S3 Object Lock:
configure an R2 bucket lock covering `heads/` out of band. Do not pass `--lock`
to R2. A successful PUT alone does not prove that a bucket lock is configured.
Administrative credentials able to alter R2 bucket-lock rules must be kept
separate from the ingestor's S3 credentials.

## Verify local history against a trusted remote checkpoint

```sh
target/release/nostoi-anchor audit.sqlite --verify \
  --endpoint https://s3.us-west-2.amazonaws.com \
  --bucket example-audit-checkpoints --region us-west-2 \
  --key heads/TRUSTED_CHECKPOINT.json --chain-id production/kernel
```

This performs GET only. Both the key and expected logical chain identity are
explicit; they are not selected from the untrusted local store. The endpoint,
bucket and selected key must identify an independently retained checkpoint.
The tool validates its schema, identity, key and format, verifies the entire
local chain, and compares the digest at the checkpoint's sequence.

- A local head behind the checkpoint fails: the tail was truncated.
- A locally valid rehashed history with a different checkpoint digest fails.
- A different logical chain or format fails.
- Additional records after the checkpoint are allowed and fully verified.
- Missing/unreadable remote evidence fails; it is not proof that local history
  is intact.

Success prints the anchor, local head and verified-record count. Verification
returns 0 on success and 1 on mismatch/error. The library API is
`nostoi::anchor::verify_anchor(path, client, key, expected_chain)`.

This operation compares content against the chosen trusted checkpoint. It does
not attest that the bucket's retention policy remains active, discover the
newest checkpoint, or cryptographically sign anchor documents. Retaining an
older checkpoint protects only its prefix; keep the newest trusted key outside
the writer's control to detect more recent truncation.

## Kernel reader resume and shutdown

```sh
target/release/kmsg-nostoi /var/lib/nostoi/kernel.sqlite --actor host:kmsg
```

The reader opens `/dev/kmsg` concurrently with existing loggers. Read access
depends on local device permissions. It records the kernel's boot UUID from
`/proc/sys/kernel/random/boot_id` on every line and coverage marker.

At startup it verifies the store, obtains a persistent sidecar file lock, and
loads the latest line/start/stop checkpoint for its actor. Keep the same actor,
store and source on restart:

- Within the same boot/source, sequences already committed are skipped, and
  newly buffered records are appended.
- The last committed line is also the crash-safe checkpoint; it does not depend
  on writing a stop marker before a crash.
- Reboots never reuse the previous boot's high sequence to skip new low ones.
- Legacy records without boot identity and source changes start a new coverage
  interval rather than guessing a deduplication checkpoint.
- Empty restarts preserve the previous sequence in start/stop records.
- A second ingestor for the same store fails before writing coverage records.
  The `.kmsg.lock` sidecar is retained; do not remove it while a reader runs.

`kmsg.coverage.gap` records describe restarts, boot/source transitions and
unavailable early buffer coverage. Unknown loss is `null`, not zero.
Where a previous sequence exists, `kmsg.loss` gives the exact skipped count;
restart gaps are labelled `restart_buffer_gap`. `kmsg.overrun` records EPIPE
immediately even when no later sequence is yet available to quantify it.

SIGTERM and SIGINT request shutdown at a record boundary. The reader commits
`kmsg.reader.stop` with the boot identity, last sequence and unresolved-overrun
status before exiting successfully. Per-record FULL-sync commits remain in
effect. SIGKILL/power loss cannot write a stop marker; the next run records an
unclean restart and resumes from committed evidence.

`--once` drains currently available records and writes a stop marker.
`--source` and `--boot-id-file` support replay fixtures; boot IDs must be UUIDs.
`--poll-ms` accepts 1–1000 ms, bounding idle shutdown latency.

The repo's `contrib/systemd/kmsg-nostoi@.service` remains a template. No unit is
installed or enabled by these changes.
