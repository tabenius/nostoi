# Durable anchor outbox

With the `s3` and `sqlite` features enabled, publishing can use a dedicated
SQLite database:

```sh
nostoi-anchor /var/log/nostoi/audit.db \
  --endpoint https://s3.us-east-1.amazonaws.com \
  --bucket retained-audit --region us-east-1 \
  --chain-id production-kernel --outbox /var/lib/nostoi/anchor-outbox.db \
  --lock compliance --retain-days 365
```

Provide credentials through `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and,
when needed, `AWS_SESSION_TOKEN`. Credentials and signed HTTP headers are not
stored in the outbox. `--outbox` conflicts with `--verify`; builds without
`sqlite` do not expose this argument. Existing publishing without an outbox
continues to use `anchor_head`.

## What is committed

The entire source chain is verified before preparing a new checkpoint. Before
any PUT for that checkpoint, a transaction commits its immutable intent:
the verified sequence and digest, logical chain identity, generated or explicit
key, original serialized payload, conditional-upload setting, lock mode,
configured retention duration, and original absolute retention deadline. The
database also commits its endpoint, bucket, region and path-style/virtual-host
target identity. These parameters are reused on retry; signatures are generated
afresh using the credentials available to that invocation.

The outbox uses SQLite WAL and `synchronous=FULL`. SQLite's durability guarantee
depends on the filesystem and storage honoring synchronization operations. Keep
the database and its SQLite sidecar files on persistent storage. Use SQLite's
backup API or a quiesced database when backing it up; copying only a live `.db`
file can omit committed WAL transactions. Filesystem permissions should protect
the checkpoint contents and target configuration. SQL triggers prevent normal
updates/deletes of intents, but are not protection against someone who controls
the database file.

Deserialized requests are checked before network I/O. The schema, checkpoint
digest, key, chain identity, provider, lock mode, timestamp, duration and deadline
must be internally consistent. The persisted payload must equal the exact
pretty-serialized checkpoint metadata; its original bytes are then sent without
reconstruction. Outbox requests must remain conditional, and the checkpoint key
must match the database row key. An inconsistent request fails closed with an
invalid-intent error and is left available for investigation. These checks do
not authenticate the database or defeat a malicious complete rewrite of its
consistent contents.

The outbox is independent of ordinary audit appends: appending records does not
upload or wait for S3, and an anchor failure does not roll back audit records.
The outbox must be separate from the source audit database. Opening the same
file (including a symlink or Unix hard-link alias), an existing audit database,
or a foreign database as the outbox is rejected. An outbox is bound to one
canonical source path and one target; opening it for another source or sending
its intents to another configured target is rejected.

## Outcomes and recovery

`anchor_intents` holds immutable requests. `anchor_outcomes` records:

| State | Meaning | Next scheduled invocation |
| --- | --- | --- |
| `pending` | Intent committed, no durable result yet | Retry original request |
| `unresolved` | Upload uncertain, or object identity/retention unconfirmed | Retry and reconcile original request |
| `rejected` | Definitive upload rejection, invalid request, or expired original lock deadline | Current matching head can retry; an expired intent requires a new key/deadline; historical rejected heads require operator review |
| `confirmed` | Upload/existing bytes and requested Object Lock retention checked at publication time, result committed | Matching current head is checked again with the original request |

Publishing first reconciles all pending/unresolved intents for the bound target,
then verifies/prepares the current chain head. Recovery stops on the first
failure and returns its error, keeping remaining intents available for another
invocation. Recovery does not need the source to still contain a historical
checkpoint: its exact verified request was already committed. The library's
`Outbox::reconcile(&client)` supports recovery without preparing a new head.

Every durable upload uses `If-None-Match: *`. An existing object is fetched and
must match the original serialized bytes exactly. It is never overwritten to
repair a conflict. Lost PUT responses can be reconciled by finding the object
at that same key. With Object Lock requested, the actual mode and deadline are
read back and must meet the original request before confirmation. Missing,
failed, or insufficient retention remains unresolved. R2 bucket locks must
still be configured externally; this client does not verify those policies.

Success is returned only after the confirmed outcome is persisted. If that
write fails after remote success, the caller receives `AnchorUnconfirmed` and
the previous durable state remains available. An unresolved transport outcome
preserves `UploadUncertain`. The CLI exits with 2 for `UploadUncertain`, 3 for
`AnchorUnconfirmed`, and 1 for other errors.

A repeated unchanged head reuses its original timestamp, bytes and retention
expiry. It does **not** acquire a later retention expiry simply because a
scheduled job ran again. Changing the lock mode or retention duration for the
same immutable key is an explicit conflict. Confirmation concerns the original
deadline, not a rolling retention period. Before any network operation for a
prepared S3 Object Lock request, an original deadline at or before the current
UTC time returns `AnchorExpired` (CLI exit 1). The deadline is checked again
after successful retention readback so a request that expires during network
operations cannot be confirmed. Returned actual retention must also still be in
the future. Ordinary non-outbox publishing of a fresh request against an older
existing object continues to verify actual retention and returns
`AnchorUnconfirmed` when that retention is insufficient or expired. An old
`anchored_at` alone does not expire an unlocked request.

An expired original deadline is refused even if an existing remote object might
have longer actual retention: recovery does not fetch it to salvage an expired
request or silently renew it. In the outbox, attempted expiry is persisted as
`rejected`, including for a previously confirmed matching head. Unselected
`confirmed` rows are historical receipts, not a live statement that their
retention remains active; there is no background expiry sweep. A new head gets
its own new key and deadline.

## Operator procedure

1. Preserve the outbox after a failed or interrupted invocation. Run the same
   command with the original source and target configuration and fresh valid
   credentials. Pending/unresolved requests are automatically reconciled.
2. Inspect local state with a read-only SQLite connection if needed:
   `SELECT key, state FROM anchor_outcomes ORDER BY key;`. The intent's `request`
   JSON contains the original checkpoint, payload byte array and deadline.
3. Fix credentials or remote permissions for rejected uploads. A rejected
   request for the current head is retried by repeating the original command.
   Historical rejected requests are deliberately excluded from automatic
   recovery; investigate them before restoring their outcome state to `pending`
   with an intentional SQLite transaction, then use `Outbox::reconcile` or the
   original CLI invocation. Do not modify their intents.
4. If an existing object differs, preserve both copies and investigate. Do not
   delete or overwrite it as part of recovery.
   For `AnchorExpired`, preserve the old intent and publish the checkpoint under
   a new explicit immutable `--key`, which prepares a new deadline. The first
   invocation may reject an expired pending intent during reconciliation; after
   that rejection is committed, repeat the invocation with the new key. Merely
   marking the expired intent `pending` will produce `AnchorExpired` again and
   will not change its bytes or deadline. Changing `--retain-days` under its old
   key is still a conflict. Never edit the old deadline to simulate renewal.
5. For an intentional destination migration, finish reconciliation against the
   original target first, retain that outbox, and use a new outbox for the new
   target. This is a separate publication; old intents cannot be redirected.
   Moving the source path similarly requires retaining the original outbox for
   recovery and starting a new source-bound outbox. A new outbox does not bypass
   an existing remote immutable-key conflict.

The outbox does not have a daemon, timers, or background retry threads. Durability
makes an interrupted intent actionable; completion requires another invocation
and a reachable target that accepts the request and exposes the required
retention information.
