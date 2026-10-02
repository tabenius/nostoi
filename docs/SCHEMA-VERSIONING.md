# Schema revisions and compatibility metadata

Database schema, encoded record/request format, payload format, and software
version are independent version domains. A database index or enforcement change
does not require rewriting hashed audit records.

## Current versions

| Domain | Identifier/revision |
| --- | --- |
| Native audit database application ID | `0x4e53544f` (`NSTO`) |
| Native audit database schema | `1` |
| Anchor outbox database application ID | `0x4e534f42` (`NSOB`) |
| Anchor outbox database schema | `1` |
| Native audit record | `nostoi-v1` (unchanged) |
| Published checkpoint | `nostoi-anchor-v1` (unchanged) |
| New prepared-request envelope | `nostoi-prepared-anchor-v1` |
| New kmsg line and coverage/checkpoint payloads | `nostoi-kmsg-v1` |

Both owned database types use `PRAGMA application_id` for identity and
`PRAGMA user_version` for their independently managed schema revision.
They have a singleton `nostoi_schema_meta` row containing:

- `component`: `nostoi-audit-store` or `nostoi-anchor-outbox`;
- `schema_revision`, checked against the header;
- `record_format`: the current write format for that component;
- `created_by_version` and `last_migrated_by_version`: the schema implementation's
  Cargo package version;
- `adopted_legacy`: whether the known unversioned layout was adopted.

Unknown legacy creation software is stored as `unknown`, not inferred from
the current binary. Inspection exposes that value as `null`. A healthy reopen
does not change the creation/migration labels. These are compatibility and
diagnostic labels, not cryptographically authenticated provenance or proof
that the chain is intact.

## Inspect without migration

```sh
nostoi schema /var/lib/nostoi/kernel.sqlite --json
nostoi schema /var/lib/nostoi-anchor/kernel/outbox.sqlite --json
```

The `schema` command requires the `sqlite` feature (enabled by default). It can
inspect an outbox without the S3 feature or cloud credentials. Library callers
use `nostoi::schema::inspect(path) -> SchemaInfo`.

For a known unversioned database, inspection reports revision `0`, application
ID `0`, and `legacy_unversioned: true`. Readers validate compatible table columns,
identity, supported revision and metadata consistency; they do not stamp the
database. Normal SQLite WAL/shared-memory management may still create sidecars.

## Writer initialization and legacy adoption

Before persistent schema or journal-mode changes, writers check:

1. The application ID belongs to the expected component, or both identity and
   revision are zero for a new/legacy database.
2. The revision is supported. Unknown/newer revisions are refused explicitly.
3. Versioned metadata exists and agrees with the header and component.
4. Existing table/constraint/trigger definitions match the known historical
   contract; SQL keyword/whitespace spelling is normalized outside quoted text.
5. No unrelated data tables/views are being claimed as a dedicated owned store.

Compatible read layouts are deliberately broader than writer adoption. A reader
can verify evidence whose enforcement trigger was removed; a writer will not
silently restore an unfamiliar or incomplete enforcement contract and claim it
as this revision. Column compatibility alone is insufficient for adoption.

The supported migration is **known unversioned layout → revision 1**. Native
record tables and outbox intent/outcome tables stay unchanged. Metadata creation,
identity and revision updates occur within the caller's IMMEDIATE transaction.
Outbox source binding is checked before adoption; its final binding operation
commits with the migration. Errors or crashes before commit roll the changes back.

Foreign or incomplete layouts, wrong identities, missing/inconsistent metadata
and unsupported revisions are refused. Readers of Ephor's external database
retain their existing format adapter and do not stamp Nostoi metadata or assume
that Ephor's `user_version` belongs to Nostoi.

Only deployments with version-aware writers can enforce the future-revision
gate. Historical binaries that never checked these headers cannot acquire that
behavior retroactively; upgrade writers before deploying newer schemas.

## Prepared-request envelope compatibility

New durable requests contain:

```json
{
  "v": "nostoi-prepared-anchor-v1",
  "anchor": { "v": "nostoi-anchor-v1" },
  "body": [],
  "only_if_absent": true,
  "lock": null,
  "retain_days": 0
}
```

This is a shape illustration, not a valid upload: the full checkpoint fields
and exact serialized body are required by request validation.

An absent envelope `v` is the historical format and remains supported. An
explicit unknown version is refused with `Error::UnsupportedSchema`; null and
non-string versions are malformed, not treated as legacy. Unknown fields remain
rejected. Existing immutable request strings are not backfilled or reserialized.
Migration/recovery preserves the key, payload bytes, checkpoint time, target
binding and original retention deadline. An adopted outbox can therefore contain
both historical envelopes and newly versioned ones.

## kmsg payload compatibility

New line, start/stop, loss and coverage-marker bodies carry
`"schema": "nostoi-kmsg-v1"`. This payload tag is independent of the outer
`"v": "nostoi-v1"` hash-chain record version.

Resume accepts the historical checkpoint shape with no payload tag. A present
unknown or non-string tag fails before the ingestor writes new coverage records.
Old record bodies and digests are not backfilled. Generic audit verification
still treats bodies as payload data; the kmsg consumer owns their interpretation.

## Future revision policy

Add explicit, tested migration steps and version-specific validation before
changing a persisted contract. Do not merely edit DDL and leave revision 1, or
bump the counter and assume existing databases have upgraded. Each owned
database maintains its own revision history and stable application ID through
the proposed crate split.

Tests cover read-only legacy inspection, exact audit-row preservation, original
outbox request/retention replay, metadata CLI output, rejected future revisions
and identities without persistent changes, transaction rollback, malformed
request tags, and legacy/future kmsg checkpoint behavior.
