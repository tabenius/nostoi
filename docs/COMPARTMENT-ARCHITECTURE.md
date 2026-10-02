# Proposed compartment boundaries

This is a restructuring recommendation, not a completed crate migration.
The current streaming, diagnostics and measurement batch retains public module
paths and executable names.

## Runtime responsibilities

| Compartment | Required access | Durable responsibility |
| --- | --- | --- |
| Kernel ingestor | Read kernel device/boot ID; write its audit store | Commit each message and coverage/checkpoint record |
| Anchor publisher | Read audit history; write a separate outbox; HTTPS and publishing credential | Persist an exact intent, upload/reconcile, persist outcome |
| Independent verifier | Read local history; HTTPS with read-only remote credential; independently selected checkpoint | Compare full local history with retained external evidence |

The existing `kmsg-nostoi` process and publisher/verifier systemd templates
already establish most of this layout. Separate processes under separate users
allow actual filesystem, device, network and credential restrictions. Shared
Rust modules make responsibilities easier to review; library/crate boundaries
make dependencies and API contracts explicit. OS configuration supplies the
runtime permission boundary.

The outbox belongs to the publisher. Its mutable attempt/outcome state is
separate from the ingestor's append-only evidence and the verifier's trusted
remote checkpoint selection. A publisher outage or blocked HTTPS retry should
not stall kernel ingestion. A verifier needs neither the publisher credential
nor write access to its outbox.

Existing files and immutable object formats are sufficient communication
boundaries. A new network-facing daemon or per-record IPC call would add an
interface and lifecycle to maintain. The ingestion hot path should continue
calling the chain library directly and committing locally.

## Library/crate responsibilities

A staged target could be:

```text
Cargo.toml                    workspace plus compatible nostoi facade
src/lib.rs                    re-exports preserving public module paths
src/bin/                      thin CLI/process entry points
crates/
  nostoi-core/                canonicalization, formats, incremental verifier,
                             JSONL and optional SQLite storage
  nostoi-anchor/              S3 transport, prepared anchors, outbox/recovery
  nostoi-kmsg/                Linux source and restart/coverage state machine
bindings/                    Python, WIT, JavaScript adapters
contrib/systemd/             deployment templates and credential/config helper
tests/                       cross-compartment regression/interoperability tests
```

Keep one authoritative implementation of canonicalization and digest rules.
The core exposes streaming reports and checkpoint heads without importing
cloud types. The anchor library depends on core verification, and the kernel
library depends on the local writer API. Core never depends on either process
adapter. The root facade can preserve `nostoi::verify`, `nostoi::sqlite`, and
feature-gated `nostoi::anchor`/`nostoi::outbox` paths while the implementation
moves underneath them.

## Benefits

- **Failure isolation:** cloud failures, outbox reconciliation and verifier
  crashes remain independent of ongoing collection.
- **Credential isolation:** only the publisher can PUT; verification uses GET
  credentials and an operator-controlled checkpoint. The ingestor has no cloud
  credential.
- **Dependency isolation:** HTTP/TLS dependencies stay in the anchor build;
  Linux signal/device support stays in the kernel build; portable bindings use
  the core. Cargo feature combinations and advisory scope become easier to
  explain and test.
- **Smaller contracts:** a verified head/stream report, an immutable prepared
  request and a publisher-owned outcome have distinct types and ownership.
  Networking failures do not become core format errors.
- **Independent testing and deployment:** core vectors, SQLite snapshots,
  network fault injection and restart/process tests can have focused suites.
  The publisher can be upgraded without restarting the ingestor.
- **Resource control:** per-process memory/CPU limits and retry budgets can be
  configured independently. Streaming verification now avoids retaining the
  whole chain, making that separation practical at larger sizes.

## Costs and migration order

More crates introduce manifests, release/version coordination, conversions
between core and transport errors, and a larger feature/build matrix. Separate
processes have scheduling and memory overhead. Neither a directory move nor a
crate split changes FULL-sync commit latency by itself.

Recommended sequence:

1. Define public boundary types and preserve current format/API test vectors.
2. Extract core and the anchor/outbox package together, using a facade to avoid
   dependency cycles and breaking callers. Keep SQLite optional initially.
3. Move the kernel reader and restart state machine into a Linux-specific crate;
   keep its executable as a thin adapter for arguments, signals and service IO.
4. Add CI checks for portable core, native storage, cloud publisher, Linux
   ingestor, bindings and the complete workspace.
5. Validate deployed users/permissions with the existing repo-only templates.

The migration must preserve canonical bytes, immutable outbox request bytes and
deadlines, actor/boot/sequence checkpoints, exit codes and trusted-key selection.
Core must remain usable without networking. No executable IPC protocol is
needed for this first restructuring.
