# Compartment boundaries

The restructuring described here has been carried out. The workspace is split
into three crates, one per compartment, behind a compatibility facade, and each
executable now belongs to the crate whose code it runs.

## Runtime responsibilities

| Compartment | Required access | Durable responsibility |
| --- | --- | --- |
| Kernel ingestor | Read kernel device/boot ID; write its audit store | Commit each message and coverage/checkpoint record |
| Anchor publisher | Read audit history; write a separate outbox; HTTPS and publishing credential | Persist an exact intent, upload/reconcile, persist outcome |
| Independent verifier | Read local history; HTTPS with read-only remote credential; independently selected checkpoint | Compare full local history with retained external evidence |

The `kmsg-nostoi` binary and the publisher/verifier systemd templates establish
this layout at runtime. Separate processes under separate users allow actual
filesystem, device, network and credential restrictions. Shared Rust modules
make responsibilities easier to review; crate boundaries make dependencies and
API contracts explicit. OS configuration supplies the runtime permission
boundary.

The outbox belongs to the publisher. Its mutable attempt/outcome state is
separate from the ingestor's append-only evidence and the verifier's trusted
remote checkpoint selection. A publisher outage or blocked HTTPS retry should
not stall kernel ingestion. A verifier needs neither the publisher credential
nor write access to its outbox.

Existing files and immutable object formats are sufficient communication
boundaries. There is no network-facing daemon and no per-record IPC call. The
ingestion hot path calls the chain library directly and commits locally.

## Crate layout

```text
Cargo.toml                    workspace root plus the compatible nostoi facade
src/lib.rs                    facade: re-exports preserving public module paths
src/main.rs, src/tui.rs       the nostoi CLI and TUI
crates/
  nostoi-core/                canonicalization, formats, incremental verifier,
                              JSONL and optional SQLite storage
  nostoi-anchor/              S3 transport, prepared anchors, outbox/recovery,
                              and the nostoi-anchor binary
  nostoi-kmsg/                Linux source, restart state machine, kmsg-nostoi
bindings/                     Python, WIT, JavaScript adapters
contrib/systemd/              deployment templates and credential/config helper
tests/                        cross-compartment tests for the facade and CLI
```

Each crate carries the tests for the code it owns: streaming verification and
the format vectors in `nostoi-core`, the anchoring/outbox/scheduling/schema
integration tests in `nostoi-anchor`, and the restart tests in `nostoi-kmsg`.
Tests that exercise the `nostoi` CLI stay in the root package, which owns that
binary.

There is one authoritative implementation of canonicalization and digest rules,
in `nostoi-core`. It exposes streaming reports and checkpoint heads without
importing cloud types, and it has no networking, CLI or Linux dependency.
`nostoi-anchor` depends on core verification; `nostoi-kmsg` depends on the local
writer API. Core never depends on either. The root facade keeps
`nostoi::verify`, `nostoi::sqlite` and the feature-gated
`nostoi::anchor`/`nostoi::outbox` paths while the implementation sits
underneath them.

Attestations do not change the compartments: the document, its canonical bytes
and its binding to a chain head are portable and live in `nostoi-core` with the
rest of the format work, while the `ssh-keygen -Y sign` driver sits in the facade
next to the CLI that uses it. A verifier that only needs to check what a document
claims needs no SSH tooling at all.

`nostoi::Error` still carries the variant set it always had, and it converts
from both `nostoi-core` and `nostoi-anchor` errors, so `?` and existing match
arms keep working. Code that constructs or matches anchor variants directly
should prefer `nostoi_anchor::Error` when it depends on that crate.

## Benefits

- **Failure isolation:** cloud failures, outbox reconciliation and verifier
  crashes remain independent of ongoing collection.
- **Credential isolation:** only the publisher can PUT; verification uses GET
  credentials and an operator-controlled checkpoint. The ingestor has no cloud
  credential.
- **Dependency isolation:** HTTP/TLS dependencies stay in the anchor build;
  Linux signal/device support stays in the kmsg build; portable bindings use
  the core. Cargo feature combinations and advisory scope become easier to
  explain and test. The kmsg crate builds with no HTTP stack at all.
- **Smaller contracts:** a verified head/stream report, an immutable prepared
  request and a publisher-owned outcome have distinct types and ownership.
  Networking failures do not become core format errors.
- **Independent testing and deployment:** core vectors, SQLite snapshots,
  network fault injection and restart/process tests have focused suites. The
  publisher can be upgraded without restarting the ingestor.
- **Resource control:** per-process memory/CPU limits and retry budgets can be
  configured independently. Streaming verification avoids retaining the whole
  chain, making that separation practical at larger sizes.

## What the split does not buy

More crates introduced manifests, release/version coordination and a larger
feature/build matrix, which is why `docs/RELEASING.md` now specifies a
publication order. Neither a directory move nor a crate split changes FULL-sync
commit latency by itself.

The migration preserved canonical bytes, immutable outbox request bytes and
deadlines, actor/boot/sequence checkpoints, exit codes, trusted-key selection
and every published format and schema revision. No executable IPC protocol was
introduced.

Deployments still need validation with the repo-only templates before any unit
is installed; the split does not set permissions for you.