# Native, Python and WebAssembly

For suite-wide rules on recording bounded action intents before side effects,
see [audit-first operations](AUDIT-FIRST.md).

All bindings call the same Rust verifier. The WIT contract is
[`bindings/component/wit/world.wit`](../bindings/component/wit/world.wit).
The component exports canonical-json, verify-jsonl, append-jsonl and append-delta-jsonl from
`chains`, and canonical-bytes and verify-document from `attestations`. JSON text
crosses the boundary so unsigned 64-bit integers are never rounded by JavaScript.
Results contain JSON reports; a broken chain is `ok: false`, while API errors
(invalid format, rejected append, malformed draft) are errors/exceptions.

## Python 3.11+

Build from the repository (Rust and maturin required):

```sh
python -m pip install ./bindings/python
```

```python
import nostoi
nostoi.append('events.sqlite', kind='tool.call', actor='agent:demo',
              body={'tool': 'read', 'count': 18446744073709551615})
assert nostoi.verify('events.sqlite')['ok']
text = nostoi.append_jsonl('', kind='tool.call', body={'tool': 'read'},
                          at='2026-09-27T12:00:00Z')
assert nostoi.verify_jsonl(text)['ok']
```

`append` and `verify` support both JSONL and SQLite, including existing Ephor
SQLite chains for verification. `append_jsonl` and `verify_jsonl` work in memory.
Appending a broken chain raises ValueError; file I/O failures raise OSError.
`append_delta_jsonl` takes the same arguments as `append_jsonl`, verifies the
entire supplied history, and returns only the new bytes (including a leading
newline if the existing history needs one). Concatenating history and delta
produces exactly the same bytes as `append_jsonl`.
The stdlib reference remains in contrib/python for producers that cannot ship
an extension. The native package uses a CPython stable ABI with Python 3.11 as
its floor. Linux x86-64 was tested locally; other platforms need wheel builds
and platform verification before being advertised as release targets.

### Attestations from Python

The portable half of an attestation — what was signed, and whether it is still
true of a chain — needs no `ssh-keygen`, so a binding can do it:

```python
import nostoi
document = {'v': 'nostoi-attestation-v1', 'chain': 'events', 'format': 'nostoi-v1',
            'seq': 2, 'digest': '…', 'anchored_at': '2026-09-27T13:00:00Z',
            'principal': 'alice@laptop', 'fingerprint': 'SHA256:…'}
# The exact bytes a signature covers, so a receiver can reproduce what was signed.
signed = nostoi.attestation_canonical_bytes(document)
report = nostoi.verify_attestation('events.jsonl', document)
assert report['ok'] and report['coverage'] == 'current'
```

`verify_attestation` reports `signature: 'unchecked'` and always will: these
functions have no allowed-signers file, so they cannot have verified a
signature and must not imply that they did. A stale attestation is reported
(`coverage: {'stale': True, 'ahead_by': n}`) rather than raised, because
"this is out of date" is an answer; use the `nostoi` CLI to check a signature.

## WIT component and JavaScript

```sh
rustup target add wasm32-wasip2
cargo build -p nostoi-component --target wasm32-wasip2 --release
cd bindings/javascript
npm ci
npm run build
npm test
```

```js
import { chains } from './dist/nostoi.js';
const text = chains.appendJsonl('', {
  at: '2026-09-27T12:00:00Z', actor: 'agent:demo', kind: 'tool.call',
  subject: undefined, bodyJson: '{"count":18446744073709551615}'
});
console.log(JSON.parse(chains.verifyJsonl(text, undefined)).ok);
// Return only the new bytes rather than copying the history back to the host.
const delta = chains.appendDeltaJsonl(text, {
  at: '2026-09-27T12:01:00Z', actor: 'agent:demo', kind: 'tool.finished',
  subject: undefined, bodyJson: '{"status":"succeeded"}'
});
console.log(JSON.parse(chains.verifyJsonl(text + delta, undefined)).verified); // 2
```

```js
import { attestations } from './dist/nostoi.js';
// Reports are JSON text with snake_case keys, as `verifyJsonl` reports are.
const report = JSON.parse(attestations.verifyDocument(text, document, undefined));
console.log(report.coverage, report.signature); // current unchecked
```

Do not pass large integers through JavaScript Number or JSON.parse/stringify
before verification. Preserve original JSON text, or encode decimal business
values as strings. The generated TypeScript declarations describe the WIT ABI.
Jco supplies JavaScript bindings and WASI shims for Node and browser bundlers;
bare browser imports need a bundler/import map for preview2-shim. Node execution
is tested; browser bundler integration is not a separately shipped application.

`attestations` checks a document against a chain the host holds as text. It
verifies no signature and holds no keys: a signature needs a private key, and
this interface deliberately has nowhere to put one. A component that must
verify signatures needs `ssh-keygen` on the host side, or a native SSHSIG
implementation on top of WebCrypto.

The component has no filesystem API. Its host supplies complete JSONL and an
explicit RFC 3339 timestamp and owns storage, locks and atomic writes. It does
not expose SQLite. The Rust standard library contributes WASI runtime imports
(stdio/environment/monotonic-clock); these are visible in `wasm-tools component
wit`. No permission to arbitrary files or network is needed by the chain API.
A no-default-features Rust library also builds for wasm32-unknown-unknown;
use the WIT component above for an exported interoperable interface.

### Resource and security boundaries

Portable verification and both append functions retain only the current parsed
record, rather than a parsed copy of the whole history. The supplied JSONL text
still occupies memory, and each call still scans the complete history: verification
is O(history bytes) time and O(largest record) additional parsing memory. The
delta API avoids a history-sized result and lets a host persist or transmit only
the new bytes. It is not an incremental trusted-checkpoint verifier or a mesh
replication protocol. Bound input and record sizes at the host before calling it.

For either append API, hold a lock across reading, verification and durable
commit, or use a storage compare-and-swap against the exact source revision.
A delta is valid only for that history; do not apply it to a changed head or
acknowledge success before durable storage. A receiver must verify its resulting
chain and compare independently trusted anchors to detect rollback or rewritten
history. Hash-chain verification is not sender authentication, human approval,
signature verification or encryption. Restrict plaintext to authorized memory-pool
members and use authenticated encryption for confidential replication.

Critical actions still follow [audit-first operations](AUDIT-FIRST.md): verify
authorization and any required human approval, durably record the bounded intent,
then execute and record the outcome. An API result alone grants no permission
and proves no persistence. Aya enforcement, encrypted resumable transport,
background indexing and replication scheduling belong to host integrations.

## Conformance

Rust tests check the stdlib Python reference and published format vectors.
Native Python and generated JavaScript tests exercise tampering, rejected
appends, Unicode, unsigned 64-bit integers and WeftMark input. Set
NOSTOI_INTEROP_DIR to an existing temporary directory, run Python tests first,
then JavaScript tests; the latter assert byte-identical records. Finally verify
javascript.jsonl with Python to exercise the reverse direction.
