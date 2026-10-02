# Native, Python and WebAssembly

For suite-wide rules on recording bounded action intents before side effects,
see [audit-first operations](AUDIT-FIRST.md).

All bindings call the same Rust verifier. The WIT contract is
[`bindings/component/wit/world.wit`](../bindings/component/wit/world.wit).
The component exports canonical-json, verify-jsonl and append-jsonl. JSON text
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
The stdlib reference remains in contrib/python for producers that cannot ship
an extension. The native package uses a CPython stable ABI with Python 3.11 as
its floor. Linux x86-64 was tested locally; other platforms need wheel builds
and platform verification before being advertised as release targets.

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
```

Do not pass large integers through JavaScript Number or JSON.parse/stringify
before verification. Preserve original JSON text, or encode decimal business
values as strings. The generated TypeScript declarations describe the WIT ABI.
Jco supplies JavaScript bindings and WASI shims for Node and browser bundlers;
bare browser imports need a bundler/import map for preview2-shim. Node execution
is tested; browser bundler integration is not a separately shipped application.

The component has no filesystem API. Its host supplies complete JSONL and an
explicit RFC 3339 timestamp and owns storage, locks and atomic writes. It does
not expose SQLite. The Rust standard library contributes WASI runtime imports
(stdio/environment/monotonic-clock); these are visible in `wasm-tools component
wit`. No permission to arbitrary files or network is needed by the chain API.
A no-default-features Rust library also builds for wasm32-unknown-unknown;
use the WIT component above for an exported interoperable interface.

## Conformance

Rust tests check the stdlib Python reference and published format vectors.
Native Python and generated JavaScript tests exercise tampering, rejected
appends, Unicode, unsigned 64-bit integers and WeftMark input. Set
NOSTOI_INTEROP_DIR to an existing temporary directory, run Python tests first,
then JavaScript tests; the latter assert byte-identical records. Finally verify
javascript.jsonl with Python to exercise the reverse direction.
