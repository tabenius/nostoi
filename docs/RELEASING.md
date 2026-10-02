# Preparing 0.1.0

The repository is public at https://github.com/tabenius/nostoi. The Rust crate is
prepared for crates.io; no registry upload or release tag is performed by this
change. Python/npm distribution names and publication credentials must be
confirmed separately. JavaScript is intentionally private in package.json until
that release decision. Binding crates are workspace-only (`publish = false`).

Run from a clean checkout with Rust, Python, maturin, Node and wasm-tools:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --locked
cargo test --no-default-features --lib --locked
cargo build --no-default-features --lib --target wasm32-unknown-unknown
cargo build -p nostoi-component --target wasm32-wasip2 --release
wasm-tools validate target/wasm32-wasip2/release/nostoi_component.wasm
cargo publish --dry-run
```

Build/install the Python wheel, run bindings/python/tests, build the JavaScript
package and run its tests as described in INTEROPERABILITY.md. CI repeats the
cross-language equality check. Inspect `cargo package --list`: only the core
crate, licenses, README, logo and conformance sources should enter crates.io.

Before publishing: review the diff and CI, confirm crates.io ownership, check
license files, choose a tag matching Cargo.toml, and record the tested toolchain.
The manifest's Rust floor applies to the core crate; the independently versioned
binding tools may need newer Rust. Publish only after explicitly authorizing a
registry release. `cargo publish` uploads the crate; a GitHub visibility change
does not publish it to crates.io.

## Current limits

Verification is linear and reads the chain into memory. Each file append
re-verifies history, so repeated single-record appends have quadratic total
verification cost as a chain grows. Benchmark real workloads before promising
large-log throughput. There is no external security audit, signed-head protocol,
PII scanner or crypto-shredding yet. A valid chain does not prove the events are
true or complete, and tail truncation/full rewriting need an external trusted
head to detect. Anchor and replicate logs according to the actual threat model.
