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
cross-language equality check. Inspect `cargo package --list`: each crate should
enter crates.io with only its own source, tests, licenses, README and logo.

Before publishing: review the diff and CI, confirm crates.io ownership, check
license files, choose a tag matching Cargo.toml, and record the tested toolchain.
The manifest's Rust floor applies to the core crate; the independently versioned
binding tools may need newer Rust. Publish only after explicitly authorizing a
registry release. `cargo publish` uploads the crate; a GitHub visibility change
does not publish it to crates.io.

## Publication order

The workspace is split into crates that depend on each other, and none of them
has been published yet. crates.io requires a dependency to exist before the
crate that requires it can be packaged, so a release cannot be a single
`cargo publish`. Publish in dependency order:

```sh
cargo publish -p nostoi-core        # no intra-workspace dependencies
cargo publish -p nostoi-anchor      # needs nostoi-core
cargo publish -p nostoi-kmsg        # needs nostoi-core
cargo publish -p nostoi             # needs all three
```

Until `nostoi-core` is on the registry, `cargo package`/`cargo publish` for the
other three fails with `no matching package named nostoi-core found`. That is
the expected pre-release state, not a manifest defect, and CI therefore dry-runs
`nostoi-core` only and checks the other three with `cargo package --list`,
which needs no registry resolution. Inspect those lists: each crate must carry
only its own source, tests and manifest, and the root crate must not carry
`crates/`.

`nostoi::` paths remain available from the root `nostoi` crate, so consumers do
not have to migrate. New code should depend on the compartment it needs.

## Current limits

Verification is linear and reads the chain into memory. Each file append
re-verifies history, so repeated single-record appends have quadratic total
verification cost as a chain grows. Benchmark real workloads before promising
large-log throughput. There is no external security audit, signed-head protocol,
PII scanner or crypto-shredding yet. A valid chain does not prove the events are
true or complete, and tail truncation/full rewriting need an external trusted
head to detect. Anchor and replicate logs according to the actual threat model.
