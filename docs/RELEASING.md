# Preparing 0.1.0

## Lightweight CLI/TUI installation

The tagged candidate workflow builds on GitHub-hosted Ubuntu 22.04; no local
Rust toolchain, checkout, Pandoc, Node or Python bindings are needed to install
the resulting `nostoi_0.1.0_amd64.deb`. This package contains the CLI/TUI binary,
license files and README only. Shared-library dependencies are derived from
the ELF binary. OpenSSH is a runtime dependency for SSH attestations.

A separate Linux amd64 Python abi3 wheel is built and tested for Python 3.11+
in the same workflow. Install that wheel when Python consumers need the native
bindings; it does not require Rust or maturin on the consuming machine.

The package is installed and exercised in Debian 12, Ubuntu 24.04 and Kali
rolling containers before publication. CLI, SQLite and tamper-refusal tests
are software release gates; documentation rendering is not one.

Use the signed release manifest and SHA256SUMS to verify downloads at
`https://dl.ragbaz.cc/v1/nostoi/v0.1.0/`. This is explicitly a candidate release,
not a security audit or a crates.io/PyPI/npm publication.

### Artifact lifecycle

| Activity | Required local files | Temporary files that may be evicted afterwards |
| --- | --- | --- |
| Run CLI/TUI | Installed Debian package; its declared OS dependencies | Downloaded `.deb` after installation and hash verification |
| Develop/debug | Source checkout; Cargo.lock; Rust toolchain; optional binding tools | `target/` after tests; recreate with Cargo or prefer hosted CI |
| Python binding work | Python binding source plus maturin/Rust for builds, or a compatible installed wheel | Wheel downloads, build products after verification |
| JS/WASM binding work | WIT/component source, Rust WASM targets and Node/jco | Generated WASM and JS outputs after interop verification |
| Publish release | GitHub-hosted build, package smoke tests, signed manifest and R2 mirror | Runner build directories after publication |
| Read docs | README or downloaded docs | No document renderer required to run software |

Before evicting a downloaded artifact, retain its immutable release URL,
SHA-256, version/platform and purpose. Never treat uncommitted source, audit
chains, trusted anchors, signatures, keys or unique debug evidence as a cache.
RAGBAZ component manifests describe cross-project phase dependencies;
Cargo records the internal `nostoi-core`, optional `nostoi-anchor` and
`nostoi-kmsg` workspace dependencies. Those are crates in this repository,
not separate project edges. Packaging is not an SBOM or an artifact garbage
collector; do not automatically delete other projects' files.

The repository is public at https://github.com/tabenius/nostoi. The Rust crate is
prepared for crates.io; no registry upload or release tag is performed by this
change. Python/npm distribution names and publication credentials must be
confirmed separately. JavaScript is intentionally private in package.json until
that release decision. Binding crates are workspace-only (`publish = false`).

Run from a clean checkout with Rust, Python, maturin, Node and wasm-tools:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
sh -n contrib/systemd/nostoi-anchor-runner
python3 contrib/systemd/test_anchor_runner.py
cargo test --locked -p nostoi --test attestation -- --nocapture   # signs for real
cargo test --no-default-features --features sqlite --example large_chain --locked
cargo build --no-default-features --lib --locked
cargo build --no-default-features --lib --target wasm32-unknown-unknown
cargo build -p nostoi-component --target wasm32-wasip2 --release
wasm-tools validate target/wasm32-wasip2/release/nostoi_component.wasm
cargo publish --dry-run --locked -p nostoi-core
```

`ssh-keygen` has to be on `PATH` for the attestation suite. It signs with a
throwaway key generated per run, so the suite skips when the tool is absent —
which is right on a laptop and wrong in CI, hence the explicit invocation.

Build/install the Python wheel, run bindings/python/tests, build the JavaScript
package and run its tests as described in INTEROPERABILITY.md. CI repeats the
cross-language equality check. Inspect `cargo package --list`: each crate should
enter crates.io with only its own source, tests, licenses, README and logo.

The root package includes `/tests/*.rs` rather than `/tests/**`, which keeps the
attestation suite's committed test key out of the published artifact. Cargo
ignores `exclude` when `include` is present, so the narrowing has to be in
`include`, and CI checks all four crates' package lists for it.

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
large-log throughput. There is no external security audit, PII scanner or
crypto-shredding yet. Signed attestations exist
(`docs/ATTESTATIONS.md`) but they carry no independent timestamp: a signature
proves authorship, not when, so publishing it somewhere append-only remains the
operator's job. A valid chain does not prove the events are
true or complete, and tail truncation/full rewriting need an external trusted
head to detect. Anchor and replicate logs according to the actual threat model.
