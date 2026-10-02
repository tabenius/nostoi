# Dependency remediation

Verified on 2026-10-02, based on commit `485f6ec`, on
`codex/dependency-remediation`. Scope: native Python bindings, JavaScript
component build tooling, their lockfiles, and interoperability CI.

## Findings and fixes

GitHub's API (`gh api repos/tabenius/nostoi/dependabot/alerts --paginate`)
reported eight open alerts covering six distinct advisories:

| Dependency | Advisory | Affected manifests | Remediation |
| --- | --- | --- | --- |
| PyO3 | [GHSA-36hh-v3qg-5jq4](https://github.com/advisories/GHSA-36hh-v3qg-5jq4), iterator out-of-bounds reads, high | `bindings/python/Cargo.toml`, `Cargo.lock` (alerts 1, 7) | Require `0.29`; lock PyO3 and its four companion crates at `0.29.3` (patched floor `0.29.0`). |
| PyO3 | [GHSA-chgr-c6px-7xpp](https://github.com/advisories/GHSA-chgr-c6px-7xpp), missing closure `Sync` bound, medium | Same manifests (alerts 2, 8) | Same upgrade. |
| decompress | [GHSA-mp2f-45pm-3cg9](https://github.com/advisories/GHSA-mp2f-45pm-3cg9), archive/link escapes, critical | `bindings/javascript/package-lock.json` (alert 3) | Remove the unmaintained extractor through the upstream weval upgrade below. |
| decompress | [GHSA-h39j-r5qq-r9mm](https://github.com/advisories/GHSA-h39j-r5qq-r9mm), duplicate-path symlink write, medium | Same lockfile (alert 4) | Same removal. |
| decompress | [GHSA-jwp9-9v96-94mx](https://github.com/advisories/GHSA-jwp9-9v96-94mx), arbitrary hardlinks, medium | Same lockfile (alert 5) | Same removal. |
| decompress | [GHSA-hrh2-vp3x-79xf](https://github.com/advisories/GHSA-hrh2-vp3x-79xf), symlink-chain escape, critical | Same lockfile (alert 6) | Same removal. |

The original npm tree was:

```text
@bytecodealliance/jco@1.35.0
  @bytecodealliance/componentize-js@0.22.0
    @bytecodealliance/weval@0.4.1
      decompress@4.2.1
```

`jco@1.35.0` was already the registry's latest version. npm's suggested forced
fix downgraded jco to `1.17.9`. Instead, a manifest-level npm override selects
the upstream `@bytecodealliance/weval@0.5.0` release. Its downloader replaces
decompress and its plugins with `tar` and `fflate`; the regenerated lockfile
resolves `tar@7.5.22` and `fflate@0.8.3`. No decompress package remains. The
override preserves jco's existing transpile CLI and weval's default-export
downloader API. It also selects the actual weval `v0.5.0` executable release.
Revisit the override when componentize-js updates its own weval requirement.

The existing Rust binding signatures, `Bound<PyModule>` registration and
`wrap_pyfunction!` calls compile against PyO3 0.29.3 without source changes.
The `abi3-py311` feature remains enabled; actual extension execution was
verified on both Python 3.11 and 3.14.

CI now audits all npm dependencies (including development tooling) and uses
locked Cargo resolution for Python wheel and JavaScript component builds.
`npm test` includes downloader security regression checks before the existing
component interoperability checks.

## Executed verification

Environment: Linux x86-64, Rust 1.98.1, Node 24.21.0, npm 12.1.0,
maturin 1.15.0, uv 0.12.19, CPython 3.14.7 and 3.11.16.
Commands below run from the repository root unless a directory is specified.

| Command/check | Actual result |
| --- | --- |
| `cargo check -p nostoi-python` | Passed with PyO3 0.29.3. |
| `cargo test --workspace --all-features --locked` | 69 runtime tests and 1 doctest passed; no failures or ignored tests. Covers all workspace members, anchor HTTP failures, kernel ingestion restart recovery, SQLite, CLI and Python/Rust conformance. |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Passed without warnings. |
| `cargo fmt --all --check` | Passed. |
| `cargo build --no-default-features --lib --target wasm32-unknown-unknown --locked` | Passed. |
| `maturin build --locked --manifest-path bindings/python/Cargo.toml --out bindings/python/dist` | Built `nostoi-0.1.0-cp311-abi3-manylinux_2_34_x86_64.whl`. |
| Install that wheel with `uv pip install --python <venv>/bin/python bindings/python/dist/*.whl`, then `<venv>/bin/python -m unittest discover -s bindings/python/tests -v` | Both tests passed on each of CPython 3.14.7 and 3.11.16. Confirmed the imported module is the installed `_native.abi3.so`. Exercises JSONL/SQLite appends, tamper refusal, missing-file errors, canonical Unicode, large integers and invalid inputs. |
| `npm ci` in `bindings/javascript` | Clean install succeeded; audited 72 packages, zero vulnerabilities. |
| `npm run build` in `bindings/javascript` | Locked release `wasm32-wasip2` component build and jco transpilation succeeded. |
| `NOSTOI_INTEROP_DIR=<shared-directory> npm test` in `bindings/javascript`, after Python tests use the same directory | All 6 Node security test cases passed (one parent plus five subtests): normal executable extraction, traversal, hardlink, symlink chain and duplicate symlink/file. Existing component checks passed: append/verify, tamper refusal, precision, WeftMark vector and byte-identical Python/JavaScript output. |
| Verify `javascript.jsonl` using installed Python `nostoi.verify_jsonl` | Two JavaScript-produced records verified on both Python versions. |
| Invoke installed weval's default downloader, then run its returned binary with `--version` | Real release downloaded/extracted and printed `weval 0.5.0`. |
| `npm audit` in `bindings/javascript` | Zero vulnerabilities, including development dependencies. |
| `cargo-audit 0.22.2 audit --db target/advisory-db` | Updated RustSec database (1,279 advisories); scanned 267 locked crate dependencies; no vulnerabilities or warnings. |
| `git diff --check` | Passed. |

`test-extraction.mjs` copies the installed downloader into a disposable cache
directory and supplies generated tar.xz releases through a mocked `fetch`.
Normal extraction must produce an executable. Hostile extraction may reject
or skip entries, but must preserve an outside sentinel's contents and inode
link count. These tests exercise the upstream extraction implementation,
not a replacement implemented by this repository. They run on Linux x86-64
(the interoperability CI platform); other platforms skip the fixture suite.

## Remaining status

No dependency advisories remain in the tested npm or Rust dependency graphs.
The GitHub API still reports the eight original alerts on the default branch;
they are expected to close after this branch is merged and Dependabot rescans
the updated manifests. No alerts were dismissed or audits bypassed.

The Windows ZIP extraction path and non-Linux release binaries were not
executed locally. The project's actual WIT component build, native Python
extension tests and bidirectional interoperability all passed. There are no
remaining remediation blockers on the tested platform.
