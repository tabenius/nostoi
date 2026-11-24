# Adoption review: Nostoi

*Reviewed 2026-10-14 by a review subagent against the working tree at
`/srv/ragbaz/src/vendors/ragbaz/head/nostoi`, branch `feat/crypto-shredding`
(`b043bf9`, four commits ahead of `origin/main` at `9f30341`). Nothing in the
repository was modified to produce this review.*

## Scope and verdict in one paragraph

Nostoi is unusually easy to *start* with and unusually hard to *depend on*.
The zero-to-first-chain path took four commands and the zero-to-signed-chain
path took six; the canonical-JSON contract is the single best-argued format
decision in the fleet, and it is enforced by real cross-language tests that
pass on this machine. The problems are almost entirely about **distribution
and convergence**, not about the format or the code. Nothing is published:
`nostoi`, `nostoi-core` are absent from crates.io, `nostoi` is absent from PyPI,
`@nostoi/audit` is absent from npm, there are zero git tags and zero GitHub
releases. The heaviest adopter in the fleet (Mouseion) therefore **vendors the
whole repository as a git submodule pinned 7 commits behind `main`**, the
runtime (rebekah) pins a **rev** 14 commits behind `main`, and three Python
consumers (frog, sylvae, weftmark) each ship their own ~20-line bespoke module
loader that hunts for `contrib/python/nostoi.py` by guessing workspace-relative
paths, each behind a differently-named environment variable. Signing is worse:
Mouseion invented `nostoi-anchor-v0` (hand-rolled Ed25519 in WebCrypto) that
Nostoi does not read, and WeftMark writes `nostoi-attestation-v1` documents
signed with **OpenPGP**, which `nostoi verify-attestation` cannot check because
it only speaks SSHSIG via `ssh-keygen`. Interoperability is **real for
`nostoi-v1` records and nominal for everything above the record.**

Ranked remedies are in [§4](#4-ranked-recommendations). The cheapest high-leverage
items are a `docs/README.md` index, a corrected CLI table, a published
`nostoi-core` on crates.io, and an explicit read-side rule for the "no floats"
invariant — all under a day of work between them.

---

## 1. OUR FORMATS FIRST — the priority

### 1.1 The `nostoi-v1` record and the canonical-JSON contract

The record is small and the rules are stated in one place that a new adopter will
actually read:

```
/srv/ragbaz/src/vendors/ragbaz/head/nostoi/README.md:105-126
```

`{"v","seq","previous","at","actor"?,"kind","subject"?,"body","digest"}`, `seq`
running from 1 with no gaps, `previous` = the prior digest or 64 zeros,
`digest` = lowercase-hex SHA-256 of the record **minus `digest`** rendered as
canonical JSON. The canonical form is defined *by reference to Python*
(`json.dumps(record, sort_keys=True, separators=(",", ":"))`) rather than by a
prose specification, and the Rust implementation says so at the top of
`crates/nostoi-core/src/canonical.rs:1-21`.

That reference choice is the single highest-leverage decision in the repository.
It means the spec has a second, independent, zero-dependency implementation
(`contrib/python/nostoi.py`, 218 lines, stdlib only), and that the two are
checked against each other **in both directions**:

- `tests/cli.rs:70-124` — `python_and_rust_write_one_chain_together`
- `contrib/python/test_conformance.py` — 22 known-answer and rejection tests
- `crates/nostoi-core/src/format.rs:333-349` — a literal expected digest computed
  from the Python spelling, embedded as a string constant

I ran these on this machine and they pass:

```
$ cargo test --offline --locked -p nostoi-core --no-default-features
test result: ok. 7 passed; 0 failed  (bundle)
test result: ok. 6 passed; 0 failed  (streaming_verify)
test result: ok. 1 passed; 0 failed  (doc-tests)

$ cargo test --offline --locked -p nostoi --test cli
test result: ok. 6 passed; 0 failed

$ python3 contrib/python/test_conformance.py
Ran 22 tests in 0.036s -- OK
```

And by hand, the Python reference verifies a Rust-written chain and Rust
verifies a Python-written chain, with matching heads.

**The one real defect in this layer.** The "no floats, integers within 64 bits"
rule is enforced **only on write, never on read**, and the README states it as
though it were a format invariant. I confirmed by hand:

| record body | `nostoi append` | `nostoi verify` | `contrib/python/nostoi.py` verify |
| --- | --- | --- | --- |
| `{"n":1.5}` | refused, exit 2 | **✓ intact, exit 0** | **ok: True** |
| `{"n":2**100}` | refused, exit 2 | **✓ intact, exit 0** | **ok: True** |
| `{"n":-5}` | refused, exit 2 | **✓ intact, exit 0** | **ok: True** |
| `{"n":1e+16}` | refused, exit 2 | **✓ intact, exit 0** | **ok: True** |

This is not pedantry, because it is exactly the failure the rule exists to
prevent. In Node:

```
$ node -e 'console.log(JSON.stringify(JSON.parse("18446744073709551615")))'
18446744073709552000
```

A JavaScript producer that round-trips a body through `JSON.parse`/`JSON.stringify`
— entirely natural, and something most JS callers will do without thinking — silently
rewrites `18446744073709551615` to `18446744073709552000`. Nostoi then reports the
mangled chain as **intact, exit 0**, because the digest is recomputed over the
mangled bytes. Two different chains, both green, no warning.

`docs/INTEROPERABILITY.md:89-91` does warn about this for the WIT/JS path, and
`crates/nostoi-core/src/canonical.rs:16-18` explains why the verifier deliberately
re-encodes whatever lexical form it read. The gap is that **nothing at the CLI
or verifier level enforces or reports it**, and the README's phrasing
("`body` is a JSON object. **No floats** … and integers within 64 bits") invites
the reader to believe the verifier will catch it. A `verify --strict-numbers`
that exits 2 with `record 7: body has a non-integer number` would close this for
roughly an afternoon.

A related fleet inconsistency: Mouseion's own invariant 2
(`Mouseion/AGENTS.md`) imposes a *tighter* rule — "no floats and no integers
beyond 2^53: use strings" — while nostoi permits up to 2^64-1. Two numeric
limits are in force across the fleet with no document reconciling them.

### 1.2 The append-only SQLite store

This is the strongest single design decision after canonical JSON, and I verified
it end to end. Schema (dumped live from a chain nostoi created):

```sql
CREATE TABLE nostoi_records (
    seq INTEGER PRIMARY KEY CHECK (seq >= 1),
    previous TEXT NOT NULL CHECK (length(previous) = 64),
    digest TEXT NOT NULL UNIQUE CHECK (length(digest) = 64),
    record TEXT NOT NULL CHECK (json_valid(record))
) STRICT;
-- + trigger nostoi_records_extend_chain  (BEFORE INSERT: seq follows head,
--   previous matches head, record carries its own chain fields, digest matches)
-- + trigger nostoi_records_no_update     (BEFORE UPDATE -> RAISE ABORT)
-- + trigger nostoi_records_no_delete     (BEFORE DELETE -> RAISE ABORT)
```

The claim at `README.md:136-144` is "any SQLite client can read and verify the
file but only Nostoi can append". I tested it against the stock `sqlite3`
binary, with no Nostoi loaded:

```
$ sqlite3 ev.sqlite "delete from nostoi_records where seq=1;"
Error: nostoi: records are append-only                       -- refused
$ sqlite3 ev.sqlite "update nostoi_records set record='{}' where seq=1;"
Error: nostoi: records are append-only                       -- refused
$ sqlite3 ev.sqlite "insert into nostoi_records values (...)"
Parse error: no such function: nostoi_digest                 -- refused
$ sqlite3 ev.sqlite "select seq, digest from nostoi_records;"
1|379bdb7bc153e7485309bbf6cd73867be092ee8068aaab86f1ab327a5c76804e  -- read fine
```

So append-only is enforced **by the database itself**, not by trust in the
writer, and it survives a hostile or careless client. `pragma journal_mode`
reports `wal`. `application_id` is `0x4e53544f` ("NSTO") and `nostoi schema
--json` reads it without migrating — `tests/cli.rs:328-353` asserts that
`nostoi schema` never writes a byte.

One wording nit: "any SQLite client can read **and verify**" is slightly
overstated. A plain client can read rows and can *detect* tampering only via the
append-only triggers; to *verify* the digest chain it needs to register
`nostoi_digest()` or recompute the digest itself. Worth one sentence in
`docs/SCHEMA-VERSIONING.md`.

### 1.3 The CLI surface, exit codes and error messages

This is the best part of the adoption story. The exit contract is stated in
`src/main.rs:1-4`, repeated in the README table, implemented in
`src/main.rs:699-707`, and pinned by `tests/cli.rs:32-67`
(`exit_codes_say_intact_broken_or_error`). I exercised the whole surface.

Error messages are unusually good, and they are *prescriptive* rather than
merely descriptive:

```
$ nostoi verify nope.jsonl
✗ nope.jsonl: nope.jsonl: No such file or directory (os error 2)          exit=2

$ nostoi append demo.jsonl --kind x --body '{"n":1.5}'
nostoi: 1.5 is not a 64-bit integer; write decimals and large numbers as strings   exit=2

$ nostoi verify nov.jsonl                  # a JSON file that is not a chain
✗ nov.jsonl: not a chain Nostoi knows (nostoi-v1, weftmark-ledger-v1 or ephor-audit-v1)  exit=2

$ nostoi append tampered.jsonl --kind x    # extending a broken chain
nostoi: tampered.jsonl: not appended, the chain is broken: record 1 was altered: ...    exit=1

$ nostoi verify trunc.jsonl
✗ trunc.jsonl (nostoi-v1): record 1 is unreadable: EOF while parsing a value at line 1 column 200; no record is intact  exit=1
```

Note that "record 1 was altered: its content does not match its digest; no
record is intact" distinguishes *altered*, *unreadable*, *does not link to its
predecessor*, and *unavailable* — four different situations, four different
exit-relevant answers. `docs/AUDIT-FIRST.md` and the site's `/verification/`
page both make the point that collapsing them destroys the evidence.

**Two concrete CLI defects.**

1. **An empty file verifies as OK.** `nostoi verify empty.jsonl` prints
   `✓ empty.jsonl (nostoi-v1): 0 records intact, head (empty)` and exits **0**.
   A newly-created, never-written chain is indistinguishable from an intact
   one at the exit-code level. The site's `/verification/` page calls this out
   in prose ("a chain that verifies because it is empty"), but the CLI says
   nothing and the README does not. For an adoption-critical audit tool this
   is the single most likely silent-failure mode, and it costs about five lines
   to fix (`--require-nonempty`, or a distinct note on the summary line).

2. **The README command table is out of date and incomplete.** `README.md:44-52`
   lists seven commands: `verify`, `append`, `head`, `show`, `log`, `tui`,
   `formats`. The binary has **fourteen**: it is also missing `schema`,
   `attest`, `verify-attestation`, `verify-bundle`, `keygen` and `forget`
   (`nostoi --help`; `src/main.rs:29-252`). `attest` and `verify-attestation`
   are mentioned only in passing in the "What tamper-evidence does and does
   not do" prose, and `keygen`/`forget` (crypto-shredding) are not mentioned
   anywhere in the README and are not on `main` at all. A new adopter reading
   the README would not know the signing workflow is a first-class command.

3. **A mangled `ssh-keygen` failure.** With a world-readable key:

   ```
   $ nostoi attest demo.jsonl --key ./id_ed25519 --principal reviewer@box
   nostoi: ssh-keygen -Y failed: @         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
   exit=2
   ```

   The banner survives, the actionable line ("Permissions 0644 … are too
   open; try `chmod 600`") does not. `docs/ATTESTATIONS.md:208-209` does tell
   the reader `chmod 600` your key, but the error should not require having
   read the manual. This is a small fix in the `ssh-keygen` stderr handling in
   `src/attest.rs`.

Everything else in the CLI behaved exactly as documented. `log --follow`
streams only verified records and treats a trailing partial line as a write in
progress rather than a break (`src/main.rs:669-676`, pinned by
`tests/cli.rs:127-147`). `formats` is self-documenting and prints the three
formats with one-line descriptions. `--format` accepts the historical
`kagp-audit-v1` alias and a bare `nostoi-v1` (`crates/nostoi-core/src/format.rs:54-69`).

### 1.4 Zero to a signed chain: the actual time-to-first-value

This is the number that matters for adoption, so I measured it rather than
estimating. From an empty directory, with `ssh-keygen` already on `PATH`:

```
nostoi append demo.jsonl --kind tool.call --actor agent:claude --subject cs-42 \
    --body '{"tool":"weft_handoff_create"}'          # 1 record, digest printed
nostoi append demo.jsonl --kind skill.run --actor agent:claude --subject sess-7 \
    --body '{"skill":"focus-time"}'
nostoi verify demo.jsonl                              # exit 0
nostoi attest demo.jsonl --key ./id_ed25519 --principal reviewer@box
    # prints: attested seq=2 digest=d51d04e2… by reviewer@box with key SHA256:WUWp9u0c…
    # prints: the exact allowed_signers line to install
    # prints: the exact verify-attestation command to run next
    # prints: "pin that fingerprint somewhere the host cannot rewrite"
printf 'reviewer@box %s\n' "$(cat id_ed25519.pub)" > allowed_signers
nostoi verify-attestation demo.jsonl --allowed-signers allowed_signers \
    --principal reviewer@box --fingerprint SHA256:WUWp9u0c…
    # ✓ signature verified … covers the current head
    # prints the exact signed bytes
```

Six commands, no intermediate files to understand, and the tool tells you the
next command at every step. The `allowed_signers` line and the fingerprint pin
are *printed for you* rather than described. That is unusually good CLI design
and it is the strongest argument for Nostoi's adoption case.

The chain file itself is plain, canonical, one-line-per-record JSONL that a
human can read and `jq` with no Nostoi installed — a real property when the
auditor is not you.

### 1.5 Language bindings and their actual maturity

| Surface | State | Honest assessment |
| --- | --- | --- |
| Rust library (`nostoi`, `nostoi-core`, `nostoi-anchor`, `nostoi-kmsg`) | Mature, 248 `#[test]`s, four crates with feature-gated compartments | Ready. This is the real product. |
| Python stdlib reference (`contrib/python/nostoi.py`) | 218 lines, 22 conformance tests, cross-checked both ways | **Ready, and the one to reach for.** |
| Python native binding (PyO3, abi3) | `bindings/python`, 7 tests | Works, but unpublished, Linux-x86-64-only-tested, and every fleet consumer bypasses it anyway. |
| WIT component + generated JS/TS | `bindings/component/wit/world.wit` (35 lines), 24 JS asserts | Clean contract (JSON text across the boundary so `u64` survives JS), but unpublished, `private: true` in `package.json`, and no filesystem API by design. |
| JS attestation | `verify-document` only, `signature: 'unchecked'` always | Honest, and honestly documented. |

`docs/INTEROPERABILITY.md` is the best doc in the repository for this layer: it
states the two limitations plainly ("Linux x86-64 was tested locally; other
platforms need wheel builds and platform verification before being advertised as
release targets"; "browser bundler integration is not a separately shipped
application"), and it refuses to over-claim. The README at lines 93-96 even
corrects an earlier over-claim in the repo's own history ("The bindings do not
expose attestation verification yet, so 'portable' currently means the format is
reproducible outside Rust rather than that a verifier is shipped for you"), which
corresponds to commit `7f02921 "Stop claiming the bindings can verify an
attestation"`. That is a project that has already caught itself over-claiming
once — a good sign.

### 1.6 Anchoring and signing — where interoperability goes nominal

**Anchoring** (`nostoi-anchor`, S3/R2, fan-out, durable outbox, systemd
templates) is genuinely well documented and architecturally careful:
`docs/ANCHORING-AND-KMSG.md`, `docs/ANCHOR-FANOUT.md`,
`docs/DURABLE-ANCHOR-OUTBOX.md`, `docs/ANCHOR-SCHEDULING.md`,
`docs/STREAMING-VERIFICATION.md`, `docs/S3-DIAGNOSTICS.md`,
`docs/LARGE-CHAIN-BENCHMARKS.md`. Exit codes 0/2/3/4 are distinct
(`crates/nostoi-anchor/src/main.rs:123-125,244-246,264-268`), publisher and
verifier use separate credentials, and the repo ships systemd templates with
`.env.example` files plus a shell/Python test harness for the runner
(`contrib/systemd/`). `docs/RELEASING.md` is an honest pre-release document
that names the publication order and explains why `cargo publish` cannot yet be
a single command.

**`nostoi-anchor-v0` does not exist in Nostoi.** The prompt and Mouseion's
terminology table both treat `nostoi-anchor-v0` as a Nostoi format. It is not.
`grep -rn 'nostoi-anchor-v0'` finds **zero** occurrences anywhere in
`/srv/ragbaz/src/vendors/ragbaz/head/nostoi`. It exists only in Mouseion:
`Mouseion/src/nostoi.js:16`, `Mouseion/scripts/sign-head.mjs`, `Mouseion/migrations/0002_scrolls.sql:159`,
`Mouseion/genesis/genesis.sql`, and `Mouseion/AGENTS.md:22`, which describes it
as "Nostoi's **planned** 'signed head anchor'". So the fleet's heaviest adopter
hand-rolled its own Ed25519 signing document in WebCrypto, and the public site
links to repository docs that describe a different signing story.

**The attestation story forks in three.**

| Producer | Document | Signature | Nostoi can verify it? |
| --- | --- | --- | --- |
| `nostoi attest` | `nostoi-attestation-v1` | SSHSIG via `ssh-keygen -Y sign` | ✅ yes, `verify-attestation` |
| Mouseion `scripts/sign-head.mjs` | `nostoi-anchor-v0` | raw Ed25519, hand-rolled in `src/sshsig.js` | ❌ no |
| WeftMark `scripts/attest-workspace.py` | `nostoi-attestation-v1` | **OpenPGP** via `gpg --detach-sign` | ❌ no |

WeftMark's script says so itself at lines 20-22: *"…the nostoi tooling uses
`ssh-keygen -Y sign`, so this bundle is deliberately readable by a standard
Python implementation, so a future `nostoi attest --driver gpg` is a swap rather
than a redesign."* That is a clearly-named, correctly-scoped known gap — but it
means **two of the fleet's three signing producers produce artefacts the
reference tool refuses**, and the shared format name `nostoi-attestation-v1`
actively hides that.

Related and smaller: the built-in `--portable` verifier
(`crates/nostoi-core/src/sshsig.rs:250-297`) is **Ed25519-only** and refuses
rather than guessing. `docs/ATTESTATIONS.md:174-175` says "Any key
`ssh-keygen` supports works: Ed25519, RSA, ECDSA, FIDO/security keys, a
hardware token" — true of the `ssh-keygen` path, silently untrue of
`--portable`. One sentence needed.

What is *not* a defect, and should be read as a strength:
`docs/ATTESTATIONS.md:358-391` contains an explicit table of what attestation
does and does not detect, including "Attestation backdated after the fact — **Not
detected**", "Private key stolen, attacker signs — **Not detected**", and "A
valid chain does not prove the events in it are true". Few tools in this space
are this honest about themselves.

### 1.7 How the fleet actually uses it today

| Project | Mechanism | Depth | Notes |
| --- | --- | --- | --- |
| **Mouseion** | `nostoi-v1` in Cloudflare D1, with D1 triggers mirroring the SQLite store's; chain mirrored to R2 as `chain/mouseion.jsonl` | **Deepest.** Real. | **Vendors nostoi as a git submodule** (`Mouseion/vendor/nostoi`, pinned at `688f02b`, 7 commits behind `main`). Has its own `src/nostoi.js` canonical-JSON + digest implementation, cross-checked by its own test suite against the vendored CLI and the vendored Python reference. Also **consumes** nostoi attestation bundles (`src/attestations.js`, `src/sshsig.js`, migration 0006) and verifies them in WebCrypto — so Mouseion is both a producer of a *non*-nostoi anchor format and a consumer of the real one. |
| **rebekah** | Ships the CLI in its Nix image | **Real, versioned.** | `rebekah/flake.nix:14-18` pins `github:tabenius/nostoi/4e3827a…` — **14 commits behind `main`**. Packaged by `rebekah/nix/packages/nostoi.nix`. `rebekah doctor` verifies every reachable chain; `rebekah/tests/smoke.sh:66` asserts `ok binary/nostoi`. |
| **sylvae** | `contrib/python/nostoi.py` loaded by path; `SYLVAE_NOSTOI_LEDGER` | Moderate. | `sylvae/src/sylvae/runner.py:65-90`. Ships its own copy next to `__init__` plus two workspace-relative fallbacks. |
| **frog** | Same Python reference by path; `FROG_NOSTOI_PYTHON`, `FROG_NOSTOI_LEDGER` | Moderate. | `frog/src/ragbaz_frog/store.py:404-455`. Writes `*.requested` intents in a separate FULL-sync transaction before side effects — the `docs/AUDIT-FIRST.md` contract, actually implemented. |
| **weftmark** | Own `weftmark-ledger-v1` JSONL (read by nostoi); consumes nostoi's Python reference for the workspace attestation | Moderate. | `weftmark/src/weftmark/adapters/jsonl_ledger.py`; `--nostoi-python` flag in both `scripts/attest-workspace.py` and `scripts/verify-workspace.py`. Signs with **OpenPGP** (see above). |
| **ephor** | `ephor-audit-v1` in `governance_events`, SQLite/PostgreSQL | Read-only. | Private repo (`BAZ.AI-Governance`, present locally). Verified against a **published hash vector** in `crates/nostoi-core/src/format.rs:305-323` and the `kagp-audit-v1` legacy tag is handled. Rebekah can verify ephor chains (`rebekah/tests/smoke.sh:88`). |
| **ragbaz-minotaur** | Shells out to the `nostoi` CLI | Shallow. | `scripts/runtime-status.py:214-216`, `:336`. Its `doc/candidate-readiness-2026-10-02.md:98` still lists "Obtain/pin its actual API" as open. |

**The honest summary: interoperability is real for `nostoi-v1` records and
nominal above the record.**

- **Real**: Mouseion, frog, sylvae, weftmark and rebekah all produce or consume
  the *same bytes*, and three separate projects independently reimplement or
  vendor the same canonical-JSON rule and cross-check it against the reference.
  That is a genuinely strong interop result for a fleet tool.
- **Nominal**: five independent *loader mechanisms* for the same 218-line Python
  file; three *pinning mechanisms* (submodule, Nix rev, path discovery); two
  mutually incompatible signing stories sharing one format name; one parallel
  anchor format (`nostoi-anchor-v0`) that Nostoi cannot read; and five different
  environment-variable names for the same concept
  (`FROG_NOSTOI_PYTHON`, `SYLVAE_NOSTOI_PYTHON`, `FROG_NOSTOI_LEDGER`,
  `SYLVAE_NOSTOI_LEDGER`, `--nostoi-python`).

That last bullet is the clearest single piece of evidence in this review. When
five consumers each write their own loader, the integration is not real yet; it
is five coincidences that currently agree.

### 1.8 Setup, toolchain and other friction

**Rust toolchain.** `rust-version = "1.89"` on all four crates. Local toolchain is
1.98.1. Non-issue.

**Build.** `cargo build --release` from a clean checkout works and produces
`nostoi`, and the `default-features = false` split means a pure verifier needs
no SQLite, no CLI, no Linux. This is well done.

**Python.** Three ways to get Nostoi into Python, all of which work, none of
which is obvious from the README:
1. `contrib/python/nostoi.py` — copy or path-load (what all five fleet consumers do),
2. `python -m pip install ./bindings/python` — needs Rust + maturin, unpublished,
3. `pip install nostoi` — does not exist.

**JavaScript.** `bindings/javascript` with `npm ci && npm run build && npm test`,
needing `wasm32-wasip2`, `jco`, and Node 24. Unpublished and `private: true`.
`bindings/javascript/dist/` is **`.gitignore`d**, so the committed tree has no
usable artefact.

**ssh-keygen** is a hard requirement for signing (`tests/cli.rs:149-156` skips
silently without it; CI has an explicit step to make the skip visible,
`.github/workflows/ci.yml:47-53`). Fine — but it is a runtime dependency on an
OpenSSH CLI for the *core accountability feature*, which is worth stating
plainly to an adopter rather than discovering.

**CI runs on a self-hosted runner.** `.github/workflows/ci.yml:22` —
`runs-on: [self-hosted, linux, x64]`, "this repository's own runner,
`tabenius-nostoi`, registered on the development host". Reasonable for a
single-owner fleet tool; it means an outside contributor's PR gets no
verification, and a runner outage silently stops CI. Also `npm audit` runs
(`.github/workflows/ci.yml:92`), which is good.

**Documentation hygiene.** Every relative link in `README.md` and in all 18
`docs/*.md` files resolves — I checked all of them programmatically; zero
broken. But:

- `docs/` has **18 files and no `README.md` or index**. A new adopter has to
  read the root README to learn `docs/` exists, then to guess an ordering.
- `docs/AUDIT-REVIEW-20251002.md` and `docs/IMPLEMENTATION-PLAN-20251002.md`
  are dated working documents, not reference; they will age badly next to
  normative docs with no marker distinguishing them.
- `docs/health.json` is a machine contract sitting in a human docs directory
  with no schema link.
- No `CONTRIBUTING.md`, no `SECURITY.md`, no `CODE_OF_CONDUCT.md`, no
  `CHANGELOG.md`.

**Licensing.** `MIT OR Apache-2.0` in `Cargo.toml:7`, both licence files
present, `LICENSE-MIT` names a copyright holder. GitHub reports `Apache-2.0`
(it reads one of the two). For an adopter choosing a licence this is
unambiguous in Cargo terms and slightly ambiguous on the GitHub badge; trivial
fix.

**Stale build artefacts in the tree.** `target/release/nostoi` (Oct 2) predates
the current source and **lacks `attest`, `verify-attestation`, `verify-bundle`,
`keygen` and `forget`**; `target/debug/nostoi` (Oct 13) has them. `target/` is
gitignored so this never ships — but anyone who reads this review by running the
release binary will get the wrong command list. Worth a `make clean`-equivalent
note, or nothing at all, since it is local-only.

### 1.9 "From zero to a signed chain" — the precise checklist

For a new adopter inside the fleet, today, with no Nostoi artefact installed:

1. Get the CLI: `cargo build --release` from the repo (no crates.io entry), or
   the Nix package `rebekah/nix/packages/nostoi.nix`, or the Mouseion submodule.
2. `nostoi append CHAIN --kind K` — no init step, no config, no schema, works
   on JSONL or `.sqlite`.
3. `nostoi verify CHAIN` for `ok:true, verified:N, head:{seq,digest}` as JSON.
4. Optionally `nostoi attest CHAIN --key ~/.ssh/id_ed25519 --principal you@host`.
5. Copy the printed `allowed_signers` line into a file; pin the printed
   fingerprint **outside the host**.
6. `nostoi verify-attestation CHAIN --allowed-signers FILE --principal you@host --fingerprint SHA256:…`
   → `signature: "verified"`, `coverage: "current"`.
7. Publish the `.attestation.json` + `.attestation.sig` somewhere append-only
   (the tool tells you so, twice, correctly — a signature proves authorship, not
   time).

That is genuinely short. For **Python** producers the honest answer is different:
vendor or point at `contrib/python/nostoi.py`, and note that it has **no
attestation support at all** — `seal`/`open_sealed` need PyNaCl, and there is no
`attestation_canonical_bytes` in the stdlib reference. The native binding has
`attestation_canonical_bytes` but it is unpublished and Python must still reach
for a signature tool itself.

---

## 2. FIRECRAWL.DEV SECOND — the public documentation surface

### 2.1 What actually exists (verified live, 2026-10-14)

**There is a public site: `https://nostoi.ragbaz.cc/`.** This is not obvious from
the repository — nothing in `nostoi/` mentions it, and it is not linked from the
GitHub repo's `homepage` field (which is `null`). I found it by probing.

| Thing | Status | How I verified |
| --- | --- | --- |
| Public GitHub repo | ✅ `github.com/tabenius/nostoi`, public, not archived, 0 stars / 0 forks | `GET api.github.com/repos/tabenius/nostoi` → HTTP 200, `"private": false` |
| Public docs site | ✅ `https://nostoi.ragbaz.cc/`, HTTP 200, Cloudflare, full `data-project="river"` chrome | direct fetch |
| `robots.txt` | ✅ `Allow: /` + `Sitemap:` | HTTP 200, 69 bytes |
| `sitemap.xml` | ✅ 8 URLs | HTTP 200, 722 bytes |
| Canonical URLs | ✅ `<link rel="canonical">` on every page | present on `/`, `/verification/` |
| `<meta name="description">` | ✅ one-sentence description on every page | present |
| Open Graph / Twitter cards | ✅ `og:title`, `og:description`, `og:image`, `twitter:card` | present on `/` |
| Structured data (Schema.org / JSON-LD / Microdata) | ❌ **zero** on every page I checked | counted `schema.org`, `application/ld+json`, `itemscope` across `/`, `/verification/`, `/bytes/`, `/quorum/`, `/tail-risk/`, `/publications/` → 0, 0, 0 |
| `llms.txt` | ❌ HTTP 404 | direct fetch |
| Markdown rendering of pages | ❌ no `/index.md`, `/llms-full.txt`, or `.md` variants | all HTTP 404 |
| GitHub Releases | ❌ **0** | `api.github.com/.../releases` → `[]` |
| Git tags | ❌ **0** | `git tag -l` empty; `git describe --tags` → "No names found" |
| `CHANGELOG.md` / release-notes feed | ❌ absent from the repo root listing | root contents listing |
| crates.io `nostoi` / `nostoi-core` | ❌ **HTTP 404** `"crate \`nostoi\` does not exist"` | `crates.io/api/v1/crates/nostoi` |
| PyPI `nostoi` | ❌ **HTTP 404** | `pypi.org/pypi/nostoi/json` |
| npm `@nostoi/audit` | ❌ **HTTP 404** | `registry.npmjs.org/@nostoi%2Faudit` (also `"private": true` in `package.json`) |
| GitHub topics | ❌ empty array | API |
| `homepage` field | ❌ `null` | API |

### 2.2 How the site reads to an extractor, and to a human

I scraped every page in the sitemap over plain HTTP and extracted the text. The
finding is not that extraction fails — the HTML is clean, semantic and
server-rendered, and a markdown extractor gets readable prose. The finding is
that **the content extracted is not documentation.**

- `/` — "Tamper-evident audit chains for systems whose actions must remain open
  to examination… Let the record outlive the system." Three shell blocks:
  `git clone … && cargo build --release --bin nostoi && ./target/release/nostoi formats`,
  two `append` invocations, and a Python tamper demo. **This is the single most
  useful page on the site and it is good**: a one-paragraph definition, an
  explicit honesty banner ("Active development · verifier, CLI and TUI in source;
  registry publication pending"), and a runnable path from clone to two records.
- `/verification/` — a four-question essay on integrity vs signer trust vs
  external observation, and a genuinely excellent explanation of how to read an
  exit status. No code.
- `/bytes/` — canonical bytes, why there are no floats, and what they do not buy.
  No code.
- `/quorum/` — independence of custody, fan-out, why it is not majority vote.
  No code.
- `/tail-risk/` — correlated failures, missingness, what p50/p95/p99 does and
  does not license you to claim. No code.
- `/publications/` — three dated essays. **Not a changelog.** It is a blog, and
  nothing on it is versioned.
- `/privacy/`, `/contact/` — studio pages, not project docs.

So: **zero install instructions beyond `cargo build`, zero CLI reference, zero
API reference, zero copy-paste examples for `verify`, `attest`, `verify-attestation`,
`log --follow`, `tui` or `nostoi-anchor`.** The site links out to
`github.com/tabenius/nostoi/blob/main/docs/*.md`, which is better than nothing
but pushes the reader back to GitHub's HTML.

**Firecrawl-verified vs inferred.** `firecrawl_scrape` returned an empty result
for every URL I tried in this environment, including `github.com/tabenius/nostoi`,
so I could not measure Firecrawl's own extraction quality. Everything above was
fetched directly over HTTP and parsed by me. What I can say with confidence is
the structural fact that determines extractor behaviour: server-rendered semantic
HTML with no client-side dependency, a `robots.txt` that permits everything, and
a sitemap — Firecrawl will get the text. **What I am inferring** is the shape of
the ranking and comprehension loss downstream, from the absence of `llms.txt`,
the absence of markdown surfaces, and the absence of structured data.

### 2.3 Discoverability: the numbers

Firecrawl web search (keyless, `categories` unset) for
`nostoi tamper-evident audit chains Rust CLI`, `site:github.com/tabenius/nostoi`,
and `"nostoi" audit chain tabenius` returned **zero results mentioning Nostoi**.
The only near-miss on a broader query was a different project,
`ogentic-audit-core`, which the search engine returned for "portable,
tamper-evident audit log". For a tool whose entire value proposition is
"discoverable by anyone who needs an audit chain", Nostoi is currently invisible
to a web or LLM reader.

### 2.4 The minimal fix

This is not expensive. A Rust CLI with no site needs very little to become
readable by an extractor:

1. **Commit an `llms.txt` and serve it at `/llms.txt`** — ~20 lines, a day's
   work. One paragraph on what it is, the install command, the format summary,
   and a link list.
2. **Add JSON-LD to the landing page and the docs pages.** `@type: SoftwareApplication`
   on `/`, `@type: TechArticle` or `Article` on the essays. See §3.
3. **Publish `docs/` as HTML or as `.md` at stable URLs.** Right now the site's
   outbound links land on `blob/main/docs/*.md`, where `main` is a moving ref.
   Pin to a tag once 0.1.0 exists.
4. **Fix the "registry publication pending" banner** by actually publishing
   `nostoi-core`, `nostoi`, then `nostoi-anchor`, `nostoi-kmsg`, in the order
   `docs/RELEASING.md:53-58` already specifies, and cutting a `v0.1.0` tag so
   `releases` is non-empty and there is a CHANGELOG to point at.
5. **Set the GitHub repo `homepage` to the site** (currently `null`), and add
   topics (`audit`, `hash-chain`, `tamper-evident`, `ledger`, `compliance` —
   the `keywords` in `Cargo.toml:9` are already correct).

---

## 3. SCHEMA.ORG THIRD — where the vocabulary legitimately applies

Mouseion has already done a version of this exercise and got it largely right:
`Mouseion/doc/03-Schema_org_mapping.md` is a model of the discipline this section
asks for — a mapping table with an explicit "Constraint" column, a
"Useful further overlaps, not yet implemented" table, a "Mismatches: do not
flatten these" section, and an honest closing note that its external validator
checks "have not been run yet". I will not repeat its analysis. This section
answers the narrower question: **where Schema.org legitimately applies to Nostoi
itself and to the chains it carries.**

### 3.1 Legitimate applications

**The tool (`https://nostoi.ragbaz.cc/`).** `SoftwareApplication` is correct and
currently absent:

| Property | Value | Why it is honest |
| --- | --- | --- |
| `@type` | `SoftwareApplication` | A CLI, library and TUI is an application, not a `Dataset`. |
| `applicationCategory` | `"DeveloperApplication"` or `"SecurityApplication"` | It is tamper-evidence tooling. |
| `operatingSystem` | `"Linux (systemd, kmsg); nostoi-core is portable"` | Honest about the split — do **not** claim cross-platform for `kmsg-nostoi`. |
| `softwareVersion` | `0.1.0` | Only once a tag exists; before that, omit rather than assert. |
| `license` | `https://spdx.org/licenses/MIT.html` **and** `…/Apache-2.0.html` | Both are real (`Cargo.toml:7`, both files present). "MIT OR Apache-2.0" is not a licence, so name both. |
| `maintainer` | `{"@type": "Organization", "name": "RAGBAZ", "url": "https://ragbaz.cc"}` | Established — the site footer, the sibling projects, the studio pages. Do **not** put a `Person` here; authorship of a chain is a different claim from authorship of the tool. |
| `author` | omit, or `RAGBAZ` as `Organization` | An organization is defensible; naming an individual invites a claim about the code's authorship that nothing establishes. |
| `url`, `sameAs` | `https://github.com/tabenius/nostoi` | Verified to exist and be the repository named in `Cargo.toml:8`. |
| `softwareHelp` | `https://nostoi.ragbaz.cc/` | Point the help at the site, not the repo — that is the fix for §2.3's discoverability problem. |
| `codeRepository` | `https://github.com/tabenius/nostoi` | Verified live. |
| `downloadUrl` / `installUrl` | **omit until crates.io exists** | Both return HTTP 404 today. |

Note `SoftwareSourceCode` is a reasonable secondary node for the repository
(`codeRepository`, `programmingLanguage: "Rust"`, and `SoftwareSourceCode.targetProduct`
→ the `SoftwareApplication`), but it belongs on the *repository* page, and GitHub
gives you no place to put it. The landing page is the better host.

**A chain file.** A `.jsonl` chain is a text file carrying a sequence of
tamper-evident statements. `DigitalDocument` is the honest parent, with
`MediaObject` for the bytes:

| Property | Value | Caveat |
| --- | --- | --- |
| `@type` | `DigitalDocument` | Not `Article` — no author, no prose. |
| `encoding` → `MediaObject` | `encodingFormat: "application/x-ndjson"`, `contentSize`, `contentUrl` | Real and checkable. |
| `sha256` | the **chain file's own digest** | See the trap in §3.2.1. |
| `identifier` | the **head digest** at the attested position | See §3.2.2. |
| `dateCreated` | the `at` of the **first** record | Defensible; say "first record" in the accompanying prose. |
| `version` | omit — or `"1"` for the *format* | A chain has no version in the `SoftwareApplication` sense. See §3.2.3. |
| `keywords` | the distinct `kind` values, if the producer chooses to publish them | Opt-in only. |

**An attestation document or bundle.** This is the cleanest mapping in the whole
schema, because the document genuinely *is* a named, signed, structured statement:

| Property | Value |
| --- | --- |
| `@type` | `DigitalDocument` (or `CreativeWork`) |
| `identifier` | the attestation document's own digest |
| `contentSize`, `encodingFormat` | the sidecar bytes |
| `signer` | `{"@type": "Person", "name": "alice@laptop"}` — **see §3.2.5, this one is conditional** |
| `about` | `{"@type": "DigitalDocument", "identifier": <chain head digest>}` |
| `dateCreated` | `anchored_at` — **see §3.2.4, do not emit this** |

**A published chain as a feed.** If you ever export a chain for a browser to
consume, `DataFeed` / `DataFeedItem` is defensible: each record is genuinely a
feed item with a stable position, a timestamp and a digest. `DataFeedItem.position`
maps cleanly to `seq`, `item` to the record. But see §3.2.2 before you write
`Dataset`.

### 3.2 Mismatches and abuse risks — where Schema.org actively misleads

**1. `sha256` is a file digest, not a chain-head digest.** This is the most
likely mechanical error. Schema.org's `sha256` is defined on `MediaObject` as the
hash of *the entity's bytes*. In a chain, the record digest is a hash of the
canonical JSON *of that record*, and `previous` chains it to its predecessor —
so **there is no "chain file sha256" that the chain itself vouches for.** The
head digest is the hash of the *last record's canonical bytes*; hashing the
concatenated file gives a different value that nobody in the system computes or
checks. Emit `sha256` only for a real file you actually hashed, and put the head
digest on `identifier`. Mouseion already states this rule at
`Mouseion/doc/03-Schema_org_mapping.md:35` ("File `sha256` hashes those exact
bytes. A manifest digest is not a file digest") and it should be copied.

**2. Do NOT call a chain a `Dataset`.** `Dataset` means "a collection of data
with a distribution mechanism and a stated licence". A `nostoi-v1` chain is
none of those things: it is an *append-only integrity log*, its licence is the
code's, and nobody distributes it in the `Dataset` sense. Labelling a chain
`Dataset` would imply (a) a licence attached to the records and (b) a
stable distribution endpoint — both false, both legally meaningful, both the kind
of false a reader acts on. Use `DigitalDocument`, or `DataFeed` if you are
publishing a stream.

**3. Do NOT use `version` for the format name, and do not claim a chain version.**
`schema.org/version` is "the version of the software or creative work", and
`SoftwareApplication.softwareVersion` is the release number. `nostoi-v1` is a
**format identifier**, and the fleet already has a live incident of this
confusion: Mouseion's `mouseion.scroll/v0` is its own API schema, and
`Mouseion/doc/03-Schema_org_mapping.md:79-81` explicitly warns not to relabel it
as a Schema.org release. Nostoi's analogue is real: `docs/SCHEMA-VERSIONING.md`
separates *schema revisions* (`nostoi-audit-store` schema 1, `application_id
0x4e53544f`) from record *formats* (`nostoi-v1`). Two version axes, one
`version`-shaped word. Put the format in `identifier`/`about`, and let
`softwareVersion` carry `0.1.0` and nothing else.

**4. Do NOT emit `dateModified` for an append-only chain.** This is the sharpest
misleading case, because it is *plausible, easy, and always wrong in a way that
matters.* `dateModified` means "when this thing's content last changed". An
append-only chain's records never change — and yet `nostoi --json` happily hands
you the last record's `at`, which is exactly what a naive integration would map
to `dateModified`. The result is a page claiming a document was modified on a
date, for a document that is by construction immutable, which is precisely the
wrong claim for an *audit* surface. If you want a "last activity" signal, model
it honestly: `dateCreated` for record 1, a stated `additionalType` or prose for
the head's `at`, and — if you must — `datePublished` for the moment the
*anchor* was made, because that genuinely is a publication event.
Mouseion made exactly this call at `Mouseion/doc/03-Schema_org_mapping.md:69-71`
("Sitemaps omit `lastmod` rather than invent it from publication time").

**5. Do NOT use `ClaimReview` for a verification result.** This is the worst
possible abuse and it is attractive precisely because Nostoi produces a
review-shaped answer. `ClaimReview` is Google fact-checking markup: it asserts
that someone reviewed a claim and reached a `Rating`. Emitting it from
`nostoi verify --json` would tell a search engine that an automated hash check
is a human-authored fact-check, with a rating attached. It would be false,
it is structured data that Google surfaces prominently, and it is the single
most likely way this project could cause real harm to a reader's understanding.
`docs/ATTESTATIONS.md:387` already says the right thing — "An attestation
exists, chain intact: **Proves nothing about whether the *contents* are true**,
only that someone vouched" — and Mouseion says it at
`Mouseion/doc/03-Schema_org_mapping.md:61-64`. If you want machine-readable
integrity, use `DigitalDocument` + `identifier` + a custom vocabulary term in
your own namespace. Never `ClaimReview`, never `Rating`.

**6. `signer` is a claim, and on this chain it is one you cannot always make.**
`schema.org:signer` (a `Person` or `Organization`) is a **declaration of who
signed**. For a `nostoi-attestation-v1` document it is legitimate *only if the
signature has been verified against an allowed-signers file with a pinned
fingerprint*, which `docs/ATTESTATIONS.md:374-387` spells out. Two constraints
make the naive mapping wrong:
- `attest --author` is documented as "the signer's own words" that is published
  permanently (`src/main.rs:170-172`) — it is a free-text self-description, not
  an identity claim.
- `principal` is whatever string the signer passed. `docs/ATTESTATIONS.md:283-287`
  warns that an `allowed_signers` entry does not narrow: "a raw key listed under
  two principals verifies for both". A verified signature proves *a key you
  already trusted signed it*, which is narrower than "this person signed it".
If you emit `signer`, say so in adjacent prose, and only after a successful
`verify-attestation`.

**7. `author` and `creator` are wrong for a chain record, and wrong for `actor`.**
`nostoi-v1` has `actor`, and `docs/AUDIT-FIRST.md:8` forbids putting secrets or
unbounded text in it. `actor: "agent:claude"` names a *software agent*, not a
`Person` or `Organization`. Mapping `actor` → `author` would assert that
Claude authored the record, which is a claim about machine authorship that
Schema.org has no vocabulary for and that nobody has established. If you need
the field on a page, use your own namespace. Mouseion's invariant 4 is the same
instinct applied correctly: "A real name is **never** connected to a pseudonym in
anything public."

**8. Do not imply licensing or authorship of the records.** The tool is
`MIT OR Apache-2.0`. That licence covers *the code*. Attaching `license` to a
chain or an attestation would assert a licence over records the publisher may
not own. `docs/ATTESTATIONS.md:148-151` makes the analogous point about evidence
bytes ("Binary evidence never enters the document"). Emit `license` on the
`SoftwareApplication` node and nowhere else.

**9. `identifier` on a chain is a *pointer*, not a name.** Per §3.2.2, a head
digest identifies a position in a chain. It is a legitimate `identifier` value —
but it resolves only against a copy of that exact chain at that exact prefix. Do
not publish it as a stable URL, a DOI-style handle, or an `identifier` that
implies a registry lookup will find something. Mouseion's id-namespace work
(`Mouseion/AGENTS.md` invariant 14) is the counter-example done well: they
minted a namespace precisely so their ids are resolvable.

**10. `additionalProperty` is not declared on `CreativeWork`.** Per
`Mouseion/doc/03-Schema_org_mapping.md:65-68`, do not dump `chain_seq`,
`record_digest`, `coverage` and `attestation_fingerprint` into an
`additionalProperty` bag just because they are key/value pairs. Use
`PropertyValue` with a typed `propertyID` from your own vocabulary, attached to a
node where the property is legal, or keep them in the body.

### 3.3 The one-sentence version

Schema.org legitimately describes **the tool** (`SoftwareApplication`,
`license`, `maintainer`, `codeRepository`, `softwareVersion`), **a chain file**
(`DigitalDocument` + `MediaObject` with a real `sha256` and a real
`contentSize`), **an attestation document** (`DigitalDocument` + `identifier` +
`about`, with `signer` only after a pinned-fingerprint verification), and **a
published feed** (`DataFeed`/`DataFeedItem`, `position` → `seq`). It must not be
used to express a verification *result* (`ClaimReview`), a chain's *format*
(`version`/`softwareVersion`), a chain's *last-activity time* (`dateModified`), a
chain's *kind* (`Dataset`), a record's *actor* (`author`/`creator`), or a
licence over records or evidence. The general rule that resolves all ten: **if a
Schema.org property carries an implication the code does not actually guarantee —
a licence, a rating, an authorship, a modification time, a stable resolution — do
not emit it.**

---

## 4. RANKED RECOMMENDATIONS

Effort is in engineer-days. "Adoption effect" is my judgement of how much this
moves the number of projects outside the author who can usefully depend on
Nostoi.

### P0 — cheap, high leverage. Do these first.

| # | Action | Where | Effort | Adoption effect |
| --- | --- | --- | --- | --- |
| P0.1 | **Publish `nostoi-core`, then `nostoi`, `nostoi-anchor`, `nostoi-kmsg` to crates.io and cut `v0.1.0`.** The order, the dry-run command and the file-list checks are already written in `docs/RELEASING.md:47-67` and `.github/workflows/ci.yml:116-146`. | `docs/RELEASING.md` | 0.5 d + an authorization decision | **Largest single unlock.** Turns "clone a repo" into `cargo add nostoi`. Currently *every* consumer is a fork, a submodule or a path guess. Removes rebekah's rev-pin and Mouseion's submodule as the only options. |
| P0.2 | **Ship one canonical Python entry point.** Publish `nostoi` on PyPI as a pure-Python package wrapping `contrib/python/nostoi.py` (no maturin, no Rust, works on any platform), and adopt a single documented resolution order: `NOSTOI_PYTHON` env var → installed `nostoi` → vendored path. Then delete frog's and sylvae's bespoke loaders in favour of `import nostoi`. | new `bindings/python/stdlib/` or `contrib/python/`; `frog/src/ragbaz_frog/store.py:404-438`; `sylvae/src/sylvae/runner.py:65-90`; `weftmark/scripts/{attest,verify}-workspace.py` | 1–2 d + adoption | Five bespoke loaders and five env-var names collapse to one. This is the clearest "interoperability is nominal" evidence in the review, and the fix is small. |
| P0.3 | **Add `docs/README.md`** — an ordered index of all 18 docs with one line each and an explicit "start here if you want to X" routing table (audit this chain / add a chain / sign it / anchor it / ship it / publish it). Mark `AUDIT-REVIEW-20251002.md` and `IMPLEMENTATION-PLAN-20251002.md` as dated working documents. | `docs/` | 1 h | New adopters currently learn that `docs/` exists only by reading the root README, then guess an ordering across ~21,700 words. |
| P0.4 | **Correct the CLI table in the README** to all fourteen subcommands, with `attest` / `verify-attestation` / `verify-bundle` / `schema` given the same one-line treatment the others have. Add a `CHANGELOG.md` with a `0.1.0` entry. | `README.md:44-52`; new `CHANGELOG.md` | 1 h | The signing workflow is invisible in the README today, which is the workflow most adoption interest will be about. |
| P0.5 | **State the number rule as a verification rule, not a writing rule.** Add `--strict-numbers` (default **on** for `verify`, opt out with `--lenient-numbers`) that exits 2 on a body containing a float, a negative integer, or an integer outside 64 bits, naming the record. Update `README.md:118-119` to say plainly: *"Nostoi writes only such records and, by default, refuses to verify a chain that contains one."* | `crates/nostoi-core/src/{canonical,format,chain}.rs`; `src/main.rs:55-64` | 0.5 d | Closes the silent-divergence hole in §1.1 — the one place where a correct-looking green result hides a real data-loss bug. Also makes the JS `JSON.parse` round-trip failure loud instead of silent. |
| P0.6 | **Make an empty chain distinguishable.** Note it on the summary line (`✓ 0 records intact, head (empty) — nothing has been recorded yet`) and add `--require-nonempty` for exit-code-driven callers. | `src/main.rs:1164-1184` | 30 min | `verify` on a freshly-created, never-written file currently exits 0 identically to a healthy chain. This is the most likely silent-failure mode for a new adopter. |
| P0.7 | **Fix the mangled `ssh-keygen` error** so `nostoi attest` on a world-readable key says `chmod 600` rather than printing ssh-keygen's banner alone. | `src/attest.rs` (stderr handling) | 30 min | First-90-minutes experience of the headline feature. |

### P1 — moderate cost, high value.

| # | Action | Effort | Adoption effect |
| --- | --- | --- | --- |
| P1.1 | **Reconcile or explicitly separate the three signing formats.** Either implement `--driver openpgp` in `nostoi attest` (WeftMark's script already names this as "a swap rather than a redesign") **or** rename the WeftMark document to `weftmark-workspace-attestation-v1` and state in both repos that it is not nostoi-verifiable. Do not leave two incompatible artefacts sharing the name `nostoi-attestation-v1`. | 3–5 d or 2 h | Today two of three fleet signing producers emit something `nostoi verify-attestation` refuses. The shared name hides it. |
| P1.2 | **Decide `nostoi-anchor-v0`'s fate and write it down.** It is implemented only in Mouseion and is unknown to Nostoi. Either adopt it into `nostoi-core` as a documented format, or record in `Mouseion/doc/roadmap.md` and `nostoi/docs/` that Mouseion's anchor is deliberately separate, with a link. Today `Mouseion/AGENTS.md:22` describes it as a Nostoi format, which is simply true of neither the code nor the spec. | 1–3 d | Removes the most confusing single fact about Nostoi's signing surface. |
| P1.3 | **Document the Ed25519-only `--portable` restriction** in `docs/ATTESTATIONS.md:174-175`, which currently reads as though any `ssh-keygen`-supported key works for every path. | 15 min | Prevents an adopter with an RSA/FIDO attesting key from discovering the limit as a runtime refusal. |
| P1.4 | **Publish `llms.txt` at `https://nostoi.ragbaz.cc/llms.txt`**, set the GitHub repo `homepage` to the site, and add repo topics. | 2–3 h | Verified today: the site exists and is unlinked from the repo, `homepage` is `null`, topics are empty, and three Firecrawl searches returned zero Nostoi results. |
| P1.5 | **Add a `/docs/` route to the site** carrying `verify`, `attest`, `verify-attestation`, `log --follow`, `tui` and `nostoi-anchor` examples, and pin the repo links to a tag rather than `main`. | 1 d | The site has exactly three code blocks, all on `/`, none beyond `append`. |
| P1.6 | **Publish the Python wheel** (abi3, already built by CI) to PyPI and un-`private` `@nostoi/audit` on npm. | 0.5 d each | `bindings/javascript/dist/` is gitignored, so today there is no consumable JS artefact in the tree at all. |
| P1.7 | **Add a `nostoi upgrade` path note to `docs/RELEASING.md`**: what changes between revs, and that consumers must re-run cross-checks after bumping. rebekah is 14 commits behind `main` and Mouseion 7, with no recorded upgrade procedure. | 1 h | Converts two silent pins into managed dependencies. |

### P2 — expensive, or lower leverage.

| # | Action | Effort | Note |
| --- | --- | --- | --- |
| P2.1 | Add `SCHEMA-VERSIONING` / `MIGRATION.md` and a real upgrade story for `application_id` and schema revisions across existing stores. | 3–5 d | Only pays once there are external stores to migrate. |
| P2.2 | Wasmtime/Node **and browser-bundler** packaging with a worked example. | 3–5 d | `docs/INTEROPERABILITY.md:94` already says browser bundling is untested; do not claim otherwise until it is. |
| P2.3 | Move CI off the self-hosted runner, or add a GitHub-hosted fallback job for the format-only suite (`nostoi-core` needs no Linux, no network and no secrets). | 1–2 d | Also gives outside contributors verified PRs. |
| P2.4 | Add `SECURITY.md` with a disclosure route, and a `CONTRIBUTING.md`. | 2 h | Cheap, but the value only materialises with external contributors, so it sits at P2 despite the 2-hour cost. |
| P2.5 | Have an external party review the canonicalisation, the SSHSIG parsing and the SQLite trigger design. | 1–2 weeks | `docs/RELEASING.md:76` already states there is no external security audit. This is the right next step *if* the fleet intends to rely on this for real accountability. |
| P2.6 | Format/kind registry (`tool.call`, `task.claim`, `skill.run`, `key.erased`, …) with a published vocabulary. | 2–3 d | `kind` is currently a free string. A registry would help fleet-wide reporting, but it constrains adopters before there are many. |
| P2.7 | Re-examine the quadratic append cost flagged in `docs/RELEASING.md:74-77` (`docs/LARGE-CHAIN-BENCHMARKS.md` has the numbers) if per-record append throughput matters. | 5–10 d | Not a blocker at current fleet volumes. |

---

## 5. WHAT IS GENUINELY GOOD TODAY

This is a well-built tool with a serious author. The problems above are
distribution and convergence problems, not quality problems, and it would be a
mistake to read this review as a verdict on the engineering.

**The canonical-JSON decision is exemplary.** Defining the format *as Python's
`json.dumps` output* rather than as prose turned a spec into an executable
contract, and gave the project a 218-line stdlib-only reference implementation
that five separate fleet projects can use with zero dependencies. The
explanation of *why* — floats have more than one spelling, so a digest must not
depend on which one a language picks — is in `crates/nostoi-core/src/canonical.rs:16-18`,
and it is the kind of comment that prevents a future maintainer from
"simplifying" the rule away. Tests check both directions, plus 64-bit
boundaries, Unicode and tamper parity (`contrib/python/test_conformance.py`,
22 tests, passing here in 36 ms).

**The `nostoi-attestation-v1` document design is right, and its security
reasoning is better than right.** Signing the *canonical bytes of the parsed
content* rather than the bytes on disk means a pretty-print, a CRLF, or a
reordered key does not invalidate a signature — and, crucially, means no
attacker can hand you a byte sequence that *normalizes* into a valid document.
`docs/ATTESTATIONS.md:102-122` walks through the alternative ("collapse
whitespace, upper-case, compare") and shows concretely why it fails:
`{"a  b"}` vs `{"a b"}` merge, U+00A0 vs U+0020 corrupt, and
`"straße".to_uppercase()` is `"STRASSE"` — case folding is not injective.
Refusing non-NFC strings rather than rewriting them (`docs/ATTESTATIONS.md:130-143`)
is the correct call, for the correct stated reason.

**The honesty is structural, not decorative.** `docs/ATTESTATIONS.md:358-391` is
a table of what attestation *does not* detect, including "Attestation backdated
after the fact — **Not detected**", "Private key stolen, attacker signs — **Not
detected**", and "You are compelled to sign something false — **Not detectable
by this mechanism**". `docs/RELEASING.md:72-83` opens "Current limits" by
saying verification is linear and quadratic on repeated appends. The
`verify_attestation` binding reports `signature: "unchecked"` *always*, and
`docs/INTEROPERABILITY.md:56-60` explains exactly why it must and why it cannot
do otherwise. Commit `7f02921 "Stop claiming the bindings can verify an
attestation"` is a project that caught itself over-claiming and reverted it in
the open. That is the single most adoption-relevant cultural signal in the
repository: a reader can trust the "no" answers, because the author has been
willing to correct the "yes" ones.

**The SQLite store's integrity does not depend on trusting the writer.** Triggers
refuse `UPDATE` and `DELETE`, and an `INSERT` must extend the head with a digest
matching its record — enforced by the database, verified above against the stock
`sqlite3` client. `nostoi schema` is proven not to write by comparing file bytes
before and after (`tests/cli.rs:350-352`). CI fails closed on its own
packaging guard, because piping `cargo package --list` into `grep` would let an
empty listing pass as "no key found"
(`.github/workflows/ci.yml:127-140`) — that is a guard written by someone who has
been burned by that class of bug.

**The CLI teaches.** `nostoi attest` prints the `allowed_signers` line to
install, the fingerprint to pin, the exact verification command to run next, and
the reason it matters ("a signature proves authorship, not when"). `nostoi
verify` on an unattested chain says so and prints the command that fixes it. A
missing attestation is never treated as a pass (`docs/ATTESTATIONS.md:411-412`).
Four failures — altered, unreadable, does-not-link, unavailable — get four
different messages and four different exits. This is what a tool that wants to
be used by someone who has never read its manual looks like.

**The design language is respected.** `src/design.rs` carries a vendored,
unedited copy of the fleet's generated tokens with a `source-digest` and a
"Do not edit, regenerate in the design system" header. The TUI conforms rather
than hardcoding.

**The tests are documentation.** 248 Rust `#[test]`s, 44 Python test functions,
24 JavaScript assertions. `tests/cli.rs` asserts not only that exit codes are
0/1/2 but that the *messages* contain "no attestation", "nostoi attest",
"covers the current head", "the chain is at 2", "proves authorship" — so the
onboarding guidance is regression-tested and cannot rot.

**Every link in the README and all 18 docs resolves.** I checked
programmatically: zero broken. Most projects cannot say that.

**The crate split is the right call.** `nostoi-core` has no networking, CLI or
Linux dependency, which is what makes the bindings and the `default-features =
false` pure verifier possible at all. `docs/COMPARTMENT-ARCHITECTURE.md:96-101`
is honest that the split "introduced manifests, release/version coordination and
a larger feature/build matrix" and names that as the cost.

**Mouseion's integration is a real proof, not a claim.** It vendors Nostoi,
reimplements canonical JSON independently in `src/nostoi.js`, and cross-checks
its implementation against the vendored CLI *and* the vendored Python reference
in its own test suite. That is the strongest interoperability evidence in the
fleet, and it was earned by a consumer, not claimed by the author.

---

## 6. EVIDENCE APPENDIX

### 6.1 Files read in full

```
nostoi/README.md                                    (205 lines)
nostoi/Cargo.toml                                   (64)
nostoi/.github/workflows/ci.yml                      (146)
nostoi/.gitignore, nostoi/docs/health.json
nostoi/src/main.rs                                  (1210)
nostoi/crates/nostoi-core/src/format.rs             (358)
nostoi/crates/nostoi-core/src/error.rs              (32)
nostoi/crates/nostoi-core/src/portable.rs           (99)
nostoi/crates/nostoi-core/src/canonical.rs          (1-60 of N)
nostoi/tests/cli.rs                                 (353)
nostoi/contrib/python/nostoi.py                     (218)
nostoi/bindings/python/python/nostoi/__init__.py     (52)
nostoi/bindings/python/pyproject.toml
nostoi/bindings/javascript/package.json
nostoi/bindings/component/wit/world.wit             (35)
nostoi/docs/ATTESTATIONS.md                         (412)
nostoi/docs/INTEROPERABILITY.md                     (117)
nostoi/docs/RELEASING.md                            (83)
nostoi/docs/COMPARTMENT-ARCHITECTURE.md             (109)
nostoi/docs/AUDIT-FIRST.md                          (65)
```

### 6.2 Files inspected selectively

```
nostoi/crates/nostoi-core/src/{chain,jsonl,sqlite,schema,time,attestation,bundle,revocation,sealed,sshsig}.rs
nostoi/crates/nostoi-anchor/src/main.rs             (exit-code map, lines 101-268)
nostoi/crates/nostoi-anchor/Cargo.toml
nostoi/crates/nostoi-kmsg/{Cargo.toml,src/lib.rs}
nostoi/src/{attest,bindings,design,error,lib,runtime_status,theme,tui}.rs
nostoi/tests/{attestation,crypto_shredding}.rs, nostoi/tests/fixtures/README.md
nostoi/examples/{scale.rs,run_large_chain.py}
nostoi/contrib/systemd/  (env examples, unit files, runner, test_anchor_runner.py)
nostoi/docs/  (all 18 files; word counts, link resolution, 'portable'/'ed25519' greps)
Mouseion/doc/03-Schema_org_mapping.md              (111, read in full)
Mouseion/AGENTS.md                                 (supplied as session instruction)
```

### 6.3 Fleet files inspected

```
frog/AGENTS.md; frog/src/ragbaz_frog/store.py:400-455
sylvae/src/sylvae/{runner,review}.py; sylvae/tests/test_runner.py
weftmark/src/weftmark/adapters/jsonl_ledger.py; weftmark/scripts/{attest,verify}-workspace.py
weftmark/attestations/VERIFY.md; weftmark/tests/test_workspace_attestation.py
rebekah/flake.nix:10-25; rebekah/nix/packages/nostoi.nix; rebekah/tests/smoke.sh:66-88
rebekah/docs/{audit-first,deployment,runtime-status}.md
ragbaz-minotaur/scripts/runtime-status.py:198-336; ragbaz-minotaur/doc/candidate-readiness-2026-10-02.md
Mouseion/{src/nostoi.js,src/attestations.js,scripts/sign-head.mjs,genesis/genesis.sql,migrations/0002_scrolls.sql,vendor/nostoi}
```

### 6.4 Commands run

```bash
# Reading and navigation
find <nostoi> -path ./target -prune -o -path '*/node_modules' -prune -o -type f -print | sort
git log --oneline -25; git log --oneline main..HEAD; git tag -l; git branch -a
git diff -rq Mouseion/vendor/nostoi nostoi --exclude=target --exclude=.git …
git ls-tree HEAD vendor/nostoi        # (run in Mouseion)

# Tests (all passing)
cargo test --offline --locked -p nostoi-core --no-default-features
cargo test --offline --locked -p nostoi --test cli
python3 contrib/python/test_conformance.py

# Hands-on adoption walkthrough (all in /tmp/opencode/nostoi-review)
target/debug/nostoi --version | --help | formats | verify | append | head | show | log
target/debug/nostoi attest <chain> --key ./id_ed25519 --principal reviewer@box
target/debug/nostoi verify-attestation <chain> --allowed-signers … --principal … --fingerprint …
target/debug/nostoi attest --bundle … && target/debug/nostoi verify-bundle … --portable
target/debug/nostoi verify <tampered|gap|trunc|float|bignum|neg|exp|empty|nov>.jsonl
target/debug/nostoi append <b>.jsonl --kind … --body '{bad|float|" "}'
target/debug/nostoi append ev.sqlite … ; target/debug/nostoi schema ev.sqlite --json
sqlite3 ev.sqlite "insert|update|delete|select …"     # append-only proof
PYTHONPATH=contrib/python python3 -c "import nostoi; …" # both-direction interop
cp …/tests/fixtures/id_ed25519 . ; chmod 600 …        # attestation key

# Link resolution (programmatic)
python3 - <<'EOF'  # all README + docs/*.md relative links → 0 missing
# JS numeric round-trip
node -e 'console.log(JSON.stringify(JSON.parse("18446744073709551615")))'
```

**Network (read-only; no mutating call was made):**

```
GET https://api.github.com/repos/tabenius/nostoi            → 200 (private:false, 0 releases, 0 topics, homepage null)
GET https://api.github.com/repos/tabenius/nostoi/releases    → []
GET https://api.github.com/repos/tabenius/nostoi/tags        → []
GET https://api.github.com/repos/tabenius/nostoi/contents/…   → root, docs, crates, bindings listings
GET https://raw.githubusercontent.com/tabenius/nostoi/main/README.md   → 200
GET https://crates.io/api/v1/crates/nostoi                   → 404 "crate `nostoi` does not exist"
GET https://crates.io/api/v1/crates/nostoi-core              → 404 "crate `nostoi-core` does not exist"
GET https://pypi.org/pypi/nostoi/json                        → 404
GET https://registry.npmjs.org/@nostoi%2Faudit               → 404
GET https://github.com/tabenius/nostoi                       → 200 (327 KB; no JSON-LD; has meta description + OG)
GET https://nostoi.ragbaz.cc/  /robots.txt  /sitemap.xml
    /llms.txt  /llms-full.txt  /index.md  /README.md
    /.well-known/ai-plugin.json                              → as tabulated in §2.1
GET https://nostoi.ragbaz.cc/{verification,bytes,quorum,tail-risk,publications}/
GET https://ragbaz.cc/llms.txt · https://tabenius.github.io/nostoi/ · https://docs.ragbaz.cc/
firecrawl_search: "nostoi tamper-evident audit chains Rust CLI" · "site:github.com/tabenius/nostoi"
                 · "\"nostoi\" audit chain tabenius" · "nostoi crate rust hash chain \"nostoi-v1\""
```

### 6.5 What I did NOT verify

- **Firecrawl's own extraction quality.** `firecrawl_scrape` returned an empty
  result for every URL attempted in this environment, including
  `github.com/tabenius/nostoi`. Every claim in §2 about "how the docs read to an
  extractor" is therefore derived from the raw HTML I fetched and parsed
  directly. **Verified:** server-rendered semantic HTML, `robots.txt` allowing
  all, a sitemap, no `llms.txt`, no structured data, content composition.
  **Inferred:** ranking, chunking and comprehension quality in an LLM pipeline.
- **`cargo test --workspace --all-features`** — not run (full workspace build).
  I ran `nostoi-core` (no default features), the root `cli` integration suite,
  and the Python conformance suite. The anchor, kmsg, attestation, crypto-shredding
  and JS suites were **not** executed here; I read their sources and CI steps.
- **`cargo publish --dry-run -p nostoi-core`** — not run. §2.1's crates.io 404s
  were confirmed against the live crates.io API, which is the stronger claim.
- **The Python native binding and the JS/WASM bindings at runtime.** Not
  installed, not built, not run. Their maturity assessment in §1.5 comes from
  `bindings/python/src/lib.rs`, `bindings/python/tests/test_api.py` (7 tests),
  `bindings/javascript/test.mjs` (24 asserts) and `docs/INTEROPERABILITY.md`.
- **Mouseion's D1 chain, its R2 mirror, and its Worker.** Not deployed, not
  exercised. Its Nostoi integration is assessed from source and its `AGENTS.md`
  invariants only. I did not run Mouseion's `npm run nostoi:build` / `npm test`.
- **The public site's content pipeline.** I read the rendered HTML. I do not
  know whether the site is generated from the repository, from a separate CMS, or
  by hand — nothing in `nostoi/` references it, which is itself a finding.
- **`ephor` (`BAZ.AI-Governance`).** Private repo, present locally, not opened.
  The `ephor-audit-v1` assessment is from `crates/nostoi-core/src/format.rs`,
  the published hash-vector test, and rebekah's smoke test.
- **The TUI visually.** I read `src/tui.rs` and its 19 tests; I did not launch
  `nostoi tui`. (Note the `session-safety` skill's standing rule about opening
  TUIs on the host.)
- **`nostoi-anchor` against real S3/R2.** Tests use local HTTP fixtures
  (`tests/{anchor,fanout,outbox,s3}_http.rs`); no live cloud call was made.
- **Performance.** `docs/LARGE-CHAIN-BENCHMARKS.md` was read, not reproduced.
  `examples/scale.rs` and `examples/run_large_chain.py` were read, not run.
- **Anything about `docs/health.json` at runtime** — the file was read; no health
  probe was executed.

---

## 7. FINAL SCORE

| Layer | Score | One-line reason |
| --- | --- | --- |
| **Our formats** (adoption inside the fleet) | **6/10** | The format is excellent and five projects already produce the same bytes; the *installation* story is four forks, five bespoke loaders, two incompatible signing formats and one anchor format Nostoi has never heard of. |
| **firecrawl.dev** (public doc surface) | **4/10** | A real, well-built site exists and is entirely unlinked from the repo, with zero `llms.txt`, zero structured data, zero releases, and zero presence in web/LLM search. |
| **schema.org** | **2/10** (for Nostoi) | Nothing emitted anywhere. The vocabulary applies cleanly to the tool, the chain file, the attestation document and a published feed — and §3.2 lists ten specific ways it would mislead. |

The single sentence to remember: **Nostoi's problem is not that it is hard to
use, and not that it is hard to understand — it is that it is hard to *depend
on*, because nothing is published and every consumer had to invent its own way
in.** P0.1 and P0.2 together fix that for roughly two days of work.