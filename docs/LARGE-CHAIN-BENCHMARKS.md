# Large-chain memory and append-latency baseline

Measured to completion on **2026-10-02**, against library revision
`8bc212a39415f52516425d2399fa4b91e31e612d`, using the `large_chain` example
introduced alongside this document. These are native chain-library measurements,
not a production kernel-ingestion benchmark. The public `nostoi::verify` API at
this revision loads all entries; `Store::open_verified` already verifies one
SQLite row at a time. There is no comparison with an unimplemented API here.

## Reproduce

Requirements: Linux with `/proc`, Python 3, Rust, `git`, `lscpu`, and `df`.
Build artifacts may live on tmpfs; **fixtures must be on a disk-backed filesystem**
for these FULL-sync measurements. Check the parent before running:

```sh
ls "$HOME/.cache"
df -T "$HOME/.cache"
cargo build --release --no-default-features --features sqlite --example large_chain
python3 examples/run_large_chain.py \
  --binary target/release/examples/large_chain \
  --parent "$HOME/.cache" \
  --sizes 10000 100000 250000 --trials 3 --samples 1000 \
  --payload 256 --batch 1000 --api public
```

The runner creates a fresh `nostoi-large-chain-*` child under the explicitly
supplied parent. It preserves fixtures and a uniquely named `results-*.jsonl`
file, opened exclusively. Both the example and runner emit only JSON records to
stdout; diagnostics go to stderr. There is no default home path, automatic
deletion, daemon, or cache-dropping step. The runner is sequential and each tool
invocation is a new process. It fails on any failed operation.

Individual modes (replace `FIXTURE` with a **new, nonexistent child directory**
for seed, and that same directory for subsequent operations):

```sh
target/release/examples/large_chain seed --target FIXTURE --count 250000 --payload 256 --batch 1000
target/release/examples/large_chain verify --target FIXTURE --backend jsonl --api public
target/release/examples/large_chain verify --target FIXTURE --backend sqlite --api public
target/release/examples/large_chain verify --target FIXTURE --backend sqlite --api loaded
target/release/examples/large_chain startup --target FIXTURE
target/release/examples/large_chain append --target FIXTURE --count 1000 --payload 256
```

`--api public` calls `nostoi::verify`; `--api loaded` calls
`nostoi::open(...).verify()` explicitly. Both currently use loaded verification.
After integration, rerun these exact flags to compare the public API with the
loaded reference without modifying the tool to reference a new API.
`startup` and `append` always use `Store::open_verified`; the API flag affects
only `verify`. Append measurements cover the persistent native SQLite writer,
not repeated JSONL read/verify/append or `Store::open` per record.

For the same exact starting sizes after integration, run the full command above
to create new fixtures. To inspect preserved fixtures without extending them:

```sh
python3 examples/run_large_chain.py \
  --binary target/release/examples/large_chain --parent "$HOME/.cache" \
  --existing /home/xyzzy/.cache/nostoi-large-chain-8lti__r4 \
  --sizes 10000 100000 250000 --trials 3 --api public --skip-append
```

Repeat with `--api loaded` for a loaded-reference run. The directory labels are
base sizes: preserved SQLite files now have **13,000 / 103,000 / 253,000 rows**;
JSONL files retain **10,000 / 100,000 / 250,000 rows**. Results report actual
record counts. Without `--skip-append`, `--existing` deliberately extends the
SQLite fixtures again. Startup still opens the Store normally (WAL metadata may
be created/removed); this is not a read-only SQLite connection.

## Method and durability

* Seed builds matching native JSONL and SQLite chains, with fixed timestamp
  `2026-01-01T00:00:00Z`, actor `host:benchmark`, kind `benchmark.record`, subject
  `fixture`, and body `{"message":"<256 ASCII x characters>"}`. The 256-byte
  figure is the message payload, not the entire encoded record. Canonical
  JSONL averages approximately 560–562 bytes per record including the newline.
* Seed uses **core `format::nostoi_record` and `canonical::to_string`**, not
  duplicated hashing. The SQLite connection comes from `Store::open`, so the
  library schema, append-only triggers and `nostoi_digest` UDF are active for
  every INSERT. Setup retains one record plus bounded I/O/SQLite buffers,
  not a chain-sized vector. SQLite fixture transactions contain 1,000 records;
  JSONL is buffered and synced once at completion. **Bulk seed elapsed times
  are not per-record durable ingestion timings.**
* Verify times encompass file opening, parsing, hashing, chain verification and
  loaded-entry cleanup. Startup times encompass `Store::open_verified` including
  Store setup and verification, excluding later close/checkpoint. Process launch
  and the runner's warmup reads are outside the timed operations.
* Before every verify, startup and append child, the runner sequentially reads
  both fixture files in 1 MiB chunks. This requests **warm OS page-cache** reads;
  eviction is still possible. Each child starts with a fresh SQLite process
  cache. Append's preceding full startup scan also warms database pages. No
  privileged/global cache control or CPU tuning was performed.
* `append` opens/verifies once, then times **each native `Store::append` call**,
  one record per transaction/commit. Payload construction occurs outside the
  per-append timer; canonicalization, hashing, triggers, commit and automatic
  checkpoints occur inside. Each trial has 1,000 samples. Nearest-rank
  percentiles use sorted sample index `ceil(p*n)-1`, without interpolation.
  Trials extend the same fixture: starting counts are base, base+1,000,
  base+2,000. Native durability is unchanged.
* Measured SQLite settings on every Store: **journal_mode=WAL,
  synchronous=FULL (2), wal_autocheckpoint=1,000 pages, page_size=4,096,
  cache_size=-2,000**, bundled SQLite **3.53.2**. The tool refuses other
  journal/synchronous settings. No batching or weaker synchronization is used
  for measured appends. Fsync calls were not traced/counted; FULL is the
  library's per-record synchronization setting, not a hardware power-loss test.
* Append loop elapsed includes payload construction and a file-size stat after
  each append. Per-append percentiles exclude those operations. The tool also
  reports the sum of timed append calls. Explicit PASSIVE checkpoint stats and
  duration are recorded **after** the measured loop; default autocheckpoints
  inside commits remain part of append latency. WAL sizes are logical lengths,
  not total bytes written or physical allocated blocks.
* Peak RSS is Linux `/proc/self/status` **VmHWM**, in KiB, from the measured
  executable, not the Python runner or a combined suite. It includes library
  parsing/entry allocations, allocator retention, SQLite cache and process
  overhead; it excludes unmapped kernel page cache. `startup_peak_rss_kib` is
  read immediately after startup/settings and before Store close; the tables
  use that field for startup, and `peak_rss_kib` for other modes. Linux's proc
  RSS accounting is approximate: the later post-close read can be a few hundred
  KiB lower. Treat small differences as accounting/noise, not memory savings.
  `child_rusage_peak_rss_kib` is a diagnostic from `wait4`: it can retain the
  Python pre-exec fork RSS floor (~18 MiB here), so it is **not** used for small
  writer/seed peaks. `/usr/bin/time` was unavailable on this host.

## Host and preserved evidence

* Intel **Core Ultra 7 155H**, 22 online logical CPUs; default scheduling and
  frequency scaling, no affinity pinning. Shared development host, not isolated.
* Kali GNU/Linux Rolling **2026.3**, x86_64, kernel **7.1.5+kali-amd64**
  (`#1 SMP PREEMPT_DYNAMIC Kali 7.1.5-1kali1 (2026-07-29)`).
* `rustc 1.98.1 (48a229cea 2026-09-01)`, Cargo release profile, only `sqlite`
  enabled, bundled SQLite from the checked-in lockfile.
* Fixtures: **ext4**, `/dev/nvme0n1p5`, mounted at `/home`. About 8.4 GiB
  available before the final suite. Worktree/build: tmpfs under `/tmp/opencode`.
* Final suite started **2026-10-02T06:58:58.413607+00:00**. All 45 child
  operations completed: 3 seeds, 18 verification trials, 9 startup trials,
  9 append trials, 6 post-append verifications. All verification reports intact.
* Explicitly created, preserved test-data directory:
  **`/home/xyzzy/.cache/nostoi-large-chain-8lti__r4`**.
  Raw evidence: **`results-20261002T065858413491Z.jsonl`** inside that directory.
  It contains full precision metrics, commands, head digests, sizes, settings,
  OS/CPU/filesystem context and revision. Earlier smoke/measurement attempts were
  also preserved; the tables below use only this final suite.

## Baseline: seed sizes and bounded setup memory

Seed elapsed excludes initial schema creation and the final explicit checkpoint;
it includes record generation, batched SQL commits, JSONL flush and sync.

| Base records | JSONL bytes | SQLite bytes after seed close | Bulk seed elapsed ms | Seed peak RSS KiB |
|---:|---:|---:|---:|---:|
| 10,000 | 5,598,894 | 9,039,872 | 138.372 | 6,800 |
| 100,000 | 56,088,895 | 90,468,352 | 2,115.143 | 6,792 |
| 250,000 | 140,388,895 | 226,263,040 | 6,720.191 | 6,852 |

Seed WAL lengths before close: 5,541,432 / 8,293,592 / 8,293,592 bytes.
Close removed WAL files. Final preserved SQLite lengths after 3,000 measured
appends: 11,751,424 / 93,171,712 / 228,982,784 bytes. Together with JSONL,
the final fixture files occupy about 511 MiB of logical data. Largest measured
process peak was about 681 MiB including post-append verification. All requested
sizes fit; no size was curtailed by resources.

## Baseline: public verification and verified-writer startup

Each cell lists **trial 1 / trial 2 / trial 3**. Each trial used a fresh process
and the exact base record count. RSS values are KiB (divide by 1,024 for MiB).

| Records | JSONL verify elapsed ms | JSONL verify peak RSS KiB | SQLite verify elapsed ms | SQLite verify peak RSS KiB |
|---:|---|---|---|---|
| 10,000 | 52.243 / 49.921 / 48.778 | 30,036 / 30,036 / 30,188 | 51.482 / 52.650 / 52.047 | 34,008 / 33,608 / 34,080 |
| 100,000 | 417.257 / 436.851 / 414.973 | 276,804 / 276,592 / 276,416 | 447.619 / 462.992 / 436.733 | 279,620 / 279,760 / 279,828 |
| 250,000 | 1,094.382 / 1,098.322 / 1,037.816 | 686,076 / 686,324 / 686,524 | 1,072.300 / 1,136.704 / 1,111.835 | 690,036 / 689,788 / 689,472 |

| Records | `Store::open_verified` elapsed ms | Startup peak RSS KiB |
|---:|---|---|
| 10,000 | 40.319 / 47.192 / 37.708 | 7,196 / 7,040 / 6,952 |
| 100,000 | 374.834 / 378.148 / 362.372 | 7,200 / 6,888 / 7,088 |
| 250,000 | 867.521 / 859.382 / 926.493 | 7,188 / 7,116 / 6,968 |

On this fixture, the existing public loaded verification peak rises to about
670 MiB (JSONL) / 674 MiB (SQLite) at 250k records. The existing verified writer
startup remains approximately 7 MiB while still spending ~0.86–0.93 s scanning
the chain. These are measured observations at this revision and host.

## Baseline: native FULL-sync append latency

All latency columns are **milliseconds**; each row is a separate process with
**1,000 measured commits**. Startup is excluded from loop elapsed and quantiles.
No pooled quantiles or percentiles-of-percentiles are implied.

| Base size | Trial | Initial rows | p50 | p95 | p99 | max | Loop elapsed ms | Process peak RSS KiB |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10,000 | 1 | 10,000 | 0.761 | 1.011 | 1.354 | 9.878 | 798.449 | 7,204 |
| 10,000 | 2 | 11,000 | 0.762 | 0.964 | 1.132 | 5.686 | 785.025 | 7,172 |
| 10,000 | 3 | 12,000 | 0.770 | 1.024 | 1.892 | 3.462 | 811.509 | 7,020 |
| 100,000 | 1 | 100,000 | 0.762 | 1.104 | 1.655 | 9.998 | 813.255 | 7,296 |
| 100,000 | 2 | 101,000 | 0.762 | 0.988 | 1.588 | 10.872 | 802.235 | 7,072 |
| 100,000 | 3 | 102,000 | 0.769 | 1.128 | 1.882 | 10.093 | 833.507 | 7,088 |
| 250,000 | 1 | 250,000 | 0.767 | 1.012 | 1.503 | 9.945 | 803.391 | 6,988 |
| 250,000 | 2 | 251,000 | 0.758 | 1.034 | 1.423 | 10.556 | 800.169 | 7,008 |
| 250,000 | 3 | 252,000 | 0.764 | 1.049 | 1.540 | 10.004 | 813.341 | 7,196 |

## WAL and checkpoint evidence

Each append process began with zero WAL bytes. SHM was 32,768 bytes while open.
The maximum WAL length observed after each commit equaled the final loop WAL
length below; this is an allocated-length high-water observation, not cumulative
WAL write traffic. Default autocheckpoints recycle WAL space, so the final
PASSIVE frame counts represent the then-current log cycle, not all trial writes.

| Base size | Trial | Max/final loop WAL bytes | PASSIVE log/checkpointed frames | PASSIVE elapsed ms |
|---:|---:|---:|---:|---:|
| 10,000 | 1 | 4,124,152 | 940 / 940 | 2.968 |
| 10,000 | 2 | 4,124,152 | 873 / 873 | 2.239 |
| 10,000 | 3 | 4,132,392 | 886 / 886 | 2.164 |
| 100,000 | 1 | 4,124,152 | 863 / 863 | 2.944 |
| 100,000 | 2 | 4,120,032 | 960 / 960 | 3.968 |
| 100,000 | 3 | 4,144,752 | 901 / 901 | 3.175 |
| 250,000 | 1 | 4,124,152 | 895 / 895 | 3.308 |
| 250,000 | 2 | 4,124,152 | 920 / 920 | 3.847 |
| 250,000 | 3 | 4,136,512 | 967 / 967 | 3.336 |

All explicit checkpoints reported busy=0, with all reported frames checkpointed.
PASSIVE did not truncate WAL length; Store close removed WAL and SHM. Subsequent
read-only verification can create an empty WAL/SHM pair, so a preserved directory
may contain these sidecars even though the checkpoint/close measurement was zero.

## Checks and limits

```sh
cargo fmt --all -- --check
cargo test --no-default-features --features sqlite --example large_chain
cargo clippy --no-default-features --features sqlite --example large_chain -- -D warnings
cargo build --release --no-default-features --features sqlite --example large_chain
```

Example guard tests check matching backend heads/reports across a partial final
bulk batch, refusal to reseed an existing directory without altering its JSONL,
native append after bulk setup, active append-only triggers, and refusal to
create a missing measurement target. A 10-record / 5-append disk-backed smoke
suite also completed, and the final large suite reverified every extended chain.

Limits: three trials and 1,000 commits per trial provide modest tail sampling;
maxima are particularly sensitive to scheduling/storage noise. This is a single
host, warm-requested page-cache run with a repetitive fixed payload and no
concurrent writers, cold-cache campaign, fault injection, long-lived WAL reader,
kernel source, batching of measured ingestion, restart/deduplication work, or
anchor publishing. No tracing isolates fsync, checkpoint, hashing or parsing
costs. Results are a reproducible integration baseline, not a throughput or
latency guarantee for production ingestion.
