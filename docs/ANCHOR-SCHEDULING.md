# Periodic publishing and independent verification

`contrib/systemd/` contains repository-only system service/timer templates, a
POSIX-shell runner, nonsecret environment examples, and offline regression tests.
They do not install or enable anything, provision buckets, or change IAM policy.
An operator must adapt and deploy them. Use systemd with `LoadCredential` support
(version 247 or newer), and a `nostoi-anchor` build with `cli,s3` and, for SQLite,
`sqlite`. The publisher requires the durable `--outbox` CLI interface.

## Instances and configuration

Use a simple instance name such as `kernel`, not a source path or a systemd-escaped
absolute filename. For example, `nostoi-anchor@kernel.timer` invokes
`nostoi-anchor@kernel.service`; `nostoi-verify@kernel.timer` invokes the independent
verification service. Paths are values in environment files, never instance names.

For an operator-managed deployment, copy the four `.service`/`.timer` templates to
the system unit directory and install `nostoi-anchor-runner` as
`/usr/local/libexec/nostoi-anchor-runner` with mode 0755. Install the binary at
`/usr/local/bin/nostoi-anchor`. The helper also accepts an absolute
`NOSTOI_ANCHOR_BIN` override in the operator-owned environment file. Do not allow
the source writer to replace the binary, helper, units, or configuration.

Adapt `anchor.env.example` to `/etc/nostoi/anchor/kernel.env`, and
`verify.env.example` to `/etc/nostoi/verify/kernel.env`. These are systemd
`EnvironmentFile` syntax, not shell scripts: no `export`, command substitution,
or shell sourcing. Quote values with spaces using systemd's environment-file
quoting rules. The runner quotes every CLI argument and validates required values.
`CHAIN` and publisher `OUTBOX` must be absolute paths; `ENDPOINT` must use HTTPS.
Always specify `CHAIN_ID`, `BUCKET`, and `REGION` explicitly.

The publisher example uses `OUTBOX=/var/lib/nostoi-anchor/kernel/outbox`.
`StateDirectory=nostoi-anchor/%i` creates the instance's private state directory;
only that directory is a writable persistent exception to `ProtectSystem=strict`.
Keep the configured outbox inside it. Preserve it across upgrades and failures:
publication first recovers pending exact intents, then persists and uploads a new
snapshot. Do not delete uncertain intents or substitute a freshly generated key
as a retry strategy. Each instance needs its own outbox. The verifier does not
read an outbox and cannot accept `OUTBOX`, `LOCK`, or `RETAIN_DAYS`.

Optional publisher `LOCK=compliance` requires positive `RETAIN_DAYS`, and an
already provisioned S3 Object Lock bucket. The templates intentionally support
only compliance mode. With R2 set `REGION=auto`, use the R2 HTTPS endpoint, omit
both lock settings, and have the bucket's retention rules configured independently.
Publishing success alone does not establish R2 bucket-lock policy.

## Separate identities and credentials

The named accounts `nostoi-publisher` and `nostoi-verifier` are placeholders for
operator-created, unprivileged service accounts. Adapt `User` and `Group` locally;
do not fall back to root. The example `nostoi-readers` group grants source read
access only, not ingest privileges. Keep the verifier account distinct from the
publisher account, and make neither a member of the other's private group.

The services load these three credential files from separate directories:

| Service | Credential directory for `kernel` |
| --- | --- |
| Publisher | `/etc/nostoi/credentials/anchor-kernel/` |
| Verifier | `/etc/nostoi/credentials/verify-kernel/` |

In each directory, `aws-access-key-id` and `aws-secret-access-key` contain the
respective raw values, optionally newline-terminated. `aws-session-token` contains
the session token, or is an **existing empty file** when no token is used. All three
files are required by `LoadCredential`; the empty token explicitly clears any
inherited token. Rotate temporary credentials and renew their token before expiry.

Use root-owned credential directories mode 0700 and files mode 0600. The system
manager reads the originals and exposes private credential copies to the service.
The helper exports `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional
`AWS_SESSION_TOKEN` only to its child process, never in `ExecStart` arguments or
log messages. When used outside systemd without `CREDENTIALS_DIRECTORY`, it also
accepts those standard AWS environment variables directly. Avoid tracing or
printing that environment. Do not put live secrets in environment examples.

Give publisher cloud credentials only the bucket/prefix operations needed for
conditional upload and reconciliation GET, plus retention operations for requested
Object Lock. Give verifier credentials GET-only access to the selected checkpoint
objects, with no PUT, DELETE, or retention-policy administration rights. Keep
bucket/policy administrator credentials separate from both.

Use root-owned units, helper and binary, not writable by service accounts. Use
root-owned environment directories mode 0750 and files mode 0640 (or 0600 when
only the system manager needs to read them). The verification trust configuration
must be writable only by the independent operator, never the source writer or
publisher. Publisher state is mode 0700 with umask 0077; do not grant the verifier
access to it.

## Source permissions, including live SQLite

Both services need search (`x`) permission on every source parent directory and
read permission on the chain. For example, a dedicated read group or ACL can
provide directory mode 0750 and file mode 0640 while retaining the ingestor as
owner. Do not grant either account write access to the source directory, database,
JSONL file, or sidecars. A group used for writing the source is not a suitable
readers group. Ensure newly created/rotated files retain the required read ACLs.

SQLite is opened read-only. For a live WAL database, read access to the main
database alone is insufficient: the current `-wal` and **already initialized
`-shm` shared-memory sidecar** must also be available and readable, including
directory traversal. The ingestor must create/maintain those files with appropriate
read permissions. The sandbox makes the source filesystem read-only, so a reader
cannot create a missing shared-memory file or initialize it by writing. SQLite
versions supporting read-only WAL (3.22+) can read with existing usable sidecars;
verify this against your live deployment. Sidecars may disappear at final writer
close or be recreated on restart. If they are unavailable, let the service fail
visibly and fix the ingestor lifecycle/ACLs; do not grant source writes or use
`immutable=1` on a changing live database. A consistent SQLite backup/snapshot
made by the ingestor is another operator-managed source option; copying only the
main file while WAL writes continue is not a consistent snapshot.

`ProtectHome=yes` hides home directories; place the source outside them or adapt
the sandbox deliberately. `PrivateTmp=yes` means a source in host `/tmp` is not
visible. HTTPS networking is allowed through IPv4/IPv6 and Unix sockets for
DNS; normal system CA certificates and resolver configuration remain readable.
The publisher's outbox is the only persistent writable path. Private temporary
directories remain available to each service.

## An independently trusted checkpoint pointer

Set verifier `TRUSTED_KEY` to an actual, operator-selected retained checkpoint key.
The example's placeholder must be replaced. The helper never chooses the newest
key from publisher output, the outbox, a writer-controlled local file, or a bucket
listing. `CHAIN_ID` is the expected logical identity, not a name inferred from the
source. Verification invokes `--verify --key KEY --chain-id ID`, performing GET
only and comparing verified local history with that checkpoint.

The independent operator obtains and accepts a confirmed checkpoint key through
a separately trusted evidence channel, checks its bucket/chain identity and
expected advancement, records it outside writer control, then atomically replaces
the operator-owned verifier environment file. Subsequent oneshot invocations read
the new pointer; no daemon restart is needed for an environment-file-only change.
Do not automatically consume the publisher's journal or outbox as the trust
pointer. Advancing or rolling back the pointer is an explicit independent trust
decision; retain the prior accepted evidence and do not silently select an older
key when verification fails. An older checkpoint protects only its prefix, so the
operator must advance the pointer to detect truncation of newer acknowledged
history. GET-only verification does not itself attest current retention policy.

## Schedule and failure handling

Publishing runs every 15 minutes at minutes 00/15/30/45; verification runs
independently at 07/22/37/52. Each has up to two minutes of randomized delay and
30 seconds accuracy. `Persistent=true` triggers a catch-up after downtime rather
than replaying every missed interval. Neither timer depends on the other or treats
a publishing result as verification evidence. These are bounded polling schedules,
not a guarantee of successful remote publication within 15 minutes.

The services have a ten-minute execution timeout and no immediate restart loop.
The same instance does not overlap itself. Large histories may need an
operator-adjusted timeout/schedule. A killed or failed publisher retains its
outbox for recovery on the next invocation. Monitor failed services and journal
results through your existing alerting system. All nonzero exits fail the unit:
exit 2 means upload outcome unknown; exit 3 means stored/found but unconfirmed.
Neither is a successful checkpoint. Reconcile pending intents and investigate
identity/retention failures. A timer's next attempt does not erase the need to
review a previous failure. Verification mismatch, truncation, broken history,
missing evidence, and unreadable source/credentials fail visibly as well.

## Offline validation from the repository

```sh
sh -n contrib/systemd/nostoi-anchor-runner
shellcheck -s sh contrib/systemd/nostoi-anchor-runner
python3 contrib/systemd/test_anchor_runner.py
systemd-analyze verify contrib/systemd/nostoi-anchor@.service \
  contrib/systemd/nostoi-anchor@.timer contrib/systemd/nostoi-verify@.service \
  contrib/systemd/nostoi-verify@.timer
```

Tests use a local fake executable and temporary credential files, checking exact
argument boundaries, publisher/verifier separation, required configuration,
credential precedence, optional session tokens, and exit-code propagation. They
perform no cloud IO and do not need `--outbox` in the checkout's current binary.
`systemd-analyze verify` may report the uninstalled helper or absent deployment
accounts; distinguish these deployment prerequisites from unit syntax errors.
These checks do not install or enable units. The coordinator validates the real
CLI integration after merging the outbox implementation.
