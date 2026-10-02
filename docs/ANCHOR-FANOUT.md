# Anchoring to more than one destination

One remote checkpoint answers one question: *was this chain rewritten?* When
that checkpoint lives in one bucket under one account, the answer is only as
strong as that account, and it is a single vendor. Publishing the same
checkpoint to several destinations under separate administrations means an
attacker has to reach all of them.

This is what `nostoi-anchor --targets` does. It is not a new protocol: the
checkpoint format, the write-once upload and the recovery contract are the ones
already in use, applied N times.

## What you get, and what it costs

Each destination is confirmed independently: the object is written under
`If-None-Match: *` and its Object Lock retention is read back and checked before
success is reported. A destination that is down, refused or ambiguous does not
stop the others, and is reported as such.

What fan-out does **not** buy is one more layer of cryptographic assurance. Every
destination is still asked, in the end, by software running on the machine being
audited. The gain is that those answers now come from several places: an attacker
who compromises one destination can lie about it, but cannot lie about all of
them at once without also compromising every account the operator uses.

## Target file

```json
{
  "chain_id": "production/kernel",
  "targets": [
    {
      "name": "aws",
      "endpoint": "https://s3.us-west-2.amazonaws.com",
      "bucket": "audit-checkpoints",
      "region": "us-west-2",
      "lock": "compliance",
      "retain_days": 365,
      "credentials": "aws"
    },
    {
      "name": "b2",
      "endpoint": "https://s3.us-west-004.backblazeb2.com",
      "bucket": "audit-checkpoints",
      "region": "us-west-004",
      "path_style": true,
      "lock": "compliance",
      "retain_days": 365,
      "credentials": "b2"
    },
    {
      "name": "r2",
      "endpoint": "https://account.r2.cloudflarestorage.com",
      "bucket": "audit-checkpoints",
      "region": "auto",
      "credentials": "r2"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `chain_id` | Identity recorded in every checkpoint. Empty means the chain path. |
| `key` | Optional explicit object key. Empty generates one from the chain identity, sequence and digest, identical for every destination. |
| `format` | Format name recorded in the checkpoint. Defaults to `nostoi-v1`. |
| `name` | Stable short name, and the name of this destination's outbox file. 1–64 characters from `A-Z a-z 0-9 - _ .`, not starting with a dot. |
| `endpoint` | Must be an absolute `https://` URL. |
| `bucket`, `region` | As for a single destination; `auto` for providers with no regions. |
| `path_style` | Forced on for R2. |
| `provider` | Optional `s3` or `r2`. Detected from the host when omitted. |
| `lock`, `retain_days` | `governance` or `compliance`; omit both for R2. |
| `credentials` | Subdirectory of the credentials directory holding this destination's key. |

Names become filenames (`<outbox-dir>/<name>.sqlite`), so they are restricted to
characters that cannot escape that directory. A name is also how a result is
reported and how a credential is chosen, so it should mean something to a human
reading a log.

### Why `provider` can be stated

Detection is by hostname, which is right for the two public endpoints and wrong
for a bucket behind a custom domain or a private VPC endpoint: those are served
as ordinary S3 hosts, and sending `x-amz-object-lock-*` headers to a service
that silently ignores them would report a retention that is not there. State
`"provider": "r2"` when detection cannot see the truth.

## Publishing

```sh
nostoi-anchor /var/lib/nostoi/kernel.sqlite \
  --targets /etc/nostoi/anchors.json \
  --outbox-dir /var/lib/nostoi/outbox \
  --credentials-dir /run/credentials/nostoi
```

```
TARGET           PROVIDER STATE           DURABLE   KEY
aws              s3       confirmed       yes       heads/kernel-9aff10-00000003-eb4baa48a5.json
b2               s3       confirmed       yes       heads/kernel-9aff10-00000003-eb4baa48a5.json
r2               r2       confirmed       yes       heads/kernel-9aff10-00000003-eb4baa48a5.json

3 of 3 destinations confirmed at seq=3
```

The chain is verified **once** for the whole batch, and one `anchored_at` is used
for every destination. Cost therefore does not grow with the number of
destinations, and a later disagreement between destinations is about the chain
rather than about clock skew.

Each state means something different:

| State | Meaning |
| --- | --- |
| `confirmed` | Written, and its retention read back as requested. |
| `already-anchored` | The key already held this checkpoint; a write-once object keeps its original timestamp. |
| `unresolved` | The upload may have landed. The durable intent survives, so re-running retries the original bytes. |
| `rejected` | Refused, unreachable or misconfigured. Nothing was written. |

Exit codes: `0` everything confirmed, `2` something unresolved, `3` something
rejected, `1` a configuration or usage error. `unresolved` and `rejected` are
distinguished because only the first can be resolved by retrying.

## Verifying

```sh
nostoi-anchor /var/lib/nostoi/kernel.sqlite \
  --targets /etc/nostoi/anchors.json \
  --verify --key heads/kernel-9aff10-00000003-eb4baa48a5.json \
  --credentials-dir /run/credentials/nostoi
```

```
TARGET           PROVIDER ANSWER
aws              s3        seq=3 digest=eb4baa48a5b70513
b2               s3        seq=3 digest=eb4baa48a5b70513
r2               s3        unusable: s3: GetObject failed with status 503 Service Unavailable

agreed checkpoint: chain=production/kernel format=nostoi-v1 seq=3 digest=eb4baa48a5...
local chain verified: 3 records, head seq=3 digest=eb4baa48a5...

warning: 1 destination(s) could not be read, so this rests on fewer
destinations than configured:
  r2: s3: GetObject failed with status 503 Service Unavailable
```

Verification is deliberately stricter than publishing:

- **Destinations must agree.** Two destinations committing to different
  `(chain, format, seq, digest)` tuples is a conflict, reported with exit `4`.
  It is not a majority vote, because a compromised destination can be made to
  say anything and a majority of dishonest answers is still a lie.
- **A destination that cannot be read is not agreement.** It is listed under
  `unusable` and the run still succeeds if at least one destination confirmed the
  chain, but the reduced assurance is stated rather than hidden.
- **No destination answering is a failure**, not a pass.
- **The key is never chosen for you.** `verify` requires an explicit `--key`; a
  trusted checkpoint has to be picked from somewhere the auditor trusts.

## Credentials

With `--credentials-dir`, each destination reads `aws-access-key-id`,
`aws-secret-access-key` and an optional `aws-session-token` named after its
`credentials` field, in either of two layouts:

```
# per-destination directories
/run/credentials/nostoi/aws/aws-access-key-id
/run/credentials/nostoi/b2/aws-access-key-id

# or flat files, which is what LoadCredential= can produce
/run/credentials/nostoi/aws-aws-access-key-id
/run/credentials/nostoi/b2-aws-access-key-id
```

The flat layout is the one to use with systemd, because `LoadCredential=` takes
an ID that has to be a usable filename and cannot contain a slash:

```ini
LoadCredential=aws-aws-access-key-id:/etc/nostoi/credentials/aws/access-key-id
LoadCredential=aws-aws-secret-access-key:/etc/nostoi/credentials/aws/secret
LoadCredential=b2-aws-access-key-id:/etc/nostoi/credentials/b2/access-key-id
LoadCredential=b2-aws-secret-access-key:/etc/nostoi/credentials/b2/secret
```

A destination that names a `credentials` subdirectory **never** falls back to
the unprefixed files. That would quietly hand it another destination's key, or a
shared one, which is the thing per-destination credentials exist to prevent; the
refusal names the file it wanted instead. A destination that names none may use
the unprefixed files, which is how a single-destination unit loads one set.

Separate keys per destination are the point. One credential that can write to
every destination removes most of what fan-out is for. A destination whose
credential is missing is reported as `rejected` and the others still publish.

Without `--credentials-dir` the process environment is used
(`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`), which is
what a single-destination run does today.

## Under systemd

The repo templates stay uninstalled. `contrib/systemd/nostoi-anchor-runner`
switches to a fan-out when `TARGETS` is set, and in that mode exports no AWS
variables at all:

```ini
Environment=CHAIN=/var/lib/nostoi/kernel.sqlite
Environment=CHAIN_ID=production/kernel
Environment=TARGETS=/etc/nostoi/anchors.json
Environment=OUTBOX_DIR=/var/lib/nostoi/outbox
LoadCredential=aws-aws-access-key-id:/etc/nostoi/credentials/aws/access-key-id
LoadCredential=aws-aws-secret-access-key:/etc/nostoi/credentials/aws/secret
LoadCredential=b2-aws-access-key-id:/etc/nostoi/credentials/b2/access-key-id
LoadCredential=b2-aws-secret-access-key:/etc/nostoi/credentials/b2/secret
```

`CHAIN_ID` still comes from the EnvironmentFile, so the chain identity stays
operator-controlled rather than living in a data file; it overrides whatever the
target file says.

Single-destination variables (`ENDPOINT`, `BUCKET`, `REGION`, `LOCK`,
`RETAIN_DAYS`) are **refused** when `TARGETS` is set rather than ignored, so a
half-migrated unit fails loudly instead of quietly publishing to one place.
Per-destination retention belongs in the target file.

In this mode the runner exports no AWS variables at all: credentials come only
from the files systemd copied into the service's private credential directory.
The runner passes that directory's path through, and `nostoi-anchor` reads each
destination's own files from it as described above.

## Choosing destinations

The order of preference is: **provider-enforced immutability first, independence
second**.

| Destination | Write-once enforcement | Notes |
| --- | --- | --- |
| AWS S3 | Object Lock, provider-enforced | `COMPLIANCE` cannot be shortened or deleted by anyone, including the account root. |
| Backblaze B2 | Object Lock, provider-enforced | Speaks the S3 API, so no code change: a second independent implementation of the same guarantee. |
| Ceph RGW | Object Lock on supporting releases | S3-compatible; confirm Object Lock is enabled on the zone. |
| Cloudflare R2 | Bucket lock, operator-enforced | No Object Lock headers; send no `lock` and configure a bucket lock on the `heads/` prefix out of band. Nostoi refuses to send lock headers to R2 rather than pretending. |

Two destinations from *different* providers is the useful combination: AWS plus
B2 gives two independent implementations of provider-enforced immutability. Two
buckets in the same AWS account gives one account, and an account compromise
reaches both.

A destination with no provider-enforced immutability (R2 without a bucket lock,
or any bucket the operator can rewrite) is still worth having as a second
opinion, but it must not be the only place a checkpoint lives, and its
`retain_until` should not be treated as a guarantee. Nostoi cannot verify a
bucket policy from inside the protocol; it verifies the bytes it read back.

**Not** recommended: SSH, SFTP or SCP to a second host. A POSIX filesystem
cannot express "cannot be deleted before date X", so the remote user can always
remove the checkpoint afterwards and the retention deadline becomes a claim
rather than an enforced fact. Write-once at publish time is achievable
(`ln`-based exclusive create), but it is a weaker guarantee than Object Lock,
and it adds host keys, key distribution and a second service to operate. If you
need an air-gapped destination, use one that enforces immutability.

## What fan-out does not change

- The checkpoint format is unchanged (`nostoi-anchor-v1`), so existing objects
  still verify and can be added to a fan-out later.
- Each destination keeps its own outbox with the same schema and the same
  recovery contract, so a destination's stuck intent cannot block or corrupt
  another's. One destination being unreachable is not a reason to stop the rest.
- Credential scopes are unchanged: the publisher can write, the verifier can
  read, and the verifier still never needs write access to an outbox.