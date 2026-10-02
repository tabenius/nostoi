# Attestations: a named person behind a chain head

A chain proves nothing inside it changed after the fact. A remote
[anchor](ANCHORING-AND-KMSG.md) proves a copy of the head exists somewhere you
trust. Neither says **who** looked at it or **when**, and that gap is where an
audit stops being checkable and starts being believed.

An attestation is that missing statement. It is a small document naming one chain
head, signed by one key, verifiable by anyone holding that key's public half.

```console
$ nostoi attest audit.jsonl --key ~/.ssh/id_ed25519 --principal alice@laptop
attested seq=1841 digest=5ec18be9… by alice@laptop with key SHA256:n/a9jjWMZ…
  timestamp 2026-02-01T12:24:00Z
  document   audit.jsonl.attestation.json
  signature  audit.jsonl.attestation.sig

add this line to your allowed_signers file:
  alice@laptop ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILP+SVu+956LGFuCkbRjqOoLMuoX…

then check it: nostoi verify-attestation audit.jsonl --allowed-signers FILE \
  --principal alice@laptop --fingerprint SHA256:n/a9jjWMZ…
pin that fingerprint somewhere the host cannot rewrite, and publish the signature
somewhere it cannot be retracted: a signature proves authorship, not when.
```

## What it is for

Detecting a rewrite is technical. Being able to say *"this was reviewed and
released by a named person at a stated time, and here is their signature"* is an
accountability property, and the two fail differently. A stolen key can produce
a perfectly valid attestation for a chain that never existed. What it cannot do
is produce one that a verifier holding a **pinned fingerprint** accepts, or one
that demonstrably predates a compromise.

That last point is the part people get wrong. **A signature proves authorship, not
time.** If your key is obtained later — by an attacker or by whoever compelled
you — they can produce an attestation that claims to predate the compromise, and
it will verify perfectly. To defeat that you need a timestamp from somewhere the
host cannot reach; see [Give the signature a time you can defend](#give-the-signature-a-time-you-can-defend).

## The document

```json
{"anchored_at":"2026-02-01T12:24:00Z","chain":"production/kernel","digest":"5ec18be9…","format":"nostoi-v1","fingerprint":"SHA256:n/a9jjWMZ…","principal":"alice@laptop","seq":1841,"v":"nostoi-attestation-v1"}
```

One line of canonical JSON — the same rule a record's digest uses,
`json.dumps(record, sort_keys=True, separators=(",", ":"))` — so the bytes that
were signed are reproducible in any language. `nostoi-attestation-v1` is the
whole format:

| Field | Meaning |
| --- | --- |
| `v` | `nostoi-attestation-v1`. |
| `chain` | Chain identity, matching what an anchor for this chain records. |
| `format` | Record format of the chain (`nostoi-v1`). |
| `seq`, `digest` | The attested head. |
| `anchored_at` | When the attestation was made, RFC 3339 UTC. |
| `principal` | The signing identity, matching an `allowed_signers` entry. |
| `fingerprint` | The signing key's `SHA256:` fingerprint. |
| `anchor_key` | Optional: the remote checkpoint this head was also anchored at. |

Two properties are worth stating explicitly.

**The document is small.** It names a head, not a copy of the chain, so signing
takes a moment however long the chain grows, and one signature covers all of it.

**It is a sidecar.** `<chain>.attestation.json` and `<chain>.attestation.sig`,
beside the chain and never inside it. `nostoi-v1` records are immutable and
append-only; putting signatures in them would mean a new record format and a new
revision for something that is not part of the chain's integrity.

## What canonical means here, and what it does not

The signature is checked against the canonical bytes of the **parsed content**,
never against the bytes that happened to be on disk. That one decision is what
makes formatting irrelevant:

| On disk | Canonical bytes | Result |
| --- | --- | --- |
| One line, sorted keys | identical | verifies |
| Pretty-printed, any indent | same content | verifies, reported as reformatted |
| CRLF line endings | same content | verifies |
| Reordered keys | same content | verifies |
| **Any changed value** | **different content** | **refused** |

`nostoi verify-attestation` reports a reformatted document as a note rather than a
failure, and `--canonicalize` rewrites it. That repair is lossless precisely
because the signature was already checked against the bytes being replaced:

```console
$ nostoi verify-attestation audit.jsonl --allowed-signers allowed_signers --principal alice@laptop
✓ …: signature verified, signed by alice@laptop with key SHA256:n/a9jjWMZ…
  note: the document is formatted, not canonical; the signature covers the same content either way
  fix with: nostoi verify-attestation audit.jsonl --canonicalize
```

`nostoi verify-attestation` also prints the exact bytes it verified, so they can
be diffed against what you believe you signed.

### Why not normalize the text instead

The tempting alternative — collapse whitespace, upper-case, compare — is wrong, and
demonstrably so:

```
{"body":{"note":"a  b"}}   and   {"body":{"note":"a b"}}
```

are different chains, and folding whitespace merges them. `a b` and `a b`
(U+00A0 against U+0020) are different too: JSON's insignificant whitespace is
exactly space, tab, LF and CR, and it lives *outside* string literals, so a
Unicode-aware folder corrupts content. Case folding is not injective either —
`"straße".to_uppercase()` is `"STRASSE"`. Any of those would mean the signature
attests to the normalized text, so an attacker could hand you any byte sequence
that normalizes into a valid document, including one that reads misleadingly to
whoever inspects it.

Canonicalization avoids all of it structurally rather than by rule: parse into a
value, re-serialize with sorted keys. The value tree survives, so nothing is lost
and nothing is invented.

### Encodings

The signed bytes are **ASCII whatever the content**, because strings are escaped
as `\uXXXX` outside printable ASCII. An encoding mismatch cannot corrupt them:
`"café"` is signed as `caf\u00e9`.

The one encoding-related thing that *is* content is a string's Unicode
normalization form. NFC `caf\u00e9` and NFD `cafe\u0301` are canonically
equivalent, look identical, and hash differently — and filesystems disagree:
macOS has historically handed out decomposed names where Linux hands out composed
ones, so an accented chain path can digest differently per machine. Attestation
**refuses** a non-NFC string rather than rewriting it:

```
chain is not in Unicode NFC form; the same text can be written two ways that
look identical and hash differently, so attestation refuses the ambiguous one
```

Rewriting would be worse than refusing: the signed bytes would no longer be the
ones you typed. Fix the input instead — rename the file, or restate the identity.

Byte-level problems are named for what they are, because each has a different fix:
a UTF-8 byte-order mark (remove it), bytes that are not UTF-8 (re-encode), and an
unreadable file (permissions) are three distinct errors rather than one "invalid
JSON".

**Binary evidence never enters the document.** A digest, or hex/base64 with the
encoding named in the field — digests are already hex. Never raw bytes, never a
lossy transcoding.

## Signing

Signing is a human step, and nothing here runs unattended.

```sh
nostoi attest CHAIN --key PATH --principal NAME [options]
```

| Option | Default | Notes |
| --- | --- | --- |
| `--key` | `~/.ssh/id_ed25519` | Private key. Passed as argv, never through a shell. A leading `~` is expanded, since argv does not get it from a shell. |
| `--principal` | required | The identity to record. Must match an `allowed_signers` entry. |
| `--chain-id` | the chain path | Chain identity, matching what an anchor would record. |
| `--format` | detected | `nostoi-v1`, `weftmark-ledger-v1`, `ephor-audit-v1`. |
| `--namespace` | `nostoi-attestation` | Signing namespace. Scopes the signature so it cannot be replayed as a signature for some other use of the same key. |
| `--anchor-key` | none | The remote checkpoint this head was also anchored at. |
| `--program` | `ssh-keygen` | Which tool to use. |
| `--dry-run` | off | Sign and report without writing the sidecars, so a signature can be reviewed before it becomes evidence. |
| `--json` | off | Machine-readable output. |

Any key `ssh-keygen` supports works: Ed25519, RSA, ECDSA, FIDO/security keys, a
hardware token, or an agent-loaded key.

Signing prints the `allowed_signers` line to install and the fingerprint to pin.
It also reports what it replaced, if there was an earlier attestation:

```console
$ nostoi attest audit.jsonl --key ~/.ssh/id_ed25519 --principal alice@laptop
  replaced an attestation of seq=1839 signed by alice@laptop
```

### Passphrases

Whether a key needs one is read from the key file before anything runs: the
OpenSSH format's cipher name is `none` when unencrypted, and traditional PEM
announces `Proc-Type: 4,ENCRYPTED`. So the predictable failure is reported before
`ssh-keygen` is spawned, instead of after, as:

```
could not unlock /home/you/.ssh/id_ed25519: ssh-keygen needs an interactive
terminal, a loaded ssh-agent, or a key without a passphrase. Attesting is a human
step by design: run this from a terminal, load the key into ssh-agent first, or
use a key without a passphrase.
```

`ssh-keygen` says "incorrect passphrase supplied to decrypt private key" when it
cannot reach a terminal, which sends people hunting for a typo in a passphrase
that was never mistyped. That wording is still caught as a fallback, for agent and
hardware-token cases.

The public key for the `allowed_signers` line is read from the `.pub` file
`ssh-keygen` writes beside the private key, so an encrypted key is prompted for
**once** per signature rather than twice.

Note also that `ssh-keygen` refuses a private key other users can read. `chmod
600` your key.

```
could not unlock /home/you/.ssh/id_ed25519: ssh-keygen needs an interactive
terminal, a loaded ssh-agent, or a key without a passphrase. Attesting is a human
step by design; a service must not sign on its own.
```

## Verifying

```sh
nostoi verify-attestation CHAIN --allowed-signers FILE --principal NAME --fingerprint SHA256:…
```

| Option | Default | Notes |
| --- | --- | --- |
| `--allowed-signers` | required | A file with a line for the principal. |
| `--principal` | required | The identity to verify. |
| `--fingerprint` | none | **Pin this.** See below. |
| `--namespace` | `nostoi-attestation` | Must match what the signature was made in. |
| `--program` | `ssh-keygen` | |
| `--json` | off | |

Every step fails closed. A missing sidecar, an empty signature, a bad signature,
a signature made in another namespace, an unknown principal, a key that is not the
pinned one, and a chain that no longer matches are all failures. Exit code 1 means
"not trustworthy" and nothing else: formatting is reported, never fatal, so a stray
pretty-print does not look like a security problem.

```
$ nostoi verify-attestation audit.jsonl --allowed-signers allowed_signers \
    --principal alice@laptop --fingerprint SHA256:n/a9jjWMZ…
✓ audit.jsonl: signature verified, signed by alice@laptop with key SHA256:n/a9jjWMZ…
  attested seq=1841 at 2026-02-01T12:24:00Z
  covers the current head
```

### Current, stale, and what each means

An attestation names one position. A chain keeps growing, so most of the time an
attestation is *behind* the head — and that is not a failure:

| Coverage | Meaning | Exit |
| --- | --- | --- |
| `current` | The attestation names the chain's current head. | 0 |
| `stale` | The chain has advanced; the attestation still covers the intact prefix it names. | 0, with the caveat printed |
| `truncated` | The chain ends before the attested position. | 1 |
| `rewritten` | The chain does not verify at the attested position. | 1 |

Verification uses the verified checkpoint *at the attested sequence*, not just the
head, so an attestation over an intact prefix stays valid as the chain grows and
truncation stays detectable. Both matter: a stale pass and a truncated fail have
to be distinguishable, or one of them is a lie.

## Pin the fingerprint, or the trust anchor is a file

`ssh-keygen -Y verify` trusts whatever key the `allowed_signers` file lists for
the principal. If an attacker can edit that file, they can substitute a key and
produce attestations that verify. This is not a hypothetical limitation; it is how
the tool works, and there is a test that demonstrates it.

What cannot be substituted silently is the fingerprint. Verification parses the
key fingerprint out of `ssh-keygen`'s own success line and requires it to equal
both the fingerprint in the document and the one pinned on the command line.

**Pin it somewhere the host cannot rewrite.** A pinned fingerprint inside a
config file on the machine being audited protects nothing, because whoever can
rewrite the chain can rewrite that file. Somewhere out of band:

- in the repository, published to a forge the host does not administer;
- in a buyer- or customer-facing document, or a signed release;
- in a hardware token's owner record, or a KRL you distribute;
- in the operator's own password manager, referenced by the runbook.

One more thing to know about `allowed_signers`: options on an entry do **not**
narrow it for a plain public key. `cert-authority`, `principals=` and
`expiry-time` constrain *certificates*; a raw key listed under two principals
verifies for both. An entry is either a key you trust for that name or it is not
there, so the fingerprint pin is what has to be right.

`--fingerprint` is optional so that an allowed-signers-only workflow is possible,
but verification then warns that the trust anchor is a file:

```
note: no --fingerprint was pinned, so the allowed_signers file is the only trust
anchor; pin the fingerprint to refuse a substituted key
```

## Give the signature a time you can defend

A signature says who signed. It does not say when, and a signature obtained later
can be backdated convincingly. If the question "did this exist before date X?"
matters, publish the signature somewhere append-only at the time you make it.
Cheapest options, roughly in order:

- push the document and signature to a **public repository you do not
  administer from that host** — a signed commit's history is evidence, even
  though it is not write-once;
- a **transparency log** (certificate-transparency style), if you need
  publicly verifiable ordering;
- a **countersignature** from a second key or a second person, who then applies
  the same rule recursively;
- mail it to yourself, or send it to someone who keeps it.

Nostoi cannot do this for you and does not pretend to: the attestation's
`anchored_at` is the time on the signing host's clock, which is exactly the thing
you do not fully control. The pinning above stops a substituted key; only an
external timestamp stops a backdated one.

## Where the attestation lives in the workflow

Attestation sits next to anchoring, not instead of it:

- The **anchor** proves a copy of the head exists somewhere the attacker cannot
  rewrite, continuously and automatically.
- The **attestation** says a named person vouched for a head at a stated moment,
  occasionally and deliberately.
- [Fan-out](ANCHOR-FANOUT.md) multiplies the first.

The read-only commands report attestation state, because that is when someone
decides to want one:

```console
$ nostoi verify audit.jsonl
✓ audit.jsonl (nostoi-v1): 1841 records intact, head 1841 5ec18be9…
  no attestation (missing audit.jsonl.attestation.json and audit.jsonl.attestation.sig);
  sign one with: nostoi attest audit.jsonl --principal you@host

$ nostoi verify audit.jsonl          # after attesting
✓ audit.jsonl (nostoi-v1): 1841 records intact, head 1841 5ec18be9…
  attested by alice@laptop with key SHA256:n/a9jjWMZ… at seq 1841 (2026-02-01T12:24:00Z)
  [covers the current head; signature not checked here]
```

Those commands are given no `allowed_signers` file, so they cannot check the
signature and say `signature not checked here`. `--json` reports the same under an
`attestation` object with `"signature": "unchecked"`. `nostoi verify-attestation`
is the command that establishes a signature is good; the browser shows the same
state, and `a` opens the document.

When the chain moves past an attestation, it says so, because a stale signature
quietly covering an old head is the failure people miss:

```console
  attested by alice@laptop with key SHA256:n/a9jjWMZ… at seq 1839 (2026-02-01T09:00:00Z)
  [stale: the chain is at 1841; nostoi attest audit.jsonl --principal alice@laptop
   to cover it, nostoi verify-attestation to check the signature]
```

## Threats this does and does not address

### What is deliberately not defended

Stated plainly, because the list above is more comforting than the code is:

- **A symlink planted between the check and the write.** Sidecar writes refuse to
  follow a symlink, which catches one planted in advance and the accidental case.
  Closing the race properly would need `openat` with `O_NOFOLLOW` on every path
  component, which is more machinery than this warrants.
- **An attacker who can win a race on the document.** If someone can rewrite the
  sidecar and the signature together between two verifications, both are
  consistent again. That is why the fingerprint pin and an external timestamp
  exist: they are the parts that do not live on this host.
- **A key you were compelled to use.** No mechanism here can tell.
- **An unlimited document.** Documents over 64 KiB and signatures over 1 MiB are
  refused rather than read, because this code is meant to survive a machine an
  attacker has partly controlled.

| Threat | Attestation |
| --- | --- |
| Chain rewritten wholesale, digests recomputed | **Detected** — the attested digest no longer appears at that sequence |
| Tail truncated | **Detected** — the chain ends before the attested position |
| Someone claims a chain was reviewed when it was not | **Detected** — no signature exists |
| Attestation edited to name a different head | **Detected** — the signature covers the document bytes |
| Key substituted by editing `allowed_signers` | **Detected**, provided the fingerprint is pinned out of band |
| Attestation backdated after the fact | **Not detected** — needs an external timestamp |
| Private key stolen, attacker signs | **Not detected** — inherent to the key; use a hardware token and offline storage |
| You are compelled to sign something false | **Not detectable** by this mechanism |
| An attestation exists, chain intact | Proves nothing about whether the *contents* are true — only that someone vouched |

A valid chain does not prove the events in it are true, and a valid attestation
does not either. It proves that a specific person said so, about a specific head,
and that they could not have said it about any other head.

## Operational notes

- **Attest on a schedule you already keep**, not per record. Monthly, or at a
  release. Attesting per record would be signing thousands of near-identical
  documents for no additional assurance.
- **Re-attesting is cheap and reports what it replaced**, so a periodic
  attestation doubles as a record of "reviewed again on date X".
- **Sidecars are ordinary files.** Whatever protects the chain should protect
  them, and they are safe to copy off-host: the document is canonical JSON and the
  signature is text. Formatting a copy cannot invalidate it; only changing a value
  can. Run `--canonicalize` on the original if you want byte fidelity back.
- **The test fixture is not a trust anchor.** `tests/fixtures/id_ed25519` is a
  passphrase-less key committed on purpose, so the suite can pin a fingerprint as
  a literal. It signs nothing but test documents, and it must never be trusted.
- **Verification is read-only.** It opens no lock, writes nothing, and needs only
  the chain and the two sidecars plus an allowed-signers file. `--canonicalize` is
  the one exception and it only rewrites formatting, after checking that the file
  has not changed since it was verified.
- **A missing attestation is never treated as a pass.** `verify-attestation`
  exits non-zero; the read-only commands print the gap rather than staying quiet.