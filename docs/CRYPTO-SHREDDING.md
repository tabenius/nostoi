# Sealed fields and active-store erasure

Personal body fields can use a v1 XChaCha20-Poly1305 envelope. Existing chain
canonicalization is unchanged: the record digest covers **ciphertext**, so the
chain verifies whether or not a decryption key exists. Keys never enter records.
The Rust `sealed` feature enables encryption and file-backed key storage; CLI
builds enable it automatically. Default-free verifier/browser builds do not.

```sh
nostoi keygen opaque-subject-1 --chain audit.jsonl
# Put the input in a protected file, not secret-bearing command-line arguments.
nostoi append audit.jsonl --kind example --body @protected-input.json \
  --seal personal=opaque-subject-1
nostoi show audit.jsonl 1
nostoi forget opaque-subject-1 --chain audit.jsonl
nostoi verify audit.jsonl
```

`--seal field=key-id` selects a top-level body field; repeat for more fields.
Missing fields, missing keys, duplicate selections and resealing fail closed.
Keys are created explicitly; an erased ID cannot be generated again. Use opaque
IDs rather than an email/name: the key ID itself is visible in the chain.
The default store is `<chain>.keys/store.json`, in a private 0700 directory with
0600 files. `--key-store` chooses an alternate file in an owner-private directory.
Cooperating writers hold an advisory lock from load through mutation; replacement
uses a uniquely created private temporary file, fsync, rename and directory fsync.
Symlink stores and group/world-readable store files are refused.

Envelope shape:

```json
{"$sealed":{"v":1,"alg":"xchacha20poly1305","kid":"opaque-subject-1","nonce":"BASE64","ct":"BASE64"}}
```

The nonce is 24 fresh random bytes; the key is 32 random bytes. AAD is UTF-8
`xchacha20poly1305|<kid>|1`, binding algorithm, subject and version. Plaintext is
Nostoi canonical JSON and must satisfy its native integer/no-float rules.
Do not reuse a nonce with a key. The deterministic nonce API is for test vectors,
not a production mode. Rust uses the maintained AEAD crate; Python's optional
`seal`/`open_sealed` helpers use PyNaCl/libsodium, not custom cryptography.
Python chain verification and display remain stdlib-only.

## What forgetting guarantees—and does not

`forget` requires an intact nostoi-v1 chain before touching the key. It appends
`key.erasure.requested`, removes active key material with an erasure tombstone,
then appends `key.erased`. Prior record bytes/digests do not change. No key bytes
are printed or recorded. The receipt claims **active-key-store-only**, not proof
of physical erasure or proof that nobody previously decrypted the value.

The store and chain are separate durable resources, not one transaction. A crash
can leave a request without a completion receipt; retry forgetting to record the
current absence. A failed final append reports that the key was removed but the
receipt failed. It never restores a removed key merely to manufacture atomicity.
Backups, snapshots, copied keys, swap, caches, filesystem recovery and plaintext
held elsewhere can defeat effective erasure. Remove those copies under an actual
retention policy; this feature alone does not establish GDPR compliance. Key and
temporary plaintext buffers are zeroized where supported, not a claim that all
process copies have been purged. KMS-backed erasure is not implemented.

## Display and export

Human/JSON `show` and the TUI project sealed bodies as `[sealed]`; a known local
erasure tombstone makes them `[erased]`. Missing/unreadable store metadata means
unknown availability, not proof of erasure. The TUI remains redacted on a store
read error. It reads atomic tombstone snapshots without holding a writer lock.
`show --json` labels the result `display_projection`: its substituted body is
not a raw digest-verifiable record. Use `show --raw --json` or the original chain
for ciphertext export/verification. Live `log` remains a raw ciphertext stream.
No display automatically decrypts; library decryption is an explicit operation.
