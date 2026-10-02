# Test fixtures

`id_ed25519` is a throwaway key pair, generated once and committed so that the
attestation tests have a *fixed* trust anchor. It is not a secret and must never
be trusted:

- the private key has no passphrase, so anyone with this repository can sign with
  it;
- it signs nothing but test documents;
- `EXAMPLE_FINGERPRINT` in `tests/attestation.rs` must match this key. If the key
  file is ever replaced, that constant has to change with it, which is the point:
  a known-answer test catches a fingerprint parser that quietly returns the wrong
  token, and a runtime-generated key cannot do that, because both sides of such a
  test would be wrong in the same way.

`allowed_signers` is the shape a real deployment provisions out of band: several
principals in one file, one with an expiry and a `principals=` restriction, so the
parser is exercised against more than the single line the happy path uses.

Generate a replacement with:

```sh
ssh-keygen -q -t ed25519 -N '' -C 'nostoi-test@example.invalid' -f id_ed25519
ssh-keygen -y -f id_ed25519 > id_ed25519.pub
ssh-keygen -lf id_ed25519          # put the SHA256:… value in the test
```
