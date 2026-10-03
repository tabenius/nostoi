"""Nostoi's Rust verifier and locked JSONL/SQLite stores for Python."""
import json
import os
from . import _native

__version__ = "0.1.0"
__all__ = [
    "canonical", "verify", "append", "verify_jsonl", "append_jsonl",
    "attestation_canonical_bytes", "verify_attestation",
]

def _json(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))

def canonical(value):
    """Return Python-compatible canonical JSON, preserving 64-bit integers."""
    return _native.canonical_json(_json(value))

def verify(path, format=None):
    """Verify a JSONL or SQLite chain; broken chains return ok=False."""
    return json.loads(_native.verify(os.fspath(path), format))

def append(path, *, kind, body, actor=None, subject=None, at=None):
    """Append under an exclusive lock/transaction; refuse broken chains."""
    return json.loads(_native.append(os.fspath(path), kind, _json(body), actor, subject, at))

def verify_jsonl(text, format=None):
    """Verify in-memory JSONL without filesystem access."""
    return json.loads(_native.verify_jsonl(text, format))

def append_jsonl(text, *, kind, body, at, actor=None, subject=None):
    """Return the extended JSONL. Caller owns persistence and locking."""
    return _native.append_jsonl(text, kind, _json(body), at, actor, subject)


def attestation_canonical_bytes(document):
    """Return the exact bytes an attestation's signature covers.

    Portable: no filesystem and no ssh-keygen. This is what a receiver needs in
    order to reproduce what was signed, and the digest of it is worth recording.
    """
    return _native.attestation_canonical_bytes(_json(document))

def verify_attestation(path, document, format=None):
    """Check an attestation document against a chain; returns a report.

    Reports, rather than raising, for the interesting outcomes: a stale
    attestation is an answer, not an error. `signature` is always reported as
    "unchecked" because this cannot see an allowed_signers file; use the `nostoi`
    CLI to check a signature.
    """
    return json.loads(_native.verify_attestation(os.fspath(path), _json(document), format))
