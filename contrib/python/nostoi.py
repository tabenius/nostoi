"""nostoi-v1 in Python, standard library only: append to and verify a chain.

This is the reference for Python producers (WeftMark, Sylvae, Frog,
Rebekah's gateway). It writes exactly what the Rust `nostoi` crate writes and
verifies what it verifies; the crate's tests check both directions.

A record is one JSON object per line:

    {"v": "nostoi-v1", "seq": 1, "previous": "<64 hex>", "at": "<RFC 3339>",
     "actor": "...", "kind": "...", "subject": "...", "body": {...},
     "digest": "<64 hex>"}

`digest` is SHA-256 of the record without `digest`, encoded as
`json.dumps(record, sort_keys=True, separators=(",", ":"))`. `actor` and
`subject` are optional. `body` is an object with no floats (write decimals as
strings) and 64-bit integers at most.

    import nostoi
    nostoi.append("audit.jsonl", kind="skill.run", actor="agent:claude",
                  subject="run-42", body={"skill": "summarise", "input": text})
    report = nostoi.verify("audit.jsonl")
    assert report["ok"], report["problem"]
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

VERSION = "nostoi-v1"
GENESIS = "0" * 64


def _sealed_kid(kid: str) -> None:
    if not isinstance(kid, str) or not kid or len(kid.encode()) > 128 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in kid):
        raise ValueError("invalid sealed key ID")


def seal(value: Any, kid: str, key: bytes, *, nonce: bytes | None = None) -> dict[str, Any]:
    """Seal a JSON value with optional PyNaCl/libsodium, never hand-rolled crypto.

    A supplied nonce is for interoperability vectors only; never reuse a nonce
    with a key. Verification and rendering do not require PyNaCl.
    """
    import base64
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

    _sealed_kid(kid)
    _check_body(value)
    nonce = os.urandom(24) if nonce is None else nonce
    if len(key) != 32 or len(nonce) != 24:
        raise ValueError("sealed keys need 32 bytes and nonces 24 bytes")
    aad = f"xchacha20poly1305|{kid}|1".encode()
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(canonical(value).encode(), aad, nonce, key)
    return {"$sealed": {"v": 1, "alg": "xchacha20poly1305", "kid": kid,
                        "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ciphertext).decode()}}


def open_sealed(value: dict[str, Any], key: bytes) -> Any:
    """Explicit decryption. Displays never call this function automatically."""
    import base64
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt

    if not isinstance(value, dict) or set(value) != {"$sealed"}:
        raise ValueError("invalid sealed envelope")
    inner = value["$sealed"]
    if not isinstance(inner, dict) or set(inner) != {"v", "alg", "kid", "nonce", "ct"} or type(inner["v"]) is not int or inner["v"] != 1 or inner["alg"] != "xchacha20poly1305":
        raise ValueError("unsupported or malformed sealed envelope")
    _sealed_kid(inner["kid"])
    nonce = base64.b64decode(inner["nonce"], validate=True)
    ciphertext = base64.b64decode(inner["ct"], validate=True)
    if len(key) != 32 or len(nonce) != 24 or len(ciphertext) < 16:
        raise ValueError("invalid sealed key, nonce or ciphertext length")
    plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, f"xchacha20poly1305|{inner['kid']}|1".encode(), nonce, key)
    result = json.loads(plaintext)
    _check_body(result)
    return result


def render_body(value: Any, *, erased_ids=()) -> Any:
    """Data-only display projection; unknown key availability remains sealed."""
    erased = set(erased_ids)
    def visit(item):
        if isinstance(item, dict):
            if "$sealed" in item:
                inner = item["$sealed"]
                kid = inner.get("kid") if isinstance(inner, dict) else None
                return "[erased]" if isinstance(kid, str) and kid in erased else "[sealed]"
            return {k: visit(v) for k, v in item.items()}
        if isinstance(item, list):
            return [visit(v) for v in item]
        return item
    return visit(value)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(record: dict[str, Any]) -> str:
    content = {k: v for k, v in record.items() if k != "digest"}
    return hashlib.sha256(canonical(content).encode()).hexdigest()


def _check_body(value: Any) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, float):
        raise ValueError(f"{value!r} is a float; write decimals as strings")
    if isinstance(value, int):
        if not -(2**63) <= value < 2**64:
            raise ValueError(f"{value} is not a 64-bit integer; write it as a string")
        return
    if isinstance(value, list):
        for item in value:
            _check_body(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("object keys must be strings")
            _check_body(item)
        return
    raise ValueError(f"{type(value).__name__} is not JSON")


def _now() -> str:
    at = datetime.now(timezone.utc)
    return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}Z"


def _read(stream) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    records, problem = [], None
    previous = GENESIS
    for index, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError as error:
            problem = {"unreadable": {"at": index, "detail": str(error)}}
            break
        seq = record.get("seq") if isinstance(record, dict) else None
        if not isinstance(record, dict) or record.get("v") != VERSION:
            problem = {"unreadable": {"at": index, "detail": f"not a {VERSION} record"}}
            break
        if seq != len(records) + 1:
            problem = {"sequence": {"seq": seq, "expected": len(records) + 1}}
            break
        if record.get("previous") != previous:
            problem = {"link": {"seq": seq}}
            break
        if record.get("digest") != digest(record):
            problem = {"digest": {"seq": seq}}
            break
        records.append(record)
        previous = record["digest"]
    return records, problem


def verify(path: str | os.PathLike) -> dict[str, Any]:
    """Verify a nostoi-v1 JSONL chain; the first problem stops it."""
    with open(path, encoding="utf-8") as stream:
        records, problem = _read(stream)
    head = records[-1] if records else None
    return {
        "format": VERSION,
        "ok": problem is None,
        "verified": len(records),
        "head": {"seq": head["seq"], "digest": head["digest"]} if head else None,
        "problem": problem,
    }


def append(
    path: str | os.PathLike,
    *,
    kind: str,
    body: dict[str, Any] | None = None,
    actor: str | None = None,
    subject: str | None = None,
    at: str | None = None,
) -> dict[str, Any]:
    """Append a record (creating the file); refuses to extend a broken chain."""
    body = {} if body is None else body
    if not kind or not kind.strip():
        raise ValueError("kind must not be empty")
    if not isinstance(body, dict):
        raise ValueError("body must be a JSON object")
    _check_body(body)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o644)
    with os.fdopen(fd, "r+", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.seek(0)
        records, problem = _read(stream)
        if problem is not None:
            raise ValueError(f"the chain is broken, nothing appended: {problem}")
        record: dict[str, Any] = {
            "v": VERSION,
            "seq": len(records) + 1,
            "previous": records[-1]["digest"] if records else GENESIS,
            "at": at or _now(),
            "kind": kind,
            "body": body,
        }
        if actor is not None:
            record["actor"] = actor
        if subject is not None:
            record["subject"] = subject
        record["digest"] = digest(record)
        stream.write(canonical(record) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
        return record
