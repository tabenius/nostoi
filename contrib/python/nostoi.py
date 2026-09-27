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
