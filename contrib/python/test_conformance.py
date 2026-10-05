"""Conformance between `contrib/python/nostoi.py` and the Rust `nostoi` crate.

`nostoi.py` claims to write "exactly what the Rust `nostoi` crate writes and
verifies what it verifies". That claim is the whole basis on which WeftMark,
Sylvae, Frog and Rebekah's gateway may each keep their own Python audit log and
still be read by one `nostoi verify`. A claim like that rots quietly: the Rust
canonicaliser is hand-written to imitate `json.dumps`, and the day someone
"tidies" either side the digests stop agreeing and every chain written by the
other language becomes unverifiable.

So this asserts the agreement from both ends, against the built binary:

- **known answers** -- a fixed record must come out byte-identical and with the
  same digest whichever side wrote it, so a regression names itself;
- **both directions** -- Python writes and Rust verifies, and the reverse;
- **interleaved** -- alternating appends must leave one continuous chain, since
  that is how two languages will actually share a file;
- **rejection parity** -- floats, out-of-range integers, nested floats and empty
  kinds are refused by both, including exactly at the 64-bit boundaries;
- **tamper parity** -- a mutated body, a broken link, a forged digest, a wrong
  sequence and a dropped field are all caught by both;
- **escaping** -- the astral-plane and control-character cases, where a
  hand-written canonicaliser is most likely to drift from `json.dumps`.

Run it directly, or under the stdlib runner:

    python3 contrib/python/test_conformance.py
    python3 -m unittest discover -s contrib/python -p 'test_*.py'

The Rust binary is found via `$NOSTOI_BIN`, then `target/release/nostoi`, then
`target/debug/nostoi`. With none of them present every test skips rather than
fails: a Python-only checkout should not need a Rust toolchain to test its
Python.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))

import nostoi  # noqa: E402

#: A record that exercises everything the two implementations could disagree on:
#: non-ASCII, an astral-plane character, a combining-free em dash, nested
#: objects whose keys must sort at every depth, a negative integer, a boolean
#: and a null.
BODY = {
    "skill": "summarise",
    "input": "hej världen 🦆 —",
    "n": -5,
    "ok": True,
    "nil": None,
    "deep": {"b": [1, 2, {"z": "x"}], "a": "y"},
}
AT = "2026-10-05T00:00:00.000Z"

#: The digest both implementations must produce for the record above. Recorded
#: from the crate, so a change in either canonicaliser fails here by name.
KNOWN_DIGEST = "083bd67f38521e199c57691221d7d01d964b8562f74bb98e7455ca78e3973fe0"


def _find_binary() -> str | None:
    named = os.environ.get("NOSTOI_BIN")
    if named and Path(named).is_file():
        return named
    for candidate in ("target/release/nostoi", "target/debug/nostoi"):
        path = REPO / candidate
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


BINARY = _find_binary()
needs_rust = unittest.skipIf(BINARY is None,
                             "no nostoi binary; build it or set $NOSTOI_BIN")


def rust(*args: str) -> subprocess.CompletedProcess:
    assert BINARY is not None
    return subprocess.run([BINARY, *args], capture_output=True, text=True, timeout=60)


class ChainCase(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "chain.jsonl"

    def lines(self) -> list[dict]:
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]


@needs_rust
class KnownAnswerTests(ChainCase):
    def test_both_sides_write_identical_bytes_for_one_record(self):
        rust("append", "--kind", "skill.run", "--actor", "agent:claude",
             "--subject", "run-42", "--body", json.dumps(BODY), "--at", AT,
             str(self.path))
        from_rust = self.path.read_bytes()

        other = self.path.with_name("python.jsonl")
        nostoi.append(other, kind="skill.run", actor="agent:claude",
                      subject="run-42", body=BODY, at=AT)

        self.assertEqual(from_rust, other.read_bytes(),
                         "the two implementations disagree on the bytes on disk")
        self.assertEqual(json.loads(from_rust)["digest"], KNOWN_DIGEST)
        self.assertEqual(json.loads(other.read_bytes())["digest"], KNOWN_DIGEST)

    def test_the_record_carries_the_fields_both_implementations_agree_on(self):
        nostoi.append(self.path, kind="skill.run", actor="agent:claude",
                      subject="run-42", body=BODY, at=AT)
        record = self.lines()[0]
        self.assertEqual(record["v"], "nostoi-v1")
        self.assertEqual(record["seq"], 1)
        self.assertEqual(record["previous"], nostoi.GENESIS)
        self.assertEqual(record["at"], AT)
        self.assertEqual(sorted(record),
                         ["actor", "at", "body", "digest", "kind", "previous", "seq",
                          "subject", "v"])

    def test_optional_fields_are_absent_rather_than_null(self):
        nostoi.append(self.path, kind="skill.run", body={}, at=AT)
        record = self.lines()[0]
        self.assertNotIn("actor", record)
        self.assertNotIn("subject", record)


@needs_rust
class DirectionTests(ChainCase):
    def test_rust_verifies_a_chain_python_wrote(self):
        for index in range(3):
            nostoi.append(self.path, kind=f"k{index}", actor="agent:t",
                          body={"i": index}, at=AT)
        result = rust("verify", str(self.path))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_python_verifies_a_chain_rust_wrote(self):
        for index in range(3):
            rust("append", "--kind", f"k{index}", "--actor", "agent:t",
                 "--body", json.dumps({"i": index}), "--at", AT, str(self.path))
        report = nostoi.verify(self.path)
        self.assertTrue(report["ok"], report["problem"])
        self.assertEqual(report["verified"], 3)

    def test_interleaved_appends_leave_one_continuous_chain(self):
        """How the two languages will really share a file."""
        for index in range(6):
            if index % 2:
                rust("append", "--kind", f"k{index}", "--body",
                     json.dumps({"i": index}), "--at", AT, str(self.path))
            else:
                nostoi.append(self.path, kind=f"k{index}", body={"i": index}, at=AT)
        self.assertEqual(rust("verify", str(self.path)).returncode, 0)
        report = nostoi.verify(self.path)
        self.assertTrue(report["ok"], report["problem"])
        self.assertEqual([r["seq"] for r in self.lines()], [1, 2, 3, 4, 5, 6])
        self.assertEqual(report["head"]["seq"], 6)

    def test_both_report_the_same_head(self):
        nostoi.append(self.path, kind="k", body={}, at=AT)
        expected = nostoi.verify(self.path)["head"]["digest"]
        printed = rust("head", str(self.path)).stdout.split()
        self.assertIn(expected, printed)


@needs_rust
class RejectionParityTests(ChainCase):
    """Both sides must refuse the same bodies, at the boundaries too."""

    CASES = {
        "float": {"x": 1.5},
        "float nested in an object": {"a": {"b": [1, {"c": 0.1}]}},
        "above u64::MAX": {"x": 2**64},
        "below i64::MIN": {"x": -(2**63) - 1},
    }

    def test_python_refuses_what_rust_refuses(self):
        for label, body in self.CASES.items():
            with self.subTest(label):
                self.path.unlink(missing_ok=True)
                with self.assertRaises(ValueError):
                    nostoi.append(self.path, kind="k", body=body, at=AT)
                self.assertEqual(rust("append", "--kind", "k", "--body",
                                      json.dumps(body), str(self.path)).returncode,
                                 2, f"rust accepted {label}")

    def test_both_accept_the_extremes_of_the_64_bit_range(self):
        for label, value in (("u64::MAX", 2**64 - 1), ("i64::MIN", -(2**63))):
            with self.subTest(label):
                self.path.unlink(missing_ok=True)
                nostoi.append(self.path, kind="k", body={"x": value}, at=AT)
                self.assertEqual(nostoi.verify(self.path)["verified"], 1)
                self.assertEqual(rust("verify", str(self.path)).returncode, 0)

    def test_both_refuse_an_empty_kind(self):
        self.path.unlink(missing_ok=True)
        with self.assertRaises(ValueError):
            nostoi.append(self.path, kind="   ", body={}, at=AT)
        self.assertEqual(rust("append", "--kind", "  ", str(self.path)).returncode, 2)

    def test_both_refuse_a_body_that_is_not_an_object(self):
        with self.assertRaises(ValueError):
            nostoi.append(self.path, kind="k", body=[1, 2], at=AT)
        self.assertEqual(rust("append", "--kind", "k", "--body", "[1,2]",
                              str(self.path)).returncode, 2)

    def test_python_will_not_extend_a_broken_chain(self):
        nostoi.append(self.path, kind="k", body={}, at=AT)
        text = self.path.read_text().replace('"kind":"k"', '"kind":"x"')
        self.path.write_text(text)
        with self.assertRaisesRegex(ValueError, "chain is broken"):
            nostoi.append(self.path, kind="k2", body={}, at=AT)
        self.assertEqual(len(self.lines()), 1, "a record was appended anyway")


@needs_rust
class TamperParityTests(ChainCase):
    """Every mutation below must be caught by both, with the same verdict."""

    def build(self, count: int = 3) -> None:
        for index in range(count):
            nostoi.append(self.path, kind=f"k{index}", actor="agent:t",
                          body={"i": index}, at=AT)

    def rewrite(self, change) -> None:
        """Re-emit the chain canonically after mutating one record in place."""
        records = self.lines()
        self.assertGreaterEqual(len(records), 2, "build() did not write a chain")
        # `change` takes the whole list, so a mutation can address any record.
        change(records)
        self.path.write_text("".join(
            json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n"
            for r in records))

    def assertBothReject(self, label, change):
        # setUp already ran for this test; calling it again would leave the
        # first temporary directory registered for cleanup and make the path
        # this test reads depend on call order.
        self.build()
        self.rewrite(change)
        # Both must *reject*. An earlier version of this asserted the polarity
        # the other way round and so failed precisely when the two agreed.
        python_ok = nostoi.verify(self.path)["ok"]
        rust_rc = rust("verify", str(self.path)).returncode
        self.assertFalse(python_ok, f"python accepted a {label}")
        self.assertNotEqual(rust_rc, 0, f"rust accepted a {label}")

    def test_a_edited_body_is_caught(self):
        self.assertBothReject("edited body", lambda rs: rs[1]["body"].update(i=999))

    def test_a_relinked_record_is_caught(self):
        self.assertBothReject("broken link", lambda rs: rs[1].update(previous="f" * 64))

    def test_a_forged_digest_is_caught(self):
        self.assertBothReject("forged digest", lambda rs: rs[1].update(digest="0" * 64))

    def test_a_rewritten_sequence_is_caught(self):
        self.assertBothReject("wrong sequence", lambda rs: rs[1].update(seq=7))

    def test_a_dropped_field_is_caught(self):
        self.assertBothReject("dropped field", lambda rs: rs[1].pop("actor"))

    def test_a_truncated_chain_still_verifies_as_the_shorter_prefix(self):
        """Truncation is not tampering: the remaining records are intact."""
        self.build()
        self.path.write_text("".join(self.path.read_text().splitlines(keepends=True)[:2]))
        report = nostoi.verify(self.path)
        self.assertTrue(report["ok"])
        self.assertEqual(report["verified"], 2)


class EscapingTests(unittest.TestCase):
    """The cases a hand-written canonicaliser is most likely to get wrong.

    These need no Rust binary: they pin Python's output to the exact bytes the
    crate's own `matches_python_ensure_ascii_escaping` test asserts, so the two
    suites fail together if either canonicaliser moves.
    """

    def test_escaping_matches_the_bytes_the_crate_asserts(self):
        value = json.loads(r'{"b":"går 🦆 —","a":"t\tn\nq\"s\\/\u0007\u007f~"}')
        # The escaped form, which is what `ensure_ascii=True` produces and what
        # the crate asserts: non-ASCII becomes \uXXXX (lowercase hex, UTF-16
        # surrogate pairs above the BMP), DEL is escaped, `/` is not.
        self.assertEqual(
            nostoi.canonical(value),
            r'{"a":"t\tn\nq\"s\\/\u0007\u007f~","b":"g\u00e5r \ud83e\udd86 \u2014"}')

    def test_keys_sort_at_every_depth(self):
        value = json.loads(r'{"z":[{"b":null,"a":true}],"a":{"y":false,"x":{}}}')
        self.assertEqual(nostoi.canonical(value),
                         '{"a":{"x":{},"y":false},"z":[{"a":true,"b":null}]}')

    def test_solidus_is_not_escaped(self):
        self.assertEqual(nostoi.canonical({"a": "a/b"}), '{"a":"a/b"}')

    def test_large_integers_keep_their_written_form(self):
        self.assertEqual(nostoi.canonical({"x": 12345678901234567890}),
                         '{"x":12345678901234567890}')


if __name__ == "__main__":
    if BINARY is None:
        print("no nostoi binary found; Rust-parity tests will skip", file=sys.stderr)
    unittest.main()
