import json
import os
from pathlib import Path
import tempfile
import unittest
import nostoi

DRAFT = dict(at="2026-09-27T12:00:00Z", actor="agent:test", kind="test",
             body={"unicode": "🦆", "large": 2**64-1})

class Api(unittest.TestCase):
    def test_stores_and_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("audit.jsonl", "audit.sqlite"):
                p = Path(d) / name
                first = nostoi.append(p, **DRAFT)
                second = nostoi.append(p, **DRAFT)
                self.assertEqual(second["previous"], first["digest"])
                self.assertEqual(nostoi.verify(p)["verified"], 2)
            p = Path(d) / "audit.jsonl"
            p.write_text(p.read_text().replace("agent:test", "agent:other", 1))
            before = p.read_bytes()
            self.assertFalse(nostoi.verify(p)["ok"])
            with self.assertRaises(ValueError): nostoi.append(p, **DRAFT)
            self.assertEqual(before, p.read_bytes())
            with self.assertRaises(OSError): nostoi.verify(Path(d) / "absent")

    def test_portable_and_precision(self):
        text = nostoi.append_jsonl("", **DRAFT)
        self.assertEqual(nostoi.verify_jsonl(text)["verified"], 1)
        self.assertEqual(json.loads(text)["body"]["large"], 2**64-1)
        self.assertEqual(nostoi.canonical(DRAFT["body"]), json.dumps(DRAFT["body"], sort_keys=True, separators=(",", ":")))
        with self.assertRaises(ValueError): nostoi.append_jsonl("", **dict(DRAFT, body={"x":0.1}))
        with self.assertRaises(ValueError): nostoi.append_jsonl("", **dict(DRAFT, at="yesterday"))
        with self.assertRaises(ValueError): nostoi.verify_jsonl("", "unknown")
        if directory := os.environ.get("NOSTOI_INTEROP_DIR"):
            Path(directory, "python.jsonl").write_text(text)

if __name__ == "__main__": unittest.main()

class AttestationTests(unittest.TestCase):
    """The portable half of an attestation, from Python."""

    def chain(self, dir_, records=3):
        path = os.path.join(dir_, "audit.jsonl")
        for index in range(records):
            nostoi.append(path, kind="attest", body={"index": index})
        return path

    def document(self, path, **overrides):
        head = nostoi.verify(path)
        document = {
            "v": "nostoi-attestation-v1",
            "chain": "test",
            "format": "nostoi-v1",
            "seq": head["head"]["seq"],
            "digest": head["head"]["digest"],
            "anchored_at": "2026-02-01T12:00:00Z",
            "principal": "alice@laptop",
            "fingerprint": "SHA256:" + "A" * 43,
            **overrides,
        }
        return document

    def test_canonical_bytes_are_reproducible_and_ascii(self):
        with tempfile.TemporaryDirectory() as dir_:
            path = self.chain(dir_)
            document = self.document(path, title="caf\u00e9 freeze")
            first = nostoi.attestation_canonical_bytes(document)
            self.assertEqual(first, nostoi.attestation_canonical_bytes(document))
            self.assertTrue(first.isascii())
            # Key order in the caller's dict must not change what was signed.
            reordered = dict(reversed(list(document.items())))
            self.assertEqual(nostoi.attestation_canonical_bytes(reordered), first)
            self.assertIn(r"\u00e9", first)

    def test_verifying_against_a_chain(self):
        with tempfile.TemporaryDirectory() as dir_:
            path = self.chain(dir_)
            report = nostoi.verify_attestation(path, self.document(path))
            self.assertTrue(report["ok"])
            self.assertEqual(report["coverage"], "current")
            self.assertTrue(report["covers_head"])
            self.assertEqual(report["principal"], "alice@laptop")
            # It has no allowed-signers file, so it must not claim otherwise.
            self.assertEqual(report["signature"], "unchecked")

    def test_a_stale_attestation_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as dir_:
            path = self.chain(dir_, records=2)
            old = self.document(path)
            nostoi.append(path, kind="attest", body={"index": 99})
            report = nostoi.verify_attestation(path, old)
            self.assertTrue(report["ok"])
            self.assertFalse(report["covers_head"])
            self.assertEqual(report["coverage"], {"stale": True, "ahead_by": 1})

    def test_a_rewritten_or_truncated_chain_is_refused(self):
        with tempfile.TemporaryDirectory() as dir_:
            path = self.chain(dir_, records=4)
            document = self.document(path)
            text = open(path).read().splitlines()
            open(path, "w").write("\n".join(text[:2]) + "\n")
            with self.assertRaises(ValueError):
                nostoi.verify_attestation(path, document)

    def test_a_malformed_document_is_refused(self):
        with tempfile.TemporaryDirectory() as dir_:
            path = self.chain(dir_)
            document = self.document(path)
            document["seq"] = 0
            with self.assertRaises(ValueError):
                nostoi.attestation_canonical_bytes(document)
            with self.assertRaises(ValueError):
                nostoi.verify_attestation(path, document)
