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
