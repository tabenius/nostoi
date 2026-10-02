"""Offline regression tests: python3 contrib/systemd/test_anchor_runner.py."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


RUNNER = Path(__file__).with_name("nostoi-anchor-runner")
FAKE = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
Path(os.environ['CAPTURE']).write_text(json.dumps({
    'argv': sys.argv[1:],
    'credentials': {key: os.environ.get(key) for key in (
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN')},
}))
sys.exit(int(os.environ.get('FAKE_EXIT', '0')))
"""


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nostoi-runner-", dir=RUNNER.parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake = self.root / "fake anchor"
        self.fake.write_text(FAKE)
        self.fake.chmod(0o700)
        self.capture = self.root / "capture.json"
        self.credentials = self.root / "credentials"
        self.credentials.mkdir()
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "NOSTOI_ANCHOR_BIN": str(self.fake),
            "CAPTURE": str(self.capture),
            "CHAIN": "/source with spaces/chain.sqlite",
            "ENDPOINT": "https://example.invalid",
            "BUCKET": "example-bucket",
            "REGION": "us-west-2",
            "CHAIN_ID": "identity with spaces; $(never-execute)",
            "AWS_ACCESS_KEY_ID": "publisher-id",
            "AWS_SECRET_ACCESS_KEY": "publisher-secret",
            "AWS_SESSION_TOKEN": "publisher-token",
        }

    def run_helper(self, mode, extra=None, remove=(), expect=0):
        env = dict(self.env)
        env.update(extra or {})
        for name in remove:
            env.pop(name, None)
        self.capture.unlink(missing_ok=True)
        result = subprocess.run(
            ["/bin/sh", str(RUNNER), mode], env=env,
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, expect, result.stderr)
        for secret in ("publisher-id", "publisher-secret", "publisher-token",
                       "verifier-id", "verifier-secret", "verifier-token"):
            self.assertNotIn(secret, result.stdout + result.stderr)
        if expect == 1:
            self.assertFalse(self.capture.exists(), "invalid config reached executable")
            return None
        return json.loads(self.capture.read_text())

    def common_argv(self):
        return [self.env["CHAIN"], "--endpoint", self.env["ENDPOINT"],
                "--bucket", self.env["BUCKET"], "--region", self.env["REGION"],
                "--chain-id", self.env["CHAIN_ID"]]

    def credential_files(self, token="verifier-token\n"):
        for name, value in (("aws-access-key-id", "verifier-id\n"),
                            ("aws-secret-access-key", "verifier-secret\n"),
                            ("aws-session-token", token)):
            (self.credentials / name).write_text(value)
        return {"CREDENTIALS_DIRECTORY": str(self.credentials)}

    def test_publish_exact_argv_and_environment_credentials(self):
        outbox = "/state with spaces/outbox;literal"
        record = self.run_helper("publish", {"OUTBOX": outbox,
                                 "LOCK": "compliance", "RETAIN_DAYS": "365"})
        self.assertEqual(record["argv"], self.common_argv() + [
            "--outbox", outbox, "--lock", "compliance", "--retain-days", "365"])
        self.assertEqual(record["credentials"], {
            key: self.env[key] for key in (
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")})

    def test_verify_uses_independent_key_and_credentials(self):
        key = "heads/trusted checkpoint;$(literal).json"
        record = self.run_helper("verify", dict(self.credential_files(), TRUSTED_KEY=key))
        self.assertEqual(record["argv"], self.common_argv() + ["--verify", "--key", key])
        self.assertEqual(record["credentials"], {
            "AWS_ACCESS_KEY_ID": "verifier-id", "AWS_SECRET_ACCESS_KEY": "verifier-secret",
            "AWS_SESSION_TOKEN": "verifier-token"})

    def test_empty_token_file_clears_inherited_token(self):
        record = self.run_helper("verify", dict(self.credential_files(token=""), TRUSTED_KEY="heads/key"))
        self.assertIsNone(record["credentials"]["AWS_SESSION_TOKEN"])

    def test_standard_credentials_without_session_token(self):
        record = self.run_helper("publish", {"OUTBOX": "/state/outbox"}, remove=("AWS_SESSION_TOKEN",))
        self.assertEqual(record["argv"], self.common_argv() + ["--outbox", "/state/outbox"])
        self.assertIsNone(record["credentials"]["AWS_SESSION_TOKEN"])

    def test_missing_required_configuration(self):
        for mode, extra in (("publish", {"OUTBOX": "/state/outbox"}),
                            ("verify", {"TRUSTED_KEY": "heads/key"})):
            for name in ("CHAIN", "ENDPOINT", "BUCKET", "REGION", "CHAIN_ID",
                         "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
                with self.subTest(mode=mode, missing=name):
                    self.run_helper(mode, extra, remove=(name,), expect=1)
        self.run_helper("publish", expect=1)
        self.run_helper("verify", expect=1)

    def test_missing_or_empty_credential_files(self):
        extra = dict(self.credential_files(), TRUSTED_KEY="heads/key")
        for name in ("aws-access-key-id", "aws-secret-access-key", "aws-session-token"):
            with self.subTest(missing=name):
                path = self.credentials / name
                value = path.read_text()
                path.unlink()
                self.run_helper("verify", extra, expect=1)
                path.write_text(value)
        (self.credentials / "aws-secret-access-key").write_text("")
        self.run_helper("verify", extra, expect=1)

    def test_verify_forbids_publish_options(self):
        for name, value in (("OUTBOX", "/state/outbox"), ("LOCK", "compliance"),
                            ("RETAIN_DAYS", "365")):
            with self.subTest(option=name):
                self.run_helper("verify", {"TRUSTED_KEY": "heads/key", name: value}, expect=1)
        self.run_helper("publish", {"OUTBOX": "/state/outbox", "TRUSTED_KEY": "heads/key"}, expect=1)

    def test_invalid_values_and_mode(self):
        for extra in ({"CHAIN": "relative"}, {"ENDPOINT": "http://example.invalid"},
                      {"NOSTOI_ANCHOR_BIN": "relative"},
                      {"OUTBOX": "relative"}, {"LOCK": "governance"},
                      {"RETAIN_DAYS": "365"}):
            self.run_helper("publish", dict({"OUTBOX": "/state/outbox"}, **extra), expect=1)
        for days in ("", "0", "-1", "1;false", "01"):
            self.run_helper("publish", {"OUTBOX": "/state/outbox", "LOCK": "compliance",
                                       "RETAIN_DAYS": days}, expect=1)
        self.run_helper("unsupported", expect=1)

    def test_uncertain_and_unconfirmed_exits_are_preserved(self):
        for code in (2, 3):
            with self.subTest(code=code):
                self.run_helper("publish", {"OUTBOX": "/state/outbox", "FAKE_EXIT": str(code)}, expect=code)


if __name__ == "__main__":
    unittest.main()
