"""Tests for the owner-run scope CLI: edits are validated before they are written.

Run: python tests/test_scope_cli.py
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "scope_cli.py"
BASE = {
    "engagement_id": "CLI-TEST",
    "mode": "active",
    "environment": "test",
    "authorized_hosts": ["app.example.test"],
    "scope_urls": ["https://app.example.test/"],
    "audit_log": "unused",
}


def run_cli(policy_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "BURP_AGENT_POLICY": str(policy_path)}
    return subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True, env=env)


class ScopeCliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "policy.json"
        self.path.write_text(json.dumps(BASE), encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def load(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def test_set_integer_limit(self):
        result = run_cli(self.path, "set", "max_active_requests_total", "2000")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.load()["max_active_requests_total"], 2000)

    def test_set_rejects_non_integer_without_writing(self):
        before = self.path.read_text(encoding="utf-8")
        result = run_cli(self.path, "set", "max_requests_per_minute", "many")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_set_methods_list(self):
        run_cli(self.path, "set", "allowed_methods", "get, head,options")
        self.assertEqual(self.load()["allowed_methods"], ["GET", "HEAD", "OPTIONS"])

    def test_invalid_environment_is_not_written(self):
        before = self.path.read_text(encoding="utf-8")
        result = run_cli(self.path, "env", "production")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_add_and_remove_url(self):
        run_cli(self.path, "add-url", "https://app.example.test/api/")
        self.assertIn("https://app.example.test/api/", self.load()["scope_urls"])
        run_cli(self.path, "remove-url", "https://app.example.test/api/")
        self.assertNotIn("https://app.example.test/api/", self.load()["scope_urls"])

    def test_scope_url_outside_authorized_hosts_is_refused(self):
        before = self.path.read_text(encoding="utf-8")
        result = run_cli(self.path, "add-url", "https://other.example/")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_written_policy_is_private(self):
        run_cli(self.path, "env", "stage")
        self.assertEqual(oct(self.path.stat().st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
