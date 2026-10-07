"""Tests for the security mechanisms: policy, gate, redaction, audit. Run: python tests/test_core.py"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit import AuditLog, verify  # noqa: E402
from policy import Gate, Policy, PolicyError  # noqa: E402
from redact import redact_text  # noqa: E402

BASE = {
    "engagement_id": "TEST-1",
    "mode": "active",
    "authorized_hosts": ["app.lab.test", "*.lab.test"],
    "allowed_methods": ["GET", "HEAD"],
    "max_requests_per_minute": 2,
    "max_active_requests_total": 3,
    "audit_log": "unused",
}


def make_policy(tmp: str, **overrides) -> Policy:
    path = Path(tmp) / "policy.json"
    path.write_text(json.dumps({**BASE, **overrides}), encoding="utf-8")
    return Policy.load(str(path))


class PolicyLoadTests(unittest.TestCase):
    def test_empty_scope_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyError):
                make_policy(tmp, authorized_hosts=[])

    def test_missing_engagement_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyError):
                make_policy(tmp, engagement_id="  ")

    def test_unknown_mode_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyError):
                make_policy(tmp, mode="yolo")

    def test_invalid_host_pattern_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyError):
                make_policy(tmp, authorized_hosts=["bad host/path"])


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.policy = make_policy(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_exact_host_in_scope(self):
        self.assertTrue(self.policy.host_in_scope("app.lab.test"))

    def test_wildcard_matches_subdomain_only(self):
        self.assertTrue(self.policy.host_in_scope("api.lab.test"))
        # A suffix without a dot must not count as a subdomain: evillab.test is a foreign host.
        self.assertFalse(self.policy.host_in_scope("evillab.test"))
        self.assertFalse(self.policy.host_in_scope("lab.test.evil.com"))

    def test_out_of_scope_host_denied(self):
        self.assertFalse(self.policy.host_in_scope("example.com"))


class GateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.clock = [0.0]

    def tearDown(self):
        self._tmp.cleanup()

    def gate(self, **overrides) -> Gate:
        return Gate(make_policy(self._tmp.name, **overrides), clock=lambda: self.clock[0])

    def test_read_only_mode_blocks_active_requests(self):
        gate = self.gate(mode="read_only")
        with self.assertRaises(PolicyError):
            gate.check_active("app.lab.test", "GET")

    def test_method_not_allowed(self):
        gate = self.gate()
        with self.assertRaises(PolicyError):
            gate.check_active("app.lab.test", "POST")

    def test_out_of_scope_host_blocked_in_active_mode(self):
        gate = self.gate()
        with self.assertRaises(PolicyError):
            gate.check_active("example.com", "GET")

    def test_rate_limit_and_window_reset(self):
        gate = self.gate()  # max_requests_per_minute=2
        gate.check_active("app.lab.test", "GET")
        gate.check_active("app.lab.test", "GET")
        with self.assertRaises(PolicyError):
            gate.check_active("app.lab.test", "GET")
        self.clock[0] = 61.0  # the 60-second window has passed
        gate.check_active("app.lab.test", "GET")

    def test_session_total_limit(self):
        gate = self.gate(max_requests_per_minute=100)  # max_active_requests_total=3
        for _ in range(3):
            gate.check_active("app.lab.test", "GET")
        with self.assertRaises(PolicyError):
            gate.check_active("app.lab.test", "GET")


class RedactTests(unittest.TestCase):
    def test_sensitive_headers_are_redacted(self):
        raw = "GET / HTTP/1.1\nHost: app.lab.test\nCookie: session=abc123\nAuthorization: Basic dXNlcjpwYXNz"
        out = redact_text(raw)
        self.assertNotIn("abc123", out)
        self.assertNotIn("dXNlcjpwYXNz", out)
        self.assertIn("Host: app.lab.test", out)

    def test_jwt_and_bearer_tokens_are_redacted(self):
        raw = 'token: eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl and "Bearer abcdefgh12345678"'
        out = redact_text(raw)
        self.assertNotIn("eyJzdWIiOi", out)
        self.assertNotIn("abcdefgh12345678", out)


class AuditChainTests(unittest.TestCase):
    def test_chain_verifies_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(str(path), "TEST-1")
            log.record("scope_status", "allow", {})
            log.record("send_request", "deny", {"host": "example.com"}, error="out of scope")
            log.record("search_proxy_history", "allow", {"host": "app.lab.test"}, summary={"returned": 1})

            ok, _ = verify(str(path))
            self.assertTrue(ok)

            lines = path.read_text(encoding="utf-8").splitlines()
            lines[1] = lines[1].replace("out of scope", "tampered")
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            ok, msg = verify(str(path))
            self.assertFalse(ok)
            self.assertIn("line 2", msg)


if __name__ == "__main__":
    unittest.main()
