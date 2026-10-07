"""Redaction tests: secrets in headers and tokens, personal data by JSON keys.

Run: python tests/test_redact.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redact import redact_text  # noqa: E402


class RedactTests(unittest.TestCase):
    def test_sensitive_headers(self):
        out = redact_text("GET / HTTP/1.1\nHost: a\nCookie: sid=abc123\nAuthorization: Basic dXNlcjpwYXNz")
        self.assertNotIn("abc123", out)
        self.assertNotIn("dXNlcjpwYXNz", out)
        self.assertIn("Host: a", out)

    def test_tokens(self):
        out = redact_text('t: eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl and "Bearer abcdefgh12345678"')
        self.assertIn("[JWT]", out)
        self.assertNotIn("abcdefgh12345678", out)

    def test_phi_by_json_keys(self):
        raw = '{"firstName": "John", "lastName": "Smith", "birthDate": "1980-01-02", "id": 101}'
        out = redact_text(raw)
        self.assertNotIn("John", out)
        self.assertNotIn("Smith", out)
        self.assertNotIn("1980-01-02", out)
        self.assertIn('"id": 101', out)  # the identifier is not touched

    def test_phi_key_with_escaped_quotes(self):
        raw = r'{"fullName": "John \"Johnny\" Smith", "ok": 1}'
        out = redact_text(raw)
        self.assertNotIn("Smith", out)
        self.assertIn('"ok": 1', out)

    def test_non_phi_names_kept(self):
        # a vulnerability title must not be masked
        raw = '{"name": "Unencrypted communications", "severity": "LOW"}'
        self.assertIn("Unencrypted communications", redact_text(raw))


if __name__ == "__main__":
    unittest.main()
