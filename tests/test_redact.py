"""Redaction tests: secrets in headers and tokens, personal data by JSON keys.

Run: python tests/test_redact.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redact import mask_query, redact_text  # noqa: E402


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


class QueryMaskTests(unittest.TestCase):
    def test_secret_parameters_are_masked_and_others_kept(self):
        out = mask_query("/api/x?page=2&access_token=abc123&sid=zz9")
        self.assertEqual(out, "/api/x?page=2&access_token=[REDACTED]&sid=[REDACTED]")

    def test_only_whole_parameter_names_match(self):
        # "mytoken" is not a secret parameter; "token" after a dot is not a parameter either
        self.assertEqual(mask_query("/a?mytoken=1&v=token.x"), "/a?mytoken=1&v=token.x")

    def test_request_line_and_json_text(self):
        self.assertIn("?token=[REDACTED]", redact_text("GET /p?token=abc HTTP/1.1\r\nHost: a"))
        self.assertNotIn("abc", redact_text('{"next": "/p?key=abc&x=1"}'))

    def test_empty_value_is_still_masked(self):
        self.assertEqual(mask_query("/a?session="), "/a?session=[REDACTED]")


class SecretPairTests(unittest.TestCase):
    def test_secret_pairs_in_text_and_json_are_masked(self):
        self.assertNotIn("supersecret12", redact_text("note: token=supersecret12 end"))
        out = redact_text('{"password": "pw123", "name": "shop"}')
        self.assertNotIn("pw123", out)
        self.assertIn('"name": "shop"', out)  # other fields are kept

    def test_words_without_a_value_are_kept(self):
        self.assertEqual(redact_text("tokens are useful"), "tokens are useful")


if __name__ == "__main__":
    unittest.main()
