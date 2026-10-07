"""Тесты scope по URL: префиксы, порты, обход каталогов, валидация политики, окружение.

Запуск: python tests/test_scope.py
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from policy import Policy, PolicyError  # noqa: E402


def policy(tmp: str, **overrides) -> Policy:
    data = {"engagement_id": "T", "mode": "active", "environment": "test",
            "authorized_hosts": ["ehealth.test.local", "*.lab.test"],
            "scope_urls": ["https://ehealth.test.local/api/", "https://stage.lab.test/"],
            "audit_log": f"{tmp}/a.jsonl"}
    data.update(overrides)
    path = Path(tmp, "p.json")
    path.write_text(json.dumps(data), encoding="utf-8")
    return Policy.load(str(path))


class UrlScopeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.p = policy(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_prefix_matches_on_segment_boundary(self):
        self.assertTrue(self.p.url_in_scope("https://ehealth.test.local/api/patients/1"))
        self.assertTrue(self.p.url_in_scope("https://ehealth.test.local/api"))
        self.assertFalse(self.p.url_in_scope("https://ehealth.test.local/apiv2/x"))
        self.assertFalse(self.p.url_in_scope("https://ehealth.test.local/admin"))

    def test_scheme_and_port_must_match(self):
        self.assertFalse(self.p.url_in_scope("http://ehealth.test.local/api/x"))
        self.assertFalse(self.p.url_in_scope("https://ehealth.test.local:8443/api/x"))
        self.assertTrue(self.p.url_in_scope("https://ehealth.test.local:443/api/x"))

    def test_dot_segments_refused(self):
        self.assertFalse(self.p.url_in_scope("https://ehealth.test.local/api/../admin"))
        self.assertFalse(self.p.url_in_scope("https://ehealth.test.local/api/%2e%2e/admin"))
        self.assertFalse(self.p.path_allowed("/api/../admin"))

    def test_host_outside_authorized_refused(self):
        self.assertFalse(self.p.url_in_scope("https://evil.example/api/x"))

    def test_wildcard_host_with_scope_prefix(self):
        self.assertTrue(self.p.url_in_scope("https://stage.lab.test/anything"))
        self.assertFalse(self.p.url_in_scope("https://stage.lab.test:8443/anything"))

    def test_no_scope_urls_means_whole_authorized_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = policy(tmp, scope_urls=[])
            self.assertTrue(p.url_in_scope("https://ehealth.test.local/any/where"))

    def test_bad_url_inputs_do_not_raise(self):
        for url in ("", "not a url", "https://", "https://ehealth.test.local:99999/x", "ftp://ehealth.test.local/"):
            self.assertFalse(self.p.url_in_scope(url), url)


class PolicyValidationTests(unittest.TestCase):
    def test_scope_url_host_must_be_authorized(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyError):
                policy(tmp, scope_urls=["https://other.example/"])

    def test_scope_url_scheme_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyError):
                policy(tmp, scope_urls=["ftp://ehealth.test.local/"])

    def test_environment_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyError):
                policy(tmp, environment="production")
            self.assertTrue(policy(tmp, environment="STAGE").environment_ok)
            self.assertFalse(policy(tmp, environment="").environment_ok)


if __name__ == "__main__":
    unittest.main()
