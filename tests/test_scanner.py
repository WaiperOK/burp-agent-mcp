"""Тесты правил сканера: какие пробы строятся и что считается кандидатом. Запуск: python tests/test_scanner.py"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scanner  # noqa: E402
from httpmsg import MsgError  # noqa: E402

HOST = "ehealth.test.local"
GET_WITH_COOKIE = f"GET /api/patients/101 HTTP/1.1\r\nHost: {HOST}\r\nCookie: sid=s\r\n\r\n"
POST = f"POST /api/visits HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 2\r\n\r\n{{}}"


class PlanTests(unittest.TestCase):
    def test_only_safe_methods_are_scanned(self):
        with self.assertRaises(MsgError):
            scanner.endpoint_from_raw(POST, "history")

    def test_auth_probe_only_for_authenticated_endpoints(self):
        ep = scanner.endpoint_from_raw(GET_WITH_COOKIE, "history")
        anon = scanner.endpoint_from_raw(f"GET /api/public HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")
        probes = scanner.build_probes([ep, anon], ("auth",), 50)
        auth = [p for p in probes if p.check == "auth"]
        self.assertEqual(len(auth), 1)
        self.assertNotIn("Cookie", auth[0].raw)

    def test_budget_cuts_probes_but_keeps_baselines_first(self):
        ep = scanner.endpoint_from_raw(GET_WITH_COOKIE, "history")
        probes = scanner.build_probes([ep], ("auth", "ids", "malformed", "reflect"), 2)
        self.assertEqual([p.check for p in probes], ["baseline", "auth"])

    def test_budget_covers_whole_endpoints_not_only_baselines(self):
        # разные шаблоны пути: один представитель на шаблон, поэтому пути должны различаться
        eps = [scanner.endpoint_from_raw(f"GET /api/{name}/{i} HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")
               for name, i in (('a', 1), ('b', 2), ('c', 3))]
        checks = ("ids", "malformed", "reflect")
        one = scanner.build_probes(eps, checks, 7)  # один эндпоинт = 5 проб; второй целиком не влезает
        self.assertEqual(len({p.endpoint.key for p in one}), 1)
        self.assertEqual({p.check for p in one}, {"baseline", "ids", "malformed", "reflect"})
        two = scanner.build_probes(eps, checks, 10)
        self.assertEqual(len({p.endpoint.key for p in two}), 2)
        for key in {p.endpoint.key for p in two}:
            self.assertIn("malformed", [p.check for p in two if p.endpoint.key == key])

    def test_ids_probe_uses_neighbors_and_skips_negative(self):
        zero = scanner.endpoint_from_raw(f"GET /api/patients/0 HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")
        probes = scanner.build_probes([zero], ("ids",), 50)
        self.assertEqual([p.note for p in probes if p.check == "ids"], ["id 0->1"])

    def test_reflect_marker_is_unique_per_probe(self):
        ep = scanner.endpoint_from_raw(GET_WITH_COOKIE, "history")
        a = [p.marker for p in scanner.build_probes([ep], ("reflect",), 9) if p.check == "reflect"]
        b = [p.marker for p in scanner.build_probes([ep], ("reflect",), 9) if p.check == "reflect"]
        self.assertNotEqual(a, b)

    def test_unknown_check_rejected(self):
        ep = scanner.endpoint_from_raw(GET_WITH_COOKIE, "history")
        with self.assertRaises(MsgError):
            scanner.build_probes([ep], ("dos",), 5)


class JudgeTests(unittest.TestCase):
    def setUp(self):
        self.ep = scanner.endpoint_from_raw(GET_WITH_COOKIE, "history")
        self.base = {"status": "200", "length": 40}

    def _probe(self, check, raw=None, marker=""):
        return scanner.Probe(check, self.ep, raw or GET_WITH_COOKIE, marker=marker)

    def test_auth_not_enforced(self):
        f = scanner.judge(self._probe("auth"), "200", 30, "body", self.base)
        self.assertEqual(f["candidate"], "auth_not_enforced_candidate")

    def test_auth_enforced_gives_nothing(self):
        self.assertIsNone(scanner.judge(self._probe("auth"), "401", 0, "", self.base))

    def test_server_error_on_malformed(self):
        f = scanner.judge(self._probe("malformed"), "500", 9, "x", self.base)
        self.assertEqual(f["candidate"], "server_error_on_malformed_input")

    def test_reflection_needs_marker_in_body(self):
        probe = self._probe("reflect", marker="zqabc")
        self.assertEqual(scanner.judge(probe, "200", 20, "value zqabc", self.base)["candidate"],
                         "reflected_input_candidate")
        self.assertIsNone(scanner.judge(probe, "200", 20, "nothing here", self.base))

    def test_baseline_anonymous_only_for_endpoints_without_auth(self):
        anon_ep = scanner.endpoint_from_raw(f"GET /api/public HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")
        f = scanner.judge(scanner.Probe("baseline", anon_ep, anon_ep.raw), "200", 50, "x", None)
        self.assertEqual(f["candidate"], "anonymous_200_candidate")
        self.assertIsNone(scanner.judge(self._probe("baseline"), "200", 50, "x", None))


if __name__ == "__main__":
    unittest.main()
