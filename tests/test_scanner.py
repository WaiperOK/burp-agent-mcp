"""Scanner rule tests: which probes are built and what counts as a candidate. Run: python tests/test_scanner.py"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio  # noqa: E402

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
        # distinct path templates: one representative per template, so the paths must differ
        eps = [scanner.endpoint_from_raw(f"GET /api/{name}/{i} HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "history")
               for name, i in (('a', 1), ('b', 2), ('c', 3))]
        checks = ("ids", "malformed", "reflect")
        one = scanner.build_probes(eps, checks, 7)  # one endpoint = 5 probes; the second one does not fit whole
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


class OnFindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_callback_fires_for_each_candidate(self):
        ep = scanner.endpoint_from_raw(f"GET /api/patients/101 HTTP/1.1\r\nHost: {HOST}\r\nCookie: s=1\r\n\r\n", "history")
        probes = scanner.build_probes([ep], ("auth",), 10)

        async def send(probe):  # the auth probe succeeds: authorization is not enforced
            return "HTTP/1.1 200 OK\r\n\r\nbody"

        async def gate_wait(endpoint):
            return None

        seen, result = [], {}
        out = await scanner.run(probes, send, gate_wait, lambda e: None, min_delay_s=0, max_seconds=30,
                                should_stop=lambda: False, result=result, on_finding=seen.append)
        self.assertEqual(len(seen), len(out["findings"]))
        self.assertEqual([f["candidate"] for f in seen], ["auth_not_enforced_candidate"])


class ReproduceTests(unittest.IsolatedAsyncioTestCase):
    def _run(self, responses, max_requests=None):
        ep = scanner.endpoint_from_raw(f"GET /api/patients/101 HTTP/1.1\r\nHost: {HOST}\r\nCookie: s=1\r\n\r\n", "history")
        probes = scanner.build_probes([ep], ("auth",), 10)
        queue = list(responses)

        async def send(probe):  # pops scripted responses in order
            return queue.pop(0)

        async def gate_wait(endpoint):
            return None

        return scanner.run(probes, send, gate_wait, lambda e: None, min_delay_s=0, max_seconds=30,
                           should_stop=lambda: False, result={}, on_finding=lambda f: None,
                           max_requests=max_requests)

    async def test_candidate_that_reproduces_is_marked(self):
        ok = "HTTP/1.1 200 OK\r\n\r\nbody"
        out = await self._run([ok, ok, ok])  # baseline, auth probe, then the repeat of the candidate
        self.assertTrue(out["findings"][0]["reproduced"])

    async def test_flaky_candidate_is_kept_but_marked(self):
        ok = "HTTP/1.1 200 OK\r\n\r\nbody"
        denied = "HTTP/1.1 403 Forbidden\r\n\r\nno"
        out = await self._run([ok, ok, denied])  # the repeat is refused: the candidate is not confirmed
        self.assertEqual(len(out["findings"]), 1)
        self.assertFalse(out["findings"][0]["reproduced"])

    async def test_repeat_never_exceeds_the_scan_limit(self):
        ok = "HTTP/1.1 200 OK\r\n\r\nbody"
        # the limit is spent by the baseline and the auth probe, so the repeat must be skipped, not sent
        out = await self._run([ok, ok], max_requests=2)
        self.assertEqual(out["sent"], 2)
        self.assertIsNone(out["findings"][0]["reproduced"])
        self.assertIn("reserved", out["findings"][0]["reproduce_error"])


if __name__ == "__main__":
    unittest.main()
