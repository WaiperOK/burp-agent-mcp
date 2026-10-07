"""Intruder tests: refusals before the first request, ceilings, stops, audit report without values.

Run: python tests/test_intruder.py
"""

import asyncio
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import intruder  # noqa: E402
from httpmsg import MsgError  # noqa: E402
from policy import PolicyError  # noqa: E402

HOST = "ehealth.test.local"
BASE = f"GET /api/patients/101 HTTP/1.1\r\nHost: {HOST}\r\n\r\n"


def resp(status: int, body: str = "x") -> str:
    return f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\r\n{body}"


class CheckTargetTests(unittest.TestCase):
    def test_auth_paths_refused(self):
        raw = f"POST /api/login HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\n\r\n" + '{"password": "x"}'
        with self.assertRaises(MsgError):
            intruder.check_target(raw, "json:password", ["a"])

    def test_auth_header_refused(self):
        with self.assertRaises(MsgError):
            intruder.check_target(BASE, "header:Authorization", ["a"])
        with self.assertRaises(MsgError):
            intruder.check_target(BASE, "header:Cookie", ["a"])

    def test_limits(self):
        with self.assertRaises(MsgError):
            intruder.check_target(BASE, "path:2", [])
        with self.assertRaises(MsgError):
            intruder.check_target(BASE, "path:2", ["1"] * (intruder.MAX_PAYLOADS + 1))
        with self.assertRaises(MsgError):
            intruder.check_target(BASE, "path:2", ["x" * (intruder.MAX_PAYLOAD_LEN + 1)])
        with self.assertRaises(MsgError):
            intruder.check_target(BASE, "path:2", ["1\n2"])

    def test_ok_target(self):
        intruder.check_target(BASE, "path:2", ["101", "102"])  # does not raise


class RunTests(unittest.IsolatedAsyncioTestCase):
    def _gate(self, state):
        def gate():
            if state.get("deny"):
                raise PolicyError("rate limit: max_requests_per_minute reached")
        return gate

    async def test_interesting_rows_and_baseline(self):
        # record 102 exists (200, long body), the others return 404.
        async def send(raw):
            if "/api/patients/102" in raw.split("\r\n")[0]:
                return resp(200, "y" * 500)
            if "/api/patients/101" in raw.split("\r\n")[0]:
                return resp(200, "y" * 500)
            return resp(404, "not found")

        audit = []
        out = await intruder.run(BASE, "path:2", ["102", "103", "104"], send, self._gate({}), audit.append,
                                 max_requests=10, min_delay_s=0)
        self.assertEqual(out["baseline"]["status"], "200")
        statuses = [r["status"] for r in out["rows"]]
        self.assertEqual(statuses, ["200", "404", "404"])
        self.assertEqual([r["i"] for r in out["interesting"]], [1, 2])  # 404 differs from the baseline 200

    async def test_stops_on_server_pushback(self):
        calls = []

        async def send(raw):
            calls.append(raw)
            return resp(429 if len(calls) == 2 else 200)

        out = await intruder.run(BASE, "path:2", ["1", "2", "3", "4"], send, self._gate({}), lambda e: None,
                                 max_requests=10, min_delay_s=0, baseline=False)
        self.assertIn("server pushback 429", out["stopped"])
        self.assertEqual(len(calls), 2)

    async def test_respects_request_limit(self):
        async def send(raw):
            return resp(200)

        out = await intruder.run(BASE, "path:2", ["1", "2", "3", "4", "5"], send, self._gate({}), lambda e: None,
                                 max_requests=2, min_delay_s=0, baseline=False)
        self.assertEqual(len(out["rows"]), 2)
        self.assertEqual(out["stopped"], "request limit reached")

    async def test_gate_denial_stops_whole_run(self):
        state = {"deny": False}
        sent = []

        async def send(raw):
            sent.append(raw)
            state["deny"] = True  # after the first request the gate starts refusing
            return resp(200)

        out = await intruder.run(BASE, "path:2", ["1", "2", "3"], send, self._gate(state), lambda e: None,
                                 max_requests=10, min_delay_s=0, baseline=False)
        self.assertEqual(len(sent), 1)
        self.assertIn("rate limit", out["stopped"])

    async def test_consecutive_errors_stop(self):
        async def send(raw):
            raise RuntimeError("upstream down")

        out = await intruder.run(BASE, "path:2", [str(i) for i in range(10)], send, self._gate({}),
                                 lambda e: None, max_requests=20, min_delay_s=0, baseline=False)
        self.assertEqual(out["stopped"], "too many consecutive errors")
        self.assertEqual(out["errors"], intruder.MAX_ERRORS)

    async def test_audit_has_hash_not_payload(self):
        async def send(raw):
            return resp(200)

        audit = []
        await intruder.run(BASE, "path:2", ["secret-payload-value"], send, self._gate({}), audit.append,
                           max_requests=5, min_delay_s=0, baseline=False)
        self.assertTrue(audit)
        for entry in audit:
            self.assertNotIn("secret-payload-value", repr(entry))
            if entry.get("kind") == "payload":
                self.assertEqual(len(entry["payload_sha256"]), 64)


class TruncatedTests(unittest.IsolatedAsyncioTestCase):
    async def test_truncated_response_not_compared_by_length(self):
        async def send(raw):
            if raw.split("\r\n")[0].endswith("/103 HTTP/1.1"):
                return resp(200, "z" * 50) + " (truncated)"  # Burp cut the output
            return resp(200, "y" * 500)

        out = await intruder.run(BASE, "path:2", ["101", "103"], send, lambda: None, lambda e: None,
                                 max_requests=5, min_delay_s=0)
        row = out["rows"][1]
        self.assertTrue(row["truncated"])
        self.assertIsNone(row["length"])
        self.assertEqual(out["interesting"], [])  # same status, the length is not compared


if __name__ == "__main__":
    unittest.main()
