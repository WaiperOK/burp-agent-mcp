"""Tests for the gateway tools against a fake upstream (no Burp history needed).

The upstream imitates the target: only /api/patients/101 and /api/patients/102 exist (200), everything else is 404.
Run: python tests/test_tools.py
"""

import asyncio
import dataclasses
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TMP = tempfile.mkdtemp(prefix="burp-agent-test-")
SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/api/patients/{id}": {"get": {}, "put": {}},
        "/api/visits": {"post": {}, "get": {}},
        "/api/admin": {"get": {}},
    },
}
Path(TMP, "spec.json").write_text(json.dumps(SPEC), encoding="utf-8")
Path(TMP, "payloads").mkdir(exist_ok=True)
Path(TMP, "payloads", "ids.txt").write_text("102\n999\n\n103\n", encoding="utf-8")
Path(TMP, "policy.json").write_text(json.dumps({
    "engagement_id": "TEST-TOOLS",
    "mode": "active",
    "environment": "test",
    "scope_urls": ["https://ehealth.test.local/"],
    "scan_min_delay_ms": 1,
    "authorized_hosts": ["ehealth.test.local"],
    "allowed_methods": ["GET", "HEAD", "OPTIONS", "POST"],
    "max_requests_per_minute": 1000,
    "max_active_requests_total": 1000,
    "audit_log": f"{TMP}/audit.jsonl",
    "upstream_sse_url": "http://127.0.0.1:1/",
    "allowed_paths": ["/api/patients", "/api/visits"],
    "openapi_files": [f"{TMP}/spec.json"],
    "findings_file": f"{TMP}/findings.jsonl",
    "browser_proxy": None,
    "browser_profile_dir": f"{TMP}/profile",
    "payload_dir": f"{TMP}/payloads",
    "intruder_min_delay_ms": 1,
    "screenshots_dir": f"{TMP}/shots",
}), encoding="utf-8")
os.environ["BURP_AGENT_POLICY"] = f"{TMP}/policy.json"

import httpmsg  # noqa: E402
import server  # noqa: E402
from history_index import HistoryIndex  # noqa: E402
from policy import Gate, PolicyError  # noqa: E402

HOST = "ehealth.test.local"


def req(host, method, path, extra="", body=""):
    head = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n{extra}"
    if body:
        head += f"Content-Length: {len(body)}\r\n"
    return head + "\r\n" + body


def resp(status, ctype, body=""):
    return f"HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\n\r\n{body}"


FAKE_HISTORY = [
    {"request": req(HOST, "GET", "/api/patients/101", "Cookie: sid=secret123\r\n"),
     "response": resp(200, "application/json", '{"id": 101, "name": "Test A", "email": "a@example.test"}')},
    {"request": req(HOST, "GET", "/api/patients/102", "Cookie: sid=secret123\r\n"),
     "response": resp(200, "application/json", '{"id": 102, "name": "Test B"}')},
    {"request": req(HOST, "GET", "/static/app.js"),
     "response": resp(200, "application/javascript", 'fetch("/api/visits?patient=" + id);')},
    {"request": req("evil.example", "GET", "/api/x"),
     "response": resp(200, "application/json", "{}")},
    {"request": req(HOST, "POST", "/api/visits", "Content-Type: application/json\r\n", '{"patient": {"id": 101}}'),
     "response": resp(201, "application/json", '{"ok": true}')},
]
SCANNER = "\n".join([
    json.dumps({"name": "Unencrypted communications", "detail": "no TLS",
                "httpService": {"host": HOST, "port": 443}}),
    json.dumps({"name": "Other host", "detail": "x", "httpService": {"host": "evil.example", "port": 443}}),
])
SENT, REPEATER = [], []


async def fake_upstream(tool, arguments):
    if tool == "get_proxy_http_history":
        off, cnt = arguments["offset"], arguments["count"]
        items = FAKE_HISTORY[off:off + cnt]
        return json.dumps(items) if items else "Reached end of items"
    if tool == "get_proxy_http_history_regex":  # as in Burp: filters by record text, offset counts matches
        rx = re.compile(arguments["regex"])
        matched = [it for it in FAKE_HISTORY if rx.search(it["request"] + "\n" + it["response"])]
        off, cnt = arguments["offset"], arguments["count"]
        items = matched[off:off + cnt]
        return json.dumps(items) if items else "Reached end of items"
    if tool == "send_http1_request":
        SENT.append(arguments)
        first = arguments["content"].split("\r\n")[0]
        if "%27" in first:  # a quote in the path: an unhandled server error
            return resp(500, "text/plain", "internal error")
        echo = re.search(r"zq=([A-Za-z0-9]+)", first)
        if echo:  # a parameter reflected in the response
            return resp(200, "text/html", f"<p>value {echo.group(1)}</p>")
        if first.split(" ")[1].split("?")[0] in ("/api/patients/101", "/api/patients/102"):
            return resp(200, "application/json", '{"ok": true, "pad": "' + "y" * 400 + '"}')
        return resp(404, "application/json", '{"error": "not found"}')
    if tool == "create_repeater_tab":
        REPEATER.append(arguments)
        return "tab created"
    if tool == "get_scanner_issues":
        return SCANNER
    raise AssertionError(f"unexpected upstream tool: {tool}")


server._upstream = fake_upstream


class PathTests(unittest.TestCase):
    def test_normalize_path(self):
        self.assertEqual(httpmsg.normalize_path("/api/patients/101?x=1"), "/api/patients/{id}")
        self.assertEqual(httpmsg.normalize_path("/a/3f2504e0-4f89-11d3-9a0c-0305e82c3301/b"), "/a/{id}/b")
        self.assertEqual(httpmsg.normalize_path("/"), "/")

    def test_path_allowed_prefix_only(self):
        self.assertTrue(server.POLICY.path_allowed("/api/patients/102"))
        self.assertFalse(server.POLICY.path_allowed("/admin"))
        self.assertFalse(server.POLICY.path_allowed("/api/patients/1 HTTP/1.1\r\nX: y"))


class ReadToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_list_endpoints_cache_and_fresh(self):
        fresh = await server.list_endpoints(fresh=True)
        self.assertFalse(fresh["cached"])
        again = await server.list_endpoints()
        self.assertTrue(again["cached"])
        self.assertEqual(again["endpoints"], fresh["endpoints"])

    async def test_list_endpoints_groups_and_excludes_out_of_scope(self):
        out = await server.list_endpoints()
        eps = {(e["method"], e["path"]): e for e in out["endpoints"]}
        self.assertEqual(eps[("GET", "/api/patients/{id}")]["count"], 2)
        self.assertEqual(eps[("GET", "/api/patients/{id}")]["statuses"], ["200"])
        self.assertEqual(out["total_endpoints"], 3)

    async def test_search_bundles_reads_exported_bodies(self):
        bodies = Path(TMP, "bodies")
        bodies.mkdir(exist_ok=True)
        (bodies / "a.txt").write_text('x; fetch("/api/visits?patient=" + id); y', encoding="utf-8")
        (bodies / "b.txt").write_text('fetch("/api/visits")', encoding="utf-8")
        (bodies / "index.jsonl").write_text(
            json.dumps({"host": HOST, "path": "/static/app.js", "sha256": "aa", "file": "a.txt",
                        "content_type": "application/javascript"}) + "\n"
            + json.dumps({"host": "evil.example", "path": "/x.js", "sha256": "bb", "file": "b.txt"}) + "\n"
            + json.dumps({"host": HOST, "path": "/gone.js", "sha256": "cc", "file": "missing.txt"}) + "\n",
            encoding="utf-8")
        out = await server.search_bundles(r'fetch\("/api/visits')
        self.assertEqual(len(out["matches"]), 1)
        self.assertEqual(out["matches"][0]["path"], "/static/app.js")
        self.assertEqual(out["matches"][0]["sha256"], "aa")

    async def test_search_bundles_without_export_explains(self):
        original = server.POLICY
        server.POLICY = dataclasses.replace(original, findings_file=f"{TMP}/nowhere/findings.jsonl")
        try:
            out = await server.search_bundles("x")
            self.assertIn("no exported bodies", out["note"])
        finally:
            server.POLICY = original

    async def test_get_history_item_redacts_cookie(self):
        out = await server.get_history_item(1)
        self.assertIn("Cookie: [REDACTED]", out["request"])
        self.assertNotIn("secret123", out["request"])

    async def test_get_history_item_out_of_scope_denied(self):
        self.assertIn("error", await server.get_history_item(3))

    async def test_history_item_cache_returns_same_record(self):
        first = await server.get_history_item(0)
        second = await server.get_history_item(0)
        self.assertEqual(first["request"], second["request"])
        self.assertIn(0, server._ITEM_CACHE)

    async def test_diff_responses_key_paths(self):
        out = await server.diff_responses(0, 1)
        self.assertTrue(out["diff"]["same_status"])
        self.assertEqual(out["diff"]["only_in_a"], ["email"])
        self.assertEqual(out["diff"]["only_in_b"], [])
        self.assertNotIn("body", out["a"])

    async def test_openapi_coverage(self):
        out = await server.openapi_coverage("spec.json")
        self.assertEqual(out["operations_total"], 5)
        self.assertEqual(out["covered"], 2)

    async def test_openapi_coverage_unknown_file_denied(self):
        self.assertIn("error", await server.openapi_coverage("/etc/passwd"))

    async def test_scanner_issues_scope_filter(self):
        out = await server.scanner_issues(limit=5)
        self.assertEqual([i["name"] for i in out["issues"]], ["Unencrypted communications"])

    async def test_policy_hash_is_audited(self):
        lines = Path(TMP, "audit.jsonl").read_text(encoding="utf-8").splitlines()
        loaded = [json.loads(l) for l in lines if '"policy_loaded"' in l]
        self.assertTrue(loaded)
        self.assertEqual(loaded[0]["summary"]["sha256"], server.POLICY.policy_sha256)


class ReplayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        SENT.clear()

    async def test_replay_changes_path_header_and_drops_cookie(self):
        out = await server.replay_variant(0, "IDOR: another user record 102", path="/api/patients/102",
                                          set_headers={"X-Test": "1"}, remove_headers=["Cookie"])
        self.assertEqual(out["status"], "200")
        content = SENT[-1]["content"]
        self.assertTrue(content.startswith("GET /api/patients/102 HTTP/1.1\r\n"))
        self.assertIn(f"Host: {HOST}", content)
        self.assertIn("X-Test: 1", content)
        self.assertNotIn("Cookie:", content)
        self.assertNotIn("Content-Length", content)
        self.assertEqual(SENT[-1]["targetHostname"], HOST)

    async def test_replay_path_outside_allowed_denied(self):
        out = await server.replay_variant(0, "x", path="/admin")
        self.assertIn("allowed_paths", out["error"])
        self.assertEqual(SENT, [])

    async def test_replay_cannot_change_host(self):
        out = await server.replay_variant(0, "x", set_headers={"Host": "evil.example"})
        self.assertIn("cannot be set manually", out["error"])
        self.assertEqual(SENT, [])

    async def test_replay_body_recomputes_content_length(self):
        body = '{"patient": {"id": 102}}'
        out = await server.replay_variant(4, "check the visit owner", body=body)
        self.assertNotIn("error", out)
        self.assertIn(f"Content-Length: {len(body)}", SENT[-1]["content"])

    async def test_replay_requires_reason(self):
        self.assertIn("reason is required", (await server.replay_variant(0, "   "))["error"])
        self.assertEqual(SENT, [])

    async def test_replay_denied_in_read_only(self):
        original = server.GATE
        server.GATE = Gate(dataclasses.replace(server.POLICY, mode="read_only"))
        try:
            out = await server.replay_variant(0, "x", path="/api/patients/102")
            self.assertIn("read_only", out["error"])
            self.assertEqual(SENT, [])
        finally:
            server.GATE = original


class IntruderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        SENT.clear()

    async def test_intruder_finds_existing_ids(self):
        out = await server.intruder_run(0, "path:2", "IDOR: enumerate patient ids",
                                        payloads=["102", "999", "103"], baseline=True)
        self.assertNotIn("error", out)
        self.assertEqual([r["status"] for r in out["rows"]], ["200", "404", "404"])
        self.assertEqual([r["i"] for r in out["interesting"]], [1, 2])
        self.assertEqual(out["baseline"]["status"], "200")
        self.assertNotIn("pad", json.dumps(out))  # no body in the response

    async def test_intruder_payload_file_from_payload_dir(self):
        out = await server.intruder_run(0, "path:2", "IDOR", payload_file="ids.txt")
        self.assertEqual(len(out["rows"]), 3)

    async def test_intruder_refuses_auth_header(self):
        out = await server.intruder_run(0, "header:Cookie", "x", payloads=["1"])
        self.assertIn("auth", out["error"])
        self.assertEqual(SENT, [])

    async def test_intruder_refuses_out_of_scope_record(self):
        out = await server.intruder_run(3, "path:1", "x", payloads=["1"])
        self.assertIn("error", out)
        self.assertEqual(SENT, [])

    async def test_intruder_needs_exactly_one_payload_source(self):
        out = await server.intruder_run(0, "path:2", "x")
        self.assertIn("exactly one", out["error"])

    async def test_intruder_refuses_path_outside_allowed(self):
        out = await server.intruder_run(0, "path:0", "x", payloads=["ok"])  # /api -> /ok
        self.assertIn("allowed_paths", out["error"])
        self.assertEqual(SENT, [])


class RepeaterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        SENT.clear()
        REPEATER.clear()

    async def test_repeater_tab_no_traffic(self):
        out = await server.repeater_tab(0, "IDOR", tab_name="idor-102", path="/api/patients/102",
                                        set_headers={"X-Test": "1"})
        self.assertNotIn("error", out)
        self.assertEqual(SENT, [])  # no traffic to the target
        self.assertEqual(len(REPEATER), 1)
        self.assertEqual(REPEATER[0]["tabName"], "idor-102")
        self.assertTrue(REPEATER[0]["content"].startswith("GET /api/patients/102 HTTP/1.1"))

    async def test_repeater_tab_path_checked(self):
        out = await server.repeater_tab(0, "x", path="/admin")
        self.assertIn("allowed_paths", out["error"])
        self.assertEqual(REPEATER, [])


class BrowserModeTests(unittest.IsolatedAsyncioTestCase):
    async def test_browser_actions_denied_in_read_only(self):
        original = server.POLICY
        server.POLICY = dataclasses.replace(original, mode="read_only")
        try:
            out = await server.browser_open("http://127.0.0.1/", "x")
            self.assertIn("read_only", out["error"])
            out = await server.browser_fill("#q", "x", "x")
            self.assertIn("read_only", out["error"])
        finally:
            server.POLICY = original


class PolicyIntegrityTests(unittest.IsolatedAsyncioTestCase):
    async def test_active_actions_fail_closed_after_policy_edit(self):
        path = Path(TMP, "policy.json")
        original = path.read_bytes()
        SENT.clear()
        try:
            path.write_bytes(original + b"\n")  # the file is edited after the gateway started
            out = await server.replay_variant(0, "x", path="/api/patients/102")
            self.assertIn("changed since the gateway started", out["error"])
            out = await server.intruder_run(0, "path:2", "x", payloads=["102"])
            self.assertIn("changed since the gateway started", out["error"])
            self.assertEqual(SENT, [])
            status = await server.scope_status()  # reads still work, and they show the state
            self.assertEqual(status["mode"], "active")
        finally:
            path.write_bytes(original)
        out = await server.replay_variant(0, "x", path="/api/patients/102")
        self.assertNotIn("error", out)  # everything works again after the file is restored


class FindingsTests(unittest.IsolatedAsyncioTestCase):
    async def test_findings_scope_and_redaction(self):
        Path(TMP, "findings.jsonl").write_text(
            json.dumps({"ts": "t", "host": HOST, "path": "/x", "check": "jwt_in_response_body",
                        "evidence": "token eyJabcdefgh.abcdefgh.abcdefgh leaked"}) + "\n"
            + json.dumps({"ts": "t", "host": "evil.example", "path": "/", "check": "c", "evidence": "e"}) + "\n",
            encoding="utf-8")
        out = await server.read_passive_findings()
        self.assertEqual(len(out["findings"]), 1)
        self.assertIn("[JWT]", out["findings"][0]["evidence"])
        self.assertNotIn("eyJabcdefgh", out["findings"][0]["evidence"])


class ParseHistoryTests(unittest.TestCase):
    def test_json_list(self):
        self.assertEqual(len(httpmsg.parse_history(json.dumps([{"request": "GET / HTTP/1.1"}]))), 1)

    def test_partial_fields(self):
        raw = ('{"request":"GET /a HTTP/1.1\\r\\nHost: h\\r\\n\\r\\n","response":"HTTP/1.1 200 OK\\r\\n\\r\\nabc'
               '.. (truncated)')
        items = httpmsg.parse_history(raw)
        self.assertTrue(items[0]["response_truncated"])
        self.assertFalse(items[0]["request_truncated"])


class DryRunTests(unittest.IsolatedAsyncioTestCase):
    async def test_dry_run_shows_request_without_sending_or_spending_budget(self):
        SENT.clear()
        before = server.GATE.usage()["active_total_used"]
        out = await server.request_url("https://ehealth.test.local/api/patients/102?x=1", "preview",
                                       headers={"Cookie": "sid=secret123"}, dry_run=True)
        self.assertTrue(out["dry_run"])
        self.assertTrue(out["would_send"].startswith("GET /api/patients/102?x=1 HTTP/1.1"))
        self.assertNotIn("secret123", out["would_send"])  # the cookie value is redacted
        self.assertEqual(SENT, [])
        self.assertEqual(server.GATE.usage()["active_total_used"], before)

    async def test_dry_run_still_enforces_scope(self):
        out = await server.request_url("https://evil.example/", "preview", dry_run=True)
        self.assertIn("error", out)


class UrlScopeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        SENT.clear()

    async def test_request_url_in_scope_sends_and_builds_from_url(self):
        out = await server.request_url("https://ehealth.test.local/api/patients/102?x=1", "check by URL",
                                       headers={"X-Test": "1"})
        self.assertNotIn("error", out)
        self.assertEqual(out["status"], "200")
        self.assertTrue(SENT[-1]["content"].startswith("GET /api/patients/102?x=1 HTTP/1.1\r\nHost: ehealth.test.local"))
        self.assertEqual(SENT[-1]["targetHostname"], "ehealth.test.local")
        self.assertEqual(SENT[-1]["targetPort"], 443)

    async def test_request_url_out_of_scope_denied(self):
        out = await server.request_url("https://evil.example/api/x", "x")
        self.assertIn("not in", out["error"])  # the host outside authorized_hosts is checked before the URL
        self.assertEqual(SENT, [])

    async def test_request_url_traversal_denied(self):
        out = await server.request_url("https://ehealth.test.local/api/../admin", "x")
        self.assertIn("error", out)
        self.assertEqual(SENT, [])

    async def test_request_url_needs_reason(self):
        self.assertIn("reason is required", (await server.request_url("https://ehealth.test.local/", " "))["error"])

    async def test_scope_urls_narrow_replay(self):
        original = server.POLICY
        server.POLICY = dataclasses.replace(original, scope_urls=("https://ehealth.test.local/api/patients/",))
        try:
            out = await server.replay_variant(4, "x")  # POST /api/visits is outside the scope_urls prefix
            self.assertIn("not in scope", out["error"])
            self.assertEqual(SENT, [])
        finally:
            server.POLICY = original

    async def test_non_test_environment_denies_active_actions(self):
        original = server.POLICY
        server.POLICY = dataclasses.replace(original, environment="prod")
        try:
            out = await server.request_url("https://ehealth.test.local/api/patients/102", "x")
            self.assertIn("environment", out["error"])
            self.assertEqual(SENT, [])
            status = await server.scope_status()  # reads stay available
            self.assertEqual(status["mode"], "active")
        finally:
            server.POLICY = original


class BudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_status_and_plan_report_budget(self):
        status = await server.scope_status()
        self.assertIn("active_total_remaining", status["budget"])
        plan = await server.scan_plan(source="history")
        self.assertIn("budget_remaining", plan)

    async def test_scan_is_trimmed_to_remaining_budget(self):
        original = server.GATE
        server.GATE = Gate(dataclasses.replace(server.POLICY, max_active_requests_total=4))
        SENT.clear()
        try:
            out = await server.scan_start("budget trim", source="history", max_requests=150)
            self.assertNotIn("error", out, out)
            self.assertLessEqual(out["plan"]["probes"], 4)
            for _ in range(100):
                status = await server.scan_status(out["job_id"])
                if status["state"] != "running":
                    break
                await asyncio.sleep(0.05)
            self.assertLessEqual(len(SENT), 4)
        finally:
            server.GATE = original

    async def test_exhausted_budget_refuses_scan(self):
        original = server.GATE
        server.GATE = Gate(dataclasses.replace(server.POLICY, max_active_requests_total=0))
        try:
            out = await server.scan_start("no budget", source="history")
            self.assertIn("exhausted", out["error"])
        finally:
            server.GATE = original


class ScanTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        SENT.clear()

    async def _wait(self, job_id: str, timeout: float = 30.0) -> dict:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            status = await server.scan_status(job_id)
            if status["state"] != "running":
                return status
            if asyncio.get_running_loop().time() > deadline:
                self.fail("scan did not finish in time")
            await asyncio.sleep(0.1)

    async def test_scan_plan_sends_nothing(self):
        out = await server.scan_plan(source="history")
        self.assertNotIn("error", out)
        self.assertGreater(out["plan"]["probes"], 0)
        self.assertEqual(SENT, [])

    async def test_scan_finds_known_candidates_and_only_safe_methods(self):
        out = await server.scan_start("scanner test on a known stand", source="history")
        self.assertNotIn("error", out, out)
        status = await self._wait(out["job_id"])
        self.assertEqual(status["state"], "done", status)
        kinds = {(f["candidate"], f["url"].split("?")[0]) for f in status["findings"]}
        self.assertIn(("auth_not_enforced_candidate", "https://ehealth.test.local/api/patients/101"), kinds)
        self.assertIn(("server_error_on_malformed_input", "https://ehealth.test.local/api/patients/%27"), kinds)
        self.assertIn(("neighbor_object_exists", "https://ehealth.test.local/api/patients/102"), kinds)  # neighbouring id
        self.assertTrue(any(k == "reflected_input_candidate" for k, _ in kinds))
        # only safe methods: not a single POST to the stand
        self.assertTrue(all(sent["content"].split(" ")[0] in ("GET", "HEAD", "OPTIONS") for sent in SENT))
        self.assertLessEqual(status["sent"], server.POLICY.scan_max_requests)
        findings_file = Path(TMP, "scan_findings.jsonl")
        self.assertTrue(findings_file.is_file())
        self.assertEqual(oct(findings_file.stat().st_mode & 0o777), "0o600")  # findings: owner only

    async def test_scan_respects_max_requests(self):
        out = await server.scan_start("limit", source="history", max_requests=3)
        status = await self._wait(out["job_id"])
        self.assertLessEqual(status["sent"], 3)

    async def test_scan_stop_halts_job(self):
        out = await server.scan_start("stop", source="history")
        await server.scan_stop(out["job_id"])
        status = await self._wait(out["job_id"])
        self.assertIn(status["state"], ("stopped", "done"))

    async def test_scan_needs_reason_and_rejects_bad_checks(self):
        self.assertIn("reason is required", (await server.scan_start(" "))["error"])
        out = await server.scan_plan(source="history", checks="auth,dos")
        self.assertIn("unknown checks", out["error"])

    async def test_scan_denied_outside_test_environment(self):
        original = server.POLICY
        server.POLICY = dataclasses.replace(original, environment="prod")
        try:
            out = await server.scan_start("x", source="history")
            self.assertIn("environment", out["error"])
            self.assertEqual(SENT, [])
        finally:
            server.POLICY = original


class HistorySearchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._saved_index = server.HISTORY
        self._saved_upstream = server._upstream
        server.HISTORY = HistoryIndex(max_records=500, page=server.HISTORY_PAGE, on_reset=server._ITEM_CACHE.clear)
        server._ITEM_CACHE.clear()
        server._TTL_CACHE.clear()  # aggregates cached by earlier tests must not answer these ones
        self.history_offsets = []  # offsets of every get_proxy_http_history call
        self.tools_called = []  # every upstream tool name, in order

        async def counting(tool, arguments):
            self.tools_called.append(tool)
            if tool == "get_proxy_http_history":
                self.history_offsets.append(arguments["offset"])
            return await fake_upstream(tool, arguments)

        server._upstream = counting

    def tearDown(self):
        server._upstream = self._saved_upstream
        server.HISTORY = self._saved_index
        server._ITEM_CACHE.clear()
        server._TTL_CACHE.clear()

    async def test_search_finds_in_scope_records_and_redacts_them(self):
        out = await server.search_proxy_history(host=HOST, path_contains="/api/patients")
        self.assertNotIn("error", out)
        self.assertEqual([i["history_id"] for i in out["items"]], [0, 1])
        self.assertTrue(out["complete"])
        dumped = json.dumps(out)
        self.assertNotIn("evil.example", dumped)  # out of scope, never returned
        self.assertNotIn("secret123", dumped)  # the cookie is redacted
        self.assertNotIn("a@example.test", dumped)  # the e-mail in the response is redacted

    async def test_search_within_max_age_is_served_from_the_index(self):
        await server.search_proxy_history(host=HOST)  # indexes everything and caches the matched records
        self.history_offsets.clear()
        out = await server.search_proxy_history(host=HOST, path_contains="/api/visits")
        self.assertEqual([i["history_id"] for i in out["items"]], [4])
        self.assertEqual(self.history_offsets, [])  # no call to Burp at all

    async def test_fresh_search_reads_only_the_tail(self):
        await server.search_proxy_history(host=HOST)
        self.history_offsets.clear()
        out = await server.search_proxy_history(host=HOST, path_contains="/api/visits", fresh=True)
        self.assertEqual([i["history_id"] for i in out["items"]], [4])
        # the tail record as a check, then an empty page; the matched record is already cached
        self.assertEqual(self.history_offsets, [4, 5])

    async def test_endpoint_summary_and_coverage_come_from_the_index(self):
        out = await server.list_endpoints(fresh=True)
        self.assertEqual(out["total_endpoints"], 3)
        self.assertTrue(out["complete"])
        cov = await server.openapi_coverage("spec.json", fresh=True)
        self.assertNotIn("error", cov)
        self.assertEqual(cov["covered"], 2)  # GET /api/patients/{id} and POST /api/visits are in the history
        self.assertNotIn("get_proxy_http_history_regex", self.tools_called)  # no regex rescans any more

    async def test_incomplete_index_gives_partial_result_that_is_not_cached(self):
        original = server.HISTORY.refresh

        async def stop_at_once(fetch, time_budget_s=20.0, max_age_s=0.0):  # simulates a build cut by the budget
            return await original(fetch, time_budget_s=0, max_age_s=max_age_s)

        server.HISTORY.refresh = stop_at_once
        try:
            partial = await server.list_endpoints(fresh=True)
        finally:
            del server.HISTORY.refresh
        self.assertFalse(partial["complete"])
        full = await server.list_endpoints()  # the next call continues the build and is complete
        self.assertTrue(full["complete"])
        self.assertFalse(full["cached"])  # the partial result was not cached, so this is a real recomputation
        self.assertEqual(full["total_endpoints"], 3)

    async def test_out_of_scope_host_is_refused(self):
        out = await server.search_proxy_history(host="evil.example")
        self.assertIn("not in authorized scope", out["error"])

    async def test_cleared_and_refilled_history_is_not_served_from_cache(self):
        await server.search_proxy_history(host=HOST)  # caches records 0, 1, 2 and 4
        original = list(FAKE_HISTORY)
        FAKE_HISTORY[:] = [  # Burp cleared the history and captured new traffic: ids are reused
            {"request": req(HOST, "GET", "/api/patients/101"), "response": original[0]["response"]},
            {"request": req(HOST, "GET", "/api/patients/999"), "response": original[1]["response"]},
            {"request": req(HOST, "GET", "/static/app.js"), "response": original[2]["response"]},
            {"request": req(HOST, "POST", "/api/visits"), "response": original[4]["response"]},
        ]
        try:  # fresh=true: within max age the index would still show the old history, by design
            out = await server.search_proxy_history(host=HOST, path_contains="/api/patients", fresh=True)
        finally:
            FAKE_HISTORY[:] = original
        self.assertNotIn("error", out)
        self.assertEqual([i["path"] for i in out["items"]], ["/api/patients/101", "/api/patients/999"])

    async def test_stale_cache_entry_is_detected(self):
        await server.search_proxy_history(host=HOST)  # the index holds record 1, the cache holds it too
        server._ITEM_CACHE[1] = {"request": req(HOST, "GET", "/api/other"), "response": ""}  # a wrong record
        out = await server.search_proxy_history(host=HOST, path_contains="/api/patients")
        self.assertIn("changed during the search", out["error"])
        self.assertNotIn(1, server._ITEM_CACHE)  # the bad entry is dropped, so the next call loads it fresh
        self.assertEqual(server.HISTORY.entries, [])  # and the index starts over


if __name__ == "__main__":
    unittest.main()
