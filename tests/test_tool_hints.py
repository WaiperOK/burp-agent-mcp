"""Tool hints match behaviour: a read-only tool sends nothing to a target, and a tool that sends traffic is refused
in read_only mode. The hints are what a host shows before a call, so they must be true.

Burp and the browser are replaced by stubs, so no traffic leaves this machine. Run: python tests/test_tool_hints.py
"""

import dataclasses
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TMP = tempfile.mkdtemp(prefix="burp-agent-hints-")
Path(TMP, "policy.json").write_text(json.dumps({
    "engagement_id": "HINTS-TEST", "mode": "active", "environment": "test",
    "authorized_hosts": ["ehealth.test.local", "127.0.0.1"],
    "scope_urls": ["https://ehealth.test.local/", "http://127.0.0.1:3000/"],
    "allowed_paths": ["/api/patients", "/api/visits"], "allowed_methods": ["GET", "HEAD", "OPTIONS", "POST"],
    "audit_log": f"{TMP}/audit.jsonl", "upstream_sse_url": "http://127.0.0.1:1/",
    "findings_file": f"{TMP}/findings.jsonl", "browser_proxy": None,
    "browser_profile_dir": f"{TMP}/profile", "payload_dir": f"{TMP}/payloads", "screenshots_dir": f"{TMP}/shots",
    "universal_output_dir": f"{TMP}/universal", "openapi_files": [],
    "max_requests_per_minute": 1000, "max_active_requests_total": 1000,
}), encoding="utf-8")
os.environ["BURP_AGENT_POLICY"] = f"{TMP}/policy.json"

import server  # noqa: E402
from browser_guard import BrowserError  # noqa: E402

# Browser methods that act on a page (navigate, type, click, submit). A read-only tool must never call one of these.
BROWSER_ACTIONS = {"open", "click", "fill", "press", "back", "reload", "crawl", "sign_in", "screenshot"}

# Every read-only tool with arguments that are valid enough to reach its code.
READ_ONLY_CALLS = {
    "scope_status": {}, "search_proxy_history": {}, "list_endpoints": {}, "get_history_item": {"history_id": 0},
    "search_bundles": {"pattern": "patients"}, "openapi_coverage": {"filename": "missing.json"},
    "diff_responses": {"history_a": 0, "history_b": 1}, "scanner_issues": {}, "read_passive_findings": {},
    "read_universal_report": {"name": "report_input.json"}, "browser_state": {}, "browser_text": {},
    "browser_links": {}, "browser_forms": {}, "browser_wait": {"selector": "#none", "timeout_ms": 10},
    "scan_plan": {}, "scan_status": {"job_id": "none"}, "plugin_list": {},
}

# Every tool that sends traffic to a target (openWorldHint=true), with arguments that would send it.
TARGET_CALLS = {
    "send_request": {"host": "ehealth.test.local", "port": 443, "use_https": True,
                     "raw_request": "GET /api/patients HTTP/1.1\r\nHost: ehealth.test.local\r\n\r\n", "reason": "x"},
    "replay_variant": {"history_id": 0, "reason": "x"},
    "intruder_run": {"history_id": 0, "position": "query:q", "reason": "x", "payloads": ["1"]},
    "request_url": {"url": "https://ehealth.test.local/api/patients", "reason": "x"},
    "scan_start": {"reason": "x"},
    "browser_open": {"url": "https://ehealth.test.local/", "reason": "x"},
    "browser_click": {"selector": "#go", "reason": "x"},
    "browser_press": {"key": "Enter", "reason": "x"},
    "browser_back": {"reason": "x"},
    "browser_reload": {"reason": "x"},
    "browser_crawl": {"start_url": "https://ehealth.test.local/", "reason": "x"},
    "login_local": {"url": "http://127.0.0.1:3000/login", "reason": "x"},
}


RECORD = {"request": "GET /api/patients/101 HTTP/1.1\r\nHost: ehealth.test.local\r\n\r\n",
          "response": "HTTP/1.1 200 OK\r\n\r\n{}"}

# Tools that change something on this machine (a Repeater tab, a form field, a job state, a build) and send nothing.
# plugin_write is not called here: it writes into the plugins folder of the machine it runs on.
LOCAL_CALLS = {
    "repeater_tab": {"history_id": 0, "reason": "x"},
    "browser_fill": {"selector": "#q", "value": "x", "reason": "x"},
    "scan_stop": {"job_id": "none"},
    "plugin_compile": {"name": "nope", "reason": "x"},
    "browser_screenshot": {},
}


class StubBrowser:
    """Every browser method is recorded and fails: nothing starts, nothing is sent."""

    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        async def method(*args, **kwargs):
            self.calls.append(name)
            raise BrowserError("browser is not used in these tests")
        return method


class HintTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.upstream_calls = []
        self._saved = server._upstream, server.BROWSER, server.POLICY
        self.browser = StubBrowser()

        async def upstream(tool, arguments):
            self.upstream_calls.append(tool)
            if tool in ("get_proxy_http_history", "get_proxy_http_history_regex") and arguments.get("offset", 0) == 0:
                return json.dumps([RECORD])  # one record, so replay_variant gets as far as the mode check
            return "[]"

        server._upstream = upstream
        server.BROWSER = self.browser

    def tearDown(self):
        server._upstream, server.BROWSER, server.POLICY = self._saved

    async def test_read_only_tools_send_no_traffic_and_no_browser_action(self):
        for name, args in READ_ONLY_CALLS.items():
            with self.subTest(tool=name):
                self.upstream_calls.clear()
                self.browser.calls.clear()
                await getattr(server, name)(**args)
                self.assertNotIn("send_http1_request", self.upstream_calls)
                self.assertFalse(set(self.browser.calls) & BROWSER_ACTIONS, self.browser.calls)

    async def test_local_tools_send_no_traffic(self):
        for name, args in LOCAL_CALLS.items():
            with self.subTest(tool=name):
                self.upstream_calls.clear()
                await getattr(server, name)(**args)
                self.assertNotIn("send_http1_request", self.upstream_calls)

    async def test_traffic_tools_are_refused_in_read_only_mode(self):
        server.POLICY = dataclasses.replace(self._saved[2], mode="read_only")
        for name, args in TARGET_CALLS.items():
            with self.subTest(tool=name):
                self.upstream_calls.clear()
                self.browser.calls.clear()
                out = await getattr(server, name)(**args)
                self.assertIn("read_only", out.get("error", ""), out)
                self.assertNotIn("send_http1_request", self.upstream_calls)
                self.assertEqual(self.browser.calls, [])

    async def test_the_tables_cover_exactly_the_hinted_tools(self):
        # a new tool must be added to the tables above, so its hints get checked against what it does
        tools = {t.name: t.annotations for t in await server.mcp.list_tools()}
        self.assertEqual(set(READ_ONLY_CALLS), {n for n, a in tools.items() if a.readOnlyHint})
        self.assertEqual(set(TARGET_CALLS), {n for n, a in tools.items() if a.openWorldHint})
        local = {n for n, a in tools.items() if not a.readOnlyHint and not a.openWorldHint}
        self.assertEqual(set(LOCAL_CALLS) | {"plugin_write"}, local)


if __name__ == "__main__":
    unittest.main()
