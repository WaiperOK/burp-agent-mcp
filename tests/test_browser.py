"""Tests for the browser guard on a real Chromium (Playwright). No network access is needed.

Local site: 127.0.0.1 (in scope). localhost and other.test are outside the scope: their resources and WebSocket
must be cut. Run: python tests/test_browser.py
(needs: pip install playwright websockets && playwright install chromium)
"""

import asyncio
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from browser_guard import BrowserError, GuardedBrowser  # noqa: E402
from policy import Policy, PolicyError  # noqa: E402

TMP = tempfile.mkdtemp(prefix="burp-browser-test-")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


WS_PORT = free_port()


class Site(BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_address[1]
        if self.path == "/":
            body = f"""<!doctype html><html><head><meta charset="utf-8"><title>Test stand</title>
<script src="http://localhost:{port}/x.js"></script></head>
<body><p>Test patient</p>
<a href="/next">next</a>
<a href="http://localhost:{port}/other">localhost link</a>
<a href="http://other.test/">external</a></body></html>""".encode()
            ctype = "text/html; charset=utf-8"
        elif self.path == "/next":
            body, ctype = "<!doctype html><title>Next</title><p>next page</p>".encode(), "text/html; charset=utf-8"
        elif self.path == "/crawl":
            body = f"""<!doctype html><html><head><meta charset="utf-8"><title>Crawl</title></head><body>
<a href="/next">next</a>
<a href="/logout">sign out</a>
<a href="http://other.test/">external</a></body></html>""".encode()
            ctype = "text/html; charset=utf-8"
        elif self.path == "/form":
            body = """<!doctype html><html><head><meta charset="utf-8"><title>Form</title></head><body>
<form action="/submit" method="post">
<input name="q" id="q" type="text">
<input name="password" id="pw" type="password">
<select name="lang"><option>uk</option></select>
<button type="submit">Go</button></form></body></html>""".encode()
            ctype = "text/html; charset=utf-8"
        elif self.path == "/ws":
            body = f"""<!doctype html><html><body><script>
window.wsOk = null; window.wsBad = null;
const ok = new WebSocket("ws://127.0.0.1:{WS_PORT}/");
ok.onopen = () => ok.send("ping");
ok.onmessage = (e) => {{ window.wsOk = "echo:" + e.data; }};
ok.onerror = () => {{ window.wsOk = window.wsOk || "error"; }};
const bad = new WebSocket("ws://localhost:{WS_PORT}/");
bad.onopen = () => {{ window.wsBad = "opened"; }};
bad.onerror = () => {{ window.wsBad = "error"; }};
setTimeout(() => {{ window.wsBad = window.wsBad || "timeout"; }}, 4000);
</script></body></html>""".encode()
            ctype = "text/html; charset=utf-8"
        else:
            body, ctype = b"window.hit = 1;", "application/javascript"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_ws_echo():
    """WebSocket echo server on 127.0.0.1 in a separate thread."""
    import websockets

    ready = threading.Event()

    def runner():
        async def echo(ws):
            async for msg in ws:
                await ws.send(msg)

        async def main():
            async with websockets.serve(echo, "127.0.0.1", WS_PORT):
                ready.set()
                await asyncio.Future()

        asyncio.run(main())

    threading.Thread(target=runner, daemon=True).start()
    ready.wait(5)


def make_policy():
    path = Path(TMP) / "policy.json"
    path.write_text(json.dumps({
        "engagement_id": "TEST-BROWSER",
        "mode": "active",
        "authorized_hosts": ["127.0.0.1"],
        "audit_log": f"{TMP}/audit.jsonl",
        "browser_proxy": None,
        "browser_profile_dir": f"{TMP}/profile",
        "screenshots_dir": f"{TMP}/shots",
    }), encoding="utf-8")
    return Policy.load(str(path))


class BrowserGuardTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Site)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        try:
            start_ws_echo()
        except ImportError:
            cls.ws_available = False
        else:
            cls.ws_available = True

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    async def asyncSetUp(self):
        self.browser = GuardedBrowser(make_policy())
        self.base = f"http://127.0.0.1:{self.port}"

    async def asyncTearDown(self):
        await self.browser.close()

    async def _open_or_skip(self, url):
        try:
            return await self.browser.open(url)
        except BrowserError as ex:
            msg = str(ex).lower()
            if "playwright" in msg or "executable" in msg or "browser start" in msg:
                self.skipTest(f"browser is not available: {ex}")
            raise

    # ----- navigation and guard -----

    async def test_crawl_follows_same_host_links_and_skips_sign_out(self):
        out = await self.browser.crawl(f"{self.base}/crawl", max_pages=10, max_depth=2)
        urls = [v["url"] for v in out["visited"]]
        self.assertEqual(urls, [f"{self.base}/crawl", f"{self.base}/next"])
        self.assertGreaterEqual(out["skipped_links"], 2)  # the sign-out link and the external link

    async def test_crawl_stops_at_the_page_limit(self):
        out = await self.browser.crawl(f"{self.base}/crawl", max_pages=1, max_depth=2)
        self.assertEqual(len(out["visited"]), 1)

    async def test_open_in_scope(self):
        out = await self._open_or_skip(self.base + "/")
        self.assertEqual(out["title"], "Test stand")
        self.assertEqual(out["status"], 200)

    async def test_out_of_scope_subresource_is_blocked(self):
        await self._open_or_skip(self.base + "/")
        self.assertIn("localhost", self.browser.blocked)
        text = await self.browser.text()
        self.assertIn("Test patient", text)

    async def test_out_of_scope_navigation_refused_before_browser(self):
        with self.assertRaises(PolicyError):
            await self.browser.open("http://example.org/")

    async def test_links_carry_host(self):
        await self._open_or_skip(self.base + "/")
        hosts = {l["host"] for l in await self.browser.links()}
        self.assertIn("127.0.0.1", hosts)
        self.assertIn("other.test", hosts)

    async def test_click_in_scope_navigates(self):
        await self._open_or_skip(self.base + "/")
        out = await self.browser.click('a[href="/next"]')
        self.assertTrue(out["url"].endswith("/next"))
        self.assertEqual(out["host"], "127.0.0.1")

    async def test_click_to_out_of_scope_is_aborted(self):
        await self._open_or_skip(self.base + "/")
        out = await self.browser.click('a[href="http://other.test/"]')
        self.assertIn("other.test", out["blocked"])
        self.assertNotIn("other.test", out["url"])

    async def test_back_returns_to_previous_page(self):
        await self._open_or_skip(self.base + "/")
        await self.browser.click('a[href="/next"]')
        out = await self.browser.back()
        self.assertTrue(out["url"].endswith("/"))

    async def test_websocket_in_scope_passes_and_out_of_scope_blocked(self):
        if not self.ws_available:
            self.skipTest("websockets is not installed")
        await self._open_or_skip(self.base + "/ws")
        self.assertTrue(self.browser.ws_guarded)
        page = await self.browser._ensure()
        for _ in range(40):
            ok = await page.evaluate("window.wsOk")
            bad = await page.evaluate("window.wsBad")
            if ok and bad:
                break
            await asyncio.sleep(0.1)
        self.assertEqual(ok, "echo:ping")  # 127.0.0.1 is in scope: the connection went through
        self.assertNotEqual(bad, "opened")  # localhost is outside the scope: the connection was cut
        self.assertIn("localhost", self.browser.blocked)

    async def test_navigation_outside_scope_url_prefix_refused(self):
        scoped_path = Path(TMP) / "scoped.json"
        scoped_path.write_text(json.dumps({
            "engagement_id": "TEST-BROWSER", "mode": "active", "environment": "test",
            "authorized_hosts": ["127.0.0.1"], "scope_urls": [f"{self.base}/next"],
            "audit_log": f"{TMP}/audit2.jsonl", "browser_proxy": None,
            "browser_profile_dir": f"{TMP}/profile2", "screenshots_dir": f"{TMP}/shots2",
        }), encoding="utf-8")
        browser = GuardedBrowser(Policy.load(str(scoped_path)))
        try:
            with self.assertRaises(PolicyError):  # the host is allowed, but the path is outside scope_urls
                await browser.open(self.base + "/")
        finally:
            await browser.close()

    # ----- forms and input -----

    async def test_forms_mark_password_as_sensitive(self):
        await self._open_or_skip(self.base + "/form")
        forms = await self.browser.forms()
        fields = {f["name"]: f for f in forms[0]["fields"] if f["name"]}
        self.assertTrue(fields["password"]["sensitive"])
        self.assertFalse(fields["q"]["sensitive"])
        self.assertEqual(forms[0]["action_host"], "127.0.0.1")

    async def test_fill_text_field_works(self):
        await self._open_or_skip(self.base + "/form")
        await self.browser.fill("#q", "test")
        page = await self.browser._ensure()
        self.assertEqual(await page.input_value("#q"), "test")

    async def test_fill_password_refused(self):
        await self._open_or_skip(self.base + "/form")
        with self.assertRaises(PolicyError):
            await self.browser.fill("#pw", "secret")
        with self.assertRaises(PolicyError):
            await self.browser.fill("input[name=password]", "secret")
        page = await self.browser._ensure()
        self.assertEqual(await page.input_value("#pw"), "")

    async def test_fill_rejects_long_or_multiline_value(self):
        await self._open_or_skip(self.base + "/form")
        with self.assertRaises(PolicyError):
            await self.browser.fill("#q", "x" * 301)
        with self.assertRaises(PolicyError):
            await self.browser.fill("#q", "a\nb")

    async def test_press_whitelist(self):
        await self._open_or_skip(self.base + "/form")
        out = await self.browser.press("Escape")
        self.assertEqual(out["key"], "Escape")
        with self.assertRaises(PolicyError):
            await self.browser.press("Delete")

    async def test_wait_for_and_state(self):
        await self._open_or_skip(self.base + "/form")
        self.assertTrue((await self.browser.wait_for("#q", 2000))["found"])
        state = await self.browser.state()
        self.assertEqual(state["forms"], 1)
        self.assertEqual(state["host"], "127.0.0.1")

    # ----- screenshot -----

    async def test_screenshot_written_with_private_permissions(self):
        await self._open_or_skip(self.base + "/")
        out = await self.browser.screenshot()
        path = Path(out["path"])
        self.assertTrue(path.is_file())
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(path.parent.stat().st_mode & 0o777), "0o700")


if __name__ == "__main__":
    unittest.main()
