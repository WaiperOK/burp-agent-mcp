"""Gateway browser: Chromium via Playwright, all traffic goes through the Burp proxy.

Guard: every HTTP request and every WebSocket connection is checked against authorized_hosts;
requests to other hosts are cut before sending. Heavy resources (images, fonts, media) are cut for speed.
The model never fills passwords or secret fields (fill refuses them). The person logs in with the
`login` command: a window opens with the same profile, and the person closes it.

Manual login:
  BURP_AGENT_POLICY=policy.json python browser_guard.py login https://app.example.test/
"""

import asyncio
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from policy import Policy, PolicyError


class BrowserError(Exception):
    pass


SENSITIVE_RE = re.compile(r"pass|pwd|token|otp|secret|card|iban|cvv|passport|ipn|rnokpp|\btax\b|\bpin\b|ssn", re.I)
SENSITIVE_AUTOCOMPLETE = {"current-password", "new-password", "one-time-code", "cc-number", "cc-csc", "cc-exp"}
PRESS_KEYS = {"Enter", "Tab", "Escape", "ArrowDown", "ArrowUp", "Space"}
HEAVY_RESOURCES = {"image", "media", "font"}
MAX_FILL = 300
FORMS_JS = """els => els.map(f => ({
  action: f.action || '', method: (f.method || 'get').toUpperCase(),
  fields: Array.from(f.querySelectorAll('input,select,textarea,button')).map(e => ({
    tag: e.tagName.toLowerCase(), type: (e.type || '').toLowerCase(), name: e.name || '', id: e.id || '',
    autocomplete: e.autocomplete || '',
    sensitive: (e.type || '').toLowerCase() === 'password'
      || /pass|pwd|token|otp|secret|card|iban|cvv|passport|ipn|rnokpp|pin|ssn/i.test((e.name || '') + ' ' + (e.id || ''))
  }))
}))"""


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


# links that sign out or change data are never followed by the crawler
SKIP_LINK_RE = re.compile(r"log-?out|sign-?out|delete|remove|destroy|reset|checkout|payment|unsubscribe", re.I)


class GuardedBrowser:
    def __init__(self, policy: Policy, headless: bool = True):
        self.policy = policy
        self.headless = headless
        self.blocked: list[str] = []  # hosts the guard cut (last 50)
        self.blocked_total = 0
        self.ws_guarded = False
        self._pw = None
        self._ctx = None
        self._page = None
        self._lock = asyncio.Lock()

    # ----- lifecycle -----

    async def _ensure(self):
        if self._page is not None:
            return self._page
        profile = Path(self.policy.browser_profile_dir).expanduser()
        if (profile / "SingletonLock").exists():
            raise BrowserError("browser profile is busy: close the manual login window; "
                               "if this is a leftover from a crash, delete SingletonLock in the profile directory")
        try:
            from playwright.async_api import async_playwright
        except ImportError as ex:
            raise BrowserError("playwright is not installed: pip install playwright && playwright install chromium") from ex
        try:
            self._pw = await async_playwright().start()
            opts = {"headless": self.headless, "ignore_https_errors": True}
            if self.policy.browser_proxy:
                opts["proxy"] = {"server": self.policy.browser_proxy}
            profile.mkdir(parents=True, exist_ok=True)
            self._ctx = await self._pw.chromium.launch_persistent_context(str(profile), **opts)
            await self._ctx.route("**/*", self._guard)
            if hasattr(self._ctx, "route_web_socket"):
                await self._ctx.route_web_socket("**/*", self._ws_guard)
                self.ws_guarded = True
            self._page = self._ctx.pages[0] if self._ctx.pages else await self._ctx.new_page()
            if not self.ws_guarded and hasattr(self._page, "route_web_socket"):
                await self._page.route_web_socket("**/*", self._ws_guard)
                self.ws_guarded = True
        except Exception as ex:
            raise BrowserError(f"browser start failed: {str(ex)[:300]}") from ex
        return self._page

    async def close(self):
        if self._ctx is not None:
            await self._ctx.close()
        if self._pw is not None:
            await self._pw.stop()
        self._ctx = self._pw = self._page = None

    async def sign_in(self, login_url: str, email: str, password: str, *, email_selector: str,
                      password_selector: str, submit_selector: str, response_path: str) -> dict:
        """Signs in with a test account on a local test application, in this browser (through the guard and proxy).

        The caller has checked that the host is local and in scope. The values are typed into the page here and are
        not returned. Only the HTTP status of the sign-in answer comes back.
        """
        async def fn(page):
            await page.goto(login_url, wait_until="domcontentloaded", timeout=20000)
            await page.wait_for_selector(email_selector, timeout=20000)
            await page.fill(email_selector, email, timeout=10000)
            await page.fill(password_selector, password, timeout=10000)
            async with page.expect_response(lambda r: r.url.split("?")[0].endswith(response_path),
                                            timeout=20000) as answer:
                await page.click(submit_selector, timeout=10000)
            status = (await answer.value).status
            return {"signed_in": status == 200, "status": status}
        return await self._act(fn)

    async def crawl(self, start_url: str, *, max_pages: int, max_depth: int) -> dict:
        """Opens the pages reachable from start_url by links on the same host and port, breadth first.

        Each page load goes through the guard and the proxy, so its traffic lands in Burp history. Links that sign out
        or change data (logout, delete, reset, checkout, payment) are skipped. Nothing is typed or submitted.
        """
        origin = urlsplit(start_url).netloc

        async def fn(page):
            visited, queue, seen, skipped = [], [(start_url, 0)], {start_url}, 0
            while queue and len(visited) < max_pages:
                url, depth = queue.pop(0)
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=20000)
                    await page.wait_for_timeout(1000)  # let the page's own requests run
                except Exception as ex:  # a page that fails is reported; the crawl goes on
                    visited.append({"url": url, "error": type(ex).__name__})
                    continue
                if urlsplit(page.url).netloc != origin:  # a redirect pointed off the target: the guard cut it there
                    visited.append({"url": page.url, "left_target": True})
                    continue
                visited.append({"url": page.url})
                if depth >= max_depth:
                    continue
                hrefs = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                for href in hrefs:
                    parts = urlsplit(href)
                    if parts.scheme not in ("http", "https") or parts.netloc != origin or SKIP_LINK_RE.search(href):
                        skipped += 1
                        continue
                    if href not in seen:
                        seen.add(href)
                        queue.append((href, depth + 1))
            return {"visited": visited, "left_in_queue": len(queue), "skipped_links": skipped}
        return await self._act(fn)

    async def bearer_token(self) -> str | None:
        """The bearer token the signed-in page keeps in localStorage, if any. Used inside the gateway, never returned."""
        async def fn(page):
            return {"token": await page.evaluate("() => localStorage.getItem('token')")}
        return (await self._act(fn)).get("token") or None

    # ----- guard -----

    def _note_blocked(self, host: str) -> None:
        self.blocked = (self.blocked + [host])[-50:]
        self.blocked_total += 1

    async def _guard(self, route):
        req = route.request
        host = _host(req.url)
        # navigation is checked by URL (scope_urls), page resources by host
        out_of_scope = not self.policy.host_in_scope(host) or (
            req.resource_type == "document" and not self.policy.url_in_scope(req.url))
        if out_of_scope:
            self._note_blocked(host)
            await route.abort("blockedbyclient")
            return
        if self.policy.block_heavy_resources and req.resource_type in HEAVY_RESOURCES:
            await route.abort("blockedbyclient")  # saves time; not counted as a scope block
            return
        await route.continue_()

    async def _ws_guard(self, ws):
        host = _host(ws.url)
        if self.policy.host_in_scope(host):
            ws.connect_to_server()
        else:
            self._note_blocked(host)
            await ws.close()

    # ----- actions -----

    async def _act(self, fn):
        async with self._lock:
            page = await self._ensure()
            start = self.blocked_total
            try:
                result = await fn(page)
            except (BrowserError, PolicyError):
                raise
            except Exception as ex:
                new = self.blocked_total - start
                note = f"; blocked hosts: {', '.join(self.blocked[-new:])}" if new else ""
                raise BrowserError(f"{type(ex).__name__}: {str(ex)[:300]}{note}") from None
            new = self.blocked_total - start
            result["blocked"] = self.blocked[-new:] if new else []
            return result

    async def open(self, url: str) -> dict:
        if not self.policy.url_in_scope(url):
            raise PolicyError(f"url is not in scope: {_host(url)}")

        async def fn(page):
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            return {"url": page.url, "title": await page.title(), "status": resp.status if resp else None}

        return await self._act(fn)

    async def state(self) -> dict:
        async def fn(page):
            forms = await page.eval_on_selector_all("form", "els => els.length")
            return {"url": page.url, "title": await page.title(), "host": _host(page.url),
                    "forms": forms, "ws_guarded": self.ws_guarded}
        return await self._act(fn)

    async def text(self) -> str:
        async def fn(page):
            return {"text": await page.inner_text("body", timeout=5000)}
        return (await self._act(fn))["text"]

    async def links(self) -> list[dict]:
        async def fn(page):
            rows = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => ({text: (e.innerText || '').trim().slice(0, 200), href: e.href}))")
            return {"links": rows}
        rows = (await self._act(fn))["links"]
        for row in rows:
            row["host"] = _host(row["href"])
        return rows

    async def forms(self) -> list[dict]:
        async def fn(page):
            return {"forms": await page.eval_on_selector_all("form", FORMS_JS)}
        out = []
        for form in (await self._act(fn))["forms"]:
            form["action_host"] = _host(form["action"]) if form["action"] else _host(await self._current_url())
            out.append(form)
        return out

    async def _current_url(self) -> str:
        async with self._lock:
            page = await self._ensure()
            return page.url

    async def wait_for(self, selector: str, timeout_ms: int = 5000) -> dict:
        timeout_ms = max(100, min(int(timeout_ms), 15000))

        async def fn(page):
            await page.wait_for_selector(selector, timeout=timeout_ms)
            return {"found": True}
        return await self._act(fn)

    async def click(self, selector: str) -> dict:
        async def fn(page):
            await page.click(selector, timeout=10000)
            await page.wait_for_load_state("domcontentloaded", timeout=15000)
            return {"url": page.url, "title": await page.title(), "host": _host(page.url)}
        return await self._act(fn)

    async def fill(self, selector: str, value: str) -> dict:
        if len(value) > MAX_FILL or "\n" in value or "\r" in value:
            raise PolicyError("value is too long or multiline")

        async def fn(page):
            info = await page.eval_on_selector(
                selector,
                "e => ({type: (e.type || '').toLowerCase(), name: e.name || '', id: e.id || '', "
                "ac: e.autocomplete || ''})")
            if (info["type"] == "password" or SENSITIVE_RE.search(info["name"] + " " + info["id"])
                    or info["ac"] in SENSITIVE_AUTOCOMPLETE):
                raise PolicyError("field looks like a secret or password: the agent does not fill it; "
                                  "log in manually with the login command")
            await page.fill(selector, value, timeout=10000)
            return {"filled": True}
        return await self._act(fn)

    async def press(self, key: str) -> dict:
        if key not in PRESS_KEYS:
            raise PolicyError(f"key is not allowed: {key}; allowed: {sorted(PRESS_KEYS)}")

        async def fn(page):
            await page.keyboard.press(key)
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=3000)
            except Exception:
                pass  # the key press may not have triggered navigation
            return {"url": page.url, "host": _host(page.url), "key": key}
        return await self._act(fn)

    async def back(self) -> dict:
        async def fn(page):
            await page.go_back(wait_until="domcontentloaded", timeout=15000)
            return {"url": page.url, "host": _host(page.url)}
        return await self._act(fn)

    async def reload(self) -> dict:
        async def fn(page):
            await page.reload(wait_until="domcontentloaded", timeout=30000)
            return {"url": page.url, "host": _host(page.url)}
        return await self._act(fn)

    async def screenshot(self) -> dict:
        shots = Path(self.policy.screenshots_dir).expanduser()
        shots.mkdir(parents=True, exist_ok=True)
        os.chmod(shots, 0o700)
        path = shots / f"{int(time.time() * 1000)}.png"

        async def fn(page):
            await page.screenshot(path=str(path))
            return {"path": str(path)}
        out = await self._act(fn)
        os.chmod(path, 0o600)
        return out


async def _manual_login(url: str) -> None:
    """Visible window with the same profile. The person logs in and the person closes the window."""
    policy_path = os.environ.get("BURP_AGENT_POLICY")
    if not policy_path:
        sys.exit("BURP_AGENT_POLICY is not set")
    policy = Policy.load(policy_path)
    if not policy.host_in_scope(_host(url)):
        sys.exit(f"host is not in authorized scope: {_host(url)}")

    from playwright.async_api import async_playwright

    profile = str(Path(policy.browser_profile_dir).expanduser())
    async with async_playwright() as pw:
        opts = {"headless": False, "ignore_https_errors": True}
        if policy.browser_proxy:
            opts["proxy"] = {"server": policy.browser_proxy}
        ctx = await pw.chromium.launch_persistent_context(profile, **opts)
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()
        await page.goto(url)
        print("Log in to the application by hand, then close the browser window.")
        await ctx.wait_for_event("close", timeout=0)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "login":
        asyncio.run(_manual_login(sys.argv[2]))
    else:
        print("usage: python browser_guard.py login <url>")
        sys.exit(2)
