"""Тесты клиента upstream: Burp недоступен и восстанавливается.

Настоящий SSE-сервер MCP поднимается в потоке (uvicorn + FastMCP), его останавливают и запускают снова.
Запуск: python tests/test_upstream.py
"""

import asyncio
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

from upstream import UpstreamClient, UpstreamError  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_fake_burp():
    m = FastMCP("fake-burp")

    @m.tool()
    def get_proxy_http_history(count: int, offset: int) -> str:
        return "Reached end of items"

    return m.sse_app()


class FakeBurp:
    """Фейковый Burp MCP по SSE, который можно остановить и поднять на том же порту."""

    def __init__(self, port: int):
        self.port = port
        self.server = None
        self.thread = None

    def start(self):
        config = uvicorn.Config(make_fake_burp(), host="127.0.0.1", port=self.port, log_level="error")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.time() + 5
        while not self.server.started and time.time() < deadline:
            time.sleep(0.05)

    def stop(self):
        if self.server is not None:
            self.server.should_exit = True
            self.thread.join(5)
            self.server = None


class UnavailableTests(unittest.IsolatedAsyncioTestCase):
    async def test_unreachable_burp_fails_fast_with_reason(self):
        client = UpstreamClient("http://127.0.0.1:1/", call_timeout=5, connect_timeout=2)
        t = time.perf_counter()
        with self.assertRaises(UpstreamError) as ctx:
            await client.call("get_proxy_http_history", {"count": 1, "offset": 0})
        self.assertLess(time.perf_counter() - t, 4.5)
        self.assertIn("upstream unavailable", str(ctx.exception))
        await client.close()


class ReconnectTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_recovers_after_burp_restart(self):
        port = free_port()
        burp = FakeBurp(port)
        burp.start()
        client = UpstreamClient(f"http://127.0.0.1:{port}/sse", call_timeout=3, connect_timeout=2)
        try:
            self.assertEqual(await client.call("get_proxy_http_history", {"count": 1, "offset": 0}),
                             "Reached end of items")
            calls_before = client.calls

            burp.stop()  # Burp упал
            with self.assertRaises(UpstreamError):
                await client.call("get_proxy_http_history", {"count": 1, "offset": 0})

            burp.start()  # Burp снова поднят на том же порту
            recovered = False
            for _ in range(60):  # клиент сам переподключается с экспоненциальной паузой
                try:
                    out = await client.call("get_proxy_http_history", {"count": 1, "offset": 0})
                    recovered = out == "Reached end of items"
                    break
                except UpstreamError:
                    await asyncio.sleep(0.5)
            self.assertTrue(recovered, "клиент не восстановился после перезапуска Burp")
            self.assertGreater(client.calls, calls_before)
        finally:
            await client.close()
            burp.stop()


if __name__ == "__main__":
    unittest.main()
