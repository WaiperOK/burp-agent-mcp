"""Persistent connection to the official Burp MCP Server (SSE).

Previously every call opened a new SSE session (about 17 ms). Here one session lives in a background task,
and calls go through a queue (about 2 ms). The background task owns the anyio contexts entirely: they cannot be
opened and closed from different tasks. The connection is re-established with exponential backoff.
"""

import asyncio
import contextlib

from mcp import ClientSession
from mcp.client.sse import sse_client


class UpstreamError(RuntimeError):
    pass


class UpstreamClient:
    def __init__(self, url: str, call_timeout: float = 60, connect_timeout: float = 5):
        self.url = url
        self.call_timeout = call_timeout
        self.connect_timeout = connect_timeout
        self._queue: asyncio.Queue | None = None
        self._task: asyncio.Task | None = None
        self._connected = asyncio.Event()
        self._last_error = ""
        self.calls = 0  # for debugging and measurements

    def _ensure_task(self) -> None:
        if self._task is None or self._task.done():
            self._queue = asyncio.Queue()
            self._connected = asyncio.Event()
            self._task = asyncio.create_task(self._run())

    async def call(self, tool: str, arguments: dict) -> str:
        self._ensure_task()
        if not self._connected.is_set():
            try:
                await asyncio.wait_for(self._connected.wait(), self.connect_timeout)
            except asyncio.TimeoutError:
                raise UpstreamError(f"upstream unavailable: {self._last_error or 'not connected'}") from None
        fut = asyncio.get_running_loop().create_future()
        await self._queue.put((tool, arguments, fut))
        self.calls += 1
        try:
            return await asyncio.wait_for(fut, self.call_timeout)
        except asyncio.TimeoutError:
            raise UpstreamError(f"upstream {tool} timed out") from None

    async def close(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task

    async def _run(self) -> None:
        backoff = 0.5
        while True:
            try:
                async with sse_client(self.url) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        self._connected.set()
                        self._last_error = ""
                        backoff = 0.5
                        while True:
                            tool, arguments, fut = await self._queue.get()
                            if fut.done():  # the caller has already left on timeout
                                continue
                            try:
                                # a timeout here too: a hung Burp must not block the queue forever
                                result = await asyncio.wait_for(
                                    session.call_tool(tool, arguments), self.call_timeout)
                            except BaseException as ex:  # the connection may drop or hang
                                if isinstance(ex, asyncio.CancelledError):
                                    raise
                                if not fut.done():
                                    fut.set_exception(UpstreamError(f"upstream {tool} failed: {str(ex)[:200]}"))
                                raise
                            text = "".join(getattr(c, "text", "") for c in result.content)
                            if fut.done():
                                continue
                            if result.isError:
                                fut.set_exception(UpstreamError(f"upstream {tool} error: {text[:500]}"))
                            else:
                                fut.set_result(text)
            except asyncio.CancelledError:
                self._fail_pending("client closed")
                raise
            except BaseException as ex:  # reconnect; BaseExceptionGroup comes from anyio
                reason = ex.exceptions[0] if isinstance(ex, BaseExceptionGroup) and ex.exceptions else ex
                self._last_error = str(reason)[:200]
                self._connected.clear()
                self._fail_pending(self._last_error)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 10)

    def _fail_pending(self, reason: str) -> None:
        while self._queue is not None and not self._queue.empty():
            _, _, fut = self._queue.get_nowait()
            if not fut.done():
                fut.set_exception(UpstreamError(f"upstream unavailable: {reason}"))
